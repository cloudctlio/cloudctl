"""Declared layer of the system model, read from IaC artifacts.

Supported inputs (all read from files; nothing here calls a cloud API or runs
terraform/cdk):

  * Terraform state JSON (format version 4; ``terraform state pull`` output)
  * Terraform plan JSON (``terraform show -json <planfile>``)
  * CloudFormation templates (JSON, or YAML without short-form tags) and
    CDK synth output (``cdk.out/`` with ``manifest.json``)

Each resource becomes a node carrying its declared config and its IaC address
(Terraform address or ``Stack/LogicalId``), the source file where known, and a
module path (Terraform module, or CDK construct path). References between
resources become ``declared`` edges.

Known gaps (honest limits, listed so callers can report them):
  * Terraform state records no source file, only the address.
  * References through ``module.<name>.<output>`` are not followed into the
    child module's resources (no output -> resource mapping without the source).
  * CloudFormation short-form YAML tags (!Ref, !GetAtt, !Sub) need a loader
    that knows them; :func:`load_cfn_template` registers one.
"""
from __future__ import annotations

import json
import os
import re

from cloudctl.verify.model import Node, SystemModel

# ── Terraform ────────────────────────────────────────────────────────────────


def _tf_address(module: str, rtype: str, name: str, index_key=None) -> str:
    base = f"{module + '.' if module else ''}{rtype}.{name}"
    if index_key is None:
        return base
    if isinstance(index_key, str):
        return f'{base}["{index_key}"]'
    return f"{base}[{index_key}]"


def _strip_index(address: str) -> str:
    return re.sub(r"\[[^\]]*\]$", "", address)


def _tf_name_from_attrs(attrs: dict) -> str:
    for k in ("name", "function_name", "bucket", "role_name", "cluster_name",
              "queue_name", "table_name", "identifier"):
        v = attrs.get(k)
        if isinstance(v, str) and v:
            return v
    return ""


def load_terraform_state(model: SystemModel, state: dict, source_file: str = "") -> dict:
    """Fold a Terraform v4 state document into the declared layer.

    Edges come from each instance's recorded ``dependencies`` (Terraform's own
    record of references) plus ARNs or names of other resources that appear in
    an instance's attribute values. Returns counts for reporting."""
    if not isinstance(state, dict) or state.get("version") != 4:
        raise ValueError("expected Terraform state format version 4")
    added: list[tuple[str, list[str], dict]] = []
    groups: dict[str, list[str]] = {}
    for res in state.get("resources") or []:
        if res.get("mode") != "managed":
            continue  # data sources are reads, not parts of the system
        module = res.get("module", "")
        rtype, name = res.get("type", ""), res.get("name", "")
        for inst in res.get("instances") or []:
            attrs = inst.get("attributes") or {}
            addr = _tf_address(module, rtype, name, inst.get("index_key"))
            arn = attrs.get("arn") if isinstance(attrs.get("arn"), str) else ""
            node = model.add_node(Node(
                id=arn or addr, type=rtype, name=_tf_name_from_attrs(attrs), arn=arn or "",
                iac_address=addr, iac_file=source_file, iac_module=module,
                declared=attrs,
            ), "declared")
            groups.setdefault(_strip_index(addr), []).append(node.id)
            added.append((node.id, list(inst.get("dependencies") or []), attrs))
    edges = 0
    for nid, deps, attrs in added:
        for dep in deps:
            # A dependency on a counted/for_each resource means every instance.
            for target in groups.get(_strip_index(dep), [dep]):
                if model.add_edge(nid, target, "declared", via="tf_dependency", detail=dep):
                    edges += 1
        for dst in sorted(model.find_references(json.dumps(attrs, default=str), exclude=nid)):
            if model.add_edge(nid, dst, "declared", via="tf_value_ref"):
                edges += 1
    return {"resources": len(added), "edges": edges}


def _plan_modules(mod: dict, prefix: str = ""):
    """Yield (module_address, module_dict) for planned_values module trees."""
    yield mod.get("address", prefix), mod
    for child in mod.get("child_modules") or []:
        yield from _plan_modules(child, child.get("address", ""))


def _config_modules(mod: dict, prefix: str = ""):
    """Yield (module_address, module_config) for configuration module trees."""
    yield prefix, mod
    for call_name, call in (mod.get("module_calls") or {}).items():
        child_prefix = f"{prefix + '.' if prefix else ''}module.{call_name}"
        yield from _config_modules(call.get("module") or {}, child_prefix)


def _ref_to_address(ref: str, module_prefix: str) -> str | None:
    """``aws_iam_role.r.arn`` -> ``[module.x.]aws_iam_role.r``. Skips vars,
    locals, data sources, module outputs, and self/each/count."""
    parts = ref.split(".")
    if len(parts) < 2 or parts[0] in ("var", "local", "data", "module", "path",
                                      "terraform", "self", "each", "count"):
        return None
    head = f"{parts[0]}.{_strip_index(parts[1])}"
    return f"{module_prefix + '.' if module_prefix else ''}{head}"


def load_terraform_plan(model: SystemModel, plan: dict, source_file: str = "") -> dict:
    """Fold ``terraform show -json`` output into the declared layer: nodes from
    ``planned_values`` (falling back to ``prior_state``), edges from the
    ``references`` of every expression in ``configuration``."""
    if not isinstance(plan, dict) or "format_version" not in plan:
        raise ValueError("expected terraform show -json output (missing format_version)")
    count = 0
    groups: dict[str, list[str]] = {}
    root = (plan.get("planned_values") or {}).get("root_module") or \
           ((plan.get("prior_state") or {}).get("values") or {}).get("root_module") or {}
    for mod_addr, mod in _plan_modules(root):
        for r in mod.get("resources") or []:
            if r.get("mode", "managed") != "managed":
                continue
            vals = r.get("values") or {}
            arn = vals.get("arn") if isinstance(vals.get("arn"), str) else ""
            addr = r.get("address", "")
            model.add_node(Node(
                id=arn or addr, type=r.get("type", ""), name=_tf_name_from_attrs(vals),
                arn=arn or "", iac_address=addr, iac_file=source_file,
                iac_module=mod_addr or "", declared=vals,
            ), "declared")
            groups.setdefault(_strip_index(addr), []).append(model.resolve(addr) or addr)
            count += 1
    edges = 0
    cfg_root = (plan.get("configuration") or {}).get("root_module") or {}
    for prefix, mod in _config_modules(cfg_root):
        for r in mod.get("resources") or []:
            if r.get("mode", "managed") != "managed":
                continue
            src_base = f"{prefix + '.' if prefix else ''}{r.get('type')}.{r.get('name')}"
            for attr, refs in _expression_refs(r.get("expressions") or {}):
                for ref in refs:
                    dst = _ref_to_address(ref, prefix)
                    if not dst:
                        continue
                    for src in groups.get(src_base, [src_base]):
                        for target in groups.get(dst, [dst]):
                            if model.add_edge(src, target, "declared", via="tf_ref",
                                              detail=f"{attr} <- {ref}"):
                                edges += 1
    return {"resources": count, "edges": edges}


def _expression_refs(exprs, path: str = ""):
    """Walk a configuration expressions tree yielding (attr_path, [refs])."""
    if isinstance(exprs, dict):
        if "references" in exprs and isinstance(exprs["references"], list):
            yield path, exprs["references"]
        for k, v in exprs.items():
            if k in ("references", "constant_value"):
                continue
            yield from _expression_refs(v, f"{path}.{k}" if path else k)
    elif isinstance(exprs, list):
        for i, v in enumerate(exprs):
            yield from _expression_refs(v, f"{path}[{i}]")


# ── CloudFormation / CDK ─────────────────────────────────────────────────────


def _cfn_refs(obj) -> list[tuple[str, str]]:
    """(logical_id, how) for every Ref / GetAtt / Sub reference in a value."""
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "Ref" and isinstance(v, str):
                out.append((v, "Ref"))
            elif k == "Fn::GetAtt":
                if isinstance(v, list) and v:
                    out.append((str(v[0]), "GetAtt"))
                elif isinstance(v, str):
                    out.append((v.split(".")[0], "GetAtt"))
            elif k == "Fn::Sub":
                tmpl = v[0] if isinstance(v, list) and v else v
                if isinstance(tmpl, str):
                    for m in re.findall(r"\$\{([^}!][^}]*)\}", tmpl):
                        out.append((m.split(".")[0], "Sub"))
                if isinstance(v, list) and len(v) > 1:
                    out.extend(_cfn_refs(v[1]))
            else:
                out.extend(_cfn_refs(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_cfn_refs(v))
    return out


def _cfn_physical_name(rtype: str, props: dict) -> str:
    """The generic CloudFormation naming convention ``<TypeSuffix>Name``
    (Function -> FunctionName, Table -> TableName, Role -> RoleName)."""
    suffix = rtype.split("::")[-1] if rtype else ""
    v = props.get(f"{suffix}Name")
    return v if isinstance(v, str) else ""


def load_cfn_template(model: SystemModel, template: dict, stack: str,
                      source_file: str = "", physical_ids: dict | None = None) -> dict:
    """Fold one CloudFormation template into the declared layer.

    ``physical_ids`` optionally maps logical id -> physical id or ARN (from
    ``describe_stack_resources``, recorded); it is what joins template
    resources to live nodes when the template does not set a physical name."""
    physical_ids = physical_ids or {}
    resources = (template or {}).get("Resources") or {}
    pseudo = {"AWS::Region", "AWS::AccountId", "AWS::StackName", "AWS::Partition",
              "AWS::URLSuffix", "AWS::NoValue", "AWS::StackId"}
    params = set(((template or {}).get("Parameters") or {}).keys())
    for lid, res in resources.items():
        props = res.get("Properties") or {}
        meta = res.get("Metadata") or {}
        phys = physical_ids.get(lid, "")
        arn = phys if isinstance(phys, str) and phys.startswith("arn:") else ""
        name = _cfn_physical_name(res.get("Type", ""), props) or (
            phys if phys and not arn else "")
        addr = f"{stack}/{lid}"
        model.add_node(Node(
            id=arn or addr, type=res.get("Type", ""), name=name, arn=arn,
            iac_address=addr, iac_file=source_file,
            iac_module=meta.get("aws:cdk:path", stack), declared=props,
        ), "declared")
    edges = 0
    for lid, res in resources.items():
        src = f"{stack}/{lid}"
        refs = _cfn_refs(res.get("Properties") or {})
        deps = res.get("DependsOn") or []
        refs += [(d, "DependsOn") for d in ([deps] if isinstance(deps, str) else deps)]
        for target, how in refs:
            if target in pseudo or target in params or target not in resources:
                continue
            if model.add_edge(src, f"{stack}/{target}", "declared", via=f"cfn_{how}"):
                edges += 1
    return {"resources": len(resources), "edges": edges}


def _yaml_cfn_loader():
    import yaml

    class _Loader(yaml.SafeLoader):
        pass

    def _multi(loader, suffix, node):
        tag = "Fn::" + suffix if suffix not in ("Ref", "Condition") else suffix
        if isinstance(node, yaml.ScalarNode):
            val = loader.construct_scalar(node)
            if suffix == "GetAtt":
                val = val.split(".", 1)
        elif isinstance(node, yaml.SequenceNode):
            val = loader.construct_sequence(node, deep=True)
        else:
            val = loader.construct_mapping(node, deep=True)
        return {tag: val}

    _Loader.add_multi_constructor("!", _multi)
    return _Loader


def read_template_file(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        import yaml
        return yaml.load(text, Loader=_yaml_cfn_loader())


def load_cdk_out(model: SystemModel, cdk_out_dir: str,
                 physical_ids: dict | None = None) -> dict:
    """Read every stack template listed in ``cdk.out/manifest.json``.
    ``physical_ids`` maps stack name -> {logical id -> physical id}."""
    with open(os.path.join(cdk_out_dir, "manifest.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    totals = {"stacks": 0, "resources": 0, "edges": 0}
    for art_id, art in sorted((manifest.get("artifacts") or {}).items()):
        if art.get("type") != "aws:cloudformation:stack":
            continue
        tfile = (art.get("properties") or {}).get("templateFile")
        if not tfile:
            continue
        stack = (art.get("properties") or {}).get("stackName") or art_id
        path = os.path.join(cdk_out_dir, tfile)
        res = load_cfn_template(model, read_template_file(path), stack, source_file=path,
                                physical_ids=(physical_ids or {}).get(stack))
        totals["stacks"] += 1
        totals["resources"] += res["resources"]
        totals["edges"] += res["edges"]
    return totals


def load_iac_path(model: SystemModel, path: str, physical_ids: dict | None = None) -> dict:
    """Load one IaC artifact, detecting its kind from content."""
    if os.path.isdir(path):
        if os.path.exists(os.path.join(path, "manifest.json")):
            return {"kind": "cdk", **load_cdk_out(model, path, physical_ids)}
        raise ValueError(f"{path}: directory without cdk manifest.json")
    doc = read_template_file(path)
    if isinstance(doc, dict) and doc.get("version") == 4 and "resources" in doc:
        return {"kind": "terraform_state", **load_terraform_state(model, doc, path)}
    if isinstance(doc, dict) and "format_version" in doc and (
            "planned_values" in doc or "configuration" in doc):
        return {"kind": "terraform_plan", **load_terraform_plan(model, doc, path)}
    if isinstance(doc, dict) and "Resources" in doc:
        stack = os.path.splitext(os.path.basename(path))[0].replace(".template", "")
        return {"kind": "cloudformation",
                **load_cfn_template(model, doc, stack, path, (physical_ids or {}).get(stack))}
    raise ValueError(f"{path}: not a recognised Terraform state/plan or CloudFormation template")
