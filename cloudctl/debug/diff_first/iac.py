"""Expected-state adapters: read what the user's IaC says SHOULD be deployed.

Every adapter turns its tool's own format into the same ``ExpectedState`` (a
dict of ``Resource`` keyed by IaC address, with CloudFormation type names), so
the drift, window, flow and explain checks never care which IaC was used.

Adapters shipped here:

* ``TerraformAdapter``  - local ``terraform.tfstate``, ``terraform show -json``
  output, or a plan JSON (its ``resource_drift`` is Terraform's own refresh diff).
* ``CloudFormationAdapter`` - plain templates and CDK (``cdk.out``), with the
  deployed stack's resources and CloudFormation's own drift-detection results.
* ``PulumiAdapter`` - ``pulumi stack export`` JSON (file or CLI).
* ``BaselineAdapter`` - no IaC at all: a last-known-good snapshot from cctl's own
  baseline file or AWS Config history at the last healthy time.

Anything else plugs in by subclassing ``IaCAdapter`` and appending to
``ADAPTERS``. All adapters are read-only: they never run plan/apply/deploy, and
the only commands they may run are ``terraform show -json`` and
``pulumi stack export`` (both read state, change nothing).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cloudctl.debug.diff_first.model import DriftItem, Resource
from cloudctl.debug.diff_first.normalize import canonical_type, get_field, norm_key

_NAME_FIELDS = ("function_name", "functionname", "name", "bucket", "bucketname",
                "table_name", "tablename", "queue_name", "queuename", "topic_name",
                "rule_name", "role_name", "rolename", "policy_name", "policyname",
                "statemachinename", "streamname", "servicename", "apiname")


def _first_str(config: dict, names: tuple[str, ...]) -> str:
    v = get_field(config, *names)
    return v if isinstance(v, str) else ""


def own_arn(cfn_type: str, value) -> str:
    """An ``arn`` field is the resource's own only when it is of the same
    service: an EventBridge target's ``arn`` is the function it invokes."""
    from cloudctl.debug.diff_first.resolve import arn_service, type_service
    if not isinstance(value, str) or not value.startswith("arn:"):
        return ""
    return value if arn_service(value) == type_service(cfn_type) else ""


def own_name(cfn_type: str, config: dict) -> str:
    """The resource's OWN name. A field only counts when it is plain ``name`` or
    names this type (``FunctionName`` on a function, ``QueueName`` on a queue):
    an event-source mapping's ``function_name`` names the function, not the
    mapping, so it must not become the mapping's name."""
    import re as _re
    if not isinstance(config, dict):
        return ""
    last = cfn_type.split("::")[-1]
    last_n = norm_key(last)
    words = [w.lower() for w in _re.findall(r"[A-Z][a-z0-9]*", last)] or [last_n]
    best = ""
    for k, v in config.items():
        if not isinstance(v, str) or not v or v.startswith(("arn:", "https://", "{")):
            continue
        nk = norm_key(k)
        if nk == "name" or (last_n and last_n in nk and nk.endswith("name")) or \
                nk == f"{words[-1]}name" or (nk == last_n):
            if nk == "name":
                return v
            best = best or v
    return best


@dataclass
class ExpectedState:
    kind: str                                   # terraform | cloudformation | cdk | pulumi | baseline | none
    root: str = ""
    resources: dict[str, Resource] = field(default_factory=dict)
    drift: list[DriftItem] = field(default_factory=list)   # drift the tool itself computed
    notes: list[str] = field(default_factory=list)
    unavailable: str = ""                       # why nothing could be read
    taken_at: str | None = None                 # baselines: when the snapshot was taken

    def merge(self, other: "ExpectedState") -> None:
        for k, r in other.resources.items():
            self.resources.setdefault(k, r)
        self.drift.extend(other.drift)
        self.notes.extend(other.notes)


class IaCAdapter:
    name = "base"

    def detect(self, root: Path) -> bool:  # pragma: no cover - interface
        raise NotImplementedError

    def load(self, root: Path, live: Any = None, **kw) -> ExpectedState:  # pragma: no cover
        raise NotImplementedError


def _run_readonly(cmd: list[str], cwd: Path, timeout: int = 60) -> str | None:
    """Run a state-READING command (never plan/apply/deploy). None on any failure."""
    if not shutil.which(cmd[0]):
        return None
    try:
        out = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True,
                             timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout if out.returncode == 0 and out.stdout.strip() else None


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


# ── Terraform ────────────────────────────────────────────────────────────────

class TerraformAdapter(IaCAdapter):
    name = "terraform"

    def detect(self, root: Path) -> bool:
        return any(root.glob("*.tf")) or any(root.glob("*.tf.json")) or (root / "terraform.tfstate").exists()

    def load(self, root: Path, live: Any = None, **kw) -> ExpectedState:
        st = ExpectedState(kind="terraform", root=str(root))
        data = None
        src = ""
        env_state = os.environ.get("CLOUDCTL_TF_STATE_JSON")
        if env_state and Path(env_state).is_file():
            data, src = _load_json(Path(env_state)), env_state
        elif (root / "terraform.tfstate").is_file():
            data, src = _load_json(root / "terraform.tfstate"), "terraform.tfstate"
        elif os.environ.get("CLOUDCTL_TF_SHOW", "1") != "0":
            raw = _run_readonly(["terraform", "show", "-json"], root)
            if raw:
                try:
                    data, src = json.loads(raw), "terraform show -json"
                except ValueError:
                    data = None
        if data:
            for r in self.parse_state(data):
                st.resources[r.key] = r
            st.notes.append(f"Terraform state read from {src} ({len(st.resources)} resources)")
        else:
            st.unavailable = ("no Terraform state found: no terraform.tfstate in the root, no "
                              "CLOUDCTL_TF_STATE_JSON, and `terraform show -json` was unavailable")
        plan = os.environ.get("CLOUDCTL_TF_PLAN_JSON")
        if plan and Path(plan).is_file():
            pdata = _load_json(Path(plan)) or {}
            st.drift.extend(self.parse_plan_drift(pdata))
            st.notes.append(f"Terraform plan drift read from {plan}")
        return st

    @staticmethod
    def _resource(address: str, tf_type: str, attrs: dict) -> Resource:
        return Resource(
            key=address,
            type=canonical_type(tf_type),
            name=own_name(canonical_type(tf_type), attrs),
            physical_id=str(attrs.get("id") or ""),
            arn=own_arn(canonical_type(tf_type), attrs.get("arn")),
            config={k: v for k, v in attrs.items()},
            source="terraform",
            source_type=tf_type,
        )

    @classmethod
    def parse_state(cls, data: dict) -> list[Resource]:
        out: list[Resource] = []
        if "values" in data:                     # terraform show -json
            def walk(mod: dict) -> None:
                for r in mod.get("resources", []) or []:
                    if r.get("mode", "managed") != "managed":
                        continue
                    out.append(cls._resource(r.get("address") or f"{r['type']}.{r['name']}",
                                             r.get("type", ""), r.get("values") or {}))
                for child in mod.get("child_modules", []) or []:
                    walk(child)
            walk((data.get("values") or {}).get("root_module") or {})
            return out
        for r in data.get("resources", []) or []:  # raw state v4
            if r.get("mode", "managed") != "managed":
                continue
            base = f"{r['module']}." if r.get("module") else ""
            addr = f"{base}{r.get('type')}.{r.get('name')}"
            insts = r.get("instances") or []
            for inst in insts:
                idx = inst.get("index_key")
                key = addr if idx is None else (f'{addr}["{idx}"]' if isinstance(idx, str) else f"{addr}[{idx}]")
                out.append(cls._resource(key, r.get("type", ""), inst.get("attributes") or {}))
        return out

    @staticmethod
    def parse_plan_drift(plan: dict) -> list[DriftItem]:
        """Terraform's own refresh comparison (`resource_drift` in plan JSON)."""
        items: list[DriftItem] = []
        for rd in plan.get("resource_drift", []) or []:
            ch = rd.get("change") or {}
            before, after = ch.get("before") or {}, ch.get("after") or {}
            actions = ch.get("actions") or []
            if "delete" in actions and not after:
                items.append(DriftItem(rd.get("address", ""), canonical_type(rd.get("type", "")),
                                       str(before.get("function_name") or before.get("name") or ""),
                                       [], kind="deleted", source="terraform plan"))
                continue
            fields = [{"field": k, "expected": before.get(k), "live": after.get(k)}
                      for k in sorted(set(before) | set(after))
                      if norm_key(k) not in ("tagsall", "lastmodified") and before.get(k) != after.get(k)]
            if fields:
                items.append(DriftItem(rd.get("address", ""), canonical_type(rd.get("type", "")),
                                       str(after.get("function_name") or after.get("name") or ""),
                                       fields[:20], source="terraform plan"))
        return items


# ── CloudFormation and CDK ───────────────────────────────────────────────────

def _cfn_yaml_load(text: str) -> Any:
    import yaml

    class _Loader(yaml.SafeLoader):
        pass

    def _tag(loader, suffix, node):  # !Ref x -> {"Ref": x}, !GetAtt a.b -> {"Fn::GetAtt": ...}
        name = "Ref" if suffix == "Ref" else f"Fn::{suffix}"
        if isinstance(node, yaml.ScalarNode):
            return {name: loader.construct_scalar(node)}
        if isinstance(node, yaml.SequenceNode):
            return {name: loader.construct_sequence(node, deep=True)}
        return {name: loader.construct_mapping(node, deep=True)}

    _Loader.add_multi_constructor("!", _tag)
    return yaml.load(text, Loader=_Loader)  # noqa: S506  # nosec B506 - SafeLoader subclass that only adds CFN !Ref/!GetAtt tags


def _looks_like_template(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    res = data.get("Resources")
    return isinstance(res, dict) and any(
        isinstance(v, dict) and str(v.get("Type", "")).startswith("AWS::") for v in res.values())


class CloudFormationAdapter(IaCAdapter):
    """Plain CloudFormation templates and CDK apps (synthesised to cdk.out)."""

    name = "cloudformation"

    def detect(self, root: Path) -> bool:
        if (root / "cdk.json").exists() or (root / "cdk.out" / "manifest.json").exists():
            return True
        return bool(self._templates(root))

    def _templates(self, root: Path) -> list[tuple[str, Path]]:
        """(stack name, template path) pairs."""
        out: list[tuple[str, Path]] = []
        manifest = root / "cdk.out" / "manifest.json"
        if manifest.is_file():
            m = _load_json(manifest) or {}
            for art_id, art in (m.get("artifacts") or {}).items():
                if art.get("type") != "aws:cloudformation:stack":
                    continue
                props = art.get("properties") or {}
                tf = props.get("templateFile")
                if tf and (root / "cdk.out" / tf).is_file():
                    out.append((props.get("stackName") or art.get("displayName") or art_id,
                                root / "cdk.out" / tf))
            if out:
                return out
        stack_env = os.environ.get("CLOUDCTL_CFN_STACK", "")
        for p in sorted(list(root.glob("*.json")) + list(root.glob("*.yaml")) + list(root.glob("*.yml")) +
                        list(root.glob("*.template"))):
            if p.name in ("package.json", "cdk.json", "tsconfig.json", "package-lock.json"):
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except OSError:
                continue
            if "AWS::" not in text:
                continue
            try:
                data = json.loads(text) if p.suffix == ".json" else _cfn_yaml_load(text)
            except Exception:  # noqa: BLE001
                continue
            if _looks_like_template(data):
                out.append((stack_env or p.stem, p))
        return out

    def load(self, root: Path, live: Any = None, **kw) -> ExpectedState:
        is_cdk = (root / "cdk.json").exists() or (root / "cdk.out").exists()
        st = ExpectedState(kind="cdk" if is_cdk else "cloudformation", root=str(root))
        templates = self._templates(root)
        if not templates:
            st.unavailable = ("CDK app found but no synthesised templates in cdk.out: run "
                              "`cdk synth` first" if is_cdk else "no CloudFormation template found")
            return st
        for stack, path in templates:
            text = path.read_text(encoding="utf-8")
            try:
                data = json.loads(text) if path.suffix == ".json" else _cfn_yaml_load(text)
            except Exception as exc:  # noqa: BLE001
                st.notes.append(f"could not parse {path.name}: {exc}")
                continue
            physical: dict[str, dict] = {}
            if live is not None:
                try:
                    for row in live.stack_resources(stack) or []:
                        physical[row.get("LogicalResourceId", "")] = row
                except Exception as exc:  # noqa: BLE001
                    st.notes.append(f"stack {stack}: could not list deployed resources ({exc})")
            for logical, body in (data.get("Resources") or {}).items():
                if not isinstance(body, dict):
                    continue
                cfn_type = str(body.get("Type", ""))
                if not cfn_type.startswith("AWS::") or cfn_type == "AWS::CDK::Metadata":
                    continue
                props = body.get("Properties") or {}
                phys = physical.get(logical, {}).get("PhysicalResourceId", "")
                name = own_name(cfn_type, props)
                if not name:
                    name = phys if phys and not phys.startswith("arn:") and "/" not in phys else ""
                st.resources[f"{stack}/{logical}"] = Resource(
                    key=f"{stack}/{logical}", type=cfn_type, name=name or "",
                    physical_id=phys, arn=phys if phys.startswith("arn:") else "",
                    config=props, source="cdk" if is_cdk else "cloudformation",
                    source_type=cfn_type,
                )
            if live is not None:
                st.drift.extend(self._stack_drift(stack, live, st))
        st.notes.append(f"{st.kind} templates: {', '.join(s for s, _ in templates)} "
                        f"({len(st.resources)} resources)")
        return st

    @staticmethod
    def _stack_drift(stack: str, live: Any, st: ExpectedState) -> list[DriftItem]:
        """CloudFormation's own drift results (DescribeStackResourceDrifts).
        Starting a new detection (DetectStackDrift) changes nothing deployed but
        is opt-in: CLOUDCTL_DETECT_DRIFT=1."""
        try:
            rows = live.stack_drifts(stack, detect=os.environ.get("CLOUDCTL_DETECT_DRIFT") == "1") or []
        except Exception as exc:  # noqa: BLE001
            st.notes.append(f"stack {stack}: drift results unavailable ({exc})")
            return []
        items: list[DriftItem] = []
        for row in rows:
            status = row.get("StackResourceDriftStatus", "")
            if status in ("IN_SYNC", "NOT_CHECKED", ""):
                continue
            key = f"{stack}/{row.get('LogicalResourceId', '')}"
            res = st.resources.get(key)
            if status == "DELETED":
                items.append(DriftItem(key, row.get("ResourceType", ""), res.label() if res else "",
                                       [], kind="deleted", source="cloudformation drift detection"))
                continue
            fields = [{"field": d.get("PropertyPath", ""), "expected": d.get("ExpectedValue"),
                       "live": d.get("ActualValue"), "difference": d.get("DifferenceType", "")}
                      for d in row.get("PropertyDifferences") or []]
            items.append(DriftItem(key, row.get("ResourceType", ""), res.label() if res else "",
                                   fields[:20], source="cloudformation drift detection",
                                   changed_at=None))
        return items


# ── Pulumi ───────────────────────────────────────────────────────────────────

class PulumiAdapter(IaCAdapter):
    name = "pulumi"

    def detect(self, root: Path) -> bool:
        return (root / "Pulumi.yaml").exists() or (root / "Pulumi.yml").exists()

    def load(self, root: Path, live: Any = None, **kw) -> ExpectedState:
        st = ExpectedState(kind="pulumi", root=str(root))
        data = None
        env = os.environ.get("CLOUDCTL_PULUMI_STATE")
        if env and Path(env).is_file():
            data = _load_json(Path(env))
        else:
            for p in sorted(root.glob("*.pulumi-state.json")) + sorted(root.glob(".pulumi/stacks/**/*.json")):
                data = _load_json(p)
                if data:
                    break
        if data is None and os.environ.get("CLOUDCTL_PULUMI_EXPORT", "1") != "0":
            raw = _run_readonly(["pulumi", "stack", "export"], root)
            if raw:
                try:
                    data = json.loads(raw)
                except ValueError:
                    data = None
        if not data:
            st.unavailable = ("no Pulumi state: set CLOUDCTL_PULUMI_STATE to a `pulumi stack "
                              "export` file, or install/log in to the pulumi CLI")
            return st
        for r in self.parse_export(data):
            st.resources[r.key] = r
        st.notes.append(f"Pulumi state: {len(st.resources)} resources")
        return st

    @staticmethod
    def parse_export(data: dict) -> list[Resource]:
        dep = data.get("deployment") or (data.get("checkpoint") or {}).get("latest") or data
        out: list[Resource] = []
        for r in dep.get("resources", []) or []:
            ptype = str(r.get("type", ""))
            if not ptype.startswith("aws:"):
                continue
            outputs = r.get("outputs") or r.get("inputs") or {}
            out.append(Resource(
                key=str(r.get("urn") or ptype), type=canonical_type(ptype),
                name=own_name(canonical_type(ptype), outputs), physical_id=str(r.get("id") or ""),
                arn=own_arn(canonical_type(ptype), outputs.get("arn")), config=outputs, source="pulumi",
                source_type=ptype,
            ))
        return out


# ── No IaC: last-known-good baseline ─────────────────────────────────────────

def baseline_path(account: str, region: str) -> Path:
    base = Path(os.environ.get("CLOUDCTL_HOME") or Path.home() / ".cloudctl")
    return base / "baselines" / (account or "unknown") / f"{region}.json"


def save_baseline(resources: list[Resource], account: str, region: str, taken_at: str) -> Path:
    """Write cctl's own last-known-good snapshot (call while the app is healthy)."""
    p = baseline_path(account, region)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"taken_at": taken_at, "resources": [
        {"key": r.key, "type": r.type, "name": r.name, "physical_id": r.physical_id,
         "arn": r.arn, "config": r.config} for r in resources]}, default=str, indent=1),
        encoding="utf-8")
    return p


class BaselineAdapter(IaCAdapter):
    """Expected state when there is no IaC: what the resources looked like at
    the last healthy time. Uses cctl's own snapshot when it predates the
    incident, else AWS Config history at the last healthy time."""

    name = "baseline"

    def detect(self, root: Path) -> bool:
        return True

    def load(self, root: Path | None, live: Any = None, account: str = "", region: str = "",
             at: str | None = None, discovered: list[Resource] | None = None, **kw) -> ExpectedState:
        from cloudctl.debug.diff_first.model import to_dt
        st = ExpectedState(kind="baseline", root=str(root or ""))
        at_dt = to_dt(at)
        snap = _load_json(baseline_path(account, region))
        if snap and (at_dt is None or (to_dt(snap.get("taken_at")) or at_dt) <= at_dt):
            for row in snap.get("resources") or []:
                st.resources[row["key"]] = Resource(
                    key=row["key"], type=row.get("type", ""), name=row.get("name", ""),
                    physical_id=row.get("physical_id", ""), arn=row.get("arn", ""),
                    config=row.get("config") or {}, source="baseline", source_type=row.get("type", ""))
            st.taken_at = snap.get("taken_at")
            st.notes.append(f"cctl baseline snapshot from {st.taken_at} ({len(st.resources)} resources)")
            return st
        if live is None or not discovered:
            st.unavailable = "no IaC, no cctl baseline before the incident, and no discovered resources"
            return st
        got = 0
        for r in discovered:
            try:
                cfg = live.config_history(r, at)
            except Exception:  # noqa: BLE001
                cfg = None
            if cfg:
                st.resources[r.key] = Resource(key=r.key, type=r.type, name=r.name,
                                               physical_id=r.physical_id, arn=r.arn, config=cfg,
                                               source="baseline", source_type="aws-config")
                got += 1
        if got:
            st.taken_at = at
            st.notes.append(f"AWS Config history at {at} for {got} of {len(discovered)} resources")
        else:
            st.unavailable = ("no IaC, no cctl baseline, and AWS Config has no history for the "
                              "discovered resources (is AWS Config recording?)")
        return st


ADAPTERS: list[IaCAdapter] = [TerraformAdapter(), CloudFormationAdapter(), PulumiAdapter()]


def load_expected_state(iac_root: str | None, live: Any = None) -> ExpectedState:
    """Read the declared state from every IaC that the root contains. Returns
    kind="none" with ``unavailable`` set when there is no IaC (the caller then
    falls back to a baseline, which needs the incident window first)."""
    if not iac_root:
        return ExpectedState(kind="none", unavailable="no --iac-root given")
    root = Path(iac_root).expanduser()
    if not root.is_dir():
        return ExpectedState(kind="none", unavailable=f"{iac_root} is not a directory")
    found = [a for a in ADAPTERS if a.detect(root)]
    if not found:
        return ExpectedState(kind="none", root=str(root),
                             unavailable="no Terraform, CloudFormation/CDK or Pulumi files in the IaC root")
    merged: ExpectedState | None = None
    reasons: list[str] = []
    for a in found:
        st = a.load(root, live)
        if st.unavailable and not st.resources:
            reasons.append(f"{a.name}: {st.unavailable}")
            continue
        if merged is None:
            merged = st
        else:
            merged.kind = f"{merged.kind}+{st.kind}"
            merged.merge(st)
    if merged is None:
        return ExpectedState(kind="none", root=str(root), unavailable="; ".join(reasons))
    merged.notes.extend(reasons)
    return merged
