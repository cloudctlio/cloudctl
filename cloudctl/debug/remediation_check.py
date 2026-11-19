"""remediation_check.py — check fix steps before an operator acts on them.

Guardrails already check the root cause against fetched data. This checks the
remediation: the steps a user is most likely to copy and run. It is
deterministic, read-only and generic (no per-service rules):

  1. resolve the target — the resource the fix is about, with its type and
     service, from the IaC lookup (address, type, file) or, without IaC, from
     an ARN in the diagnosis.
  2. platform match — a step naming an AWS service that is neither the
     target's nor used anywhere in the IaC, related resources or evidence is
     flagged (ECS steps for a Lambda in an app with no ECS).
  3. drift — when the target is managed by IaC, a step that changes the cloud
     resource directly (a mutating CLI/API call or the console) is flagged
     and replaced by the IaC change.
  4. unverified names — a step naming a resource identifier found nowhere in
     the IaC, evidence or root cause goes to an unverified list, the same way
     unsourced root-cause claims do.

Fail closed: the fix counts as confirmed only when a target was resolved and
no step is flagged-and-unreplaced or unverified. Anything else is shown as
"found the cause, couldn't confirm the fix". Root-cause confidence is never
touched.
"""
from __future__ import annotations

import functools
import re

_ARN_RE = re.compile(r"arn:aws[a-z\-]*:([a-z0-9\-]+):[^\s:]*:[^\s:]*:([A-Za-z0-9\-_.]+)[:/]?([^\s,;'\"`)]*)")
_CLI_RE = re.compile(r"\baws\s+([a-z0-9\-]+)\s+([a-z0-9\-]+)")
_TF_TYPE_RE = re.compile(r"\baws_([a-z0-9]+)_[a-z0-9_]+")
# Verbs that change state. Generic API/CLI shape, not a list per service.
_MUTATING = ("put", "update", "create", "delete", "set", "attach", "detach", "modify", "add",
             "remove", "register", "deregister", "enable", "disable", "tag", "untag", "associate",
             "disassociate", "revoke", "authorize", "replace", "reset", "restore", "increase",
             "decrease", "terminate", "reboot", "force")
# An API operation counts only when the step tells the reader to invoke it
# ("run UpdateTable", "use PutRolePolicy"), so app-code advice that mentions a
# data-plane call ("add backoff around PutItem") is not mistaken for drift.
_API_OP_RE = re.compile(r"\b(?:run|call|execute|issue|invoke|use|using|via|with)\s+(?:an?\s+|the\s+)?"
                        r"((?:" + "|".join(v.capitalize() for v in _MUTATING) + r")[A-Z][A-Za-z0-9]+)\b",
                        re.IGNORECASE)
_CLI_MUT_RE = re.compile(r"\baws\s+[a-z0-9\-]+\s+(" + "|".join(_MUTATING) + r")-[a-z0-9\-]+")
_CONSOLE_RE = re.compile(r"\b(in|via|from|using|through) the (aws |management )?console\b|"
                         r"\bdirectly in (aws|the account)\b|--force-new-deployment", re.IGNORECASE)
_IDENT_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:[-:][A-Za-z0-9*]+){1,}\b")


@functools.lru_cache(maxsize=1)
def _service_ids() -> frozenset[str]:
    """AWS service ids from botocore's installed data (ecs, lambda, sqs, ...),
    read from directory names only. Falls back to an empty set."""
    try:
        import botocore.session  # noqa: PLC0415
        return frozenset(s.lower() for s in botocore.session.get_session().get_available_services())
    except Exception:  # noqa: BLE001
        return frozenset()


def _services_in_text(text: str) -> set[str]:
    """Services a step names: CLI commands, Terraform types, ARNs, and service
    ids written as a name (ECS, SQS, Lambda, DynamoDB) — a lowercase common
    word like "events" or "config" is not counted."""
    out = {m.group(1) for m in _CLI_RE.finditer(text)}
    out |= {m.group(1) for m in _TF_TYPE_RE.finditer(text)}
    out |= {m.group(1) for m in _ARN_RE.finditer(text)}
    ids = _service_ids()
    for m in re.finditer(r"(?<![\w\-/.:])([A-Za-z][A-Za-z0-9]{1,})(?![\w\-/.:])", text):
        w = m.group(1)
        if w.lower() not in ids or w.islower():
            continue
        at_start = m.start() == 0 or text[:m.start()].rstrip().endswith((".", ":", "!", "?"))
        if w.isupper() or re.search(r"[a-z][A-Z]", w) or not at_start:
            out.add(w.lower())
    return {s for s in out if s in ids} if ids else out


def _norm_service(s: str) -> str:
    return re.sub(r"v\d+$", "", s.lower())


def resolve_target(diagnosis: dict, iac_fix: dict | None = None) -> dict | None:
    """The resource the fix is about. IaC first (its address and type are
    authoritative), else a single ARN in the diagnosis that the root cause
    names. None when it can't be told."""
    fix = iac_fix or {}
    if fix.get("resource"):
        edited = fix.get("edited_resources") or []
        addr = edited[0] if edited else fix["resource"]
        rtype = addr.split("(")[-1].rstrip(")") if "(" in addr else addr.split(".")[0]
        if rtype.startswith("data."):
            rtype = addr.split(".")[1]
        svc = (rtype.split(".")[0] if "(" in addr else (rtype.split("_")[1] if "_" in rtype else rtype))
        return {"address": addr, "located": fix["resource"], "type": rtype,
                "service": _norm_service(svc), "file": fix.get("file"), "kind": fix.get("kind"),
                "iac_managed": True, "source": "iac", "related": fix.get("related") or []}
    text = " ".join([str(diagnosis.get("root_cause") or "")] +
                    [str(x) for x in diagnosis.get("affected_resources") or []] +
                    [str(x) for x in diagnosis.get("resources_investigated") or []] +
                    [str(x) for x in diagnosis.get("evidence") or []])
    arns = {}
    for m in _ARN_RE.finditer(text):
        name = (m.group(3) or m.group(2)).split("/")[-1].split(":")[0]
        arns.setdefault((m.group(1), m.group(2), name), m.group(0))
    rc = str(diagnosis.get("root_cause") or "")
    named = [k for k in arns if k[2] and k[2] in rc] or list(arns)
    if len({(k[0], k[2]) for k in named}) != 1:
        return None
    svc, rkind, name = named[0]
    deployed = str(diagnosis.get("deployment_source") or "").lower()
    return {"address": name, "located": name, "type": f"{svc}:{rkind}", "service": _norm_service(svc),
            "file": None, "kind": deployed or None,
            "iac_managed": deployed in ("terraform", "cdk", "cloudformation", "pulumi", "sam"),
            "source": "arn", "related": []}


def _apply_cmd(kind: str | None) -> str:
    if kind == "cdk":
        return "`cdk diff`, then `cdk deploy`"
    if kind == "cloudformation":
        return "a change set, then execute it"
    return "`terraform plan`, then `terraform apply`"


def check_remediation(steps: list[str], diagnosis: dict, target: dict | None,
                      iac_text: str = "", iac_fix: dict | None = None,
                      fetched_text: str = "") -> dict:
    """Check and, where possible, repair fix steps. Never raises.

    Returns {steps, confirmed, reason, flagged:[{step, reason}],
             unverified:[{step, reason}], target}. `steps` is what to show:
    flagged steps are replaced by one IaC step when the target is in IaC,
    otherwise kept but marked unverified."""
    steps = [str(s) for s in steps or [] if str(s).strip()]
    fix = iac_fix or {}
    diag_text = " ".join([str(diagnosis.get("root_cause") or "")] +
                         [str(e) for e in diagnosis.get("evidence") or []])
    # Names a step may use: the IaC when there is one (the account may hold
    # unrelated resources that discovery and evidence picked up), else the
    # diagnosis plus the data fetched in this run.
    corpus = " ".join([diag_text, iac_text] + ([] if iac_text else [fetched_text])).lower()
    allowed = {"iam", "sts", "cloudwatch", "logs", "cloudtrail"}   # cross-cutting, every resource
    if target:
        allowed.add(target["service"])
        for r in target.get("related") or []:
            m = _TF_TYPE_RE.search(r)
            if m:
                allowed.add(_norm_service(m.group(1)))
    if iac_text:
        allowed |= {_norm_service(s) for s in _TF_TYPE_RE.findall(iac_text)}
        allowed |= {_norm_service(m.group(1).split(".")[0]) for m in
                    re.finditer(r"\b(?:aws_cdk\.)?aws_([a-z0-9]+)\b", iac_text)}
    else:
        allowed |= {_norm_service(m.group(1)) for m in _ARN_RE.finditer(diag_text)}
        allowed |= {_norm_service(s) for s in _services_in_text(diag_text)}

    flagged, unverified, kept = [], [], []
    for step in steps:
        named = {_norm_service(s) for s in _services_in_text(step)}
        foreign = sorted(named - allowed)
        if foreign and target:
            what = f"{target['address']} is a {target['type']}"
            flagged.append({"step": step, "reason": f"names {', '.join(x.upper() for x in foreign)}, but {what} "
                            "and nothing in the IaC or evidence uses that service"})
            continue
        if foreign:
            unverified.append({"step": step, "reason": f"names {', '.join(x.upper() for x in foreign)}, which "
                               "nothing in the evidence shows"})
            kept.append(step)
            continue
        direct = _CLI_MUT_RE.search(step) or _CONSOLE_RE.search(step) or _API_OP_RE.search(step)
        if direct and target and target.get("iac_managed"):
            flagged.append({"step": step, "reason": f"changes AWS directly ({direct.group(0).strip()}); "
                            f"{target['address']} is managed by {target.get('kind') or 'IaC'}, so this would "
                            "drift and be undone by the next apply"})
            continue
        idents = [t for t in _IDENT_RE.findall(step)
                  if (any(c.isdigit() for c in t) or ":" in t or len(re.split(r"[-:]", t)) >= 3)
                  and not re.fullmatch(r"[a-z0-9]+:[A-Z][A-Za-z]+", t)       # IAM actions (s3:PutObject)
                  and not t.lower().startswith(("arn:", "us-", "eu-", "ap-", "sa-", "ca-", "me-", "af-"))]
        missing = [t for t in idents if t.lower() not in corpus
                   and not (target and t.lower() in str(target.get("address", "")).lower())]
        if missing:
            where = "your IaC, the evidence or the root cause" if iac_text else "the evidence or the root cause"
            unverified.append({"step": step, "reason": f"names {', '.join(missing[:3])}, which isn't in {where}"})
        kept.append(step)

    out_steps = list(kept)
    replaced = False
    if flagged and target and target.get("source") == "iac":
        where = f"{target['address']} in {target['file']}" if target.get("file") else target["address"]
        what = f": {fix['summary'].rstrip('.')}" if fix.get("summary") else ""
        diff_note = " (see the IaC fix suggestion)" if fix.get("status") == "suggested" else ""
        out_steps.insert(0, f"Change {where}{what}{diff_note}, then run {_apply_cmd(target.get('kind'))}.")
        replaced = True

    if not target:
        reason = "couldn't tie the fix to one resource"
        if fix.get("status") == "ambiguous":
            reason += f" ({len(fix.get('candidates') or [])} IaC resources matched equally)"
        elif fix.get("status") in ("not_found", "no_iac"):
            reason += " (not found in the IaC)"
    elif flagged and not replaced:
        reason = f"{len(flagged)} step(s) don't match {target['address']}"
    elif unverified:
        reason = f"{len(unverified)} step(s) name things that couldn't be checked"
    elif not out_steps:
        reason = "no fix steps"
    else:
        reason = ""
    confirmed = not reason
    return {"steps": out_steps, "confirmed": confirmed, "reason": reason, "flagged": flagged,
            "unverified": unverified, "replaced_with_iac_step": replaced, "target": target,
            "candidates": fix.get("candidates") or []}


def iac_text_for(iac_root: str | None) -> str:
    """All .tf / CDK .py text under the IaC root, for name checks. Bounded."""
    if not iac_root:
        return ""
    from pathlib import Path  # noqa: PLC0415
    from cloudctl.debug.iac_fix import _iter_files  # noqa: PLC0415
    root = Path(iac_root).expanduser()
    if not root.is_dir():
        return ""
    from cloudctl.debug.iac_fix import _interpolate_vars, _tf_blocks  # noqa: PLC0415
    parts, total = [], 0
    for p in _iter_files(root, (".tf", ".py")):
        try:
            t = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        total += len(t)
        if total > 2_000_000:
            break
        parts.append(t)
    text = "\n".join(parts)
    # Names as deployed: "${var.prefix}-api" -> "cctl-complexapp-api", plus
    # local state when present, so a step naming the real resource checks out.
    variables = {}
    for b in _tf_blocks(text):
        if b["type"] == "variable":
            m = re.search(r'^\s*default\s*=\s*"?([^"\n]*)"?\s*$', b["text"], re.MULTILINE)
            variables[b["a"]] = {"default": m.group(1).strip() if m else None}
    text += "\n" + _interpolate_vars(text, variables)
    state = root / "terraform.tfstate"
    if state.is_file() and state.stat().st_size < 5_000_000:
        text += "\n" + state.read_text(encoding="utf-8", errors="replace")
    return text
