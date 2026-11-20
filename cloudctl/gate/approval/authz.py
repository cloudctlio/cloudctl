"""Cedar authorization for approvals: may this approver approve this change?"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable, Mapping

from cloudctl.gate.models import ApprovalError, Severity

BUILTIN_POLICY = Path(__file__).parent / "builtin" / "approval.cedar"


def _sev_num(name: str) -> int:
    if not name or name.upper() == "NONE":
        return 0
    try:
        return int(Severity.parse(name))
    except ValueError:
        return int(Severity.CRITICAL)   # unknown → treat as worst


def authorize_approval(*, approver: str, approver_environments: Iterable[str], environment: str, tier: str,
                       requester: str, max_severity: str, counts: Mapping[str, int], expired: bool,
                       extra_policies: str = "") -> None:
    """Raise ApprovalError unless Cedar allows the approval."""
    try:
        import cedarpy  # noqa: PLC0415
    except ImportError as e:
        raise ApprovalError("approval authorization needs cedarpy (pip install 'cctl[gate]')") from e
    policies = BUILTIN_POLICY.read_text(encoding="utf-8") + ("\n" + extra_policies if extra_policies else "")
    entities: list[dict[str, Any]] = [
        {"uid": {"type": "Approver", "id": approver},
         "attrs": {"name": approver.lower(), "environments": sorted(set(approver_environments))}, "parents": []},
        {"uid": {"type": "Environment", "id": environment},
         "attrs": {"name": environment, "tier": tier}, "parents": []},
    ]
    request = {
        "principal": {"type": "Approver", "id": approver},
        "action": {"type": "Action", "id": "approve"},
        "resource": {"type": "Environment", "id": environment},
        "context": {
            # names compared case-insensitively for separation of duties
            "requester": requester.strip().lower(),
            "max_severity": _sev_num(max_severity),
            "change_count": int(counts.get("add", 0)) + int(counts.get("modify", 0)) + int(counts.get("destroy", 0)),
            "destroy_count": int(counts.get("destroy", 0)),
            "expired": bool(expired),
        },
    }
    try:
        result = cedarpy.is_authorized(request, policies, entities)
    except Exception as e:  # noqa: BLE001
        raise ApprovalError(f"Cedar evaluation failed: {e}") from e
    errs: list[str] = []
    try:
        errs = [str(x) for x in (result.diagnostics.errors or [])]
    except Exception:  # noqa: BLE001
        errs = ["diagnostics unavailable"]
    # Cedar skips a policy that errors; a skipped forbid must not turn into an allow.
    if errs and result.allowed:
        raise ApprovalError(f"Cedar policy evaluation reported errors; approval refused ({'; '.join(errs)})")
    if not result.allowed:
        reason = f" ({'; '.join(errs)})" if errs else ""
        raise ApprovalError(f"{approver!r} is not authorized to approve this change in {environment!r}{reason}")
