"""baseline.py — DIFFERENTIAL / BASELINE comparison (read-only).

A subtle misconfiguration is often invisible in the absolute — a value looks
plausible on its own — but obvious as a DIFFERENCE. Incidents are almost always
CHANGES: something worked, then broke. This module provides the two baseline
axes that make "wrong" self-identify, with ZERO user setup (pure read-side):

  * TEMPORAL — what did this resource's configuration look like BEFORE?
    Real version history where AWS retains it; otherwise a reconstruction of
    config-changing events from CloudTrail (whose request parameters carry the
    changed values).
  * PEER — how does this resource's configuration DIFFER from its sibling
    resources of the same type?

Plus a shared PURE structural differ.

Discipline (mirrors the config-fetcher registry): a per-type history fetcher is
"HOW to get history for this type" — raw facts out. Nothing here encodes what
any value ought to be, a "right" configuration, or which fields matter for
which fault: the differ reports differences verbatim and the model reasons. Noise
suppression is STRUCTURAL-SHAPE only and conservative — when unsure, the
difference is reported, and every suppressed difference is still listed with
its reason (nothing is silently hidden).

Read-only everywhere; any denial/absence degrades to a structured
"unavailable" result, never an exception.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timedelta, timezone

log = logging.getLogger("cloudctl.baseline")

# ── Pure structural differ ────────────────────────────────────────────────────

_MAX_DIFF_ENTRIES = 100      # hard cap on reported entries (then truncated=True)
_MAX_VALUE_CHARS = 400       # per-value truncation in diff output

# Timestamp-SHAPED values: ISO-like date / datetime strings. Purely structural —
# a shape, not a field name. Both sides must fully match for suppression.
_TS_SHAPE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?"
    r"([Zz]|[+-]\d{2}:?\d{2})?)?$"
)


def _short(value) -> object:
    """Bounded copy of a value for diff output (never mutates the input)."""
    if isinstance(value, str) and len(value) > _MAX_VALUE_CHARS:
        return value[:_MAX_VALUE_CHARS] + "…[truncated]"
    if isinstance(value, (dict, list)):
        s = json.dumps(value, default=str)
        if len(s) > _MAX_VALUE_CHARS:
            return s[:_MAX_VALUE_CHARS] + "…[truncated]"
    return value


def _suppression_reason(old, new, identity_tokens) -> str:
    """Return a reason string if this difference is structurally instance-unique
    noise, else "". CONSERVATIVE: only two shapes qualify —
      1. both values are timestamp-shaped strings (instance metadata churn);
      2. the values differ ONLY by the two compared resources' own identities
         (peer mode: e.g. two ARNs that differ solely in the peer's own name).
    Anything else — including a value that merely CONTAINS a timestamp, or an
    identifier that differs in any other way — is REPORTED, not suppressed:
    when unsure, report."""
    if isinstance(old, str) and isinstance(new, str):
        if _TS_SHAPE_RE.match(old.strip()) and _TS_SHAPE_RE.match(new.strip()):
            return "timestamp-shaped on both sides (instance metadata)"
        if identity_tokens:
            a, b = identity_tokens
            if a and b and a != b and a in old and old.replace(a, b) == new:
                return "differs only by the compared resources' own identity"
    return ""


def diff_configs(old, new, identity_tokens: tuple | None = None) -> dict:
    """Generic structural diff of two nested config structures.

    Returns {"changed": [{path, old, new}], "added": [{path, value}],
    "removed": [{path, value}], "suppressed": [{path, reason, old, new}],
    "identical": bool, "truncated": bool}.

    Reports RAW differences only — it never judges which value is correct.
    identity_tokens=(name_a, name_b): the two compared resources' own
    identifiers, used ONLY for the structural identity-suppression rule
    (peer comparison); omit for temporal diffs.
    """
    changed: list = []
    added: list = []
    removed: list = []
    suppressed: list = []
    truncated = [False]

    def _room() -> bool:
        if len(changed) + len(added) + len(removed) >= _MAX_DIFF_ENTRIES:
            truncated[0] = True
            return False
        return True

    def _leaf_diff(path: str, o, n) -> None:
        if not _room():
            return
        reason = _suppression_reason(o, n, identity_tokens)
        if reason:
            suppressed.append({"path": path, "reason": reason,
                               "old": _short(o), "new": _short(n)})
        else:
            changed.append({"path": path, "old": _short(o), "new": _short(n)})

    def _walk(path: str, o, n) -> None:
        if o == n:
            return
        if isinstance(o, dict) and isinstance(n, dict):
            for k in o:
                p = f"{path}.{k}" if path else str(k)
                if k not in n:
                    if _room():
                        removed.append({"path": p, "value": _short(o[k])})
                else:
                    _walk(p, o[k], n[k])
            for k in n:
                if k not in o and _room():
                    added.append({"path": f"{path}.{k}" if path else str(k),
                                  "value": _short(n[k])})
            return
        if isinstance(o, list) and isinstance(n, list):
            if len(o) == len(n):
                for i, (oi, ni) in enumerate(zip(o, n)):
                    _walk(f"{path}[{i}]", oi, ni)
            else:
                # different shapes: report the whole change rather than guess an
                # alignment (conservative — never silently drop elements)
                _leaf_diff(path, o, n)
            return
        _leaf_diff(path, o, n)

    _walk("", old if isinstance(old, (dict, list)) else {"value": old},
          new if isinstance(new, (dict, list)) else {"value": new})
    return {
        "changed": changed,
        "added": added,
        "removed": removed,
        "suppressed": suppressed,
        "identical": not (changed or added or removed or suppressed),
        "truncated": truncated[0],
    }


# ── Temporal baseline: per-type version-history fetchers ──────────────────────
# Registry contract (mirrors the config-fetcher registry): each entry is HOW to
# fetch retained prior versions for a resource type. It returns
#   {"snapshots": [{"version", "as_of", "config"}, ...]   # newest first
#    "change_points": [{"id", "at", "description"}, ...]  # optional, when AWS
#    "note": str}                                         # retains only markers
# Raw configs out; no judgement about what any of them ought to contain.

_MAX_SNAPSHOTS = 4


def _history_lambda(session, resource_name: str) -> dict:
    client = session.client("lambda")
    versions = client.list_versions_by_function(
        FunctionName=resource_name).get("Versions", [])
    if not versions:
        return {"snapshots": []}

    def _key(v):
        ver = v.get("Version", "")
        return float("inf") if ver == "$LATEST" else int(ver) if ver.isdigit() else -1

    versions.sort(key=_key, reverse=True)
    return {"snapshots": [
        {"version": v.get("Version"), "as_of": v.get("LastModified"),
         "config": v}
        for v in versions[:_MAX_SNAPSHOTS]
    ]}


def _history_ssm(session, resource_name: str) -> dict:
    client = session.client("ssm")
    hist = client.get_parameter_history(
        Name=resource_name, WithDecryption=False).get("Parameters", [])
    hist.sort(key=lambda p: p.get("Version", 0), reverse=True)
    return {"snapshots": [
        {"version": p.get("Version"), "as_of": p.get("LastModifiedDate"),
         "config": p}
        for p in hist[:_MAX_SNAPSHOTS]
    ]}


def _history_apigateway(session, resource_name: str) -> dict:
    """REST API deployments are retained change-POINTS (id + when + note); the
    per-deployment config content is not retrievable without a stage export, so
    only the markers are returned — the CloudTrail reconstruction supplies the
    changed values."""
    client = session.client("apigateway")
    apis = client.get_rest_apis(limit=100).get("items", [])
    target = next(
        (a for a in apis
         if resource_name in (a.get("name", ""), a.get("id", ""))
         or resource_name.lower() in a.get("name", "").lower()),
        None)
    if not target:
        return {"snapshots": [], "note": "no matching API found"}
    deployments = client.get_deployments(
        restApiId=target["id"], limit=25).get("items", [])
    deployments.sort(key=lambda d: str(d.get("createdDate", "")), reverse=True)
    return {
        "snapshots": [],
        "change_points": [
            {"id": d.get("id"), "at": d.get("createdDate"),
             "description": d.get("description", "")}
            for d in deployments[:10]
        ],
        "note": ("deployments are retained change points; their content is not "
                 "directly retrievable — see cloudtrail_reconstruction for the "
                 "changed values"),
    }


_HISTORY_FETCHERS = {
    "lambda":     _history_lambda,
    "ssm":        _history_ssm,
    "parameter":  _history_ssm,
    "apigateway": _history_apigateway,
}


def _select_history_fetcher(service_type: str):
    t = (service_type or "").strip().lower()
    if t in _HISTORY_FETCHERS:
        return _HISTORY_FETCHERS[t]
    for token in re.split(r"[:/\s]+", t):
        if token in _HISTORY_FETCHERS:
            return _HISTORY_FETCHERS[token]
    return None


def _is_denied(exc) -> bool:
    resp = getattr(exc, "response", None)
    code = str(resp.get("Error", {}).get("Code", "")) if isinstance(resp, dict) else ""
    blob = f"{code} {exc}".lower()
    return any(w in blob for w in ("accessdenied", "unauthorized", "forbidden",
                                   "not authorized"))


def _unavailable(reason: str, **extra) -> dict:
    return {"available": False, "reason": reason, **extra}


# ── Temporal baseline: CloudTrail reconstruction ──────────────────────────────
# Where AWS retains no prior version, the change events themselves often carry
# the values: a config-writing API call's requestParameters ARE the state that
# was written. Consecutive write events of the SAME kind are therefore
# consecutive config states — diffing them reconstructs before→after. The
# write-verb prefixes below are the universal AWS API naming convention (the
# mirror image of aws_read's read-verb allowlist), not service knowledge.

_WRITE_VERB_RE = re.compile(
    r"^(Update|Put|Create|Modify|Set|Delete|Attach|Detach|Associate|"
    r"Disassociate|Enable|Disable|Register|Deregister)"
)
_MAX_CHANGE_EVENTS = 12


def _cloudtrail_reconstruction(session, resource_name: str, minutes: int) -> dict:
    ct = session.client("cloudtrail")
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=min(int(minutes or 10080), 10080))

    events: list[dict] = []
    token = None
    for _ in range(3):   # bounded pagination
        kw = dict(
            LookupAttributes=[{"AttributeKey": "ResourceName",
                               "AttributeValue": resource_name}],
            StartTime=start, EndTime=end, MaxResults=50,
        )
        if token:
            kw["NextToken"] = token
        resp = ct.lookup_events(**kw)
        events.extend(resp.get("Events", []))
        token = resp.get("NextToken")
        if not token:
            break

    # keep only config-WRITING events that carry request parameters
    changes: list[dict] = []
    for e in events:
        name = e.get("EventName", "")
        if not _WRITE_VERB_RE.match(name):
            continue
        try:
            detail = json.loads(e.get("CloudTrailEvent", "{}"))
        except Exception:  # noqa: BLE001
            continue
        params = detail.get("requestParameters")
        if not isinstance(params, dict) or not params:
            continue
        uid = detail.get("userIdentity", {})
        changes.append({
            "event_name": name,
            "at": str(e.get("EventTime", "")),
            "actor": (uid.get("userName")
                      or uid.get("sessionContext", {})
                         .get("sessionIssuer", {}).get("userName", "")
                      or uid.get("arn", "").split("/")[-1]),
            "request_parameters": params,
        })
    if not changes:
        return _unavailable(
            "no config-writing events with request parameters found in the "
            "CloudTrail window")

    changes.sort(key=lambda c: c["at"])              # oldest → newest
    changes = changes[-_MAX_CHANGE_EVENTS:]

    # Diff CONSECUTIVE events of the same kind: each write's parameters are the
    # state written, so successive writes are successive states.
    by_kind: dict[str, list[dict]] = {}
    for c in changes:
        by_kind.setdefault(c["event_name"], []).append(c)
    diffs: list[dict] = []
    for kind, seq in by_kind.items():
        for prev, curr in zip(seq, seq[1:]):
            diffs.append({
                "event_name": kind,
                "from_time": prev["at"],
                "to_time": curr["at"],
                "actor": curr["actor"],
                "diff": diff_configs(prev["request_parameters"],
                                     curr["request_parameters"]),
            })

    return {
        "available": True,
        "change_events": [
            {k: (v if k != "request_parameters" else _short(json.dumps(v, default=str)))
             for k, v in c.items()}
            for c in changes[::-1]                    # newest first for reading
        ],
        "consecutive_diffs": diffs,
        "note": ("each write event's request parameters are the state that was "
                 "written; consecutive_diffs shows before→after between "
                 "successive writes of the same kind. Raw values — compare "
                 "against the current config and the symptom onset yourself."),
    }


def prior_config(session, resource_name: str, service_type: str,
                 minutes: int = 10080) -> dict:
    """TEMPORAL baseline: current-vs-prior configuration, as structured diffs.

    Tries real retained version history first (per-type registry), then always
    attempts CloudTrail reconstruction. Raw before→after facts only; never
    judges which value is correct. Any failure degrades to a structured
    'unavailable' reason — never an exception."""
    out: dict = {"resource_name": resource_name, "service_type": service_type}

    fetcher = _select_history_fetcher(service_type)
    if fetcher is None:
        out["version_history"] = _unavailable(
            f"no retained-version fetcher for type '{service_type}' — relying "
            "on the CloudTrail reconstruction")
    else:
        try:
            hist = fetcher(session, resource_name)
            snaps = hist.get("snapshots") or []
            vh: dict = {"available": bool(snaps or hist.get("change_points")),
                        "snapshots_found": len(snaps)}
            if hist.get("change_points"):
                vh["change_points"] = hist["change_points"]
            if hist.get("note"):
                vh["note"] = hist["note"]
            if len(snaps) >= 2:
                vh["diffs"] = [
                    {
                        "from_version": prev.get("version"),
                        "to_version": curr.get("version"),
                        "from_as_of": prev.get("as_of"),
                        "to_as_of": curr.get("as_of"),
                        "diff": diff_configs(prev.get("config") or {},
                                             curr.get("config") or {}),
                    }
                    # snapshots are newest-first; diff older → newer
                    for curr, prev in zip(snaps, snaps[1:])
                ]
            elif snaps:
                vh["note"] = (vh.get("note", "") +
                              " only one retained version — nothing to diff "
                              "against").strip()
            if not vh["available"]:
                vh = _unavailable("no retained versions found")
            out["version_history"] = vh
        except Exception as exc:  # noqa: BLE001
            reason = (f"baseline unavailable (access denied to version history)"
                      if _is_denied(exc)
                      else f"version-history fetch failed: {type(exc).__name__}")
            out["version_history"] = _unavailable(reason,
                                                  access_denied=_is_denied(exc))

    try:
        out["cloudtrail_reconstruction"] = _cloudtrail_reconstruction(
            session, resource_name, minutes)
    except Exception as exc:  # noqa: BLE001
        reason = ("baseline unavailable (access denied to cloudtrail:LookupEvents)"
                  if _is_denied(exc)
                  else f"cloudtrail reconstruction failed: {type(exc).__name__}")
        out["cloudtrail_reconstruction"] = _unavailable(
            reason, access_denied=_is_denied(exc))

    vh_ok = out.get("version_history", {}).get("available")
    ct_ok = out.get("cloudtrail_reconstruction", {}).get("available")
    out["baseline_unavailable"] = not (vh_ok or ct_ok)
    out["note"] = ("diffs are RAW before→after facts; this tool does not judge "
                   "which value is right. A field that changed at/near the "
                   "symptom onset on the failing path is a lead to verify, not "
                   "a verdict.")
    return out


# ── Peer baseline ─────────────────────────────────────────────────────────────

_MAX_PEERS = 3


def _fetch_config(session, service_type: str, resource_name: str) -> dict:
    """Fetch one resource's config the same way get_service_config does
    (per-type fetcher, then the generic fetcher) — raw dict, {} on failure."""
    from cloudctl.mcp.tools.debug import _SERVICE_FETCHERS  # noqa: PLC0415
    from cloudctl.debug.fetcher import DebugFetcher  # noqa: PLC0415
    fetcher = DebugFetcher(session)
    try:
        spec = _SERVICE_FETCHERS.get(service_type)
        if spec:
            method_name, hint_key = spec
            method = getattr(fetcher, method_name)
            if service_type == "ecs":
                return method(cluster_hint=resource_name,
                              service_hint=resource_name) or {}
            return method(**{hint_key: resource_name}) or {}
        return fetcher.generic_resource_config(
            service_type=service_type, resource_name=resource_name) or {}
    except Exception:  # noqa: BLE001
        return {}


def _discover_peers(session, resource_name: str, service_type: str) -> list[str]:
    """Find sibling resources of the same type, generically: same service
    namespace from the account-wide enumeration, ranked by shared name prefix
    (resources of one app/stack overwhelmingly share a naming prefix). No
    per-service knowledge; returns names only."""
    from cloudctl.mcp.tools.debug import _enumerate_resources  # noqa: PLC0415
    resources = _enumerate_resources(session)
    t = (service_type or "").strip().lower()
    same_type = [
        r["name"] for r in resources
        if r["name"] != resource_name
        and (t in r["service"].lower() or r["service"].lower() in t)
    ]

    def _common_prefix(a: str, b: str) -> int:
        n = 0
        for ca, cb in zip(a.lower(), b.lower()):
            if ca != cb:
                break
            n += 1
        return n

    ranked = sorted(same_type,
                    key=lambda n: _common_prefix(n, resource_name),
                    reverse=True)
    return [n for n in ranked if _common_prefix(n, resource_name) >= 3][:_MAX_PEERS]


def peer_comparison(session, resource_name: str, service_type: str,
                    peer_names: list | None = None,
                    configs: dict | None = None) -> dict:
    """PEER baseline: which config fields DIFFER between a resource and its
    siblings of the same type. Raw differences only — a difference is evidence
    for the model to weigh, never a verdict; nothing here says which fields
    ought to match.

    configs: optional {name: config-dict} the caller already fetched (e.g. via
    aws_read for nested resources the account enumeration cannot see) — when
    given, this is a PURE structural comparison with no AWS calls."""
    out: dict = {"resource_name": resource_name, "service_type": service_type}

    try:
        if configs and isinstance(configs, dict) and len(configs) >= 2:
            names = list(configs)
            target = resource_name if resource_name in configs else names[0]
            peers = [n for n in names if n != target]
            get_cfg = lambda n: configs[n] if isinstance(configs[n], dict) else \
                json.loads(configs[n])  # noqa: E731
            out["comparison_mode"] = "caller-supplied configs (pure diff)"
        else:
            peers = [p for p in (peer_names or []) if p and p != resource_name] \
                or _discover_peers(session, resource_name, service_type)
            if not peers:
                out["peers_unavailable"] = True
                out["reason"] = (
                    "no sibling resources of this type found to compare against "
                    "(single instance, or enumeration returned nothing). If the "
                    "siblings are nested resources, fetch their configs with "
                    "aws_read and pass them via 'configs'.")
                return out
            target = resource_name
            get_cfg = lambda n: _fetch_config(session, service_type, n)  # noqa: E731
            out["comparison_mode"] = "discovered peers (fetched configs)"

        target_cfg = get_cfg(target)
        if not target_cfg:
            out["peers_unavailable"] = True
            out["reason"] = f"could not fetch config for '{target}'"
            return out

        comparisons: list[dict] = []
        for peer in peers[:_MAX_PEERS]:
            peer_cfg = get_cfg(peer)
            if not peer_cfg:
                comparisons.append({"peer": peer,
                                    "unavailable": "could not fetch config"})
                continue
            comparisons.append({
                "peer": peer,
                "diff": diff_configs(target_cfg, peer_cfg,
                                     identity_tokens=(target, peer)),
            })
        out["peers_compared"] = [c["peer"] for c in comparisons]
        out["comparisons"] = comparisons
        out["note"] = (
            "RAW field differences between this resource and each sibling; "
            "differences that are only the resources' own identities are "
            "listed under 'suppressed'. A field where this resource diverges "
            "from otherwise-identical peers is a lead to verify against the "
            "observed failure, not a verdict.")
        return out
    except Exception as exc:  # noqa: BLE001
        reason = ("peer baseline unavailable (access denied)"
                  if _is_denied(exc)
                  else f"peer comparison failed: {type(exc).__name__}")
        out["peers_unavailable"] = True
        out["reason"] = reason
        out["access_denied"] = _is_denied(exc)
        return out
