"""The nine primitives. None of them knows what any failure looks like.

Each primitive takes JSON arguments, reads raw facts from an EvidenceSource,
and returns a :class:`Result`: PASS | FAIL | INCONCLUSIVE | UNAVAILABLE, the
facts it used (each with a pointer to its source and a timestamp), and, where
meaningful, the time the predicate first held (``onset``).

What the primitives encode is cloud semantics (how a metric is read, how IAM
decides, how security groups / NACLs / routes combine), not failure knowledge.

Time handling: primitives with a time dimension take ``window`` = one of
``incident`` | ``lookback`` | ``pre_onset`` (see evidence.Incident). The
verifier re-runs a hypothesis's predictions with ``incident`` swapped for
``pre_onset`` as its temporal control; :data:`CONTROL` says which primitives
take part in that control and which argument names hold the node a peer
control substitutes.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field

from cloudctl.verify.evidence import EvidenceSource, Incident, Unavailable, Window
from cloudctl.verify.model import SystemModel

PASS, FAIL, INCONCLUSIVE, UNAVAILABLE = "PASS", "FAIL", "INCONCLUSIVE", "UNAVAILABLE"
STATUSES = (PASS, FAIL, INCONCLUSIVE, UNAVAILABLE)
WINDOWS = ("incident", "lookback", "pre_onset")


@dataclass
class Result:
    status: str
    facts: list = field(default_factory=list)   # [{"fact", "source", "ts"}]
    reason: str = ""
    onset: int | None = None
    missing: str = ""                           # the signal that was unavailable
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {"status": self.status, "facts": self.facts[:20], "reason": self.reason}
        if self.onset is not None:
            d["onset"] = self.onset
        if self.missing:
            d["missing"] = self.missing
        if self.detail:
            d["detail"] = self.detail
        return d


@dataclass
class Context:
    model: SystemModel
    evidence: EvidenceSource
    incident: Incident


def _fact(fact: str, source: str, ts: int | None = None) -> dict:
    return {"fact": fact, "source": source, "ts": ts}


def _unavailable(exc: Unavailable) -> Result:
    return Result(UNAVAILABLE, reason=exc.reason, missing=exc.signal)


# ── argument schemas ─────────────────────────────────────────────────────────
# Kept in the one subset every provider's strict mode accepts. Types:
#   "node"   a string that must resolve to a node in the discovered graph
#   "str" / "num" / "int"
#   ("enum", (...))
#   "obj"    a nested object validated by the primitive itself

_SIGNAL_OPS = ("above", "below", "rising", "present", "absent")
_CONFIG_OPS = ("equals", "not_equals", "contains", "not_contains", "exists",
               "missing", "gt", "lt", "matches")
_STATS = ("max", "min", "avg", "sum")

SCHEMAS: dict[str, dict] = {
    "signal": {"required": {"node": "node", "query": "obj", "predicate": "obj"},
               "optional": {"window": ("enum", WINDOWS)}},
    "config": {"required": {"node": "node", "path": "str", "predicate": "obj"},
               "optional": {"window": ("enum", WINDOWS)}},
    "drift": {"required": {"node": "node", "path": "str"},
              "optional": {"live_path": "str", "window": ("enum", WINDOWS)}},
    "changed": {"required": {"node": "node"},
                "optional": {"window": ("enum", WINDOWS), "match": "str"}},
    "before": {"required": {"a": "obj", "b": "obj"},
               "optional": {"max_gap": "num"}},
    "permit": {"required": {"principal": "node", "action": "str"},
               "optional": {"resource": "node", "resource_policy": "str",
                            "window": ("enum", WINDOWS)}},
    "reach": {"required": {"src": "node", "dst": "node", "port": "int"},
              "optional": {"protocol": ("enum", ("tcp", "udp")),
                           "window": ("enum", WINDOWS)}},
    "path_health": {"required": {"anchor": "node"},
                    "optional": {"depth": "int", "first_failing": "node",
                                 "window": ("enum", WINDOWS)}},
    "peer": {"required": {"node": "node", "query": "obj"},
             "optional": {"window": ("enum", WINDOWS)}},
}

# Temporal control participation and node-carrying args for peer controls.
CONTROL: dict[str, dict] = {
    "signal": {"temporal": True, "node_args": ("node",)},
    "config": {"temporal": True, "node_args": ("node",)},
    "drift": {"temporal": True, "node_args": ("node",)},
    "changed": {"temporal": True, "node_args": ("node",)},
    "before": {"temporal": False, "node_args": ()},
    "permit": {"temporal": True, "node_args": ("principal", "resource")},
    "reach": {"temporal": True, "node_args": ("src", "dst")},
    "path_health": {"temporal": True, "node_args": ()},
    "peer": {"temporal": True, "node_args": ()},
}


def validate(name: str, args: dict, model: SystemModel) -> list[str]:
    """Schema check for one prediction. Returns a list of problems (empty =
    valid). Node arguments must resolve to a node in the discovered graph."""
    if name not in SCHEMAS:
        return [f"unknown primitive {name!r}; use one of {sorted(SCHEMAS)}"]
    if not isinstance(args, dict):
        return ["args must be an object"]
    sch = SCHEMAS[name]
    errs = []
    allowed = {**sch["required"], **sch["optional"]}
    for k in sch["required"]:
        if k not in args:
            errs.append(f"{name}: missing required arg {k!r}")
    for k, v in args.items():
        if k not in allowed:
            errs.append(f"{name}: unknown arg {k!r}")
            continue
        t = allowed[k]
        if t == "node":
            if not isinstance(v, str) or not model.resolve(v):
                errs.append(f"{name}.{k}: {v!r} is not a node in the discovered graph")
        elif t == "str" and not isinstance(v, str):
            errs.append(f"{name}.{k}: expected string")
        elif t == "num" and (not isinstance(v, (int, float)) or isinstance(v, bool)):
            errs.append(f"{name}.{k}: expected number")
        elif t == "int" and (not isinstance(v, int) or isinstance(v, bool)):
            errs.append(f"{name}.{k}: expected integer")
        elif t == "obj" and not isinstance(v, dict):
            errs.append(f"{name}.{k}: expected object")
        elif isinstance(t, tuple) and v not in t[1]:
            errs.append(f"{name}.{k}: must be one of {list(t[1])}")
    if not errs:
        errs += _validate_nested(name, args, model)
    return errs


def _validate_nested(name: str, args: dict, model: SystemModel) -> list[str]:
    errs = []
    if name in ("signal", "peer") and "query" in args:
        q = args["query"]
        keys = {"metric", "log"} if name == "signal" else {"metric", "log", "config_path"}
        if len(set(q) & keys) != 1:
            errs.append(f"{name}.query: give exactly one of {sorted(keys)}")
        if name == "peer" and ("metric" in q or "log" in q) and "predicate" not in q:
            errs.append("peer.query: a metric/log query needs a predicate")
        if "stat" in q and q["stat"] not in _STATS:
            errs.append(f"{name}.query.stat must be one of {list(_STATS)}")
    if name == "signal":
        p = args.get("predicate", {})
        if p.get("op") not in _SIGNAL_OPS:
            errs.append(f"signal.predicate.op must be one of {list(_SIGNAL_OPS)}")
        if p.get("op") in ("above", "below") and not isinstance(p.get("value"), (int, float)):
            errs.append("signal.predicate.value (number) is required for above/below")
    if name == "config":
        p = args.get("predicate", {})
        if p.get("op") not in _CONFIG_OPS:
            errs.append(f"config.predicate.op must be one of {list(_CONFIG_OPS)}")
        if p.get("op") not in ("exists", "missing") and "value" not in p:
            errs.append("config.predicate.value is required for this op")
    if name == "before":
        for k in ("a", "b"):
            ref = args.get(k, {})
            ev = ref.get("event")
            if ev not in ("change", "signal_onset", "symptom_onset"):
                errs.append(f"before.{k}.event must be change | signal_onset | symptom_onset")
            elif ev != "symptom_onset" and not model.resolve(str(ref.get("node", ""))):
                errs.append(f"before.{k}.node is not a node in the discovered graph")
            elif ev == "signal_onset" and not (isinstance(ref.get("query"), dict)
                                               and isinstance(ref.get("predicate"), dict)):
                errs.append(f"before.{k}: signal_onset needs query and predicate")
    return errs


# ── helpers ──────────────────────────────────────────────────────────────────


def _window(ctx: Context, args: dict, default: str = "incident") -> tuple[str, Window]:
    name = args.get("window", default)
    return name, ctx.incident.window(name)


def _point_in_time(ctx: Context, wname: str) -> int | None:
    """The instant a config-like read refers to. The incident window reads the
    live (current) value; pre_onset/lookback read the value at that window's
    end."""
    if wname == "incident":
        return None
    return ctx.incident.window(wname).end


_PATH_TOKEN = re.compile(r"[^.\[\]]+|\[\d+\]")


def get_path(obj, path: str):
    """Dotted path with [i] list indexes. Raises KeyError when absent."""
    cur = obj
    for tok in _PATH_TOKEN.findall(path or ""):
        if tok.startswith("["):
            idx = int(tok[1:-1])
            if not isinstance(cur, list) or idx >= len(cur):
                raise KeyError(path)
            cur = cur[idx]
        else:
            if isinstance(cur, dict) and tok in cur:
                cur = cur[tok]
            else:
                raise KeyError(path)
    return cur


def _norm(v):
    """Normalise for equality: numeric strings compare as numbers, lists as
    order-insensitive JSON, dict keys sorted."""
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str) and re.fullmatch(r"-?\d+(\.\d+)?", v.strip()):
        return float(v)
    if isinstance(v, list):
        return sorted(json.dumps(_norm(x), sort_keys=True, default=str) for x in v)
    if isinstance(v, dict):
        return {k: _norm(x) for k, x in sorted(v.items())}
    return v


def _config_pred(value, present: bool, pred: dict) -> bool:
    op, want = pred.get("op"), pred.get("value")
    if op == "exists":
        return present
    if op == "missing":
        return not present
    if not present:
        return False
    if op == "equals":
        return _norm(value) == _norm(want)
    if op == "not_equals":
        return _norm(value) != _norm(want)
    if op in ("contains", "not_contains"):
        if isinstance(value, (list, tuple)):
            hit = any(_norm(x) == _norm(want) for x in value)
        elif isinstance(value, dict):
            hit = want in value
        else:
            hit = str(want) in str(value)
        return hit if op == "contains" else not hit
    if op in ("gt", "lt"):
        try:
            a, b = float(value), float(want)
        except (TypeError, ValueError):
            return False
        return a > b if op == "gt" else a < b
    if op == "matches":
        return re.search(str(want), str(value)) is not None
    return False


def _series(ctx: Context, node: str, query: dict, window: Window) -> tuple[list, str]:
    """(points, source label) for a metric or log query. Log queries become a
    count-per-event series (value 1 per matching line)."""
    if "metric" in query:
        pts = ctx.evidence.metric_series(node, query["metric"], window)
        return pts, f"metric {query['metric']}"
    pts = [(ts, 1.0) for ts, _m in ctx.evidence.log_events(node, query["log"], window)]
    return pts, f"logs '{query['log']}'"


def _agg(values: list[float], stat: str) -> float:
    if not values:
        return 0.0
    if stat == "max":
        return max(values)
    if stat == "min":
        return min(values)
    if stat == "sum":
        return sum(values)
    return sum(values) / len(values)


def _eval_signal(ctx: Context, node: str, query: dict, pred: dict,
                 window: Window) -> Result:
    try:
        pts, label = _series(ctx, node, query, window)
    except Unavailable as exc:
        return _unavailable(exc)
    is_log = "log" in query
    stat = query.get("stat", "sum" if is_log else "max")
    vals = [v for _t, v in pts]
    op = pred.get("op")
    facts = [_fact(f"{label} = {v:g}", f"{label} on {node}", t) for t, v in pts[:10]]
    onset = None
    if op in ("above", "below"):
        thr = float(pred["value"])
        if is_log:
            agg = len(vals)
            ok = agg > thr if op == "above" else agg < thr
            onset = pts[0][0] if (ok and op == "above" and pts) else None
        else:
            if not pts:
                return Result(INCONCLUSIVE, facts, f"no datapoints for {label} in window")
            agg = _agg(vals, stat)
            ok = agg > thr if op == "above" else agg < thr
            hits = [t for t, v in pts if (v > thr if op == "above" else v < thr)]
            onset = hits[0] if (ok and hits) else None
        return Result(PASS if ok else FAIL, facts,
                      f"{stat}({label}) = {agg:g} vs {op} {thr:g}", onset=onset,
                      detail={"aggregate": agg})
    if op == "present":
        ok = any(v > 0 for v in vals)
        onset = next((t for t, v in pts if v > 0), None)
        return Result(PASS if ok else FAIL, facts,
                      f"{label}: {'present' if ok else 'absent'} in window", onset=onset)
    if op == "absent":
        ok = not any(v > 0 for v in vals)
        return Result(PASS if ok else FAIL, facts,
                      f"{label}: {'absent' if ok else 'present'} in window")
    if op == "rising":
        factor = float(pred.get("factor", 2.0))
        base_w = Window(window.start - window.length, window.start)
        try:
            base_pts, _ = _series(ctx, node, query, base_w)
        except Unavailable as exc:
            return _unavailable(exc)
        if is_log:
            cur, base = float(len(vals)), float(len(base_pts))
        else:
            if not pts or not base_pts:
                return Result(INCONCLUSIVE, facts, "need datapoints in window and baseline")
            cur, base = _agg(vals, stat), _agg([v for _t, v in base_pts], stat)
        ok = cur > base * factor and cur > base
        if ok:
            onset = next((t for t, v in pts if v > base), None)
        return Result(PASS if ok else FAIL, facts,
                      f"{stat}({label}) {cur:g} vs baseline {base:g} (x{factor:g})",
                      onset=onset, detail={"current": cur, "baseline": base})
    return Result(INCONCLUSIVE, reason=f"unknown predicate {op!r}")


# ── primitives ───────────────────────────────────────────────────────────────


def p_signal(ctx: Context, args: dict) -> Result:
    node = ctx.model.resolve(args["node"])
    _w, window = _window(ctx, args)
    return _eval_signal(ctx, node, args["query"], args["predicate"], window)


def p_config(ctx: Context, args: dict) -> Result:
    node = ctx.model.resolve(args["node"])
    wname, _ = _window(ctx, args)
    at = _point_in_time(ctx, wname)
    try:
        cfg = ctx.evidence.config_at(node, at)
    except Unavailable as exc:
        return _unavailable(exc)
    try:
        value, present = get_path(cfg, args["path"]), True
    except KeyError:
        value, present = None, False
    ok = _config_pred(value, present, args["predicate"])
    src = f"config of {node}" + (f" as of {at}" if at else " (live)")
    shown = json.dumps(value, default=str)[:200] if present else "<absent>"
    return Result(PASS if ok else FAIL, [_fact(f"{args['path']} = {shown}", src, at)],
                  f"{args['path']} {args['predicate'].get('op')} {args['predicate'].get('value', '')}".strip())


def p_drift(ctx: Context, args: dict) -> Result:
    node = ctx.model.node(args["node"])
    if not node.declared or "declared" not in node.sources:
        return Result(UNAVAILABLE, reason=f"{node.id} is not in IaC (no declared value)",
                      missing="iac")
    try:
        declared = get_path(node.declared, args["path"])
    except KeyError:
        return Result(INCONCLUSIVE, reason=f"IaC declares no value at {args['path']}")
    wname, _ = _window(ctx, args)
    at = _point_in_time(ctx, wname)
    try:
        live_cfg = ctx.evidence.config_at(node.id, at)
    except Unavailable as exc:
        return _unavailable(exc)
    live_path = args.get("live_path", args["path"])
    try:
        live = get_path(live_cfg, live_path)
    except KeyError:
        return Result(PASS, [_fact(f"declared {args['path']} = {json.dumps(declared, default=str)[:120]}; "
                                   f"live {live_path} absent", f"IaC {node.iac_address} vs live", at)],
                      "declared value has no live counterpart")
    differs = _norm(declared) != _norm(live)
    return Result(PASS if differs else FAIL, [
        _fact(f"declared {args['path']} = {json.dumps(declared, default=str)[:120]}",
              f"IaC {node.iac_address} ({node.iac_file or 'file unknown'})"),
        _fact(f"live {live_path} = {json.dumps(live, default=str)[:120]}",
              f"config of {node.id}" + (f" as of {at}" if at else " (live)"), at),
    ], "live differs from IaC" if differs else "live matches IaC")


def p_changed(ctx: Context, args: dict) -> Result:
    node = ctx.model.resolve(args["node"])
    _w, window = _window(ctx, args, default="lookback")
    try:
        evs = ctx.evidence.changes(node, window)
    except Unavailable as exc:
        return _unavailable(exc)
    m = (args.get("match") or "").lower()
    if m:
        evs = [e for e in evs if m in json.dumps(e, default=str).lower()]
    evs = sorted(evs, key=lambda e: e["ts"])
    facts = [_fact(f"{e.get('action', '?')} by {e.get('actor', '?')}"
                   + (f" ({', '.join(e.get('paths') or [])})" if e.get("paths") else ""),
                   e.get("ref") or "change record", e["ts"]) for e in evs[:10]]
    return Result(PASS if evs else FAIL, facts,
                  f"{len(evs)} change(s) on {node} in window", onset=evs[0]["ts"] if evs else None)


def _resolve_event(ctx: Context, ref: dict) -> tuple[int | None, Result | None]:
    ev = ref.get("event")
    if ev == "symptom_onset":
        return ctx.incident.onset, None
    node = ctx.model.resolve(ref["node"])
    if ev == "change":
        r = p_changed(ctx, {"node": node, "window": "lookback",
                            **({"match": ref["match"]} if ref.get("match") else {})})
        if r.status == FAIL:
            # nothing in the lookback; also look inside the incident itself
            r2 = p_changed(ctx, {"node": node, "window": "incident",
                                 **({"match": ref["match"]} if ref.get("match") else {})})
            r = r2 if r2.status == PASS else r
    else:  # signal_onset: search from the start of the lookback to the end
        win = Window(ctx.incident.window("lookback").start, ctx.incident.end)
        r = _eval_signal(ctx, node, ref["query"], ref["predicate"], win)
    return (r.onset if r.status == PASS else None), r


def p_before(ctx: Context, args: dict) -> Result:
    ta, ra = _resolve_event(ctx, args["a"])
    tb, rb = _resolve_event(ctx, args["b"])
    for t, r, label in ((ta, ra, "a"), (tb, rb, "b")):
        if t is None:
            if r is not None and r.status == UNAVAILABLE:
                return Result(UNAVAILABLE, reason=f"event {label}: {r.reason}", missing=r.missing)
            return Result(INCONCLUSIVE, reason=f"event {label} has no timestamp"
                          + (f" ({r.reason})" if r else ""))
    gap = tb - ta
    max_gap = args.get("max_gap")
    facts = [_fact(f"a at {ta}", "before.a", ta), _fact(f"b at {tb}", "before.b", tb)]
    if gap < 0:
        return Result(FAIL, facts, f"a is {-gap}s after b")
    if max_gap is not None and gap > float(max_gap):
        return Result(FAIL, facts, f"gap {gap}s exceeds max_gap {max_gap:g}s")
    return Result(PASS, facts, f"a precedes b by {gap}s")


def p_permit(ctx: Context, args: dict) -> Result:
    principal = ctx.model.resolve(args["principal"])
    resource = ctx.model.resolve(args["resource"]) if args.get("resource") else ""
    wname, _ = _window(ctx, args)
    at = _point_in_time(ctx, wname)
    try:
        sim = ctx.evidence.simulate(principal, args["action"], resource,
                                    args.get("resource_policy", ""), at)
    except Unavailable as exc:
        return _unavailable(exc)
    decision = str(sim.get("decision", "")).lower()
    matched = sim.get("matched") or []
    facts = [_fact(f"{args['action']} -> {sim.get('decision')}", "IAM policy simulation", at)]
    facts += [_fact(f"matched {json.dumps(m, default=str)[:160]}", "IAM policy simulation", at)
              for m in matched[:5]]
    if decision == "allowed":
        return Result(PASS, facts, "allowed", detail={"decision": decision})
    if decision in ("explicitdeny", "implicitdeny"):
        return Result(FAIL, facts, decision, detail={"decision": decision})
    return Result(INCONCLUSIVE, facts, f"unrecognised decision {sim.get('decision')!r}")


# ── reach: security groups, NACLs and routes, evaluated in code ──────────────


def _ip_in(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _proto_ok(rule_proto, proto: str) -> bool:
    p = str(rule_proto).lower()
    return p in ("-1", "all") or p == proto or (p == "6" and proto == "tcp") or (p == "17" and proto == "udp")


def _port_ok(rule: dict, port: int) -> bool:
    if str(rule.get("IpProtocol", rule.get("Protocol", ""))) in ("-1", "all"):
        return True
    lo = rule.get("FromPort", (rule.get("PortRange") or {}).get("From"))
    hi = rule.get("ToPort", (rule.get("PortRange") or {}).get("To"))
    if lo is None or hi is None:
        return True
    return int(lo) <= port <= int(hi)


def _sg_allows(groups: list[dict], direction: str, peer_ips: list[str],
               peer_sgs: list[str], port: int, proto: str) -> tuple[str, str]:
    """Return (verdict, rule) where verdict is allow | deny | unknown.
    Security groups are allow-only: no matching rule means deny."""
    key = "IpPermissionsEgress" if direction == "egress" else "IpPermissions"
    unknown = ""
    for sg in groups:
        for rule in sg.get(key) or []:
            if not _proto_ok(rule.get("IpProtocol", "-1"), proto) or not _port_ok(rule, port):
                continue
            for r in rule.get("IpRanges") or []:
                if any(_ip_in(ip, r.get("CidrIp", "")) for ip in peer_ips):
                    return "allow", f"{sg.get('GroupId')} {key} {r.get('CidrIp')} port {port}"
            for pair in rule.get("UserIdGroupPairs") or []:
                if pair.get("GroupId") in peer_sgs:
                    return "allow", f"{sg.get('GroupId')} {key} from {pair.get('GroupId')} port {port}"
            if rule.get("PrefixListIds"):
                unknown = f"{sg.get('GroupId')} {key} uses a prefix list (not evaluated)"
    if unknown:
        return "unknown", unknown
    ids = ",".join(sg.get("GroupId", "?") for sg in groups)
    return "deny", f"no {key} rule in [{ids}] allows {proto}/{port}"


def _nacl_decision(nacl: dict, egress: bool, ip: str, port: int, proto: str) -> tuple[str, str]:
    entries = sorted((e for e in nacl.get("Entries") or [] if bool(e.get("Egress")) == egress),
                     key=lambda e: int(e.get("RuleNumber", 32767)))
    for e in entries:
        if not _proto_ok(e.get("Protocol", "-1"), proto) or not _port_ok(e, port):
            continue
        if _ip_in(ip, e.get("CidrBlock", "")):
            act = str(e.get("RuleAction", "")).lower()
            return ("allow" if act == "allow" else "deny"), \
                f"{nacl.get('NetworkAclId')} rule {e.get('RuleNumber')} {act} {e.get('CidrBlock')}"
    return "deny", f"{nacl.get('NetworkAclId')} default deny ({'egress' if egress else 'ingress'})"


def _route(rt: dict, ip: str) -> tuple[str, str]:
    best, best_len = None, -1
    for r in rt.get("Routes") or []:
        cidr = r.get("DestinationCidrBlock", "")
        if cidr and _ip_in(ip, cidr):
            n = ipaddress.ip_network(cidr, strict=False).prefixlen
            if n > best_len:
                best, best_len = r, n
    if not best:
        return "deny", f"{rt.get('RouteTableId')} has no route to {ip}"
    if str(best.get("State", "active")).lower() == "blackhole":
        return "deny", f"{rt.get('RouteTableId')} route {best.get('DestinationCidrBlock')} is blackhole"
    target = best.get("GatewayId") or best.get("NatGatewayId") or best.get("TransitGatewayId") \
        or best.get("VpcPeeringConnectionId") or best.get("NetworkInterfaceId") or ""
    if target == "local":
        return "allow", f"{rt.get('RouteTableId')} local route {best.get('DestinationCidrBlock')}"
    return "unknown", f"{rt.get('RouteTableId')} routes {ip} via {target} (beyond the VPC; not evaluated)"


def p_reach(ctx: Context, args: dict) -> Result:
    src = ctx.model.resolve(args["src"])
    dst = ctx.model.resolve(args["dst"])
    port, proto = int(args["port"]), args.get("protocol", "tcp")
    wname, _ = _window(ctx, args)
    at = _point_in_time(ctx, wname)
    try:
        a = ctx.evidence.network(src, at)
        b = ctx.evidence.network(dst, at)
    except Unavailable as exc:
        return _unavailable(exc)
    a_ips, b_ips = list(a.get("ips") or []), list(b.get("ips") or [])
    if not a_ips or not b_ips:
        return Result(UNAVAILABLE, reason="no IP addresses for src or dst", missing="network")
    a_sgs = [g.get("GroupId") for g in a.get("security_groups") or []]
    b_sgs = [g.get("GroupId") for g in b.get("security_groups") or []]
    layers: list[tuple[str, str, str]] = []   # (layer, verdict, rule)

    if a.get("route_table"):
        v, r = _route(a["route_table"], b_ips[0])
        layers.append(("route", v, r))
    else:
        layers.append(("route", "unknown", "src route table not collected"))
    if a.get("security_groups"):
        v, r = _sg_allows(a["security_groups"], "egress", b_ips, b_sgs, port, proto)
        layers.append(("src_sg_egress", v, r))
    else:
        layers.append(("src_sg_egress", "unknown", "src security groups not collected"))
    if a.get("nacl"):
        v, r = _nacl_decision(a["nacl"], True, b_ips[0], port, proto)
        layers.append(("src_nacl_egress", v, r))
    else:
        layers.append(("src_nacl_egress", "unknown", "src NACL not collected"))
    if b.get("nacl"):
        v, r = _nacl_decision(b["nacl"], False, a_ips[0], port, proto)
        layers.append(("dst_nacl_ingress", v, r))
    else:
        layers.append(("dst_nacl_ingress", "unknown", "dst NACL not collected"))
    if b.get("security_groups"):
        v, r = _sg_allows(b["security_groups"], "ingress", a_ips, a_sgs, port, proto)
        layers.append(("dst_sg_ingress", v, r))
    else:
        layers.append(("dst_sg_ingress", "unknown", "dst security groups not collected"))

    facts = [_fact(f"{layer}: {v} ({r})", f"network config ({'live' if at is None else at})", at)
             for layer, v, r in layers]
    blocked = [(layer, r) for layer, v, r in layers if v == "deny"]
    if blocked:
        return Result(FAIL, facts, f"blocked at {blocked[0][0]}: {blocked[0][1]}",
                      detail={"blocking_layer": blocked[0][0], "blocking_rule": blocked[0][1]})
    if any(v == "unknown" for _l, v, _r in layers):
        return Result(INCONCLUSIVE, facts,
                      "no layer blocks, but not every layer could be evaluated "
                      "(stateless NACL return path is never evaluated)")
    return Result(PASS, facts, "every evaluated layer allows the flow "
                               "(stateless NACL return path not evaluated)")


def _health(ctx: Context, node: str, window: Window) -> tuple[str, list]:
    try:
        sig = ctx.evidence.failure_signals(node, window)
    except Unavailable:
        return "unknown", []
    return ("failing" if sig else "healthy"), sig


def p_path_health(ctx: Context, args: dict) -> Result:
    anchor = ctx.model.resolve(args["anchor"])
    depth = int(args.get("depth", 3))
    _w, window = _window(ctx, args)
    path = ctx.model.failing_path(anchor, max_depth=depth)
    states, facts = {}, []
    for nid in path:
        h, sig = _health(ctx, nid, window)
        states[nid] = h
        if sig:
            facts.append(_fact(f"{nid} failing: {sig[0][1][:160]}", f"failure lines on {nid}", sig[0][0]))
    failing = [n for n in path if states[n] == "failing"]
    up = ctx.model.upstream(anchor, depth)
    # The most upstream failing node: furthest from the anchor along
    # dependencies; ties broken by id for determinism.
    deepest = max(failing, key=lambda n: (up.get(n, 0), n)) if failing else None
    detail = {"states": states, "failing": failing, "first_failing": deepest}
    if all(s == "unknown" for s in states.values()):
        return Result(UNAVAILABLE, facts, "no node on the failing path is observable",
                      missing="failure_signals", detail=detail)
    if args.get("first_failing"):
        # "First failing" = the most upstream failing node among the
        # OBSERVABLE nodes; unobservable nodes further upstream are listed in
        # detail["unknown_upstream"] so a reader can see what wasn't checked.
        want = ctx.model.resolve(args["first_failing"])
        detail["unknown_upstream"] = [n for n in path if states[n] == "unknown"
                                      and ctx.model.is_upstream_of(n, want)]
        state = states.get(want)
        if state is None:
            return Result(FAIL, facts, f"{want} is not on the failing path within depth {depth}",
                          detail=detail)
        if deepest == want:
            return Result(PASS, facts, f"first failing observable node is {want}", detail=detail)
        if state == "unknown":
            return Result(UNAVAILABLE, facts, f"{want} is not observable", missing="failure_signals",
                          detail=detail)
        if state == "healthy":
            return Result(FAIL, facts, f"{want} is healthy", detail=detail)
        return Result(FAIL, facts, f"first failing node is {deepest}, not {want}", detail=detail)
    return Result(PASS if failing else FAIL, facts,
                  f"{len(failing)} failing node(s) on the path" if failing else "no failing node on the path",
                  detail=detail)


def p_peer(ctx: Context, args: dict) -> Result:
    node = ctx.model.resolve(args["node"])
    query = args["query"]
    wname, window = _window(ctx, args)
    at = _point_in_time(ctx, wname)

    def _value(nid: str):
        if "config_path" in query:
            cfg = ctx.evidence.config_at(nid, at)
            try:
                return _norm(get_path(cfg, query["config_path"]))
            except KeyError:
                return "<absent>"
        r = _eval_signal(ctx, nid, {k: v for k, v in query.items() if k != "predicate"},
                         query["predicate"], window)
        if r.status in (UNAVAILABLE, INCONCLUSIVE):
            raise Unavailable(r.missing or "signal", r.reason)
        return r.status == PASS

    try:
        mine = _value(node)
    except Unavailable as exc:
        return _unavailable(exc)
    peers = []
    for p in ctx.model.peers(node):
        if _health(ctx, p, window)[0] != "healthy":
            continue
        try:
            peers.append((p, _value(p)))
        except Unavailable:
            continue
    if not peers:
        return Result(UNAVAILABLE, reason=f"no healthy, observable peers of {node}",
                      missing="peers")
    differs = [p for p, v in peers if v != mine]
    facts = [_fact(f"{node} = {json.dumps(mine, default=str)[:80]}", f"{node}", at)] + \
            [_fact(f"peer {p} = {json.dumps(v, default=str)[:80]}", f"{p}", at) for p, v in peers[:8]]
    if len(differs) == len(peers):
        return Result(PASS, facts, f"differs from all {len(peers)} healthy peer(s)")
    if not differs:
        return Result(FAIL, facts, f"same as all {len(peers)} healthy peer(s)")
    return Result(INCONCLUSIVE, facts, f"differs from {len(differs)} of {len(peers)} healthy peers")


PRIMITIVES = {
    "signal": p_signal, "config": p_config, "drift": p_drift, "changed": p_changed,
    "before": p_before, "permit": p_permit, "reach": p_reach,
    "path_health": p_path_health, "peer": p_peer,
}
assert set(PRIMITIVES) == set(SCHEMAS) == set(CONTROL)


def canonical_args(name: str, args: dict, model: SystemModel) -> dict:
    """Resolve node identifiers to node ids so equivalent questions share one
    cache entry, whichever identifier a model used."""
    out = {}
    sch = {**SCHEMAS[name]["required"], **SCHEMAS[name]["optional"]}
    for k, v in args.items():
        out[k] = model.resolve(v) or v if sch.get(k) == "node" else v
    if name == "before":
        for k in ("a", "b"):
            ref = dict(out[k])
            if ref.get("node"):
                ref["node"] = model.resolve(ref["node"]) or ref["node"]
            out[k] = ref
    return out


def run(ctx: Context, name: str, args: dict) -> Result:
    """Validate and run one primitive. Invalid args come back INCONCLUSIVE with
    the problems listed (callers validate first; this is a backstop)."""
    errs = validate(name, args, ctx.model)
    if errs:
        return Result(INCONCLUSIVE, reason="; ".join(errs))
    try:
        return PRIMITIVES[name](ctx, canonical_args(name, args, ctx.model))
    except Unavailable as exc:
        return _unavailable(exc)
