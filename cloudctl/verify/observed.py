"""Observed layer: who actually calls whom.

Each reader takes already-fetched records (live or replayed from a recording)
and adds ``observed`` edges to the model. Nothing here calls AWS. Every edge
carries a pointer to the record it came from (event id, trace id, flow tuple,
log stream) so the verifier can cite it.

  * CloudTrail: the caller identity (an assumed role, i.e. a compute
    resource's execution role) -> the resources named in the event.
  * VPC flow logs: source ENI/IP -> destination IP, mapped to nodes through an
    IP index built from live ENI data. Only ACCEPT records make edges; REJECT
    records are kept as facts for ``reach``.
  * X-Ray: the service graph's edges, mapped to nodes by name/ARN.
  * Log lines: a node's own log lines that name another node's endpoint,
    hostname, ARN or name.

What can't be observed is not guessed: a reader with no input adds nothing,
and :func:`observability_gaps` reports which sources were absent.
"""
from __future__ import annotations

import json
import re

from cloudctl.verify.model import SystemModel


def _role_from_assumed(arn: str) -> str:
    """arn:aws:sts::123:assumed-role/RoleName/session -> role name."""
    m = re.match(r"arn:aws[a-z-]*:sts::\d*:assumed-role/([^/]+)/", arn or "")
    return m.group(1) if m else ""


def _caller_node(model: SystemModel, event: dict) -> str | None:
    ui = event.get("userIdentity") or {}
    arn = ui.get("arn", "")
    issuer = ((ui.get("sessionContext") or {}).get("sessionIssuer") or {}).get("arn", "")
    for ident in (issuer, arn, _role_from_assumed(arn), ui.get("invokedBy", "")):
        nid = model.resolve(ident) if ident else None
        if nid:
            # A role is reached by the compute that runs as it; when exactly one
            # node depends on the role through an execution_role edge, that node
            # is the caller. Otherwise the role itself is the caller.
            runners = [e.src for e in model.edges
                       if e.dst == nid and e.via == "execution_role"]
            return runners[0] if len(runners) == 1 else nid
    return None


def _event_targets(model: SystemModel, event: dict) -> set[str]:
    targets: set[str] = set()
    for r in event.get("resources") or []:
        nid = model.resolve(r.get("ARN") or r.get("resourceName") or "")
        if nid:
            targets.add(nid)
    params = event.get("requestParameters")
    if params:
        targets |= model.find_references(json.dumps(params, default=str))
    return targets


def add_cloudtrail_edges(model: SystemModel, events: list[dict]) -> int:
    """Events in CloudTrail record format (the ``CloudTrailEvent`` JSON of
    lookup_events, already parsed)."""
    added = 0
    for ev in events or []:
        if isinstance(ev.get("CloudTrailEvent"), str):
            try:
                ev = json.loads(ev["CloudTrailEvent"])
            except json.JSONDecodeError:
                continue
        caller = _caller_node(model, ev)
        if not caller:
            continue
        for tgt in sorted(_event_targets(model, ev)):
            if tgt != caller and model.add_edge(
                    caller, tgt, "observed", via="cloudtrail",
                    detail=f"{ev.get('eventSource','')}:{ev.get('eventName','')} {ev.get('eventID','')}"):
                added += 1
    return added


def build_ip_index(model: SystemModel, enis: list[dict]) -> dict[str, str]:
    """IP -> node id from live ENI descriptions. An ENI maps to a node via its
    attachment/requester or description naming the node (generic: whatever
    identifier appears)."""
    index: dict[str, str] = {}
    for eni in enis or []:
        blob = json.dumps({k: eni.get(k) for k in ("Description", "RequesterId", "Attachment",
                                                   "InterfaceType", "Groups", "TagSet")},
                          default=str)
        owner = model.resolve(eni.get("NetworkInterfaceId", ""))
        if not owner:
            refs = model.find_references(blob)
            owner = next(iter(refs)) if len(refs) == 1 else None
        if not owner:
            continue
        for addr in eni.get("PrivateIpAddresses") or []:
            ip = addr.get("PrivateIpAddress")
            if ip:
                index[ip] = owner
        if eni.get("PrivateIpAddress"):
            index[eni["PrivateIpAddress"]] = owner
    return index


def parse_flow_record(line: str) -> dict | None:
    """Default-format VPC flow log record (version 2, 14 fields)."""
    f = (line or "").split()
    if len(f) < 14 or f[0] != "2":
        return None
    try:
        return {"interface_id": f[2], "srcaddr": f[3], "dstaddr": f[4],
                "srcport": int(f[5]) if f[5] != "-" else None,
                "dstport": int(f[6]) if f[6] != "-" else None,
                "protocol": f[7], "start": int(f[10]) if f[10] != "-" else None,
                "action": f[12]}
    except ValueError:
        return None


def add_flow_log_edges(model: SystemModel, lines: list[str], ip_index: dict[str, str]) -> int:
    added = 0
    for line in lines or []:
        rec = parse_flow_record(line)
        if not rec or rec["action"] != "ACCEPT":
            continue
        a, b = ip_index.get(rec["srcaddr"]), ip_index.get(rec["dstaddr"])
        if a and b and a != b and model.add_edge(
                a, b, "observed", via="flow_log",
                detail=f"{rec['srcaddr']}->{rec['dstaddr']}:{rec['dstport']}"):
            added += 1
    return added


def add_xray_edges(model: SystemModel, service_graph: dict) -> int:
    """X-Ray GetServiceGraph output: Services[] each with ReferenceId, Name,
    Names, and Edges[{ReferenceId}]."""
    services = {s.get("ReferenceId"): s for s in (service_graph or {}).get("Services") or []}

    def _resolve(svc: dict) -> str | None:
        for ident in [svc.get("Name", "")] + list(svc.get("Names") or []):
            nid = model.resolve(ident)
            if nid:
                return nid
        return None

    added = 0
    for ref, svc in services.items():
        a = _resolve(svc)
        if not a:
            continue
        for e in svc.get("Edges") or []:
            dst = services.get(e.get("ReferenceId"))
            b = _resolve(dst) if dst else None
            if b and b != a and model.add_edge(a, b, "observed", via="xray",
                                               detail=f"ref {ref}->{e.get('ReferenceId')}"):
                added += 1
    return added


_HOST_RE = re.compile(r"(?:[a-z0-9-]+\.)+amazonaws\.com|(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?", re.IGNORECASE)


def add_log_line_edges(model: SystemModel, node_logs: dict[str, list[str]],
                       endpoints: dict[str, str] | None = None) -> int:
    """``node_logs``: {node identifier: [log lines it emitted]}.
    ``endpoints``: {hostname or URL fragment: node identifier} from live config
    (load balancer DNS names, queue URLs, DB endpoints)."""
    endpoints = endpoints or {}
    added = 0
    for ident, lines in (node_logs or {}).items():
        src = model.resolve(ident)
        if not src:
            continue
        for line in lines or []:
            targets = model.find_references(line, exclude=src)
            for host in _HOST_RE.findall(line):
                for frag, owner in endpoints.items():
                    if frag and frag in host:
                        nid = model.resolve(owner)
                        if nid and nid != src:
                            targets.add(nid)
            for tgt in sorted(targets):
                if model.add_edge(src, tgt, "observed", via="log_line", detail=line[:160]):
                    added += 1
    return added


def observability_gaps(provided: dict) -> list[str]:
    """Which observed sources were missing for this run, for the abstention
    report. ``provided``: {"cloudtrail": bool, "flow_logs": bool, "xray": bool,
    "logs": bool}."""
    labels = {"cloudtrail": "CloudTrail events", "flow_logs": "VPC flow logs",
              "xray": "X-Ray traces", "logs": "application logs"}
    return [labels[k] for k in labels if not provided.get(k)]
