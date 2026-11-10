"""The system model: a dependency graph of this org's system, discovered per run.

Three sources feed it, and every edge records which one it came from:

  declared  IaC (Terraform state/plan, CloudFormation, CDK synth)
  live      describe/list results, the role a compute resource runs as, ENIs
  observed  who actually called whom (CloudTrail, flow logs, traces, log lines)

Direction convention: an edge ``a -> b`` means *a depends on b* (a calls, reads,
assumes or routes to b). The *anchor* is the node emitting the failure. The
*failing path* is every node reachable from the anchor along dependency edges.
"Upstream" in this package means further along that direction, i.e. toward the
things a node depends on; the most upstream verified cause is the root cause.

The model is pure data plus graph queries. It knows nothing about services.
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field

SOURCES = ("declared", "live", "observed")

_ARN_RE = re.compile(r"arn:aws[a-z0-9-]*:[a-z0-9-]+:[^:\s\"']*:[^:\s\"']*:[^\s\"',}\]]+")


@dataclass
class Edge:
    src: str
    dst: str
    source: str            # declared | live | observed
    via: str = ""          # what produced it: "tf_ref", "cfn_ref", "config_ref", "cloudtrail", ...
    detail: str = ""       # pointer to the evidence (attribute path, event id, trace id)

    def key(self) -> tuple:
        return (self.src, self.dst, self.source, self.via)

    def to_dict(self) -> dict:
        return {"from": self.src, "to": self.dst, "source": self.source,
                "via": self.via, "detail": self.detail}


@dataclass
class Node:
    """One resource. ``id`` is the stable key used everywhere in the verifier:
    the ARN when known, else the IaC address, else ``type:name``."""

    id: str
    type: str = ""                       # e.g. "aws_lambda_function" / "AWS::Lambda::Function" / "lambda"
    name: str = ""
    arn: str = ""
    iac_address: str = ""                # Terraform address or CFN logical id
    iac_file: str = ""                   # source file where known
    iac_module: str = ""                 # Terraform module path / CDK construct path / stack
    declared: dict = field(default_factory=dict)   # config as declared in IaC
    live: dict = field(default_factory=dict)       # config as described live
    sources: set = field(default_factory=set)      # which layers know this node
    aliases: set = field(default_factory=set)      # other identifiers that resolve here
    observability: dict = field(default_factory=dict)  # {"metrics": [...], "log_groups": [...], "traces": bool, "config_history": bool}

    def identifiers(self) -> set:
        """Strong identifiers: each names exactly one resource."""
        ids = {self.id, self.arn, self.iac_address} | set(self.aliases)
        return {i for i in ids if i}

    def family(self) -> str:
        return type_family(self.type, self.arn)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "type": self.type, "name": self.name, "arn": self.arn,
            "iac_address": self.iac_address, "iac_file": self.iac_file,
            "iac_module": self.iac_module, "sources": sorted(self.sources),
            "observability": self.observability,
        }


class SystemModel:
    """Nodes and provenance-tagged edges, with the graph queries the verifier needs."""

    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self._edge_keys: set = set()
        self._alias: dict[str, str] = {}
        self._names: dict[str, set] = {}

    # ── construction ─────────────────────────────────────────────────────────

    def add_node(self, node: Node, source: str) -> Node:
        """Add or merge a node. Merging happens when any identifier (id, ARN,
        IaC address, name, alias) already resolves to an existing node."""
        if source not in SOURCES:
            raise ValueError(f"unknown source {source!r}")
        existing = None
        for ident in node.identifiers():
            nid = self._alias.get(ident)
            if nid:
                existing = self.nodes[nid]
                break
        if existing is None and node.name:
            # A bare name joins layers only when it is unambiguous and the two
            # sides agree on the service family; otherwise keep them apart (a
            # missed join is a visible discovery gap, a wrong join is silent).
            cands = [self.nodes[i] for i in self._names.get(node.name, ())]
            fam = node.family()
            cands = [c for c in cands if not fam or not c.family() or c.family() == fam]
            if len(cands) == 1 and (not node.arn or not cands[0].arn):
                existing = cands[0]
        if existing is None:
            node.sources.add(source)
            self.nodes[node.id] = node
            self._index(node)
            return node
        existing.sources.add(source)
        for attr in ("type", "name", "arn", "iac_address", "iac_file", "iac_module"):
            if not getattr(existing, attr) and getattr(node, attr):
                setattr(existing, attr, getattr(node, attr))
        if node.declared:
            existing.declared = {**existing.declared, **node.declared}
        if node.live:
            existing.live = {**existing.live, **node.live}
        for k, v in node.observability.items():
            existing.observability.setdefault(k, v)
        existing.aliases |= node.identifiers() - {existing.id}
        # Prefer the ARN as the primary id once one is known: it is what live
        # and observed sources speak, and it is stable across IaC refactors.
        if existing.arn and existing.id != existing.arn:
            self._rekey(existing.id, existing.arn)
            existing = self.nodes[existing.arn]
        self._index(existing)
        return existing

    def _index(self, node: Node) -> None:
        for ident in node.identifiers():
            self._alias[ident] = node.id
        for names in self._names.values():
            names.discard(node.id)
        for a in node.aliases:
            for names in self._names.values():
                names.discard(a)
        if node.name:
            self._names.setdefault(node.name, set()).add(node.id)

    def _rekey(self, old: str, new: str) -> None:
        node = self.nodes.pop(old)
        node.aliases.add(old)
        node.id = new
        self.nodes[new] = node
        for e in self.edges:
            if e.src == old:
                e.src = new
            if e.dst == old:
                e.dst = new
        self._edge_keys = {e.key() for e in self.edges}
        for k, v in list(self._alias.items()):
            if v == old:
                self._alias[k] = new
        for names in self._names.values():
            if old in names:
                names.discard(old)
                names.add(new)

    def add_edge(self, src: str, dst: str, source: str, via: str = "",
                 detail: str = "") -> Edge | None:
        """Add a dependency edge between two identifiers. Endpoints that don't
        resolve to a known node are dropped (returns None): an edge to something
        outside the model can't be verified, and silently inventing a node for
        it would hide a discovery gap."""
        if source not in SOURCES:
            raise ValueError(f"unknown source {source!r}")
        a, b = self.resolve(src), self.resolve(dst)
        if not a or not b or a == b:
            return None
        edge = Edge(a, b, source, via, detail)
        if edge.key() in self._edge_keys:
            return None
        self._edge_keys.add(edge.key())
        self.edges.append(edge)
        return edge

    # ── lookup ───────────────────────────────────────────────────────────────

    def resolve(self, ident: str) -> str | None:
        """Map any identifier (id, ARN, IaC address, name, alias) to a node id."""
        if not ident:
            return None
        if ident in self.nodes:
            return ident
        if ident in self._alias:
            return self._alias[ident]
        names = self._names.get(ident) or set()
        return next(iter(names)) if len(names) == 1 else None

    def node(self, ident: str) -> Node | None:
        nid = self.resolve(ident)
        return self.nodes.get(nid) if nid else None

    def find_references(self, blob: str, exclude: str = "") -> set[str]:
        """Node ids whose ARN or (token-bounded, >= 6 chars) name appears in a
        text blob. Same rule as get_dependency_graph's config_ref edges."""
        found: set[str] = set()
        for arn in _ARN_RE.findall(blob or ""):
            nid = self.resolve(arn)
            if nid and nid != exclude:
                found.add(nid)
        for nid, n in self.nodes.items():
            if nid == exclude or nid in found:
                continue
            for ident in (n.name, n.arn):
                if ident and len(ident) >= 6 and re.search(
                    r"(?<![A-Za-z0-9])" + re.escape(ident) + r"(?![A-Za-z0-9])", blob or ""
                ):
                    found.add(nid)
                    break
        return found

    # ── graph queries ────────────────────────────────────────────────────────

    def dependencies(self, nid: str, sources: Iterable[str] = SOURCES) -> list[str]:
        srcs = set(sources)
        return sorted({e.dst for e in self.edges if e.src == nid and e.source in srcs})

    def dependents(self, nid: str, sources: Iterable[str] = SOURCES) -> list[str]:
        srcs = set(sources)
        return sorted({e.src for e in self.edges if e.dst == nid and e.source in srcs})

    def upstream(self, nid: str, max_depth: int | None = None) -> dict[str, int]:
        """Nodes reachable from ``nid`` along dependency edges, with distance.
        Excludes ``nid`` itself. Deterministic and cycle-safe."""
        dist: dict[str, int] = {}
        frontier = [nid]
        depth = 0
        seen = {nid}
        while frontier and (max_depth is None or depth < max_depth):
            depth += 1
            nxt = []
            for cur in sorted(frontier):
                for dep in self.dependencies(cur):
                    if dep not in seen:
                        seen.add(dep)
                        dist[dep] = depth
                        nxt.append(dep)
            frontier = nxt
        return dist

    def failing_path(self, anchor: str, max_depth: int | None = None) -> list[str]:
        """The anchor plus everything it depends on, transitively, ordered by
        distance then id."""
        a = self.resolve(anchor)
        if not a:
            return []
        up = self.upstream(a, max_depth)
        return [a] + sorted(up, key=lambda n: (up[n], n))

    def on_failing_path(self, anchor: str, nid: str) -> bool:
        a, n = self.resolve(anchor), self.resolve(nid)
        return bool(a and n and (a == n or n in self.upstream(a)))

    def is_upstream_of(self, a: str, b: str) -> bool:
        """True when ``a`` is reachable from ``b`` along dependencies (a is
        further upstream than b on a chain)."""
        ra, rb = self.resolve(a), self.resolve(b)
        return bool(ra and rb and ra != rb and ra in self.upstream(rb))

    def same_chain(self, a: str, b: str) -> bool:
        return self.is_upstream_of(a, b) or self.is_upstream_of(b, a)

    def peers(self, nid: str) -> list[str]:
        """Nodes of the same type, or declared by the same IaC module. A peer is
        a candidate control; whether it is *healthy* is for the caller to judge."""
        n = self.node(nid)
        if not n:
            return []
        out = []
        for other in self.nodes.values():
            if other.id == n.id:
                continue
            same_type = bool(n.type) and other.type == n.type
            same_module = bool(n.iac_module) and other.iac_module == n.iac_module and other.type == n.type
            if same_type or same_module:
                out.append(other.id)
        return sorted(out)

    def edge_sources(self, a: str, b: str) -> list[str]:
        ra, rb = self.resolve(a), self.resolve(b)
        return sorted({e.source for e in self.edges if e.src == ra and e.dst == rb})

    # ── export ───────────────────────────────────────────────────────────────

    def summary(self, limit: int = 200) -> dict:
        """Compact view for prompts and logs: node ids are what the proposer
        must use, so they are listed exactly."""
        nodes = sorted(self.nodes.values(), key=lambda n: n.id)[:limit]
        return {
            "nodes": [{"id": n.id, "type": n.type, "name": n.name,
                       "iac": n.iac_address, "sources": sorted(n.sources)} for n in nodes],
            "edges": [e.to_dict() for e in self.edges
                      if e.src in {n.id for n in nodes} and e.dst in {n.id for n in nodes}],
            "truncated": len(self.nodes) > limit,
        }

    def to_dict(self) -> dict:
        return {"nodes": [n.to_dict() for n in sorted(self.nodes.values(), key=lambda n: n.id)],
                "edges": [e.to_dict() for e in self.edges]}

    def stats(self) -> dict:
        by_src = {s: sum(1 for e in self.edges if e.source == s) for s in SOURCES}
        nodes_by_src = {s: sum(1 for n in self.nodes.values() if s in n.sources) for s in SOURCES}
        return {"nodes": len(self.nodes), "edges": len(self.edges),
                "edges_by_source": by_src, "nodes_by_source": nodes_by_src}


_TF_FAMILY_FIX = {"security": "ec2", "subnet": "ec2", "vpc": "ec2", "instance": "ec2",
                  "route": "ec2", "network": "ec2", "lb": "elasticloadbalancing",
                  "alb": "elasticloadbalancing", "cloudwatch": "logs", "db": "rds",
                  "api": "apigateway", "apigatewayv2": "apigateway", "sfn": "states"}


def type_family(rtype: str, arn: str = "") -> str:
    """Coarse service family used only to stop name-based joins across services.
    ``aws_lambda_function`` / ``AWS::Lambda::Function`` / ``lambda`` / an ARN in
    the lambda namespace all map to ``lambda``. Unknown -> ""."""
    if arn.startswith("arn:"):
        parts = arn.split(":")
        if len(parts) > 2 and parts[2]:
            return parts[2]
    t = (rtype or "").strip()
    if not t:
        return ""
    if t.startswith("AWS::"):
        return t.split("::")[1].lower()
    if t.startswith("aws_"):
        fam = t[4:].split("_")[0]
        return _TF_FAMILY_FIX.get(fam, fam)
    return t.split(":")[0].lower()


def live_from_dependency_graph(model: SystemModel, graph: dict) -> None:
    """Fold the output of the existing ``get_dependency_graph`` tool (nodes
    ``service:name``, edges ``{from, to, via}``) into the live layer."""
    for nid in graph.get("nodes") or []:
        if not isinstance(nid, str) or ":" not in nid:
            continue
        svc, name = nid.split(":", 1)
        model.add_node(Node(id=nid, type=svc, name=name), "live")
    for e in graph.get("edges") or []:
        if isinstance(e, dict):
            model.add_edge(e.get("from", ""), e.get("to", ""), "live",
                           via=e.get("via", "config_ref"))


def live_from_snapshot(model: SystemModel, resources: list[dict]) -> None:
    """Live layer from a list of described resources:
    ``[{"arn", "type", "name", "config": {...}, "role_arn"?: str}]``.

    Edges come from one generic rule (the live config references another
    node's ARN or name) plus the execution role, which is the one live
    relation that is never a config string match by accident."""
    for r in resources or []:
        arn = r.get("arn", "")
        model.add_node(Node(id=arn or f"{r.get('type','')}:{r.get('name','')}",
                            type=r.get("type", ""), name=r.get("name", ""), arn=arn,
                            live=r.get("config") or {}), "live")
    import json as _json
    for r in resources or []:
        src = model.resolve(r.get("arn") or f"{r.get('type','')}:{r.get('name','')}")
        if not src:
            continue
        blob = _json.dumps(r.get("config") or {}, default=str)
        for dst in sorted(model.find_references(blob, exclude=src)):
            model.add_edge(src, dst, "live", via="config_ref")
        if r.get("role_arn"):
            model.add_edge(src, r["role_arn"], "live", via="execution_role")
