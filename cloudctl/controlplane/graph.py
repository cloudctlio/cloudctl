"""The change graph: what the request compiler produces and the orchestrator runs.

A change graph is a small DAG of nodes. Each node is one change the policy
gate evaluates on its own: an IaC apply in one root, or one API fix. Edges
(``depends_on``) say which nodes must succeed first.

The JSON shape is fixed and versioned (:data:`GRAPH_SCHEMA`). The model is
asked for exactly this shape, and the same strict parser validates a graph
whether a model wrote it or a person did. Unknown keys, wrong types, unknown
references and cycles are errors, never guesses.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

from cloudctl.gate.canonical import digest

GRAPH_VERSION = 1
NODE_KINDS = ("iac_apply", "api_action")
MAX_NODES = 50
_ID = re.compile(r"^[a-z][a-z0-9_-]{0,47}$")

#: JSON Schema (draft 2020-12) for the change graph. Given to the model as the
#: output contract; :func:`parse_graph` enforces the same rules (and more).
GRAPH_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "cctl change graph",
    "type": "object",
    "additionalProperties": False,
    "required": ["version", "request", "nodes", "questions"],
    "properties": {
        "version": {"const": GRAPH_VERSION},
        "request": {"type": "string", "maxLength": 2000},
        "questions": {
            "type": "array", "maxItems": 5,
            "items": {"type": "object", "additionalProperties": False, "required": ["id", "question"],
                      "properties": {"id": {"type": "string", "pattern": _ID.pattern},
                                     "question": {"type": "string", "maxLength": 300},
                                     "options": {"type": "array", "maxItems": 6,
                                                 "items": {"type": "string", "maxLength": 120}}}},
        },
        "nodes": {
            "type": "array", "maxItems": MAX_NODES,
            "items": {
                "type": "object", "additionalProperties": False,
                "required": ["id", "kind", "environment", "summary", "target", "depends_on"],
                "properties": {
                    "id": {"type": "string", "pattern": _ID.pattern},
                    "kind": {"enum": list(NODE_KINDS)},
                    "environment": {"type": "string", "maxLength": 63},
                    "summary": {"type": "string", "maxLength": 500},
                    "depends_on": {"type": "array", "items": {"type": "string"}, "maxItems": MAX_NODES},
                    "target": {
                        "type": "object", "additionalProperties": False,
                        "properties": {"iac_root": {"type": "string", "maxLength": 1024},
                                       "issue": {"type": "object"}, "fix": {"type": "object"}},
                    },
                },
            },
        },
    },
}


class GraphError(ValueError):
    """The graph is malformed. ``errors`` lists every problem found."""

    def __init__(self, errors: Iterable[str]) -> None:
        self.errors = tuple(errors)
        super().__init__("; ".join(self.errors) or "invalid change graph")


@dataclass(frozen=True)
class Question:
    id: str
    question: str
    options: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"id": self.id, "question": self.question}
        if self.options:
            d["options"] = list(self.options)
        return d


@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    environment: str
    summary: str
    depends_on: tuple[str, ...] = ()
    iac_root: str = ""
    issue: Mapping[str, Any] = field(default_factory=dict)
    fix: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target: dict[str, Any] = {}
        if self.kind == "iac_apply":
            target["iac_root"] = self.iac_root
        else:
            target["issue"] = dict(self.issue)
            target["fix"] = dict(self.fix)
        return {"id": self.id, "kind": self.kind, "environment": self.environment, "summary": self.summary,
                "target": target, "depends_on": list(self.depends_on)}


@dataclass(frozen=True)
class ChangeGraph:
    request: str
    nodes: tuple[Node, ...]
    questions: tuple[Question, ...] = ()
    version: int = GRAPH_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "request": self.request, "nodes": [n.to_dict() for n in self.nodes],
                "questions": [q.to_dict() for q in self.questions]}

    def digest(self) -> str:
        return digest(self.to_dict())

    def node(self, node_id: str) -> Node:
        for n in self.nodes:
            if n.id == node_id:
                return n
        raise KeyError(node_id)

    def order(self) -> list[str]:
        """Dependency order (Kahn's algorithm, ties broken by id, so the
        order is deterministic)."""
        return topo_order({n.id: n.depends_on for n in self.nodes})

    def downstream(self, node_id: str) -> set[str]:
        """Every node that depends on *node_id*, directly or transitively."""
        children: dict[str, set[str]] = {n.id: set() for n in self.nodes}
        for n in self.nodes:
            for d in n.depends_on:
                children.setdefault(d, set()).add(n.id)
        out: set[str] = set()
        stack = [node_id]
        while stack:
            for c in children.get(stack.pop(), ()):
                if c not in out:
                    out.add(c)
                    stack.append(c)
        return out


def topo_order(deps: Mapping[str, Iterable[str]]) -> list[str]:
    deps = {k: set(v) for k, v in deps.items()}
    missing = sorted({d for v in deps.values() for d in v} - set(deps))
    if missing:
        raise GraphError([f"depends_on names unknown node(s): {missing}"])
    indeg = {k: len(v) for k, v in deps.items()}
    children: dict[str, set[str]] = {k: set() for k in deps}
    for k, v in deps.items():
        for d in v:
            children[d].add(k)
    ready = sorted(k for k, n in indeg.items() if n == 0)
    out: list[str] = []
    while ready:
        k = ready.pop(0)
        out.append(k)
        for c in sorted(children[k]):
            indeg[c] -= 1
            if indeg[c] == 0:
                ready.append(c)
        ready.sort()
    if len(out) != len(deps):
        cyc = sorted(set(deps) - set(out))
        raise GraphError([f"the graph has a cycle among: {cyc}"])
    return out


# ── strict parsing (layer 1: shape; layer 3: graph) ─────────────────────────

def _keys(where: str, d: Any, allowed: set[str], required: set[str], errs: list[str]) -> bool:
    if not isinstance(d, Mapping):
        errs.append(f"{where}: expected an object")
        return False
    extra = sorted(set(d) - allowed)
    if extra:
        errs.append(f"{where}: unknown key(s) {extra}")
    miss = sorted(required - set(d))
    if miss:
        errs.append(f"{where}: missing key(s) {miss}")
    return not miss


def _s(where: str, v: Any, errs: list[str], *, max_len: int, pattern: Optional[re.Pattern] = None,
       allow_empty: bool = False) -> str:
    if not isinstance(v, str):
        errs.append(f"{where}: expected a string")
        return ""
    if not v.strip() and not allow_empty:
        errs.append(f"{where}: must not be empty")
    if len(v) > max_len:
        errs.append(f"{where}: longer than {max_len} characters")
    if pattern is not None and not pattern.match(v):
        errs.append(f"{where}: {v!r} does not match {pattern.pattern}")
    return v


def parse_graph(doc: Any) -> ChangeGraph:
    """Parse and validate a change graph document. Raises GraphError with
    every problem found (shape and graph structure)."""
    errs: list[str] = []
    if not _keys("graph", doc, {"version", "request", "nodes", "questions"},
                 {"version", "request", "nodes", "questions"}, errs):
        raise GraphError(errs)
    if doc["version"] != GRAPH_VERSION:
        errs.append(f"graph.version: expected {GRAPH_VERSION}")
    request = _s("graph.request", doc["request"], errs, max_len=2000, allow_empty=True)

    questions: list[Question] = []
    raw_q = doc["questions"]
    if not isinstance(raw_q, list):
        errs.append("graph.questions: expected a list")
        raw_q = []
    if len(raw_q) > 5:
        errs.append("graph.questions: at most 5")
    for i, q in enumerate(raw_q[:5]):
        w = f"questions[{i}]"
        if not _keys(w, q, {"id", "question", "options"}, {"id", "question"}, errs):
            continue
        opts = q.get("options", [])
        if not isinstance(opts, list) or len(opts) > 6 or not all(isinstance(o, str) and len(o) <= 120
                                                                  for o in opts):
            errs.append(f"{w}.options: up to 6 strings of at most 120 characters")
            opts = []
        questions.append(Question(id=_s(f"{w}.id", q["id"], errs, max_len=48, pattern=_ID),
                                  question=_s(f"{w}.question", q["question"], errs, max_len=300),
                                  options=tuple(opts)))

    nodes: list[Node] = []
    raw_n = doc["nodes"]
    if not isinstance(raw_n, list):
        errs.append("graph.nodes: expected a list")
        raw_n = []
    if len(raw_n) > MAX_NODES:
        errs.append(f"graph.nodes: at most {MAX_NODES} nodes")
    for i, n in enumerate(raw_n[:MAX_NODES]):
        w = f"nodes[{i}]"
        if not _keys(w, n, {"id", "kind", "environment", "summary", "target", "depends_on"},
                     {"id", "kind", "environment", "summary", "target", "depends_on"}, errs):
            continue
        nid = _s(f"{w}.id", n["id"], errs, max_len=48, pattern=_ID)
        kind = n["kind"]
        if kind not in NODE_KINDS:
            errs.append(f"{w}.kind: {kind!r} is not one of {NODE_KINDS}")
        env = _s(f"{w}.environment", n["environment"], errs, max_len=63)
        summary = _s(f"{w}.summary", n["summary"], errs, max_len=500)
        deps = n["depends_on"]
        if not isinstance(deps, list) or not all(isinstance(d, str) for d in deps):
            errs.append(f"{w}.depends_on: expected a list of node ids")
            deps = []
        if nid and nid in deps:
            errs.append(f"{w}.depends_on: a node cannot depend on itself")
        if len(set(deps)) != len(deps):
            errs.append(f"{w}.depends_on: duplicate ids")
        t = n["target"]
        iac_root, issue, fix = "", {}, {}
        if kind == "iac_apply":
            if _keys(f"{w}.target", t, {"iac_root"}, {"iac_root"}, errs):
                iac_root = _s(f"{w}.target.iac_root", t["iac_root"], errs, max_len=1024)
        elif kind == "api_action":
            if _keys(f"{w}.target", t, {"issue", "fix"}, {"issue"}, errs):
                issue = t["issue"] if isinstance(t["issue"], Mapping) else {}
                fix = t.get("fix", {}) if isinstance(t.get("fix", {}), Mapping) else {}
                if not issue:
                    errs.append(f"{w}.target.issue: expected a non-empty object")
                elif not isinstance(issue.get("resource"), str) or not issue.get("resource"):
                    errs.append(f"{w}.target.issue.resource: required")
        nodes.append(Node(id=nid, kind=str(kind), environment=env, summary=summary,
                          depends_on=tuple(deps), iac_root=iac_root, issue=dict(issue), fix=dict(fix)))

    ids = [n.id for n in nodes]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        errs.append(f"duplicate node ids: {dupes}")
    if errs:
        raise GraphError(errs)
    graph = ChangeGraph(request=request, nodes=tuple(nodes), questions=tuple(questions))
    graph.order()          # raises GraphError on unknown deps or cycles
    if not nodes and not questions:
        raise GraphError(["the graph has neither nodes nor questions"])
    return graph
