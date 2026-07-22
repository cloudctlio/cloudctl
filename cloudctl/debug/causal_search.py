"""Anchored ring search over a generic dependency graph (pure core).

General-purpose, standalone module — it knows NOTHING about clouds, services,
incidents, or this codebase. It has zero third-party and zero intra-project
dependencies (standard library ``typing`` only) and can be lifted into any
project unchanged: the graph could be microservices, Kubernetes objects, git
commits, build targets — anything expressible as named nodes and edges.

Problem it solves
-----------------
When a failure is observed AT a specific node, investigation effort (diffing a
config, checking history, reproducing) should start AT that node and widen
OUTWARD in order of graph distance — not land on whatever node the investigator
happened to be looking at. This module provides that ordering as a bounded,
deterministic breadth-first "ring" search:

  ring 0 = the anchor (where the failure was directly observed)
  ring 1 = its direct neighbors (either edge direction — a node the anchor
           depends on AND a node that depends on the anchor can each be
           causally relevant)
  ring 2 = their neighbors, ... up to ``max_rings``.

Each node is passed to a caller-supplied ``investigate`` callable; a
caller-supplied ``is_conclusive`` callable decides whether that node's result
explains the failure. The search stops at the end of the first ring that
produced a conclusive result.

Interface
---------
``ring_search(graph, anchor, investigate, is_conclusive, max_rings=3,
max_investigations=12) -> dict``

  graph : ``{"nodes": [str, ...], "edges": [{"from": str, "to": str}, ...]}``
      Edge dicts may carry extra keys; they are ignored. Edge endpoints not
      present in "nodes" are added implicitly (tolerant input contract).
  anchor : str — must name a node; if it does not, a structured
      ``anchor_in_graph=False`` result is returned (never an exception).
  investigate : ``Callable[[str], dict]`` — opaque per-node probe. Exceptions
      are caught and recorded as ``{"error": ...}`` for that node.
  is_conclusive : ``Callable[[dict], bool]`` — opaque judgment on a probe
      result. Exceptions are caught and treated as ``False``.
  max_rings : int — furthest ring to explore (bounded; clamped to >= 0).
  max_investigations : int — hard cap on total ``investigate`` calls.

Returns a structured dict (never raises):

  {
    "anchor": str,
    "anchor_in_graph": bool,
    "rings": {node: distance, ...},   # every node DISCOVERED within max_rings
    "trail": [                        # ring-ordered, only nodes INVESTIGATED
      {"node": str, "ring": int, "investigate_result": dict,
       "conclusive": bool},
      ...
    ],
    "conclusive_ring": int | None,    # first ring with a conclusive result
    "conclusive_node": str | None,    # first conclusive node in that ring
    "stopped": "conclusive" | "max_rings_reached" | "graph_exhausted"
             | "investigation_budget_exhausted" | "anchor_not_in_graph",
  }

Guarantees: deterministic (nodes within a ring are visited in sorted order),
cycle-safe (visited set), disconnection-safe (unreachable nodes are simply
never ringed), and bounded (``max_rings`` and ``max_investigations``).
"""
from __future__ import annotations

from typing import Callable, Dict, List, Set

__all__ = ["ring_search"]


def _adjacency(graph: dict) -> Dict[str, Set[str]]:
    """Undirected adjacency from the graph's edges (both directions matter:
    a dependency of the anchor and a dependent of the anchor are equally
    candidate causes). Tolerates malformed edges and extra edge keys."""
    adj: Dict[str, Set[str]] = {}
    for node in (graph or {}).get("nodes") or []:
        if isinstance(node, str) and node:
            adj.setdefault(node, set())
    for edge in (graph or {}).get("edges") or []:
        if not isinstance(edge, dict):
            continue
        src, dst = edge.get("from"), edge.get("to")
        if not (isinstance(src, str) and src and isinstance(dst, str) and dst):
            continue
        if src == dst:
            continue
        adj.setdefault(src, set()).add(dst)
        adj.setdefault(dst, set()).add(src)
    return adj


def ring_search(
    graph: dict,
    anchor: str,
    investigate: Callable[[str], dict],
    is_conclusive: Callable[[dict], bool],
    max_rings: int = 3,
    max_investigations: int = 12,
) -> dict:
    """Breadth-first ring search outward from ``anchor``. See module docstring
    for the full contract. Pure orchestration: this function never interprets
    what ``investigate`` returns beyond passing it to ``is_conclusive``."""
    result: dict = {
        "anchor": anchor,
        "anchor_in_graph": False,
        "rings": {},
        "trail": [],
        "conclusive_ring": None,
        "conclusive_node": None,
        "stopped": "anchor_not_in_graph",
    }
    adj = _adjacency(graph)
    if not isinstance(anchor, str) or anchor not in adj:
        return result

    result["anchor_in_graph"] = True
    max_rings = max(0, int(max_rings))
    max_investigations = max(0, int(max_investigations))

    rings: Dict[str, int] = {anchor: 0}
    frontier: List[str] = [anchor]
    ring = 0
    investigations = 0
    stopped = "graph_exhausted"

    while frontier:
        ring_conclusive = False
        for node in sorted(frontier):
            if investigations >= max_investigations:
                result["rings"] = rings
                result["stopped"] = "investigation_budget_exhausted"
                return result
            investigations += 1
            try:
                probe = investigate(node)
                if not isinstance(probe, dict):
                    probe = {"result": probe}
            except Exception as exc:  # noqa: BLE001 — a node's probe failing must not abort the search
                probe = {"error": f"{type(exc).__name__}: {str(exc)[:200]}"}
            try:
                conclusive = bool(is_conclusive(probe))
            except Exception:  # noqa: BLE001 — an undecidable result is just not conclusive
                conclusive = False
            result["trail"].append({
                "node": node,
                "ring": ring,
                "investigate_result": probe,
                "conclusive": conclusive,
            })
            if conclusive:
                ring_conclusive = True
                if result["conclusive_node"] is None:
                    result["conclusive_ring"] = ring
                    result["conclusive_node"] = node

        if ring_conclusive:
            # Complete the ring (equal-distance peers all get examined), then
            # stop: nothing farther out can outrank an equal-or-closer finding
            # in anchor-distance order.
            stopped = "conclusive"
            break

        if ring >= max_rings:
            stopped = "max_rings_reached"
            break

        next_frontier: List[str] = []
        for node in frontier:
            for neighbor in adj.get(node, ()):
                if neighbor not in rings:
                    rings[neighbor] = ring + 1
                    next_frontier.append(neighbor)
        frontier = next_frontier
        ring += 1

    result["rings"] = rings
    result["stopped"] = stopped
    return result
