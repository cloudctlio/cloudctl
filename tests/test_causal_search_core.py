"""Layer-1 tests for the PURE anchored ring search (cloudctl/debug/causal_search.py).

Deliberately domain-free: the graphs use invented node names and the
investigate/conclusive callables are fake dict lookups. If any test here needed
a cloud/vendor concept to pass, the layer separation would have failed.
"""
from __future__ import annotations

import ast
import pathlib

from cloudctl.debug.causal_search import ring_search


def _lookup_investigator(table: dict):
    """Fake investigate callable: a plain dict lookup."""
    def investigate(node: str) -> dict:
        return {"node": node, "reading": table.get(node)}
    return investigate


def _glow_is_conclusive(result: dict) -> bool:
    """Fake conclusiveness: the invented 'glow' reading."""
    return (result or {}).get("reading") == "glow"


# A little invented world: florp — zint — quux — blorb, plus gronk -> zint
# (an INCOMING edge to the anchor) and a stray disconnected node "meep".
_GRAPH = {
    "nodes": ["florp", "zint", "quux", "blorb", "gronk", "meep"],
    "edges": [
        {"from": "zint", "to": "florp"},
        {"from": "zint", "to": "quux"},
        {"from": "quux", "to": "blorb"},
        {"from": "gronk", "to": "zint"},   # points AT the anchor
    ],
}


def test_ring_assignment_matches_true_graph_distance():
    res = ring_search(_GRAPH, "zint",
                      _lookup_investigator({}), _glow_is_conclusive,
                      max_rings=3)
    assert res["anchor_in_graph"] is True
    assert res["rings"]["zint"] == 0
    assert res["rings"]["florp"] == 1
    assert res["rings"]["quux"] == 1
    assert res["rings"]["gronk"] == 1     # incoming edge counts (both directions)
    assert res["rings"]["blorb"] == 2
    assert "meep" not in res["rings"]     # disconnected — never ringed
    # Trail is ring-ordered, deterministic (sorted within each ring).
    assert [t["node"] for t in res["trail"]] == \
        ["zint", "florp", "gronk", "quux", "blorb"]
    assert [t["ring"] for t in res["trail"]] == [0, 1, 1, 1, 2]
    assert res["conclusive_ring"] is None
    assert res["stopped"] == "graph_exhausted"


def test_stops_at_first_conclusive_ring():
    # 'quux' (ring 1) glows: the whole ring is examined, then the search stops
    # — 'blorb' at ring 2 is never investigated.
    res = ring_search(_GRAPH, "zint",
                      _lookup_investigator({"quux": "glow"}),
                      _glow_is_conclusive, max_rings=3)
    assert res["conclusive_ring"] == 1
    assert res["conclusive_node"] == "quux"
    assert res["stopped"] == "conclusive"
    investigated = [t["node"] for t in res["trail"]]
    assert "blorb" not in investigated
    assert {"florp", "gronk", "quux"} <= set(investigated)  # full ring examined


def test_conclusive_at_ring_zero_stops_immediately():
    res = ring_search(_GRAPH, "zint",
                      _lookup_investigator({"zint": "glow"}),
                      _glow_is_conclusive, max_rings=3)
    assert res["conclusive_ring"] == 0
    assert res["conclusive_node"] == "zint"
    assert len(res["trail"]) == 1


def test_respects_max_ring_bound():
    res = ring_search(_GRAPH, "zint",
                      _lookup_investigator({}), _glow_is_conclusive,
                      max_rings=1)
    assert res["stopped"] == "max_rings_reached"
    assert all(t["ring"] <= 1 for t in res["trail"])
    assert "blorb" not in [t["node"] for t in res["trail"]]


def test_disconnected_anchor_is_graceful():
    res = ring_search(_GRAPH, "meep",
                      _lookup_investigator({}), _glow_is_conclusive)
    assert res["anchor_in_graph"] is True
    assert [t["node"] for t in res["trail"]] == ["meep"]
    assert res["stopped"] == "graph_exhausted"


def test_anchor_not_in_graph_is_graceful_not_an_error():
    calls = []

    def investigate(node):
        calls.append(node)
        return {}

    res = ring_search(_GRAPH, "wibble", investigate, _glow_is_conclusive)
    assert res["anchor_in_graph"] is False
    assert res["stopped"] == "anchor_not_in_graph"
    assert res["trail"] == [] and calls == []


def test_cycle_terminates_and_visits_each_node_once():
    cyclic = {
        "nodes": ["ay", "bee", "cee"],
        "edges": [
            {"from": "ay", "to": "bee"},
            {"from": "bee", "to": "cee"},
            {"from": "cee", "to": "ay"},   # cycle back to the anchor
        ],
    }
    res = ring_search(cyclic, "ay", _lookup_investigator({}),
                      _glow_is_conclusive, max_rings=4)
    nodes = [t["node"] for t in res["trail"]]
    assert sorted(nodes) == ["ay", "bee", "cee"]      # once each — no loop
    assert res["rings"] == {"ay": 0, "bee": 1, "cee": 1}


def test_investigate_exception_is_recorded_not_raised():
    def flaky(node):
        if node == "florp":
            raise RuntimeError("kaboom")
        return {"node": node, "reading": None}

    res = ring_search(_GRAPH, "zint", flaky, _glow_is_conclusive, max_rings=1)
    florp_entry = next(t for t in res["trail"] if t["node"] == "florp")
    assert "error" in florp_entry["investigate_result"]
    assert florp_entry["conclusive"] is False
    # The search continued past the failing node.
    assert {"gronk", "quux"} <= {t["node"] for t in res["trail"]}


def test_conclusive_callable_exception_treated_as_not_conclusive():
    def bad_judge(_result):
        raise ValueError("undecidable")

    res = ring_search(_GRAPH, "zint", _lookup_investigator({"zint": "glow"}),
                      bad_judge, max_rings=1)
    assert res["conclusive_ring"] is None
    assert all(t["conclusive"] is False for t in res["trail"])


def test_investigation_budget_bounds_total_calls():
    calls = []

    def counting(node):
        calls.append(node)
        return {}

    res = ring_search(_GRAPH, "zint", counting, _glow_is_conclusive,
                      max_rings=3, max_investigations=2)
    assert len(calls) == 2
    assert res["stopped"] == "investigation_budget_exhausted"


def test_edge_dicts_tolerate_extra_keys_and_malformed_entries():
    graph = {
        "nodes": ["plink", "plonk"],
        "edges": [
            {"from": "plink", "to": "plonk", "via": "whatever", "junk": 42},
            {"from": "plink"},            # malformed — ignored
            "not-a-dict",                 # malformed — ignored
            {"from": "plonk", "to": "plonk"},   # self-loop — ignored
        ],
    }
    res = ring_search(graph, "plink", _lookup_investigator({}),
                      _glow_is_conclusive)
    assert res["rings"] == {"plink": 0, "plonk": 1}


def test_edge_endpoint_not_in_nodes_list_is_added_implicitly():
    graph = {"nodes": ["plink"],
             "edges": [{"from": "plink", "to": "snork"}]}
    res = ring_search(graph, "plink", _lookup_investigator({}),
                      _glow_is_conclusive)
    assert res["rings"].get("snork") == 1


def test_non_dict_investigate_result_is_wrapped():
    def stringy(_node):
        return "just-a-string"

    def never(_result):
        return False

    res = ring_search(_GRAPH, "meep", stringy, never)
    assert res["trail"][0]["investigate_result"] == {"result": "just-a-string"}


def test_pure_core_has_zero_project_or_vendor_dependencies():
    """The separation proof at import level: the pure module may import ONLY
    from __future__ and typing — no cloud SDKs, no intra-project modules."""
    import cloudctl.debug.causal_search as core
    src = pathlib.Path(core.__file__).read_text(encoding="utf-8")
    allowed = {"__future__", "typing"}
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom):
            assert (node.module or "").split(".")[0] in allowed, node.module
