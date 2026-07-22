"""Layer-2 tests: the AWS/cloudctl adapter (cloudctl/debug/causal_search_aws.py),
the deterministic causal-anchor enforcement, and the hint-free source scan.
All AWS-touching functions are monkeypatched — no live calls anywhere."""
from __future__ import annotations

import json
import pathlib
import re

import cloudctl.mcp.tools.debug as debug_tools
from cloudctl.debug.causal_search_aws import (
    adapt_dependency_graph,
    causal_search_aws,
    enforce_causal_anchor,
    identify_anchor,
    _diff_present,
)

# Invented, non-AWS-shaped graph (namespaces/names carry no service meaning).
_RAW_GRAPH = {
    "node_count": 4,
    "edge_count": 3,
    "nodes": ["glorb:frontdoor-svc", "zap:helper-role",
              "mist:store-thing", "vex:far-widget"],
    "edges": [
        {"from": "glorb:frontdoor-svc", "to": "zap:helper-role", "via": "config_ref"},
        {"from": "glorb:frontdoor-svc", "to": "mist:store-thing", "via": "config_ref"},
        {"from": "mist:store-thing", "to": "vex:far-widget", "via": "config_ref"},
    ],
    "note": "n/a",
}

_UNAVAILABLE_PRIOR = {"version_history": {"available": False},
                      "cloudtrail_reconstruction": {"available": False},
                      "baseline_unavailable": True}
_UNAVAILABLE_PEERS = {"peers_unavailable": True, "reason": "none found"}


def _patch_tools(monkeypatch, prior=None, peers=None, graph=None,
                 graph_raises=False):
    calls = {"prior": [], "peers": [], "graph": 0}

    def fake_graph(profile, region):
        calls["graph"] += 1
        if graph_raises:
            raise RuntimeError("boom")
        return json.dumps(graph if graph is not None else _RAW_GRAPH)

    def fake_prior(resource_name, service_type, profile, region, minutes=10080):
        calls["prior"].append(resource_name)
        return json.dumps((prior or {}).get(resource_name, _UNAVAILABLE_PRIOR))

    def fake_peers(resource_name, service_type, profile, region,
                   peer_names=None, configs=None):
        calls["peers"].append(resource_name)
        return json.dumps((peers or {}).get(resource_name, _UNAVAILABLE_PEERS))

    monkeypatch.setattr(debug_tools, "get_dependency_graph", fake_graph)
    monkeypatch.setattr(debug_tools, "get_prior_config", fake_prior)
    monkeypatch.setattr(debug_tools, "compare_peers", fake_peers)
    return calls


# ── graph adaptation ──────────────────────────────────────────────────────────

def test_adapt_strips_via_and_keeps_shape():
    g = adapt_dependency_graph(_RAW_GRAPH)
    assert g["available"] is True
    assert set(g["nodes"]) == set(_RAW_GRAPH["nodes"])
    assert all(set(e) == {"from", "to"} for e in g["edges"])
    assert len(g["edges"]) == 3


def test_adapt_degrades_on_error_none_and_empty():
    assert adapt_dependency_graph({"error": "nothing enumerated"})["available"] is False
    assert adapt_dependency_graph(None)["available"] is False
    assert adapt_dependency_graph({"nodes": []})["available"] is False


# ── anchor identification (hint-free rules) ───────────────────────────────────

def test_anchor_from_failure_map_component():
    anch = identify_anchor(_RAW_GRAPH["nodes"],
                           failure_map=[{"component": "frontdoor-svc",
                                         "error_count": 4, "sample": "x"}])
    assert anch["anchor"] == "glorb:frontdoor-svc"
    assert anch["source"] == "observed_emitting_component"


def test_anchor_from_reproduction_target_when_failure_map_empty():
    store = {"native_reproduce:service_type=glorb|params=target:frontdoor-svc":
             {"result": "some concrete output"}}
    anch = identify_anchor(_RAW_GRAPH["nodes"], failure_map=[],
                           evidence_store=store)
    assert anch["anchor"] == "glorb:frontdoor-svc"
    assert anch["source"] == "reproduction_target"


def test_anchor_from_probe_target_value_text():
    # The probe's recorded RESULT may carry the identifier even if the key doesn't.
    store = {"probe_http:url=https://x.example/q":
             {"resolved": "endpoint of store-thing"}}
    anch = identify_anchor(_RAW_GRAPH["nodes"], failure_map=None,
                           evidence_store=store)
    assert anch["anchor"] == "mist:store-thing"


def test_failure_map_outranks_hint_and_repro_target():
    store = {"probe_http:url=https://x.example/store-thing": {}}
    anch = identify_anchor(_RAW_GRAPH["nodes"],
                           failure_map=[{"component": "helper-role"}],
                           evidence_store=store, anchor_hint="far-widget")
    assert anch["anchor"] == "zap:helper-role"
    assert anch["source"] == "observed_emitting_component"


def test_hint_used_only_as_last_resort():
    anch = identify_anchor(_RAW_GRAPH["nodes"], failure_map=[],
                           evidence_store={}, anchor_hint="far-widget")
    assert anch["anchor"] == "vex:far-widget"
    assert anch["source"] == "caller_hint"


def test_no_anchor_identifiable_is_graceful():
    anch = identify_anchor(_RAW_GRAPH["nodes"], failure_map=[],
                           evidence_store={}, anchor_hint=None)
    assert anch["anchor"] is None
    assert "no anchor identifiable" in anch["reason"]


# ── conclusive-proxy (_diff_present) ──────────────────────────────────────────

def test_diff_present_on_version_history_change():
    probe = {"prior_config": {"version_history": {
        "available": True,
        "diffs": [{"diff": {"changed": [{"path": "p", "old": 1, "new": 2}],
                            "added": [], "removed": []}}]}},
        "peer_comparison": _UNAVAILABLE_PEERS}
    assert _diff_present(probe) is True


def test_diff_absent_when_everything_unavailable_or_suppressed_only():
    assert _diff_present({"prior_config": _UNAVAILABLE_PRIOR,
                          "peer_comparison": _UNAVAILABLE_PEERS}) is False
    suppressed_only = {"peer_comparison": {"comparisons": [
        {"peer": "p2", "diff": {"changed": [], "added": [], "removed": [],
                                "suppressed": [{"path": "id"}]}}]}}
    assert _diff_present(suppressed_only) is False


# ── end-to-end adapter run (mocked) ───────────────────────────────────────────

def test_search_investigates_anchor_first_and_stops_on_its_diff(monkeypatch):
    prior = {"frontdoor-svc": {"version_history": {
        "available": True,
        "diffs": [{"diff": {"changed": [{"path": "knob", "old": "a", "new": "b"}],
                            "added": [], "removed": []}}]},
        "cloudtrail_reconstruction": {"available": False}}}
    calls = _patch_tools(monkeypatch, prior=prior)
    res = causal_search_aws(None, "eu-test-9",
                            failure_map=[{"component": "frontdoor-svc"}])
    assert res["available"] is True
    assert res["anchor"] == "glorb:frontdoor-svc"
    assert res["conclusive_ring"] == 0
    assert calls["prior"] == ["frontdoor-svc"]          # ring 0 only — stopped there
    assert res["trail"][0]["ring"] == 0


def test_search_widens_outward_when_anchor_shows_no_diff(monkeypatch):
    calls = _patch_tools(monkeypatch)   # everything unavailable → never conclusive
    res = causal_search_aws(None, "eu-test-9",
                            failure_map=[{"component": "frontdoor-svc"}],
                            max_rings=2)
    assert res["available"] is True
    # Anchor first, then ring-1 neighbors, then ring 2 — tolerating every
    # sub-tool returning 'unavailable' without crashing.
    assert calls["prior"][0] == "frontdoor-svc"
    assert set(calls["prior"]) == {"frontdoor-svc", "helper-role",
                                   "store-thing", "far-widget"}
    rings = res["rings"]
    assert rings["glorb:frontdoor-svc"] == 0
    assert rings["zap:helper-role"] == 1
    assert rings["mist:store-thing"] == 1
    assert rings["vex:far-widget"] == 2


def test_search_graceful_when_graph_unavailable(monkeypatch):
    _patch_tools(monkeypatch, graph={"error": "nothing enumerated"})
    res = causal_search_aws(None, "eu-test-9",
                            failure_map=[{"component": "frontdoor-svc"}])
    assert res["available"] is False and res["anchor"] is None
    assert "fall back" in res["note"]


def test_search_graceful_when_graph_call_raises(monkeypatch):
    _patch_tools(monkeypatch, graph_raises=True)
    res = causal_search_aws(None, "eu-test-9", anchor_hint="frontdoor-svc")
    assert res["available"] is False


def test_search_graceful_when_no_anchor(monkeypatch):
    _patch_tools(monkeypatch)
    res = causal_search_aws(None, "eu-test-9", failure_map=[],
                            evidence_store={}, anchor_hint=None)
    assert res["available"] is False and res["anchor"] is None
    assert "no anchor identifiable" in res["reason"]


def test_search_bounds_are_clamped(monkeypatch):
    calls = _patch_tools(monkeypatch)
    res = causal_search_aws(None, "eu-test-9",
                            failure_map=[{"component": "frontdoor-svc"}],
                            max_rings=99, max_investigations=99)
    assert res["available"] is True
    assert len(calls["prior"]) <= 8      # investigation budget ceiling


# ── enforcement: enforce_causal_anchor ────────────────────────────────────────

def _search_evidence(ring0_available: bool) -> dict:
    probe = {"prior_config": ({"version_history": {"available": True, "diffs": []},
                               "cloudtrail_reconstruction": {"available": False}}
                              if ring0_available else _UNAVAILABLE_PRIOR),
             "peer_comparison": _UNAVAILABLE_PEERS,
             "differential_available": False}
    return {
        "available": True,
        "anchor": "glorb:frontdoor-svc",
        "anchor_source": "reproduction_target",
        "rings": {"glorb:frontdoor-svc": 0, "zap:helper-role": 1,
                  "mist:store-thing": 1, "vex:far-widget": 2},
        "trail": [{"node": "glorb:frontdoor-svc", "ring": 0,
                   "investigate_result": probe, "conclusive": False}],
    }


def _verdict(root_cause: str, confidence: str) -> dict:
    return {"root_cause": root_cause, "confidence": confidence,
            "evidence": ["e1"], "remediation_steps": []}


def test_caps_one_step_when_far_cause_and_ring0_unchecked():
    fetched = {"causal_search": _search_evidence(ring0_available=False)}
    out = enforce_causal_anchor(
        _verdict("a stale grant on helper-role broke everything", "HIGH"),
        fetched)
    assert out["confidence"] == "MEDIUM"                 # one step, not a floor
    assert out["causal_anchor"]["anchored"] is False
    assert out["causal_anchor"]["cause_ring_distance"] == 1
    assert "never differential-checked" in out["causal_anchor"]["note"]
    assert "capped" in out["confidence_override_reason"]

    out2 = enforce_causal_anchor(
        _verdict("a stale grant on helper-role broke everything", "MEDIUM"),
        fetched)
    assert out2["confidence"] == "LOW"

    out3 = enforce_causal_anchor(
        _verdict("a stale grant on helper-role broke everything", "LOW"),
        fetched)
    assert out3["confidence"] == "LOW"                   # soft: never below LOW
    assert "causal_anchor" in out3


def test_untouched_when_ring0_was_checked_by_the_search():
    fetched = {"causal_search": _search_evidence(ring0_available=True)}
    verdict = _verdict("a stale grant on helper-role broke everything", "HIGH")
    assert enforce_causal_anchor(verdict, fetched) == verdict


def test_untouched_when_anchor_manually_differential_checked():
    fetched = {
        "causal_search": _search_evidence(ring0_available=False),
        "get_prior_config:resource_name=frontdoor-svc|service_type=glorb":
            {"baseline_unavailable": False},
    }
    verdict = _verdict("a stale grant on helper-role broke everything", "HIGH")
    assert enforce_causal_anchor(verdict, fetched) == verdict


def test_untouched_when_verdict_names_the_anchor():
    fetched = {"causal_search": _search_evidence(ring0_available=False)}
    verdict = _verdict("frontdoor-svc lost its entry setting", "HIGH")
    assert enforce_causal_anchor(verdict, fetched) == verdict


def test_untouched_without_any_causal_search_evidence():
    verdict = _verdict("a stale grant on helper-role broke everything", "HIGH")
    assert enforce_causal_anchor(verdict, {}) == verdict
    assert enforce_causal_anchor(verdict, None) == verdict
    # An unavailable search result (no anchor) imposes nothing either.
    fetched = {"causal_search": {"available": False, "anchor": None}}
    assert enforce_causal_anchor(verdict, fetched) == verdict


def test_untouched_when_cause_not_tied_to_any_ringed_node():
    fetched = {"causal_search": _search_evidence(ring0_available=False)}
    verdict = _verdict("an entirely different subsystem melted", "HIGH")
    assert enforce_causal_anchor(verdict, fetched) == verdict


# ── hint-free source scan over ALL new files ──────────────────────────────────

_NEW_FILES = [
    "cloudctl/debug/causal_search.py",
    "cloudctl/debug/causal_search_aws.py",
    "tests/test_causal_search_core.py",
]

# Service/scenario/incident vocabulary that must NOT be baked into the
# mechanism. (The adapter may name the TOOLS it wires — get_prior_config,
# compare_peers, native_reproduce, probe_http — those are our own API names,
# not domain hints.)
_FORBIDDEN = re.compile(
    r"appsync|graphql|cognito|apigateway|api[-_ ]gateway|dynamodb|"
    r"auth_mode|auth[_ ]mode|authenticationtype|userpool|user[-_ ]pool|"
    r"lambda|kinesis|sqs\b|sns\b|secretsmanager|rotation|efs\b|dms\b|"
    r"resolver\b|mapping[-_ ]template",
    re.I,
)


def test_new_sources_are_hint_free():
    root = pathlib.Path(__file__).resolve().parents[1]
    for rel in _NEW_FILES:
        src = (root / rel).read_text(encoding="utf-8")
        hit = _FORBIDDEN.search(src)
        assert hit is None, f"{rel} contains domain vocabulary: {hit.group(0)!r}"


def test_no_enumerated_vocab_or_field_lists_in_new_modules():
    """The two reverted traps were enumerated pattern/vocab lists. Guard the
    shape: neither new module may define a module-level list/tuple/set literal
    of 3+ strings (the only allowed collection constants are tool-name wiring
    of our own APIs, which stay under that size)."""
    import ast as _ast
    root = pathlib.Path(__file__).resolve().parents[1]
    for rel in ("cloudctl/debug/causal_search.py",
                "cloudctl/debug/causal_search_aws.py"):
        tree = _ast.parse((root / rel).read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, (_ast.Assign, _ast.AnnAssign)):
                value = getattr(node, "value", None)
                if isinstance(value, (_ast.List, _ast.Tuple, _ast.Set)):
                    strings = [e for e in value.elts
                               if isinstance(e, _ast.Constant)
                               and isinstance(e.value, str)]
                    assert len(strings) < 3, \
                        f"{rel}: module-level string list smells like a vocab list"
