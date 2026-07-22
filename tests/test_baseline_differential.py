"""DIFFERENTIAL / BASELINE comparison: a subtle misconfiguration is often
invisible in the absolute but obvious as a DIFFERENCE — vs the resource's own
prior config (temporal) or vs its siblings (peer).

These tests pin:
  * the pure structural differ — nested changes, added/removed, lists,
    CONSERVATIVE noise suppression (suppress only timestamp-shaped and
    identity-only differences; when unsure, REPORT — and suppressed entries are
    still listed, never hidden);
  * get_prior_config — retained-version path AND CloudTrail-reconstruction path
    both yield structured old→new; clean structured 'unavailable' when nothing
    is retained; graceful on AccessDenied (never an exception);
  * compare_peers — sibling discovery + field-difference reporting on invented
    types; caller-supplied configs (pure) mode; single-resource → clean
    'unavailable';
  * hint-freeness — no expected values, no scenario names, no per-field fault
    rules in the baseline code;
  * wiring — the tools are registered/allowed and a branch lands their results
    in all_fetched verbatim.
All AWS interactions are mocked; nothing here touches live AWS.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cloudctl.debug import baseline as B


def _diff(old, new, tokens=None):
    return B.diff_configs(old, new, identity_tokens=tokens)


# ── 1. pure differ ─────────────────────────────────────────────────────────────

def test_nested_change_reported_with_path_and_values():
    d = _diff({"a": {"b": {"c": "old-value"}}}, {"a": {"b": {"c": "new-value"}}})
    assert d["changed"] == [{"path": "a.b.c", "old": "old-value", "new": "new-value"}]
    assert d["identical"] is False


def test_added_and_removed_keys():
    d = _diff({"keep": 1, "gone": "x"}, {"keep": 1, "fresh": "y"})
    assert d["removed"] == [{"path": "gone", "value": "x"}]
    assert d["added"] == [{"path": "fresh", "value": "y"}]
    assert d["changed"] == []


def test_same_length_list_diffed_per_element():
    d = _diff({"l": ["a", "b", "c"]}, {"l": ["a", "B", "c"]})
    assert d["changed"] == [{"path": "l[1]", "old": "b", "new": "B"}]


def test_different_length_list_reported_whole_not_guessed():
    d = _diff({"l": [1, 2]}, {"l": [1, 2, 3]})
    assert len(d["changed"]) == 1
    assert d["changed"][0]["path"] == "l"          # conservative: no alignment guess


def test_identical_configs():
    cfg = {"a": [1, {"b": 2}], "c": "x"}
    d = _diff(cfg, json.loads(json.dumps(cfg)))
    assert d["identical"] is True
    assert d["changed"] == d["added"] == d["removed"] == d["suppressed"] == []


def test_timestamp_shaped_suppressed_but_listed():
    d = _diff({"modified": "2026-07-01T10:00:00Z"},
              {"modified": "2026-07-02T11:30:00Z"})
    assert d["changed"] == []
    assert len(d["suppressed"]) == 1
    s = d["suppressed"][0]
    assert s["path"] == "modified"
    assert "timestamp" in s["reason"]
    assert s["old"] == "2026-07-01T10:00:00Z"       # still visible, never hidden
    assert d["identical"] is False                   # a suppressed diff is still a diff


def test_value_containing_timestamp_is_reported_not_suppressed():
    # unsure → report: only values that ARE timestamps qualify, not values
    # that merely contain one
    d = _diff({"v": "deployed 2026-07-01T10:00:00Z"},
              {"v": "deployed 2026-07-02T10:00:00Z"})
    assert len(d["changed"]) == 1
    assert d["suppressed"] == []


def test_one_sided_timestamp_is_reported():
    d = _diff({"v": "2026-07-01T10:00:00Z"}, {"v": "disabled"})
    assert len(d["changed"]) == 1
    assert d["suppressed"] == []


def test_identity_only_difference_suppressed_in_peer_mode():
    d = _diff({"arn": "arn:aws:zqwibble:us-east-1:1:thing/res-a"},
              {"arn": "arn:aws:zqwibble:us-east-1:1:thing/res-b"},
              tokens=("res-a", "res-b"))
    assert d["changed"] == []
    assert len(d["suppressed"]) == 1
    assert "identity" in d["suppressed"][0]["reason"]


def test_identity_plus_real_difference_is_reported():
    # the values differ by MORE than the identities → report (conservative)
    d = _diff({"arn": "arn:aws:zqwibble:us-east-1:1:thing/res-a-v2"},
              {"arn": "arn:aws:zqwibble:us-east-1:1:thing/res-b"},
              tokens=("res-a", "res-b"))
    assert len(d["changed"]) == 1
    assert d["suppressed"] == []


def test_temporal_mode_never_suppresses_identifier_changes():
    # no identity tokens (temporal diff): a reference now pointing at a
    # DIFFERENT resource is a real change and must be reported
    d = _diff({"target": "arn:aws:zqwibble:us-east-1:1:fn/one"},
              {"target": "arn:aws:zqwibble:us-east-1:1:fn/two"})
    assert len(d["changed"]) == 1
    assert d["suppressed"] == []


def test_generic_on_invented_service_config():
    old = {"flarn": {"mode": "alpha", "count": 3}, "blat": True}
    new = {"flarn": {"mode": "omega", "count": 3}, "blat": True}
    d = _diff(old, new)
    assert d["changed"] == [{"path": "flarn.mode", "old": "alpha", "new": "omega"}]


def test_entry_cap_sets_truncated():
    old = {f"k{i}": i for i in range(150)}
    new = {f"k{i}": i + 1 for i in range(150)}
    d = _diff(old, new)
    assert d["truncated"] is True
    assert len(d["changed"]) <= B._MAX_DIFF_ENTRIES


def test_long_values_bounded():
    d = _diff({"v": "x" * 5000}, {"v": "y" * 5000})
    assert len(str(d["changed"][0]["old"])) <= B._MAX_VALUE_CHARS + 20


# ── mocked AWS plumbing ────────────────────────────────────────────────────────

class _FakeClient:
    def __init__(self, responses: dict):
        self._responses = responses
        self.calls: list = []

    def __getattr__(self, name):
        def _method(**kwargs):
            self.calls.append((name, kwargs))
            if name not in self._responses:
                raise AssertionError(f"unexpected client method: {name}")
            outcome = self._responses[name]
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        return _method


class _FakeSession:
    def __init__(self, clients: dict):
        self._clients = clients

    def client(self, service):
        if service not in self._clients:
            raise AssertionError(f"unexpected client requested: {service}")
        return self._clients[service]


def _denied():
    from botocore.exceptions import ClientError
    return ClientError({"Error": {"Code": "AccessDeniedException",
                                  "Message": "not authorized"}}, "Op")


def _trail_event(name, at, params):
    return {
        "EventName": name,
        "EventTime": at,
        "CloudTrailEvent": json.dumps({
            "requestParameters": params,
            "userIdentity": {"userName": "dev-1"},
        }),
    }


# ── 2. get_prior_config — retained-version path ────────────────────────────────

def test_version_history_diffs_old_to_new(monkeypatch):
    lam = _FakeClient({"list_versions_by_function": {"Versions": [
        {"Version": "1", "LastModified": "2026-07-01T00:00:00Z",
         "Setting": "alpha"},
        {"Version": "$LATEST", "LastModified": "2026-07-02T00:00:00Z",
         "Setting": "omega"},
    ]}})
    ct = _FakeClient({"lookup_events": {"Events": []}})
    out = B.prior_config(_FakeSession({"lambda": lam, "cloudtrail": ct}),
                         "fn-zq", "lambda")
    vh = out["version_history"]
    assert vh["available"] is True
    assert vh["snapshots_found"] == 2
    diff = vh["diffs"][0]
    assert diff["from_version"] == "1" and diff["to_version"] == "$LATEST"
    changed = {c["path"]: (c["old"], c["new"]) for c in diff["diff"]["changed"]}
    assert changed["Setting"] == ("alpha", "omega")      # raw old→new, verbatim
    # timestamp churn suppressed-but-listed, not reported as a change
    assert any(s["path"] == "LastModified" for s in diff["diff"]["suppressed"])
    assert out["baseline_unavailable"] is False


def test_single_version_yields_no_diff_but_is_flagged(monkeypatch):
    lam = _FakeClient({"list_versions_by_function": {"Versions": [
        {"Version": "$LATEST", "Setting": "only"},
    ]}})
    ct = _FakeClient({"lookup_events": {"Events": []}})
    out = B.prior_config(_FakeSession({"lambda": lam, "cloudtrail": ct}),
                         "fn-zq", "lambda")
    assert out["version_history"]["available"] is True
    assert "diffs" not in out["version_history"]
    assert "nothing to diff" in out["version_history"]["note"]


# ── 2b. get_prior_config — CloudTrail-reconstruction path ─────────────────────

def test_cloudtrail_reconstruction_diffs_consecutive_writes():
    # invented service, no retained-version fetcher: consecutive write events'
    # request parameters ARE consecutive states — diffed old→new
    ct = _FakeClient({"lookup_events": {"Events": [
        _trail_event("UpdateZqwibbleMapping", "2026-07-01T10:00:00Z",
                     {"name": "zq-1", "mapping": "field-alpha"}),
        _trail_event("UpdateZqwibbleMapping", "2026-07-01T14:20:00Z",
                     {"name": "zq-1", "mapping": "field-omega"}),
        _trail_event("DescribeZqwibble", "2026-07-01T15:00:00Z",
                     {"name": "zq-1"}),                    # read event: ignored
    ]}})
    out = B.prior_config(_FakeSession({"cloudtrail": ct}), "zq-1", "zqwibble")
    rec = out["cloudtrail_reconstruction"]
    assert rec["available"] is True
    assert len(rec["consecutive_diffs"]) == 1
    d = rec["consecutive_diffs"][0]
    assert d["event_name"] == "UpdateZqwibbleMapping"
    assert d["from_time"] == "2026-07-01T10:00:00Z"
    assert d["to_time"] == "2026-07-01T14:20:00Z"
    changed = {c["path"]: (c["old"], c["new"]) for c in d["diff"]["changed"]}
    assert changed["mapping"] == ("field-alpha", "field-omega")
    assert out["version_history"]["available"] is False    # no fetcher for type
    assert out["baseline_unavailable"] is False


def test_read_only_events_never_treated_as_config_states():
    ct = _FakeClient({"lookup_events": {"Events": [
        _trail_event("GetZqwibble", "2026-07-01T10:00:00Z", {"name": "zq-1"}),
        _trail_event("ListZqwibbles", "2026-07-01T11:00:00Z", {"max": 5}),
    ]}})
    out = B.prior_config(_FakeSession({"cloudtrail": ct}), "zq-1", "zqwibble")
    assert out["cloudtrail_reconstruction"]["available"] is False
    assert out["baseline_unavailable"] is True


def test_no_history_no_events_is_clean_unavailable():
    ct = _FakeClient({"lookup_events": {"Events": []}})
    out = B.prior_config(_FakeSession({"cloudtrail": ct}), "zq-1", "zqwibble")
    assert out["baseline_unavailable"] is True
    assert out["cloudtrail_reconstruction"]["available"] is False
    assert "reason" in out["cloudtrail_reconstruction"]


def test_access_denied_is_structured_not_raised():
    lam = _FakeClient({"list_versions_by_function": _denied()})
    ct = _FakeClient({"lookup_events": _denied()})
    out = B.prior_config(_FakeSession({"lambda": lam, "cloudtrail": ct}),
                         "fn-zq", "lambda")
    assert out["version_history"]["available"] is False
    assert out["version_history"]["access_denied"] is True
    assert "access denied" in out["version_history"]["reason"]
    assert out["cloudtrail_reconstruction"]["access_denied"] is True
    assert out["baseline_unavailable"] is True


def test_tool_wrapper_returns_json_and_never_raises(monkeypatch):
    # NOTE: distinct resource names per call — the recorder layer caches
    # identical-arg tool calls within a session (by design).
    from cloudctl.mcp.tools import debug as D
    monkeypatch.setattr(D, "_make_session",
                        lambda p, r: _FakeSession({"cloudtrail": _FakeClient(
                            {"lookup_events": {"Events": []}})}))
    out = json.loads(D.get_prior_config("zq-wrap-1", "zqwibble", None, "us-east-1"))
    assert out["baseline_unavailable"] is True

    def _boom(p, r):
        raise RuntimeError("session exploded")
    monkeypatch.setattr(D, "_make_session", _boom)
    out = json.loads(D.get_prior_config("zq-wrap-2", "zqwibble", None, "us-east-1"))
    assert out["baseline_unavailable"] is True
    assert "RuntimeError" in out["reason"]


# ── 3. compare_peers ──────────────────────────────────────────────────────────

def test_caller_supplied_configs_pure_diff():
    out = B.peer_comparison(
        None, "res-a", "zqwibble",
        configs={"res-a": {"mode": "alpha", "size": 5},
                 "res-b": {"mode": "omega", "size": 5}})
    assert out["comparison_mode"].startswith("caller-supplied")
    assert out["peers_compared"] == ["res-b"]
    changed = {c["path"]: (c["old"], c["new"])
               for c in out["comparisons"][0]["diff"]["changed"]}
    assert changed["mode"] == ("alpha", "omega")
    assert "size" not in changed                     # identical fields not reported


def test_discovery_mode_finds_prefix_siblings(monkeypatch):
    from cloudctl.mcp.tools import debug as D
    monkeypatch.setattr(D, "_enumerate_resources", lambda session: [
        {"arn": "arn:aws:zqwibble::1:t/app-zq-red", "service": "zqwibble",
         "name": "app-zq-red"},
        {"arn": "arn:aws:zqwibble::1:t/app-zq-blue", "service": "zqwibble",
         "name": "app-zq-blue"},
        {"arn": "arn:aws:otherthing::1:t/unrelated", "service": "otherthing",
         "name": "unrelated"},
    ])
    cfgs = {"app-zq-red": {"handler": "path-one", "size": 1},
            "app-zq-blue": {"handler": "path-two", "size": 1}}
    monkeypatch.setattr(B, "_fetch_config",
                        lambda session, st, name: cfgs.get(name, {}))
    out = B.peer_comparison(_FakeSession({}), "app-zq-red", "zqwibble")
    assert out["peers_compared"] == ["app-zq-blue"]
    changed = {c["path"] for c in out["comparisons"][0]["diff"]["changed"]}
    assert changed == {"handler"}


def test_no_peers_is_clean_unavailable(monkeypatch):
    from cloudctl.mcp.tools import debug as D
    monkeypatch.setattr(D, "_enumerate_resources", lambda session: [
        {"arn": "a", "service": "zqwibble", "name": "only-one"},
    ])
    out = B.peer_comparison(_FakeSession({}), "only-one", "zqwibble")
    assert out["peers_unavailable"] is True
    assert "no sibling" in out["reason"]


def test_peer_fetch_failure_is_structured(monkeypatch):
    def _boom(session):
        raise RuntimeError("enumeration exploded")
    from cloudctl.mcp.tools import debug as D
    monkeypatch.setattr(D, "_enumerate_resources", _boom)
    out = B.peer_comparison(_FakeSession({}), "res-a", "zqwibble")
    assert out["peers_unavailable"] is True
    assert "RuntimeError" in out["reason"]


def test_explicit_peer_names_used_without_discovery(monkeypatch):
    cfgs = {"res-a": {"mode": "alpha"}, "res-x": {"mode": "beta"}}
    monkeypatch.setattr(B, "_fetch_config",
                        lambda session, st, name: cfgs.get(name, {}))
    out = B.peer_comparison(_FakeSession({}), "res-a", "zqwibble",
                            peer_names=["res-x"])
    assert out["peers_compared"] == ["res-x"]
    assert out["comparisons"][0]["diff"]["changed"][0]["path"] == "mode"


def test_peer_identity_differences_suppressed_but_listed(monkeypatch):
    cfgs = {
        "res-a": {"arn": "arn:aws:zq::1:t/res-a", "mode": "same"},
        "res-b": {"arn": "arn:aws:zq::1:t/res-b", "mode": "same"},
    }
    monkeypatch.setattr(B, "_fetch_config",
                        lambda session, st, name: cfgs.get(name, {}))
    out = B.peer_comparison(_FakeSession({}), "res-a", "zqwibble",
                            peer_names=["res-b"])
    diff = out["comparisons"][0]["diff"]
    assert diff["changed"] == []                     # only identity differs
    assert len(diff["suppressed"]) == 1


# ── 4. hint-freeness ──────────────────────────────────────────────────────────

_FORBIDDEN = [
    # the reverted-attempt traps: enumerated field names / expected values
    "rotationenabled", "rotationlambdaarn", "price_cents",
    # scenario / incident names
    "resolver_misconfigured", "auth_mode_mismatch", "scenario",
    # correctness judgement / expected-value language
    "should match", "should equal", "should be", "expected value",
    "wrong value", "is incorrect",
    # per-service fault rules
    "$ctx", "itemname", "vtl",
]


def test_baseline_module_is_hint_free():
    src = Path(B.__file__).read_text(encoding="utf-8").lower()
    hits = [w for w in _FORBIDDEN if w in src]
    assert hits == [], f"baseline module leaked hints: {hits}"


def test_write_verb_filter_is_naming_convention_not_service_list():
    # the CloudTrail filter is the universal API verb convention — assert it
    # matches invented event names by verb alone
    assert B._WRITE_VERB_RE.match("UpdateFlarnblatWidget")
    assert B._WRITE_VERB_RE.match("PutGromulonPolicy")
    assert not B._WRITE_VERB_RE.match("GetFlarnblatWidget")
    assert not B._WRITE_VERB_RE.match("ListGromulons")


# ── 5. wiring ─────────────────────────────────────────────────────────────────

def test_tools_registered_and_allowed():
    from cloudctl.mcp.tools.debug import _AGENT_TOOLS
    from cloudctl.ai.guardrails import _ALLOWED_TOOLS
    names = {t["toolSpec"]["name"] for t in _AGENT_TOOLS}
    assert {"get_prior_config", "compare_peers"} <= names
    assert {"get_prior_config", "compare_peers"} <= _ALLOWED_TOOLS


class _ScriptedBedrock:
    def __init__(self, script):
        self.script = list(script)

    def converse(self, **kw):
        return self.script.pop(0)


def test_branch_lands_diff_result_in_all_fetched_verbatim(monkeypatch):
    from cloudctl.ai import graph_agent as g
    from cloudctl.mcp.tools import debug as D

    canned = {"resource_name": "zq-1", "baseline_unavailable": False,
              "cloudtrail_reconstruction": {
                  "available": True,
                  "consecutive_diffs": [{"event_name": "UpdateZqwibbleMapping",
                                         "diff": {"changed": [
                                             {"path": "mapping",
                                              "old": "field-alpha",
                                              "new": "field-omega"}]}}]}}
    monkeypatch.setattr(D, "get_prior_config",
                        lambda **kw: json.dumps(canned))

    def _tool_use(name, tool_input):
        return {"stopReason": "tool_use",
                "output": {"message": {"role": "assistant", "content": [
                    {"toolUse": {"toolUseId": "t1", "name": name,
                                 "input": tool_input}}]}}}

    def _end_turn(payload):
        return {"stopReason": "end_turn",
                "output": {"message": {"role": "assistant",
                                       "content": [{"text": json.dumps(payload)}]}}}

    conclusion = {"conclusion": "checked history", "evidence": ["e"],
                  "confidence": "LOW", "confirmed": False,
                  "phase2_needed": False, "predictions_tested": []}
    fake = _ScriptedBedrock([
        _tool_use("get_prior_config",
                  {"resource_name": "zq-1", "service_type": "zqwibble"}),
        _end_turn(conclusion),
        _end_turn(conclusion),   # phase 2, if coverage forces it
        _end_turn(conclusion),
    ])
    monkeypatch.setattr(g, "_make_bedrock", lambda *a, **k: fake)

    result = g._run_branch(
        {"service": "zqwibble", "reason": "r", "focus": "zq-1", "predictions": []},
        "operation misbehaving", None, "us-east-1", 60, "sess-test",
    )
    keys = [k for k in result.all_fetched if k.startswith("get_prior_config")]
    assert keys, f"no get_prior_config evidence stored: {list(result.all_fetched)}"
    stored = result.all_fetched[keys[0]]
    # verbatim: the raw old→new values are in the grounding corpus
    diffs = stored["cloudtrail_reconstruction"]["consecutive_diffs"]
    assert diffs[0]["diff"]["changed"][0]["old"] == "field-alpha"
    assert diffs[0]["diff"]["changed"][0]["new"] == "field-omega"


def test_prompts_carry_differential_guidance_hint_free():
    from cloudctl.ai import graph_agent as g
    assert "DIFFERENTIAL rule" in g._PHASE2_SYSTEM
    assert "DIFFERENTIAL EVIDENCE" in g._SYNTHESIZE_PROMPT
    block = g._SYNTHESIZE_PROMPT.split("DIFFERENTIAL EVIDENCE", 1)[1]
    block = block.split("Select the hypothesis", 1)[0].lower()
    for w in ("appsync", "graphql", "resolver", "lambda", "dynamodb", "vtl"):
        assert w not in block, f"synthesis differential block leaked: {w}"
