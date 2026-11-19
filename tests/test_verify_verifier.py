"""Verifier rules, decisions, the shared cache and the propose/verify loop."""
from __future__ import annotations

import json

import pytest

from cloudctl.verify.verifier import (
    CANDIDATES,
    MULTIPLE_VERIFIED,
    UNVERIFIED,
    VERIFIED,
    Verifier,
    parse_hypotheses,
    verify_loop,
)
from tests.verify_support import (
    FN,
    FN2,
    PRE,
    ROLE,
    TABLE,
    T,
    orders_ctx,
    orders_evidence_data,
    orders_model,
)

ROLE_HYP = {"node": ROLE, "property": "policy:dynamodb:PutItem", "claim": "role lost PutItem",
            "predictions": [
                {"primitive": "permit", "args": {"principal": ROLE, "action": "dynamodb:PutItem",
                                                 "resource": TABLE}, "expect": "FAIL"},
                {"primitive": "signal", "args": {"node": FN, "query": {"log": "AccessDenied"},
                                                 "predicate": {"op": "present"}}, "expect": "PASS"}]}
TABLE_THROTTLE = {"node": TABLE, "property": "throttling", "claim": "table throttles",
                  "predictions": [{"primitive": "signal", "args": {
                      "node": TABLE, "query": {"metric": "AWS/DynamoDB:ThrottledRequests"},
                      "predicate": {"op": "above", "value": 0}}, "expect": "PASS"}]}
FN_ERRORS = {"node": FN, "property": "errors", "claim": "function erroring",
             "predictions": [{"primitive": "signal", "args": {
                 "node": FN, "query": {"metric": "AWS/Lambda:Errors"},
                 "predicate": {"op": "above", "value": 1}}, "expect": "PASS"}]}


def decide(raw_hyps, ctx=None, anchor=FN):
    ctx = ctx or orders_ctx()
    hyps, errs = parse_hypotheses({"hypotheses": raw_hyps}, ctx.model)
    assert not errs, errs
    return Verifier(ctx, anchor).decide(hyps)


def rules(decision, hid):
    o = next(o for o in decision["outcomes"] if o["hypothesis"]["id"] == hid)
    return {k: v["ok"] for k, v in o["rules"].items()}, o


def test_verified_role_with_refuted_rival():
    d = decide([ROLE_HYP, TABLE_THROTTLE])
    assert d["status"] == VERIFIED
    assert d["verdict"] == {"status": VERIFIED, "node": ROLE, "property": "policy:dynamodb:PutItem",
                            "hypothesis": "h1"}
    ok, o = rules(d, "h1")
    assert all(ok.values())
    assert "pre-onset contradicted by permit" in o["rules"]["controls"]["why"]
    ok2, _ = rules(d, "h2")
    assert not ok2["predictions_hold"]


def test_chain_reports_most_upstream_as_root_and_rest_as_consequences():
    d = decide([FN_ERRORS, ROLE_HYP, TABLE_THROTTLE])
    assert d["status"] == VERIFIED
    assert d["verdict"]["node"] == ROLE
    assert [c["node"] for c in d["consequences"]] == [FN]
    ok, o = rules(d, "h1")   # the function hypothesis passed on its own
    assert ok["onset_link"] and "signal on" in o["rules"]["onset_link"]["why"]
    assert "1 healthy peer" in o["rules"]["controls"]["why"]


def test_loose_prediction_fails_its_own_pre_onset_control():
    loose = {"node": FN, "property": "timeout", "claim": "timeout is 30",
             "predictions": [{"primitive": "config", "args": {"node": FN, "path": "Timeout",
                                                              "predicate": {"op": "equals", "value": 30}}}]}
    d = decide([loose])
    ok, o = rules(d, "h1")
    assert ok["predictions_hold"] and not ok["controls"]
    assert o["rules"]["controls"]["why"] == "the same predictions also held before onset"
    assert d["status"] == UNVERIFIED


def test_unrefuted_rival_gives_candidates_with_separating_prediction():
    rival = {"node": TABLE, "property": "stream", "claim": "stream lag",
             "predictions": [{"primitive": "signal", "args": {
                 "node": TABLE, "query": {"metric": "AWS/DynamoDB:IteratorAge"},
                 "predicate": {"op": "above", "value": 1000}}}]}
    d = decide([ROLE_HYP, rival])
    assert d["status"] == CANDIDATES
    assert {c["node"] for c in d["candidates"]} == {ROLE, TABLE}
    assert d["separating_predictions"]["h2"][0]["status"] == "UNAVAILABLE"
    ok, _ = rules(d, "h1")
    assert not ok["rivals_refuted"]


def test_nothing_verified_lists_missing_signals():
    data = orders_evidence_data()
    data["unavailable"] = {"cloudtrail": "trail not readable", "iam_simulation": "denied"}
    d = decide([ROLE_HYP], ctx=orders_ctx(data))
    assert d["status"] == UNVERIFIED
    assert d["verdict"]["node"] is None
    assert {"cloudtrail", "iam_simulation"} <= set(d["missing_signals"])
    assert d["candidates"][0]["node"] == ROLE


def test_independent_causes_are_multiple_verified_in_fixed_order():
    data = orders_evidence_data()
    data["metrics"][TABLE]["AWS/DynamoDB:ThrottledRequests"] = (
        [[T + 60 * i, 50.0] for i in range(1, 15)] + [[PRE - 600 + 60 * i, 0.0] for i in range(5)])
    d = decide([TABLE_THROTTLE, ROLE_HYP], ctx=orders_ctx(data))
    assert d["status"] == MULTIPLE_VERIFIED
    assert [c["node"] for c in d["verdict"]["causes"]] == sorted([ROLE, TABLE])
    d2 = decide([ROLE_HYP, TABLE_THROTTLE], ctx=orders_ctx(data))
    assert d2["verdict"]["causes"] == [{**c, "hypothesis": c["hypothesis"]} for c in d2["verdict"]["causes"]]
    assert [c["node"] for c in d2["verdict"]["causes"]] == [c["node"] for c in d["verdict"]["causes"]]


def test_failing_upstream_node_not_covered_breaks_rule_2():
    data = orders_evidence_data()
    data["failures"] = {TABLE: [[T + 10, "ERROR InternalServerError"]], FN: [[T + 20, "ERROR boom"]]}
    d = decide([FN_ERRORS], ctx=orders_ctx(data))
    ok, o = rules(d, "h1")
    assert not ok["on_failing_path"] and TABLE in o["rules"]["on_failing_path"]["why"]


def test_node_off_the_failing_path_is_rejected():
    off = {"node": FN2, "property": "x", "claim": "the other function",
           "predictions": [{"primitive": "signal", "args": {"node": FN2, "query": {"metric": "AWS/Lambda:Errors"},
                                                            "predicate": {"op": "below", "value": 1}}}]}
    d = decide([off])
    ok, _ = rules(d, "h1")
    assert not ok["on_failing_path"]


def test_prediction_must_be_about_the_node():
    about_other = {"node": ROLE, "property": "x", "claim": "y",
                   "predictions": [{"primitive": "signal", "args": {"node": FN, "query": {"log": "AccessDenied"},
                                                                    "predicate": {"op": "present"}}}]}
    d = decide([about_other])
    ok, o = rules(d, "h1")
    assert not ok["predictions_hold"] and "about the hypothesised node" in o["rules"]["predictions_hold"]["why"]


def test_same_predictions_on_healthy_peer_fail_controls():
    data = orders_evidence_data()
    # users-fn's error metric is high too, but it emits no failure lines (healthy)
    data["metrics"][FN2]["AWS/Lambda:Errors"] = [[T + 60 * i, 5.0] for i in range(1, 15)]
    d = decide([FN_ERRORS], ctx=orders_ctx(data))
    ok, o = rules(d, "h1")
    assert not ok["controls"] and FN2 in o["rules"]["controls"]["why"]


def test_first_exercise_onset_link():
    data = orders_evidence_data()
    data["config"][TABLE] = [{"at": None, "config": {"StreamEnabled": True}},
                             {"at": PRE - 3600, "config": {"StreamEnabled": False}}]
    data["calls"] = {TABLE: [{"ts": T + 5, "caller": FN, "ref": "trace 1"}]}
    hyp = {"node": TABLE, "property": "StreamEnabled", "claim": "new stream path first exercised",
           "predictions": [{"primitive": "config", "args": {"node": TABLE, "path": "StreamEnabled",
                                                            "predicate": {"op": "equals", "value": True}}}]}
    d = decide([hyp], ctx=orders_ctx(data))
    ok, o = rules(d, "h1")
    assert ok["onset_link"] and "first exercise" in o["rules"]["onset_link"]["why"]
    assert d["status"] == VERIFIED


def test_unavailable_control_keeps_it_a_candidate():
    data = orders_evidence_data()
    data["simulate"] = [s for s in data["simulate"] if s.get("at") is None]   # no policy history
    d = decide([ROLE_HYP], ctx=orders_ctx(data))
    ok, _ = rules(d, "h1")
    # the log-signal control still contradicts (no AccessDenied pre-onset), so
    # the hypothesis passes on that one; permit's control is just unavailable
    assert ok["controls"] and d["status"] == VERIFIED
    data2 = orders_evidence_data()
    data2["simulate"] = [s for s in data2["simulate"] if s.get("at") is None]
    only_permit = {**ROLE_HYP, "predictions": ROLE_HYP["predictions"][:1]}
    d2 = decide([only_permit], ctx=orders_ctx(data2))
    ok2, o2 = rules(d2, "h1")
    assert not ok2["controls"] and "unavailable" in o2["rules"]["controls"]["why"]
    assert "policy_history" in d2["missing_signals"]


def test_cache_gives_identical_answers_whatever_identifier_a_model_uses():
    ctx = orders_ctx()
    v = Verifier(ctx, FN)
    by_arn, _ = parse_hypotheses({"hypotheses": [ROLE_HYP]}, ctx.model)
    by_name = json.loads(json.dumps(ROLE_HYP).replace(ROLE, "module.orders.aws_iam_role.orders")
                         .replace(TABLE, "orders-table").replace(FN, "orders-fn"))
    by_alias, _ = parse_hypotheses({"hypotheses": [by_name]}, ctx.model)
    d1 = v.decide(by_arn)
    calls = v.calls
    d2 = v.decide(by_alias)
    assert v.calls == calls                     # every primitive answer came from the cache
    assert d1["verdict"] == d2["verdict"]
    assert d1["outcomes"][0]["rules"] == d2["outcomes"][0]["rules"]


def test_anchor_must_be_in_graph():
    with pytest.raises(ValueError):
        Verifier(orders_ctx(), "arn:aws:lambda:us-east-1:1:function:ghost")


# ── parsing ──────────────────────────────────────────────────────────────────

def test_parse_accepts_args_json_and_rejects_bad_items():
    m = orders_model()
    raw = {"hypotheses": [
        {"node": "orders-fn", "property": "p", "claim": "c", "predictions": [
            {"primitive": "signal", "args_json": json.dumps(FN_ERRORS["predictions"][0]["args"]), "expect": "pass"}]},
        {"node": "ghost", "property": "p", "claim": "c", "predictions": []},
        {"node": FN, "property": "p", "claim": "c", "predictions": [
            {"primitive": "signal", "args_json": "{not json", "expect": "PASS"}]},
        {"node": FN, "property": "p", "claim": "c", "predictions": [
            {"primitive": "signal", "args": {"node": FN}, "expect": "MAYBE"}]},
        {"node": FN, "property": "p", "claim": "c", "predictions": []},
    ]}
    hyps, errs = parse_hypotheses(raw, m)
    assert [h.node for h in hyps] == [FN]
    assert hyps[0].predictions[0].expect == "PASS"
    joined = " | ".join(errs)
    for needle in ("not a node", "not JSON", "PASS or FAIL", "at least one prediction"):
        assert needle in joined


def test_parse_limits_and_top_level_shape():
    m = orders_model()
    hyps, errs = parse_hypotheses({"hypotheses": [FN_ERRORS] * 7}, m, max_hypotheses=5)
    assert len(hyps) == 5 and "only the first 5" in errs[0]
    assert parse_hypotheses("nope", m)[1][0].startswith("output is not JSON")
    assert "must be an object" in parse_hypotheses({"x": 1}, m)[1][0]
    assert parse_hypotheses(json.dumps({"hypotheses": [FN_ERRORS]}), m)[0][0].node == FN


# ── the loop ─────────────────────────────────────────────────────────────────

class FakeProposer:
    def __init__(self, script):
        self.script = list(script)
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        item = self.script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_loop_repairs_once_then_verifies_and_stops_early():
    bad = {"hypotheses": [{"node": "ghost", "property": "", "claim": "", "predictions": []}]}
    prop = FakeProposer([bad, {"hypotheses": [ROLE_HYP, TABLE_THROTTLE]}, {"hypotheses": []}])
    out = verify_loop(Verifier(orders_ctx(), FN), prop, rounds=3)
    assert out["status"] == VERIFIED and out["verdict"]["node"] == ROLE
    assert out["rounds"] == [{"round": 1, "proposed": 2, "new": 2, "schema_errors": [], "repaired": True}]
    assert prop.requests[1]["repair"] and "not a node" in prop.requests[1]["repair"][0]
    assert len(prop.requests) == 2      # stopped after verification
    assert out["hypotheses_dropped"] == 0


def test_loop_feeds_results_back_and_counts_dropped():
    rival = {"node": TABLE, "property": "stream", "claim": "c", "predictions": [{"primitive": "signal", "args": {
        "node": TABLE, "query": {"metric": "AWS/DynamoDB:IteratorAge"}, "predicate": {"op": "above", "value": 1}}}]}
    refute = {"node": TABLE, "property": "throttling", "claim": "c", "predictions": TABLE_THROTTLE["predictions"]}
    bad = {"hypotheses": [{"node": "ghost"}]}
    prop = FakeProposer([{"hypotheses": [ROLE_HYP, rival]}, bad, bad, {"hypotheses": [refute]}])
    out = verify_loop(Verifier(orders_ctx(), FN), prop, rounds=3)
    # round 1: candidates (unrefuted rival); round 2: invalid twice -> dropped,
    # no new hypotheses -> loop ends with the round-1 decision
    assert out["status"] == CANDIDATES
    assert out["hypotheses_dropped"] == 1
    assert prop.requests[1]["previous"] and prop.requests[1]["round"] == 2


def test_loop_survives_proposer_failure_and_respects_rounds():
    prop = FakeProposer([RuntimeError("model down")])
    out = verify_loop(Verifier(orders_ctx(), FN), prop, rounds=3)
    assert out["status"] == UNVERIFIED and "model down" in out["rounds"][0]["error"]
    loose = {"node": FN, "claim": "c", "predictions": [{"primitive": "config", "args": {
        "node": FN, "path": "Timeout", "predicate": {"op": "equals", "value": 30}}}]}
    many = [{"hypotheses": [{**loose, "property": f"p{i}"}]} for i in range(5)]
    prop2 = FakeProposer(many)
    out2 = verify_loop(Verifier(orders_ctx(), FN), prop2, rounds=2)
    assert len(prop2.requests) == 2 and out2["hypotheses_total"] == 2


def test_two_proposers_same_evidence_same_verdict():
    """The design's goal in miniature: different proposals of the same cause
    (different identifiers, extra noise hypotheses, different order) reach the
    same verdict tuple, because code decides."""
    alt = json.loads(json.dumps(ROLE_HYP).replace(ROLE, "orders-role"))
    a = verify_loop(Verifier(orders_ctx(), FN), FakeProposer([{"hypotheses": [ROLE_HYP, TABLE_THROTTLE]}]))
    b = verify_loop(Verifier(orders_ctx(), FN),
                    FakeProposer([{"hypotheses": [TABLE_THROTTLE, FN_ERRORS, alt]}]))
    key = lambda d: (d["verdict"]["status"], d["verdict"]["node"], d["verdict"]["property"])
    assert key(a) == key(b) == (VERIFIED, ROLE, "policy:dynamodb:PutItem")
