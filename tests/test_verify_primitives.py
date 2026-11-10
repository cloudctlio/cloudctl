"""The nine primitives: PASS / FAIL / INCONCLUSIVE / UNAVAILABLE, facts with
sources, and the pre-onset control window for each one that takes part."""
from __future__ import annotations

import copy

import pytest

from cloudctl.verify import primitives as P
from cloudctl.verify.evidence import FixtureEvidence, Incident, Window
from cloudctl.verify.model import Node
from cloudctl.verify.primitives import FAIL, INCONCLUSIVE, PASS, UNAVAILABLE, Context
from tests.verify_support import (
    END,
    FN,
    FN2,
    PRE,
    ROLE,
    ROLE2,
    TABLE,
    T,
    orders_ctx,
    orders_evidence_data,
    orders_model,
)


def run(ctx, name, **args):
    return P.run(ctx, name, args)


# ── windows ──────────────────────────────────────────────────────────────────

def test_incident_windows():
    inc = Incident(T, END, lookback=3600)
    assert inc.window("incident") == Window(T, END)
    assert inc.window("lookback") == Window(T - 3600, T)
    # pre_onset ends where the lookback starts, same length as the incident
    assert inc.window("pre_onset") == Window(T - 3600 - 1200, T - 3600)
    # a short incident still gets a control of at least min_control
    assert Incident(T, T + 60).window("pre_onset").length == 900
    with pytest.raises(ValueError):
        inc.window("yesterday")
    with pytest.raises(ValueError):
        Window(5, 1)


# ── signal ───────────────────────────────────────────────────────────────────

def test_signal_above_with_onset_and_control():
    ctx = orders_ctx()
    args = {"node": FN, "query": {"metric": "AWS/Lambda:Errors"}, "predicate": {"op": "above", "value": 1}}
    r = P.run(ctx, "signal", args)
    assert r.status == PASS and r.onset == T + 60
    assert r.facts and r.facts[0]["source"].startswith("metric AWS/Lambda:Errors")
    ctl = P.run(ctx, "signal", {**args, "window": "pre_onset"})
    assert ctl.status == FAIL     # errors were zero before onset


def test_signal_log_present_absent_and_counts():
    ctx = orders_ctx()
    assert run(ctx, "signal", node=FN, query={"log": "AccessDenied"}, predicate={"op": "present"}).status == PASS
    assert run(ctx, "signal", node=FN, query={"log": "AccessDenied"}, predicate={"op": "absent"}).status == FAIL
    assert run(ctx, "signal", node=FN, query={"log": "AccessDenied"},
               predicate={"op": "above", "value": 2}).status == PASS     # 3 lines
    assert run(ctx, "signal", node=FN, query={"log": "AccessDenied"}, predicate={"op": "present"},
               window="pre_onset").status == FAIL
    # quoted phrase must match verbatim
    assert run(ctx, "signal", node=FN, query={"log": '"not authorized to perform"'},
               predicate={"op": "present"}).status == PASS


def test_signal_rising_against_own_baseline():
    data = orders_evidence_data()
    # baseline window for the incident is [T-1200, T]: add low values there
    data["metrics"][FN]["AWS/Lambda:Errors"] += [[T - 600, 1.0], [T - 300, 1.0]]
    ctx = orders_ctx(data)
    r = run(ctx, "signal", node=FN, query={"metric": "AWS/Lambda:Errors", "stat": "avg"},
            predicate={"op": "rising", "factor": 2})
    assert r.status == PASS and r.detail["baseline"] == 1.0
    # no baseline datapoints -> inconclusive, not a pass
    r2 = run(ctx, "signal", node=FN2, query={"metric": "AWS/Lambda:Errors"}, predicate={"op": "rising"})
    assert r2.status == INCONCLUSIVE


def test_signal_unavailable_and_no_datapoints():
    ctx = orders_ctx()
    r = run(ctx, "signal", node=ROLE, query={"metric": "X"}, predicate={"op": "present"})
    assert r.status == UNAVAILABLE and r.missing == "metrics"
    r = run(ctx, "signal", node=FN, query={"metric": "AWS/Lambda:Throttles"}, predicate={"op": "present"})
    assert r.status == UNAVAILABLE and "ListMetrics" in r.reason
    data = orders_evidence_data()
    data["metrics"][FN]["AWS/Lambda:Duration"] = []
    r = run(orders_ctx(data), "signal", node=FN, query={"metric": "AWS/Lambda:Duration"},
            predicate={"op": "above", "value": 1})
    assert r.status == INCONCLUSIVE


# ── config ───────────────────────────────────────────────────────────────────

def test_config_predicates_and_history():
    data = orders_evidence_data()
    data["config"][FN] = [{"at": None, "config": {"Timeout": 3, "Layers": ["a", "b"], "Env": {"K": "v"}}},
                          {"at": PRE - 3600, "config": {"Timeout": 30, "Layers": ["a"]}}]
    ctx = orders_ctx(data)
    assert run(ctx, "config", node=FN, path="Timeout", predicate={"op": "lt", "value": 10}).status == PASS
    assert run(ctx, "config", node=FN, path="Timeout", predicate={"op": "equals", "value": "3"}).status == PASS
    assert run(ctx, "config", node=FN, path="Layers", predicate={"op": "contains", "value": "b"}).status == PASS
    assert run(ctx, "config", node=FN, path="Layers[1]", predicate={"op": "equals", "value": "b"}).status == PASS
    assert run(ctx, "config", node=FN, path="Env.K", predicate={"op": "matches", "value": "^v$"}).status == PASS
    assert run(ctx, "config", node=FN, path="Nope", predicate={"op": "missing"}).status == PASS
    assert run(ctx, "config", node=FN, path="Nope", predicate={"op": "equals", "value": 1}).status == FAIL
    # control: as of the pre-onset window the timeout was 30
    ctl = run(ctx, "config", node=FN, path="Timeout", predicate={"op": "lt", "value": 10}, window="pre_onset")
    assert ctl.status == FAIL and ctl.facts[0]["ts"] == PRE


def test_config_history_unavailable():
    data = orders_evidence_data()
    data["unavailable"] = {"config_history": "AWS Config recorder is off"}
    ctx = orders_ctx(data)
    assert run(ctx, "config", node=FN, path="Timeout", predicate={"op": "exists"}).status == PASS
    r = run(ctx, "config", node=FN, path="Timeout", predicate={"op": "exists"}, window="pre_onset")
    assert r.status == UNAVAILABLE and r.missing == "config_history"


# ── drift ────────────────────────────────────────────────────────────────────

def test_drift_declared_vs_live():
    data = orders_evidence_data()
    data["config"][FN][0]["config"]["Timeout"] = 3          # live drifted from IaC (30)
    ctx = orders_ctx(data)
    r = run(ctx, "drift", node=FN, path="timeout", live_path="Timeout")
    assert r.status == PASS and "IaC module.orders.aws_lambda_function.orders" in r.facts[0]["source"]
    assert run(ctx, "drift", node=FN, path="memory_size", live_path="MemorySize").status == FAIL
    # control: pre-onset live value matched IaC
    assert run(ctx, "drift", node=FN, path="timeout", live_path="Timeout", window="pre_onset").status == FAIL
    assert run(ctx, "drift", node=FN, path="no_such_attr").status == INCONCLUSIVE


def test_drift_unavailable_when_not_in_iac():
    m = orders_model()
    m.add_node(Node(id="arn:aws:sqs:us-east-1:1:handmade-q", type="sqs", name="handmade-q",
                    arn="arn:aws:sqs:us-east-1:1:handmade-q"), "live")
    ctx = orders_ctx(model=m)
    r = run(ctx, "drift", node="arn:aws:sqs:us-east-1:1:handmade-q", path="x")
    assert r.status == UNAVAILABLE and r.missing == "iac"


# ── changed ──────────────────────────────────────────────────────────────────

def test_changed_lookback_match_and_control():
    ctx = orders_ctx()
    r = run(ctx, "changed", node=ROLE)
    assert r.status == PASS and r.onset == T - 600 and "iam:PutRolePolicy" in r.facts[0]["fact"]
    assert run(ctx, "changed", node=ROLE, match="DeleteRole").status == FAIL
    assert run(ctx, "changed", node=ROLE, window="pre_onset").status == FAIL
    assert run(ctx, "changed", node=TABLE).status == FAIL       # CloudTrail on, no writes


def test_changed_unavailable_without_cloudtrail():
    data = orders_evidence_data()
    data["unavailable"] = {"cloudtrail": "trail not readable"}
    r = run(orders_ctx(data), "changed", node=ROLE)
    assert r.status == UNAVAILABLE and r.missing == "cloudtrail"


# ── before ───────────────────────────────────────────────────────────────────

def test_before_change_then_symptom():
    ctx = orders_ctx()
    a = {"event": "change", "node": ROLE}
    b = {"event": "symptom_onset"}
    assert run(ctx, "before", a=a, b=b).status == PASS
    assert run(ctx, "before", a=a, b=b, max_gap=60).status == FAIL       # 600s gap
    assert run(ctx, "before", a=b, b=a).status == FAIL
    sig = {"event": "signal_onset", "node": FN, "query": {"log": "AccessDenied"}, "predicate": {"op": "present"}}
    assert run(ctx, "before", a=a, b=sig).status == PASS
    assert run(ctx, "before", a={"event": "change", "node": TABLE}, b=b).status == INCONCLUSIVE


def test_before_propagates_unavailable():
    data = orders_evidence_data()
    data["unavailable"] = {"cloudtrail": "off"}
    r = run(orders_ctx(data), "before", a={"event": "change", "node": ROLE}, b={"event": "symptom_onset"})
    assert r.status == UNAVAILABLE and r.missing == "cloudtrail"


# ── permit ───────────────────────────────────────────────────────────────────

def test_permit_live_and_pre_onset_control():
    ctx = orders_ctx()
    r = run(ctx, "permit", principal=ROLE, action="dynamodb:PutItem", resource=TABLE)
    assert r.status == FAIL and r.detail["decision"] == "implicitdeny"
    ctl = run(ctx, "permit", principal=ROLE, action="dynamodb:PutItem", resource=TABLE, window="pre_onset")
    assert ctl.status == PASS and "orders-inline" in ctl.facts[1]["fact"]
    assert run(ctx, "permit", principal=ROLE2, action="dynamodb:PutItem", resource=TABLE).status == PASS


def test_permit_unavailable_cases():
    ctx = orders_ctx()
    r = run(ctx, "permit", principal=ROLE2, action="dynamodb:PutItem", resource=TABLE, window="pre_onset")
    assert r.status == UNAVAILABLE and r.missing == "policy_history"
    r = run(ctx, "permit", principal=ROLE, action="s3:GetObject")
    assert r.status == UNAVAILABLE
    data = orders_evidence_data()
    data["unavailable"] = {"iam_simulation": "iam:SimulatePrincipalPolicy denied"}
    assert run(orders_ctx(data), "permit", principal=ROLE, action="dynamodb:PutItem",
               resource=TABLE).status == UNAVAILABLE


# ── reach ────────────────────────────────────────────────────────────────────

DBA = "arn:aws:rds:us-east-1:111122223333:db:orders-db"


def _net_data(db_ingress_port=5432, nacl_deny=False, route=True, with_history=True):
    sg_fn = {"GroupId": "sg-fn", "IpPermissions": [],
             "IpPermissionsEgress": [{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]}
    sg_db = {"GroupId": "sg-db", "IpPermissionsEgress": [],
             "IpPermissions": [{"IpProtocol": "tcp", "FromPort": db_ingress_port, "ToPort": db_ingress_port,
                                "UserIdGroupPairs": [{"GroupId": "sg-fn"}]}]}
    allow_all = {"NetworkAclId": "acl-1", "Entries": [
        {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "Egress": True, "CidrBlock": "0.0.0.0/0"},
        {"RuleNumber": 100, "Protocol": "-1", "RuleAction": "allow", "Egress": False, "CidrBlock": "0.0.0.0/0"}]}
    db_nacl = copy.deepcopy(allow_all)
    if nacl_deny:
        db_nacl["Entries"].insert(0, {"RuleNumber": 50, "Protocol": "6", "PortRange": {"From": 5432, "To": 5432},
                                      "RuleAction": "deny", "Egress": False, "CidrBlock": "10.0.1.0/24"})
    rt = {"RouteTableId": "rtb-1", "Routes": [{"DestinationCidrBlock": "10.0.0.0/16", "GatewayId": "local"}]
          if route else [{"DestinationCidrBlock": "0.0.0.0/0", "NatGatewayId": "nat-1"}]}
    good_db_sg = copy.deepcopy(sg_db)
    good_db_sg["IpPermissions"][0]["FromPort"] = good_db_sg["IpPermissions"][0]["ToPort"] = 5432
    net = {
        FN: [{"at": None, "network": {"ips": ["10.0.1.5"], "security_groups": [sg_fn],
                                      "nacl": allow_all, "route_table": rt}}],
        DBA: [{"at": None, "network": {"ips": ["10.0.2.9"], "security_groups": [sg_db], "nacl": db_nacl}}],
    }
    if with_history:
        net[FN].append({"at": PRE - 3600, "network": net[FN][0]["network"]})
        net[DBA].append({"at": PRE - 3600, "network": {"ips": ["10.0.2.9"], "security_groups": [good_db_sg],
                                                      "nacl": allow_all}})
    data = orders_evidence_data()
    data["network"] = net
    return data


def _db_model():
    m = orders_model()
    m.add_node(Node(id=DBA, type="aws_db_instance", name="orders-db", arn=DBA), "live")
    m.add_edge(FN, DBA, "observed", via="flow_log")
    return m


def test_reach_pass_when_every_layer_allows():
    r = run(orders_ctx(_net_data(), _db_model()), "reach", src=FN, dst=DBA, port=5432)
    assert r.status == PASS
    assert any("dst_sg_ingress: allow (sg-db IpPermissions from sg-fn port 5432)" in f["fact"] for f in r.facts)


def test_reach_fail_names_blocking_sg_rule_and_control_window():
    ctx = orders_ctx(_net_data(db_ingress_port=3306), _db_model())
    r = run(ctx, "reach", src=FN, dst=DBA, port=5432)
    assert r.status == FAIL and r.detail["blocking_layer"] == "dst_sg_ingress"
    assert "sg-db" in r.detail["blocking_rule"]
    # pre-onset the DB security group allowed 5432
    assert run(ctx, "reach", src=FN, dst=DBA, port=5432, window="pre_onset").status == PASS


def test_reach_nacl_deny_route_missing_and_unknown_layers():
    r = run(orders_ctx(_net_data(nacl_deny=True), _db_model()), "reach", src=FN, dst=DBA, port=5432)
    assert r.status == FAIL and r.detail["blocking_layer"] == "dst_nacl_ingress"
    assert "rule 50 deny" in r.detail["blocking_rule"]
    r = run(orders_ctx(_net_data(route=False), _db_model()), "reach", src=FN, dst=DBA, port=5432)
    assert r.status == INCONCLUSIVE    # routed via NAT: beyond what reach evaluates
    data = _net_data()
    del data["network"][DBA][0]["network"]["nacl"]
    r = run(orders_ctx(data, _db_model()), "reach", src=FN, dst=DBA, port=5432)
    assert r.status == INCONCLUSIVE and "not every layer" in r.reason


def test_reach_unavailable_without_network_data():
    r = run(orders_ctx(_net_data(with_history=False), _db_model()), "reach", src=FN, dst=DBA, port=5432,
            window="pre_onset")
    assert r.status == UNAVAILABLE and r.missing == "network_history"
    r = run(orders_ctx(None, _db_model()), "reach", src=FN, dst=DBA, port=5432)
    assert r.status == UNAVAILABLE


# ── path_health ──────────────────────────────────────────────────────────────

def test_path_health_states_first_failing_and_control():
    ctx = orders_ctx()
    r = run(ctx, "path_health", anchor=FN)
    assert r.status == PASS
    assert r.detail["states"] == {FN: "failing", ROLE: "unknown", TABLE: "healthy"}
    assert r.detail["first_failing"] == FN
    assert run(ctx, "path_health", anchor=FN, first_failing=FN).status == PASS
    # the role is unobservable: can't say it is (or isn't) the first failing node
    assert run(ctx, "path_health", anchor=FN, first_failing=ROLE).status == UNAVAILABLE
    assert run(ctx, "path_health", anchor=FN, first_failing=TABLE).status == FAIL
    assert run(ctx, "path_health", anchor=FN, window="pre_onset").status == FAIL


def test_path_health_deepest_failing_and_unobservable_path():
    data = orders_evidence_data()
    data["failures"] = {TABLE: [[T + 10, "ERROR ProvisionedThroughputExceeded"]]}
    r = run(orders_ctx(data), "path_health", anchor=FN)
    assert r.detail["first_failing"] == TABLE      # most upstream failing node
    r = run(orders_ctx({}), "path_health", anchor=FN)
    assert r.status == UNAVAILABLE and r.missing == "failure_signals"


# ── peer ─────────────────────────────────────────────────────────────────────

def test_peer_config_differs_from_healthy_peer_and_control():
    data = orders_evidence_data()
    data["config"][FN] = [{"at": None, "config": {"Timeout": 3, "MemorySize": 512}},
                          {"at": PRE - 3600, "config": {"Timeout": 30, "MemorySize": 512}}]
    ctx = orders_ctx(data)
    r = run(ctx, "peer", node=FN, query={"config_path": "Timeout"})
    assert r.status == PASS and "users-fn" in r.facts[1]["fact"]
    assert run(ctx, "peer", node=FN, query={"config_path": "MemorySize"}).status == FAIL
    assert run(ctx, "peer", node=FN, query={"config_path": "Timeout"}, window="pre_onset").status == FAIL


def test_peer_signal_and_no_peers():
    ctx = orders_ctx()
    r = run(ctx, "peer", node=FN, query={"log": "AccessDenied", "predicate": {"op": "present"}})
    assert r.status == PASS
    r = run(ctx, "peer", node=TABLE, query={"config_path": "x"})
    assert r.status == UNAVAILABLE    # no config recorded for the table
    r = run(ctx, "peer", node=ROLE, query={"config_path": "x"})
    assert r.status == UNAVAILABLE


# ── validation and cache keys ────────────────────────────────────────────────

@pytest.mark.parametrize("name,args,needle", [
    ("nope", {}, "unknown primitive"),
    ("signal", {"node": FN, "query": {"metric": "m"}}, "missing required arg 'predicate'"),
    ("signal", {"node": "ghost", "query": {"metric": "m"}, "predicate": {"op": "present"}}, "not a node"),
    ("signal", {"node": FN, "query": {"metric": "m", "log": "x"}, "predicate": {"op": "present"}}, "exactly one"),
    ("signal", {"node": FN, "query": {"metric": "m"}, "predicate": {"op": "above"}}, "value (number)"),
    ("signal", {"node": FN, "query": {"metric": "m"}, "predicate": {"op": "present"}, "window": "x"}, "one of"),
    ("config", {"node": FN, "path": "a", "predicate": {"op": "equals"}}, "value is required"),
    ("reach", {"src": FN, "dst": TABLE, "port": "443"}, "expected integer"),
    ("reach", {"src": FN, "dst": TABLE, "port": 443, "extra": 1}, "unknown arg"),
    ("before", {"a": {"event": "deploy"}, "b": {"event": "symptom_onset"}}, "before.a.event"),
    ("peer", {"node": FN, "query": {"metric": "m"}}, "needs a predicate"),
])
def test_validate_rejects(name, args, needle):
    errs = P.validate(name, args, orders_model())
    assert any(needle in e for e in errs), errs


def test_run_backstop_returns_inconclusive_on_invalid_args():
    r = P.run(orders_ctx(), "signal", {"node": FN})
    assert r.status == INCONCLUSIVE and "missing required" in r.reason


def test_canonical_args_resolve_any_identifier():
    m = orders_model()
    a = P.canonical_args("permit", {"principal": "module.orders.aws_iam_role.orders",
                                    "action": "dynamodb:PutItem", "resource": "orders-table"}, m)
    assert a["principal"] == ROLE and a["resource"] == TABLE


def test_fixture_evidence_resolves_keys_by_any_identifier():
    m = orders_model()
    ev = FixtureEvidence({"logs": {"module.orders.aws_lambda_function.orders": [[T + 1, "ERROR x"]]}}, m)
    ctx = Context(m, ev, Incident(T, END))
    assert run(ctx, "signal", node="orders-fn", query={"log": "ERROR"}, predicate={"op": "present"}).status == PASS
