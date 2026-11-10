"""System model: nodes, provenance-tagged edges, joins and graph queries."""
from __future__ import annotations

import pytest

from cloudctl.verify.model import (
    Node,
    SystemModel,
    live_from_dependency_graph,
    live_from_snapshot,
    type_family,
)

A = "arn:aws:lambda:us-east-1:1:function:api-handler"
R = "arn:aws:iam::1:role/api-role"
Q = "arn:aws:sqs:us-east-1:1:jobs-queue"


def _m():
    m = SystemModel()
    m.add_node(Node(id=A, type="aws_lambda_function", name="api-handler", arn=A,
                    iac_address="aws_lambda_function.api"), "declared")
    m.add_node(Node(id=R, type="aws_iam_role", name="api-role", arn=R,
                    iac_address="aws_iam_role.api"), "declared")
    m.add_node(Node(id=Q, type="aws_sqs_queue", name="jobs-queue", arn=Q), "declared")
    return m


def test_merge_by_arn_keeps_both_sources():
    m = _m()
    n = m.add_node(Node(id="lambda:api-handler", type="lambda", name="api-handler", arn=A,
                        live={"Timeout": 3}), "live")
    assert n.id == A
    assert n.sources == {"declared", "live"}
    assert n.live == {"Timeout": 3}
    assert m.resolve("lambda:api-handler") == A
    assert m.resolve("aws_lambda_function.api") == A
    assert len(m.nodes) == 3


def test_name_join_requires_unambiguous_name_and_same_family():
    m = _m()
    # family matches (lambda) and the name is unique -> joins
    j = m.add_node(Node(id="lambda:api-handler", type="lambda", name="api-handler"), "live")
    assert j.id == A
    # same name, different family -> stays separate
    m.add_node(Node(id="logs:api-handler", type="logs", name="api-handler"), "live")
    assert "logs:api-handler" in m.nodes
    # now the bare name is ambiguous, so resolve() refuses to guess
    assert m.resolve("api-handler") is None


def test_rekey_to_arn_when_arn_learned_later():
    m = SystemModel()
    m.add_node(Node(id="Stack/Fn", type="AWS::Lambda::Function", name="fn-x1",
                    iac_address="Stack/Fn"), "declared")
    m.add_node(Node(id="Stack/Role", type="AWS::IAM::Role", iac_address="Stack/Role"), "declared")
    m.add_edge("Stack/Fn", "Stack/Role", "declared", via="cfn_GetAtt")
    arn = "arn:aws:lambda:us-east-1:1:function:fn-x1"
    m.add_node(Node(id=arn, type="lambda", name="fn-x1", arn=arn), "live")
    assert arn in m.nodes and "Stack/Fn" not in m.nodes
    assert m.resolve("Stack/Fn") == arn
    assert m.dependencies(arn) == ["Stack/Role"]
    assert m.resolve("fn-x1") == arn


def test_edges_to_unknown_nodes_are_dropped_and_deduplicated():
    m = _m()
    assert m.add_edge(A, "arn:aws:s3:::nowhere", "declared") is None
    assert m.add_edge(A, R, "declared", via="tf_dependency") is not None
    assert m.add_edge(A, R, "declared", via="tf_dependency") is None   # duplicate
    assert m.add_edge(A, R, "live", via="execution_role") is not None   # other source kept
    assert m.edge_sources(A, R) == ["declared", "live"]
    assert m.add_edge(A, A, "live") is None
    with pytest.raises(ValueError):
        m.add_edge(A, R, "guessed")


def test_graph_queries_failing_path_upstream_and_cycles():
    m = _m()
    m.add_edge(A, Q, "observed", via="cloudtrail")
    m.add_edge(Q, R, "declared")
    m.add_edge(R, A, "declared")      # a cycle
    assert m.upstream(A) == {Q: 1, R: 2}
    assert m.failing_path(A) == [A, Q, R]
    assert m.failing_path(A, max_depth=1) == [A, Q]
    assert m.on_failing_path(A, R) and m.on_failing_path(A, A)
    assert m.is_upstream_of(R, A) and m.is_upstream_of(A, R)  # cycle: both ways
    assert m.failing_path("nope") == []


def test_is_upstream_of_direction_without_cycle():
    m = _m()
    m.add_edge(A, Q, "declared")
    assert m.is_upstream_of(Q, A)
    assert not m.is_upstream_of(A, Q)
    assert m.same_chain(A, Q) and not m.same_chain(A, R)


def test_peers_by_type_and_module():
    m = _m()
    other = "arn:aws:lambda:us-east-1:1:function:worker"
    m.add_node(Node(id=other, type="aws_lambda_function", name="worker", arn=other), "declared")
    assert m.peers(A) == [other]
    assert m.peers(R) == []


def test_find_references_arn_and_token_bounded_names():
    m = _m()
    blob = '{"env": {"QUEUE": "jobs-queue", "X": "notjobs-queuex"}, "role": "%s"}' % R
    assert m.find_references(blob, exclude=A) == {Q, R}
    assert m.find_references("prefix-api-rolex") == set()


def test_type_family():
    assert type_family("aws_lambda_function") == "lambda"
    assert type_family("AWS::Lambda::Function") == "lambda"
    assert type_family("aws_security_group") == "ec2"
    assert type_family("", "arn:aws:sqs:us-east-1:1:q") == "sqs"
    assert type_family("") == ""


def test_live_from_dependency_graph():
    m = SystemModel()
    live_from_dependency_graph(m, {"nodes": ["lambda:fn-aaaaaa", "sqs:queue-bbbbbb", "bad"],
                                   "edges": [{"from": "lambda:fn-aaaaaa", "to": "sqs:queue-bbbbbb",
                                              "via": "config_ref"}]})
    assert set(m.nodes) == {"lambda:fn-aaaaaa", "sqs:queue-bbbbbb"}
    assert m.edges[0].source == "live" and m.edges[0].via == "config_ref"


def test_live_from_snapshot_config_refs_and_execution_role():
    m = SystemModel()
    live_from_snapshot(m, [
        {"arn": A, "type": "lambda", "name": "api-handler", "role_arn": R,
         "config": {"Environment": {"Variables": {"Q": Q}}}},
        {"arn": Q, "type": "sqs", "name": "jobs-queue", "config": {}},
        {"arn": R, "type": "iam", "name": "api-role", "config": {}},
    ])
    vias = {(e.src, e.dst, e.via) for e in m.edges}
    assert (A, Q, "config_ref") in vias
    assert (A, R, "execution_role") in vias
    assert all(e.source == "live" for e in m.edges)


def test_summary_and_stats():
    m = _m()
    m.add_edge(A, R, "declared")
    s = m.summary()
    assert {n["id"] for n in s["nodes"]} == {A, R, Q}
    assert s["edges"][0]["source"] == "declared"
    assert m.stats()["edges_by_source"] == {"declared": 1, "live": 0, "observed": 0}
