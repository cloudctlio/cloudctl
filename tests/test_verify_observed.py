"""Observed layer: CloudTrail, VPC flow logs, X-Ray, log lines."""
from __future__ import annotations

import json

from cloudctl.verify.model import Node, SystemModel
from cloudctl.verify.observed import (
    add_cloudtrail_edges,
    add_flow_log_edges,
    add_log_line_edges,
    add_xray_edges,
    build_ip_index,
    observability_gaps,
    parse_flow_record,
)

FN = "arn:aws:lambda:us-east-1:1:function:orders-fn"
ROLE = "arn:aws:iam::1:role/orders-role"
TABLE = "arn:aws:dynamodb:us-east-1:1:table/orders-table"
DB = "arn:aws:rds:us-east-1:1:db:orders-db"


def _m():
    m = SystemModel()
    for arn, t, n in ((FN, "lambda", "orders-fn"), (ROLE, "iam", "orders-role"),
                      (TABLE, "dynamodb", "orders-table"), (DB, "rds", "orders-db")):
        m.add_node(Node(id=arn, type=t, name=n, arn=arn), "live")
    m.add_edge(FN, ROLE, "live", via="execution_role")
    return m


def _event(name="PutItem"):
    return {"eventID": "e-1", "eventSource": "dynamodb.amazonaws.com", "eventName": name,
            "userIdentity": {"type": "AssumedRole",
                             "arn": "arn:aws:sts::1:assumed-role/orders-role/orders-fn",
                             "sessionContext": {"sessionIssuer": {"arn": ROLE}}},
            "requestParameters": {"tableName": "orders-table"},
            "resources": [{"ARN": TABLE}]}


def test_cloudtrail_caller_is_the_compute_behind_the_role():
    m = _m()
    assert add_cloudtrail_edges(m, [_event(), {"CloudTrailEvent": json.dumps(_event("GetItem"))}]) == 1
    e = [e for e in m.edges if e.source == "observed"][0]
    assert (e.src, e.dst, e.via) == (FN, TABLE, "cloudtrail")
    assert "PutItem e-1" in e.detail


def test_cloudtrail_unknown_caller_adds_nothing():
    m = _m()
    ev = _event()
    ev["userIdentity"] = {"arn": "arn:aws:sts::1:assumed-role/stranger/x"}
    assert add_cloudtrail_edges(m, [ev, {"CloudTrailEvent": "not json"}]) == 0


def test_flow_logs_accept_only_through_ip_index():
    m = _m()
    enis = [{"NetworkInterfaceId": "eni-1", "Description": "AWS Lambda VPC ENI-orders-fn",
             "PrivateIpAddress": "10.0.1.5"},
            {"NetworkInterfaceId": "eni-2", "Description": "RDSNetworkInterface",
             "Attachment": {"InstanceOwnerId": "amazon-rds"}, "TagSet": [{"Value": "orders-db"}],
             "PrivateIpAddresses": [{"PrivateIpAddress": "10.0.2.9"}]},
            {"NetworkInterfaceId": "eni-3", "Description": "unrelated", "PrivateIpAddress": "10.0.9.9"}]
    idx = build_ip_index(m, enis)
    assert idx == {"10.0.1.5": FN, "10.0.2.9": DB}
    lines = ["2 1 eni-1 10.0.1.5 10.0.2.9 40000 5432 6 1 60 1700000000 1700000060 ACCEPT OK",
             "2 1 eni-1 10.0.1.5 10.0.2.9 40001 5432 6 1 60 1700000000 1700000060 REJECT OK",
             "2 1 eni-1 10.0.1.5 10.0.9.9 40001 443 6 1 60 1700000000 1700000060 ACCEPT OK",
             "garbage"]
    assert add_flow_log_edges(m, lines, idx) == 1
    e = [e for e in m.edges if e.via == "flow_log"][0]
    assert (e.src, e.dst) == (FN, DB) and e.detail.endswith(":5432")


def test_parse_flow_record():
    r = parse_flow_record("2 1 eni-1 10.0.0.1 10.0.0.2 - - 1 1 60 - - REJECT NODATA")
    assert r["srcport"] is None and r["start"] is None and r["action"] == "REJECT"
    assert parse_flow_record("3 x") is None


def test_xray_service_graph_edges():
    m = _m()
    graph = {"Services": [
        {"ReferenceId": 0, "Name": "orders-fn", "Edges": [{"ReferenceId": 1}, {"ReferenceId": 9}]},
        {"ReferenceId": 1, "Name": "orders-table", "Names": ["orders-table"]},
        {"ReferenceId": 2, "Name": "external-thing", "Edges": [{"ReferenceId": 1}]}]}
    assert add_xray_edges(m, graph) == 1
    assert m.dependencies(FN, sources=["observed"]) == [TABLE]


def test_log_lines_name_endpoints_and_arns():
    m = _m()
    logs = {FN: ["connecting to orders-db.abc123.us-east-1.rds.amazonaws.com:5432",
                 f"wrote to {TABLE}", "nothing here"]}
    n = add_log_line_edges(m, logs, endpoints={"orders-db.abc123": DB})
    assert n == 2
    assert set(m.dependencies(FN, sources=["observed"])) == {DB, TABLE}


def test_observability_gaps():
    assert observability_gaps({"cloudtrail": True, "logs": True}) == ["VPC flow logs", "X-Ray traces"]
