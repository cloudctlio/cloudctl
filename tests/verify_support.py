"""Shared fixtures for the propose-then-verify tests (no AWS, no model)."""
from __future__ import annotations

import json
import os

from cloudctl.verify.evidence import FixtureEvidence, Incident
from cloudctl.verify.iac import load_terraform_state
from cloudctl.verify.model import SystemModel
from cloudctl.verify.primitives import Context

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "verify")
T = 1_700_000_000           # symptom onset
END = T + 1200              # incident window end
PRE = T - 3600              # pre-onset control window ends here (lookback = 3600)

ACCT = "111122223333"
FN = f"arn:aws:lambda:us-east-1:{ACCT}:function:orders-fn"
FN2 = f"arn:aws:lambda:us-east-1:{ACCT}:function:users-fn"
ROLE = f"arn:aws:iam::{ACCT}:role/orders-role"
ROLE2 = f"arn:aws:iam::{ACCT}:role/users-role"
TABLE = f"arn:aws:dynamodb:us-east-1:{ACCT}:table/orders-table"


def orders_model() -> SystemModel:
    m = SystemModel()
    with open(os.path.join(FIXTURES, "orders.tfstate.json"), encoding="utf-8") as fh:
        load_terraform_state(m, json.load(fh), "orders.tfstate.json")
    # live layer: the execution roles (the one live edge not a string match)
    m.add_edge(FN, ROLE, "live", via="execution_role")
    m.add_edge(FN2, ROLE2, "live", via="execution_role")
    return m


def orders_evidence_data() -> dict:
    """AccessDenied on dynamodb:PutItem after a policy change on orders-role
    10 minutes before onset. users-fn is a healthy peer."""
    deny = "ERROR AccessDeniedException: orders-role is not authorized to perform: dynamodb:PutItem"
    return {
        "metrics": {
            FN: {"AWS/Lambda:Errors": [[T + 60 * i, 5.0] for i in range(1, 15)]
                 + [[PRE - 600 + 60 * i, 0.0] for i in range(5)]},
            FN2: {"AWS/Lambda:Errors": [[T + 60 * i, 0.0] for i in range(1, 15)]
                  + [[PRE - 600 + 60 * i, 0.0] for i in range(5)]},
            TABLE: {"AWS/DynamoDB:ThrottledRequests": [[T + 60 * i, 0.0] for i in range(1, 15)]
                    + [[PRE - 600 + 60 * i, 0.0] for i in range(5)]},
        },
        "logs": {
            FN: [[T + 30, deny], [T + 90, deny], [T + 400, deny], [PRE - 300, "INFO put ok"]],
            FN2: [[T + 30, "INFO get ok"], [PRE - 300, "INFO get ok"]],
        },
        "config": {
            FN: [{"at": None, "config": {"Timeout": 30, "MemorySize": 512, "Role": ROLE}},
                 {"at": PRE - 3600, "config": {"Timeout": 30, "MemorySize": 512, "Role": ROLE}}],
            FN2: [{"at": None, "config": {"Timeout": 30, "MemorySize": 512, "Role": ROLE2}},
                  {"at": PRE - 3600, "config": {"Timeout": 30, "MemorySize": 512, "Role": ROLE2}}],
        },
        "changes": {
            ROLE: [{"ts": T - 600, "actor": f"arn:aws:iam::{ACCT}:user/deployer",
                    "action": "iam:PutRolePolicy", "paths": ["orders-inline"], "ref": "cloudtrail evt-1"}],
        },
        "simulate": [
            {"principal": ROLE, "action": "dynamodb:PutItem", "resource": TABLE,
             "decision": "implicitDeny", "matched": []},
            {"principal": ROLE, "action": "dynamodb:PutItem", "resource": TABLE, "at": PRE - 7200,
             "decision": "allowed", "matched": [{"policy": "orders-inline", "type": "IAM Policy"}]},
            {"principal": ROLE2, "action": "dynamodb:PutItem", "resource": TABLE,
             "decision": "allowed", "matched": [{"policy": "users-inline", "type": "IAM Policy"}]},
        ],
    }


def orders_ctx(data: dict | None = None, model: SystemModel | None = None) -> Context:
    m = model or orders_model()
    return Context(m, FixtureEvidence(orders_evidence_data() if data is None else data, m), Incident(T, END))
