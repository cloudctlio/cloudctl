"""Fixes grounded in the real resource, checked fix steps, fail-closed output,
and learned state scoped to the current environment.

The s1 and s3 cases reproduce the live complex-app run (Nov 18): the app's
Terraform with each scenario's bad commit applied, local state as deployed,
and the diagnosis and fix steps that run produced. Offline; a stand-in model.
"""
import json
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cloudctl.debug import iac_fix
from cloudctl.debug.remediation_check import check_remediation, iac_text_for, resolve_target

APP = Path(__file__).parent / "fixtures" / "iac_fix" / "complex_app"
PREFIX = "cctl-complexapp"


def _model(reply: dict):
    c = MagicMock()
    c.converse.return_value = {"stopReason": "end_turn", "output": {"message": {
        "role": "assistant", "content": [{"text": json.dumps(reply)}]}}}
    return c


def _state(resources: list[tuple[str, str, dict]]) -> str:
    return json.dumps({"version": 4, "resources": [
        {"mode": "managed", "type": t, "name": n, "instances": [{"attributes": a}]}
        for t, n, a in resources]})


DEPLOYED = [
    ("aws_apigatewayv2_api", "orders", {"id": "a1b2c3", "name": f"{PREFIX}-api"}),
    ("aws_lambda_permission", "api_gateway", {"id": "AllowApiGateway", "function_name": f"{PREFIX}-api"}),
    ("aws_cloudwatch_log_group", "api", {"id": f"/aws/lambda/{PREFIX}-api", "name": f"/aws/lambda/{PREFIX}-api",
                                          "arn": f"arn:aws:logs:us-east-1:111122223333:log-group:/aws/lambda/{PREFIX}-api"}),
    ("aws_lambda_function", "api", {"id": f"{PREFIX}-api", "function_name": f"{PREFIX}-api",
                                     "arn": f"arn:aws:lambda:us-east-1:111122223333:function:{PREFIX}-api"}),
    ("aws_lambda_function", "worker", {"id": f"{PREFIX}-worker", "function_name": f"{PREFIX}-worker"}),
    ("aws_iam_role", "worker", {"id": f"{PREFIX}-worker-role", "name": f"{PREFIX}-worker-role",
                                 "arn": f"arn:aws:iam::111122223333:role/{PREFIX}-worker-role"}),
    ("aws_iam_role_policy", "worker", {"id": f"{PREFIX}-worker-role:{PREFIX}-worker-policy",
                                        "name": f"{PREFIX}-worker-policy"}),
]


@pytest.fixture
def app(tmp_path, monkeypatch):
    d = tmp_path / "app"
    shutil.copytree(APP, d)
    (d / "terraform.tfstate").write_text(_state(DEPLOYED))
    monkeypatch.setenv("CLOUDCTL_IAC_FIX_CHECK", "0")
    return d


def _edit(d: Path, file: str, before: str, after: str) -> None:
    p = d / file
    t = p.read_text()
    assert before in t
    p.write_text(t.replace(before, after))


# ── s1: worker IAM policy narrowed to invoices/* ──────────────────────────────

S1_BAD = 'Resource = "${aws_s3_bucket.receipts.arn}/invoices/*"'
S1_GOOD = 'Resource = "${aws_s3_bucket.receipts.arn}/receipts/*"'
S1_DIAG = {
    "root_cause": f"The worker role {PREFIX}-worker-role only allows s3:PutObject on invoices/* in the "
                  "receipts bucket, but the worker writes receipts/<order_id>.json, so receipt orders fail "
                  "with AccessDenied, retry 3 times and land in the DLQ.",
    "evidence": [f"{PREFIX}-worker logs: AccessDenied when calling PutObject on receipts/ord-123.json",
                 "DLQ depth 7, growing", "Orders without a receipt complete normally"],
    "resources_investigated": [f"{PREFIX}-worker-role", f"{PREFIX}-worker"],
    # What the live run printed: a direct IAM change, no Terraform, "add" not swap.
    "remediation_steps": [f"Update the policy directly in AWS (PutRolePolicy) on {PREFIX}-worker-role to add "
                          "s3:PutObject on receipts/*",
                          "Replay the messages in the DLQ once the policy is fixed"],
    "deployment_source": "terraform",
    "confidence": "HIGH",
}


def test_s1_locates_the_role_and_shows_the_model_its_policy(app):
    _edit(app, "iam.tf", S1_GOOD, S1_BAD)
    client = _model({"edits": [{"file": "iam.tf", "old": f"        {S1_BAD}", "new": f"        {S1_GOOD}"}],
                     "summary": "Let the worker write receipts/* again instead of invoices/*.",
                     "remediation_steps": ["Change the WriteReceipts statement in aws_iam_role_policy.worker "
                                           "(iam.tf) to receipts/*, then run terraform plan and terraform apply."]})
    out = iac_fix.suggest_fix(S1_DIAG, str(app), client=client, model_id="m")
    assert out["resource"] == "aws_iam_role.worker"
    assert "aws_iam_role_policy.worker" in out["related"]
    sent = json.loads(client.converse.call_args.kwargs["messages"][0]["content"][0]["text"])
    shown = {t["address"]: t["text"] for t in sent["iac_text"]}
    assert "invoices/*" in shown["aws_iam_role_policy.worker"]
    assert sent["resolved_resource"]["type"] == "aws_iam_role"
    assert out["status"] == "suggested"
    assert out["edited_resources"] == ["aws_iam_role_policy.worker"]
    assert '-        Resource = "${aws_s3_bucket.receipts.arn}/invoices/*"' in out["diff"]
    assert '+        Resource = "${aws_s3_bucket.receipts.arn}/receipts/*"' in out["diff"]


def test_s1_direct_iam_change_is_replaced_by_the_terraform_change(app):
    _edit(app, "iam.tf", S1_GOOD, S1_BAD)
    client = _model({"edits": [{"file": "iam.tf", "old": f"        {S1_BAD}", "new": f"        {S1_GOOD}"}],
                     "summary": "Let the worker write receipts/* again instead of invoices/*."})
    fix = iac_fix.suggest_fix(S1_DIAG, str(app), client=client, model_id="m")
    target = resolve_target(S1_DIAG, fix)
    assert target["address"] == "aws_iam_role_policy.worker" and target["iac_managed"]
    rc = check_remediation(S1_DIAG["remediation_steps"], S1_DIAG, target, iac_text_for(str(app)), fix)
    assert [f["step"] for f in rc["flagged"]] == [S1_DIAG["remediation_steps"][0]]
    assert "drift" in rc["flagged"][0]["reason"]
    assert rc["steps"][0].startswith("Change aws_iam_role_policy.worker in iam.tf")
    assert "terraform apply" in rc["steps"][0]
    assert not any("PutRolePolicy" in s for s in rc["steps"])
    assert rc["confirmed"] is True


# ── s3: api Lambda's QUEUE_URL broken, red-herring cache error ────────────────

S3_GOOD = "      TABLE_NAME = aws_dynamodb_table.orders.name\n      QUEUE_URL  = aws_sqs_queue.orders.url\n"
S3_BAD = ("      TABLE_NAME     = aws_dynamodb_table.orders.name\n"
          '      QUEUE_URL      = "https://sqs.${var.region}.amazonaws.com/'
          '${data.aws_caller_identity.current.account_id}/${var.prefix}-orders-v2"\n'
          '      CACHE_ENDPOINT = "redis://127.0.0.1:6379"\n')
S3_DIAG = {
    "root_cause": f"The api Lambda {PREFIX}-api has QUEUE_URL pointing at {PREFIX}-orders-v2, a queue that "
                  "does not exist, so sqs:SendMessage fails on every POST /orders and the API returns 500. "
                  "The cache warmup errors on GET are handled and harmless.",
    "evidence": [f"{PREFIX}-api logs: AWS.SimpleQueueService.NonExistentQueue on SendMessage",
                 "POST /orders 5xx ratio 0.97; GET /orders/{id} 200",
                 f"arn:aws:lambda:us-east-1:111122223333:function:{PREFIX}-api Errors 214 in 15 min"],
    # The live run also investigated unrelated account resources.
    "resources_investigated": [f"{PREFIX}-api", "platform-orders:145", "platform-ecs-task"],
    "remediation_steps": [
        "Edit the ECS task definition platform-orders:145 and set QUEUE_URL to the real orders queue",
        "Force a new ECS deployment: aws ecs update-service --cluster platform --service platform-orders "
        "--force-new-deployment",
    ],
    "deployment_source": "terraform",
    "confidence": "MEDIUM",
}


def test_s3_four_equal_matches_resolve_to_the_lambda(app):
    _edit(app, "lambda.tf", S3_GOOD, S3_BAD)
    hits, _ = iac_fix.locate(app, iac_fix.candidate_names(S3_DIAG), S3_DIAG)
    assert [h.address for h in hits] == ["aws_lambda_function.api"]
    assert "chosen over" in hits[0].how
    # Without the diagnosis to separate them it stays ambiguous, as in the live run.
    tied, _ = iac_fix.locate(app, iac_fix.candidate_names(S3_DIAG))
    assert {h.address for h in tied} >= {"aws_apigatewayv2_api.orders", "aws_lambda_function.api"}


def test_s3_ecs_steps_for_a_lambda_are_held_back_and_replaced(app):
    _edit(app, "lambda.tf", S3_GOOD, S3_BAD)
    old_line = ('      QUEUE_URL      = "https://sqs.${var.region}.amazonaws.com/'
                '${data.aws_caller_identity.current.account_id}/${var.prefix}-orders-v2"')
    client = _model({"edits": [{"file": "lambda.tf", "old": old_line,
                                "new": "      QUEUE_URL      = aws_sqs_queue.orders.url"}],
                     "summary": "Point QUEUE_URL back at the real orders queue."})
    fix = iac_fix.suggest_fix(S3_DIAG, str(app), client=client, model_id="m")
    assert fix["status"] == "suggested" and fix["resource"] == "aws_lambda_function.api"
    assert "aws_sqs_queue.orders.url" in fix["diff"]
    target = resolve_target(S3_DIAG, fix)
    assert target["type"] == "aws_lambda_function" and target["service"] == "lambda"
    rc = check_remediation(S3_DIAG["remediation_steps"], S3_DIAG, target, iac_text_for(str(app)), fix)
    assert len(rc["flagged"]) == 2 and all("ECS" in f["reason"] for f in rc["flagged"])
    assert "aws_lambda_function.api is a aws_lambda_function" in rc["flagged"][0]["reason"]
    assert rc["steps"] == ["Change aws_lambda_function.api in lambda.tf: Point QUEUE_URL back at the real "
                           "orders queue (see the IaC fix suggestion), then run `terraform plan`, then "
                           "`terraform apply`."]
    assert rc["confirmed"] is True


def test_s3_without_a_resolved_resource_fails_closed(app):
    _edit(app, "lambda.tf", S3_GOOD, S3_BAD)
    fix = {"status": "ambiguous", "candidates": ["aws_apigatewayv2_api.orders (api.tf:1)",
                                                 "aws_lambda_function.api (lambda.tf:36)"]}
    diag = {**S3_DIAG, "evidence": S3_DIAG["evidence"][:2]}       # no ARN to fall back on
    rc = check_remediation(diag["remediation_steps"], diag, resolve_target(diag, fix),
                           iac_text_for(str(app)), fix)
    assert rc["confirmed"] is False
    assert "matched equally" in rc["reason"] and len(rc["candidates"]) == 2
    assert {u["step"] for u in rc["unverified"]} == set(diag["remediation_steps"])


# ── the fix step check, generic cases ─────────────────────────────────────────

TF_TARGET = {"address": "aws_dynamodb_table.orders", "located": "aws_dynamodb_table.orders",
             "type": "aws_dynamodb_table", "service": "dynamodb", "file": "main.tf", "kind": "terraform",
             "iac_managed": True, "source": "iac", "related": []}
TF_TEXT = 'resource "aws_dynamodb_table" "orders" {\n  name = "orders"\n}\nresource "aws_lambda_function" "w" {}\n'


@pytest.mark.parametrize("step,drift", [
    ("Run UpdateTable on orders to switch BillingMode to PAY_PER_REQUEST", True),
    ("aws dynamodb update-table --table-name orders --billing-mode PAY_PER_REQUEST", True),
    ("Raise write capacity in the AWS console", True),
    ("Add exponential backoff with jitter around the Lambda PutItem call", False),
    ("Set write_capacity to 10 in main.tf and run terraform apply", False),
    ("Check aws dynamodb describe-table --table-name orders afterwards", False),
])
def test_direct_changes_to_iac_managed_resources_are_flagged(step, drift):
    rc = check_remediation([step], {"root_cause": "orders table at 1 WCU"}, TF_TARGET, TF_TEXT)
    assert bool(rc["flagged"]) is drift


def test_model_written_steps_replace_the_agents_and_keep_originals(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from cloudctl.main import app as cli
    shutil.copytree(Path(__file__).parent / "fixtures" / "iac_fix" / "terraform", tmp_path / "tf")
    monkeypatch.setenv("CLOUDCTL_IAC_FIX_CHECK", "0")
    diag = {"root_cause": "DynamoDB table orders is provisioned at 1 WCU, so writes from Lambda orders-writer "
                          "are throttled.", "evidence": ["WriteThrottleEvents 412"],
            "remediation_steps": ["Run UpdateTable on orders to set PAY_PER_REQUEST"],
            "resources_investigated": ["orders", "orders-writer"], "confidence": "MEDIUM",
            "_guardrails": {"account_id": "111122223333"}}
    client = _model({"edits": [{"file": "variables.tf", "old": "  default = 1", "new": "  default = 10"}],
                     "summary": "Raise WCU to 10.",
                     "remediation_steps": ["Set var.orders_wcu default to 10 in variables.tf, then run "
                                           "terraform plan and terraform apply."]})
    out = tmp_path / "out.json"
    with patch("cloudctl.commands.debug_cmd.require_init", return_value={}), \
         patch("cloudctl.ai.graph_agent.debug_incident_graph", return_value=(json.dumps(diag), {})), \
         patch("cloudctl.ai.model_providers.make_model_client", return_value=client):
        r = CliRunner().invoke(cli, ["debug", "--agent", "--verdict", "skip", "--iac-root", str(tmp_path / "tf"),
                                     "--json-out", str(out), "orders writes throttled"],
                               env={"COLUMNS": "200", "HOME": str(tmp_path)})
    assert r.exit_code == 0, r.output
    d = json.loads(out.read_text())
    assert d["remediation_steps_original"] == diag["remediation_steps"]
    assert d["remediation_steps"][0].startswith("Set var.orders_wcu")
    assert d["remediation_confirmed"] is True and d["confidence"] == "MEDIUM"
    assert "FIX NOW" in r.output and "UpdateTable" not in r.output.split("FIX NOW")[1].split("investigated")[0]


def test_cli_shows_fix_not_confirmed_when_the_resource_is_ambiguous(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from cloudctl.main import app as cli
    tf = tmp_path / "tf"
    shutil.copytree(Path(__file__).parent / "fixtures" / "iac_fix" / "terraform", tf)
    (tf / "other.tf").write_text('resource "aws_sqs_queue" "q" {\n  name = "orders"\n}\n'
                                 'resource "aws_sns_topic" "t" {\n  name = "orders"\n}\n')
    diag = {"root_cause": "orders is slow", "evidence": ["latency p99 9 s"],
            "remediation_steps": ["Restart the orders service"], "resources_investigated": ["orders"],
            "confidence": "MEDIUM"}
    out = tmp_path / "out.json"
    with patch("cloudctl.commands.debug_cmd.require_init", return_value={}), \
         patch("cloudctl.ai.graph_agent.debug_incident_graph", return_value=(json.dumps(diag), {})), \
         patch("cloudctl.ai.model_providers.make_model_client", return_value=_model({})):
        r = CliRunner().invoke(cli, ["debug", "--agent", "--verdict", "skip", "--iac-root", str(tf),
                                     "--json-out", str(out), "orders slow"],
                               env={"COLUMNS": "200", "HOME": str(tmp_path)})
    assert r.exit_code == 0, r.output
    assert "FIX NOT" in r.output and "couldn't confirm the fix" in r.output
    assert "[unverified] Restart the orders service" in r.output
    assert "FIX NOW" not in r.output
    d = json.loads(out.read_text())
    assert d["remediation_confirmed"] is False and d["confidence"] == "MEDIUM"


# ── learned state from ~/.cloudctl is scoped to this environment ──────────────

@pytest.fixture
def polluted_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    base = home / ".cloudctl"
    (base / "patterns").mkdir(parents=True)
    (base / "prompt_lib").mkdir(parents=True)
    (base / "patterns" / "patterns.json").write_text(json.dumps([
        {"pattern_id": "throttle-orders-writes", "pattern_type": "throttle",
         "symptom_tokens": ["orders", "writes", "throttled"], "data_sources": ["get_metrics"],
         "evidence_shape": "", "confirmed_count": 9, "last_seen": "2026-11-01",
         "account_ids": ["xxxx9999"]},                                   # other account, no region
        {"pattern_id": "throttle-orders-here", "pattern_type": "throttle",
         "symptom_tokens": ["orders", "writes"], "data_sources": ["get_metrics"],
         "evidence_shape": "", "confirmed_count": 4, "last_seen": "2026-11-01",
         "account_ids": ["xxxx3333"], "regions": ["us-west-2"]},          # this account, other region
    ]))
    (base / "prompt_lib" / "corrections.jsonl").write_text("\n".join([
        json.dumps({"lessons": ["Do NOT claim 'platform-orders:145 task role lacks kms:Decrypt' without "
                                "finding it explicitly in the fetched data."]}),           # untagged
        json.dumps({"lessons": ["ALWAYS check the SQS DLQ depth when Lambda errors are elevated.",
                                "Check platform-ecs-task first for queue symptoms."],
                    "account": "xxxx3333", "region": "us-east-1"}),
        json.dumps({"lessons": ["Verify the correct service before fetching metrics."],
                    "account": "xxxx9999", "region": "us-east-1"}),
    ]) + "\n")
    (base / "prompt_lib" / "111122223333.jsonl").write_text(json.dumps(
        {"type": "hint", "symptom_token": "orders", "resource": "platform-orders", "confirmed_count": 5,
         "region": "us-east-1"}) + "\n")
    monkeypatch.setenv("HOME", str(home))
    from cloudctl.ai import live_learner
    monkeypatch.setattr(live_learner, "_BASE", base)
    return base


def test_polluted_home_never_reaches_the_prompt(polluted_home):
    from cloudctl.ai.harness import build_system_prompt
    prompt = build_system_prompt(account_id="111122223333", region="us-east-1")
    assert "platform-orders" not in prompt and "platform-ecs-task" not in prompt
    assert "ALWAYS check the SQS DLQ depth" in prompt                 # same account+region, no names
    assert "Verify the correct service" not in prompt                  # other account
    # A name discovered in this run may come back.
    prompt = build_system_prompt(account_id="111122223333", region="us-east-1",
                                 known_names={"platform-ecs-task", "platform-orders"})
    assert "platform-ecs-task" in prompt and "platform-orders:145" not in prompt


def test_polluted_home_patterns_are_scoped(polluted_home):
    from cloudctl.ai.live_learner import best_pattern_match, get_investigation_hints
    assert best_pattern_match("orders writes throttled", "111122223333", "us-east-1") is None
    assert get_investigation_hints("orders writes throttled", "111122223333", "us-east-1") == []
    assert best_pattern_match("orders writes throttled", "111122223333", "us-west-2")["pattern_id"] == \
        "throttle-orders-here"
    assert best_pattern_match("orders writes throttled") is None        # unknown account: nothing


def test_polluted_home_cannot_promote_confidence(polluted_home, tmp_path):
    from typer.testing import CliRunner
    from cloudctl.main import app as cli
    diag = {"root_cause": "orders throttled at 1 WCU", "evidence": ["WriteThrottleEvents 412"],
            "remediation_steps": [], "confidence": "MEDIUM", "_guardrails": {"account_id": "111122223333"}}
    out = tmp_path / "out.json"
    with patch("cloudctl.commands.debug_cmd.require_init", return_value={}), \
         patch("cloudctl.ai.graph_agent.debug_incident_graph",
               return_value=(json.dumps(diag), {"get_metrics:x": {}})):
        r = CliRunner().invoke(cli, ["debug", "--agent", "--verdict", "skip", "--json-out", str(out),
                                     "orders writes throttled"],
                               env={"COLUMNS": "200", "HOME": str(polluted_home.parent)})
    assert r.exit_code == 0, r.output
    assert json.loads(out.read_text())["confidence"] == "MEDIUM"


def test_learned_entries_are_written_with_their_scope(polluted_home):
    from cloudctl.ai import live_learner
    live_learner.on_confirmed_wrong("orders writes throttled", {}, {"root_cause": "x", "evidence": []},
                                    "wrong resource", account_id="111122223333", region="us-east-1")
    last = json.loads((polluted_home / "prompt_lib" / "corrections.jsonl").read_text().splitlines()[-1])
    assert last["account"] == "xxxx3333" and last["region"] == "us-east-1"
