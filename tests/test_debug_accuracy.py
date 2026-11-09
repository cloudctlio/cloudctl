"""Accuracy fixes for cloudctl debug: what reaches the model, and what the
agent's grounding checks can see.

Default path (DebugEngine):
  - dedup no longer collapses log lines / CloudTrail events that share a source
  - pruning and dedup walk the nested inventory
  - a size budget trims the lowest-priority data first and says so
  - every AI provider accepts system= and temperature=; debug uses 0
  - CloudTrail can ask for write events only; logs can paginate

Agent mode (graph_agent):
  - each distinct tool call keeps its own entry in the fetched-data corpus
  - branch tool-use loops run at temperature 0
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from cloudctl.ai.debug_engine import DebugEngine
from cloudctl.debug import context_shaper

# ── Default path: dedup / prune / budget ──────────────────────────────────────

def _provider_style_context() -> dict:
    """Context shaped like AwsProvider.fetch_debug_context output."""
    return {
        "aws": {
            "prod": {
                "compute": [
                    {"name": f"svc-{i}", "id": f"i-{i:04d}", "state": "running"} for i in range(40)
                ] + [{"name": "orders-api", "id": "i-dead", "state": "stopped"}],
            },
            "prod-readonly": {
                # The same instance seen through a second profile
                "compute": [{"name": "svc-0", "id": "i-0000", "state": "running"}],
            },
        },
        "audit_logs": [
            {"time": f"2026-11-09T10:0{i}:00Z", "source": "CloudTrail",
             "event": e, "principal": "deployer", "resource": "orders-api", "error_code": ""}
            for i, e in enumerate(["UpdateFunctionConfiguration", "PutRolePolicy",
                                   "AuthorizeSecurityGroupIngress", "UpdateService"])
        ],
        "service_logs": [
            {"time": f"2026-11-09T10:{i:02d}:00Z", "source": "CloudWatch/Logs//aws/lambda/orders",
             "event": f"ERROR line {i}"}
            for i in range(30)
        ],
    }


class TestDedup:
    def test_keeps_every_cloudtrail_event_and_log_line(self):
        ctx = _provider_style_context()
        DebugEngine._dedup_arns(ctx)
        assert len(ctx["audit_logs"]) == 4
        assert len(ctx["service_logs"]) == 30

    def test_still_drops_a_resource_seen_under_two_profiles(self):
        ctx = _provider_style_context()
        DebugEngine._dedup_arns(ctx)
        assert ctx["aws"]["prod-readonly"]["compute"] == []

    def test_old_behaviour_reference(self):
        """Documents the bug: keying on 'source' kept one event per source."""
        ctx = _provider_style_context()
        seen, kept = set(), []
        for item in ctx["service_logs"]:
            k = item.get("arn") or item.get("id") or item.get("name") or item.get("source")
            if k in seen:
                continue
            seen.add(k)
            kept.append(item)
        assert len(kept) == 1


class TestPrune:
    def test_prunes_nested_compute_and_keeps_unhealthy(self):
        ctx = _provider_style_context()
        DebugEngine._prune_context(ctx)
        compute = ctx["aws"]["prod"]["compute"]
        names = [c.get("name") for c in compute]
        assert "orders-api" in names
        assert len(compute) == 1 + 3 + 1  # unhealthy + 3 healthy + summary
        assert "additional healthy compute" in compute[-1]["_summary"]


class TestBudget:
    def test_under_budget_is_untouched(self):
        ctx = _provider_style_context()
        before = json.dumps(ctx, sort_keys=True)
        assert context_shaper.fit_to_budget(ctx, max_chars=10**7) == []
        assert json.dumps(ctx, sort_keys=True) == before

    def test_trims_inventory_before_logs_and_keeps_newest_logs(self):
        ctx = _provider_style_context()
        ctx["aws"]["prod"]["compute"] = [
            {"name": f"svc-{i}", "id": f"i-{i}", "state": "stopped", "pad": "x" * 200}
            for i in range(200)
        ]
        size_without_inventory = len(context_shaper.serialize({**ctx, "aws": {}}))
        notes = context_shaper.fit_to_budget(ctx, max_chars=size_without_inventory + 500)
        assert any(n.startswith("aws:") for n in notes)
        assert len(ctx["service_logs"]) == 30
        assert len(ctx["audit_logs"]) == 4

    def test_logs_keep_the_tail_when_trimmed(self):
        ctx = {"service_logs": [{"source": "s", "event": f"line {i}", "pad": "y" * 100} for i in range(100)]}
        context_shaper.fit_to_budget(ctx, max_chars=3000)
        assert ctx["service_logs"][-1]["event"] == "line 99"
        assert len(ctx["service_logs"]) < 100


class TestDebugPrompt:
    def test_accepts_serialized_context_and_budget_notes(self):
        from cloudctl.ai.prompts.debug import debug_prompt
        p = debug_prompt("502s", '{"a":1}', budget_notes=["aws: omitted to fit the size budget"])
        assert '{"a":1}' in p
        assert "absence below is not evidence" in p
        assert "aws: omitted" in p

    def test_dict_context_still_works(self):
        from cloudctl.ai.prompts.debug import debug_prompt
        p = debug_prompt("502s", {"a": 1})
        assert '"a": 1' in p
        assert "LEFT OUT" not in p


class TestEngineCallsModelDeterministically:
    def test_debug_uses_temperature_zero_and_shaped_context(self):
        cfg = MagicMock()
        engine = DebugEngine.__new__(DebugEngine)
        engine._cfg = cfg
        engine._fetcher = MagicMock()
        engine._fetcher.fetch_summary.return_value = _provider_style_context()
        ai = MagicMock()
        ai._invoke.return_value = json.dumps({
            "root_cause": "x", "affected_resources": [], "remediation_steps": [],
            "confidence_notes": "",
        })
        with patch.object(DebugEngine, "_fetch_symptom_context"), \
             patch.object(DebugEngine, "_detect_deployment_method", return_value=None), \
             patch("cloudctl.ai.factory.get_ai", return_value=ai), \
             patch("cloudctl.ai.factory.is_ai_configured", return_value=True):
            engine.debug("orders api erroring", cloud="aws")
        kwargs = ai._invoke.call_args.kwargs
        prompt = ai._invoke.call_args.args[0]
        assert kwargs["temperature"] == 0
        assert "ERROR line 29" in prompt and "ERROR line 0" in prompt
        assert "PutRolePolicy" in prompt


# ── Providers accept system= and temperature= ─────────────────────────────────

class TestProviders:
    def _anthropic_like(self, cls):
        obj = cls.__new__(cls)
        obj._model = "m"
        obj._client = MagicMock()
        obj._client.messages.create.return_value.content = [MagicMock(text="ok")]
        return obj

    def test_anthropic_style_providers(self):
        from cloudctl.ai.factory import AnthropicAI, VertexAI
        for cls in (AnthropicAI, VertexAI):
            obj = self._anthropic_like(cls)
            assert obj._invoke("p", system="S", temperature=0) == "ok"
            kw = obj._client.messages.create.call_args.kwargs
            assert kw["system"] == "S" and kw["temperature"] == 0

    def test_default_call_leaves_provider_defaults(self):
        from cloudctl.ai.factory import _SYSTEM_PROMPT, AnthropicAI
        obj = self._anthropic_like(AnthropicAI)
        obj._invoke("p")
        kw = obj._client.messages.create.call_args.kwargs
        assert kw["system"] == _SYSTEM_PROMPT and "temperature" not in kw

    def test_openai(self):
        from cloudctl.ai.factory import OpenAIProvider
        obj = OpenAIProvider.__new__(OpenAIProvider)
        obj._model = "m"
        obj._client = MagicMock()
        obj._client.chat.completions.create.return_value.choices = [MagicMock(message=MagicMock(content="ok"))]
        obj._invoke("p", system="S", temperature=0)
        kw = obj._client.chat.completions.create.call_args.kwargs
        assert kw["messages"][0]["content"] == "S" and kw["temperature"] == 0

    def test_ollama(self):
        from cloudctl.ai.factory import OllamaAI
        obj = OllamaAI.__new__(OllamaAI)
        obj._host, obj._model = "http://x", "m"
        obj._session = MagicMock()
        obj._session.post.return_value.json.return_value = {"response": "ok"}
        assert obj._invoke("p", system="S", temperature=0) == "ok"
        body = obj._session.post.call_args.kwargs["json"]
        assert body["prompt"].startswith("S") and body["options"]["temperature"] == 0

    def test_bedrock_body_has_temperature(self):
        from cloudctl.ai.factory import BedrockAI
        obj = BedrockAI.__new__(BedrockAI)
        obj._model, obj._region, obj._profile = "m", "us-east-1", None
        client = MagicMock()
        client.invoke_model.return_value = {"body": MagicMock(read=lambda: json.dumps(
            {"content": [{"text": "ok"}]}).encode())}
        with patch("boto3.Session") as sess:
            sess.return_value.client.return_value = client
            assert obj._invoke("p", system="S", temperature=0) == "ok"
        body = json.loads(client.invoke_model.call_args.kwargs["body"])
        assert body["temperature"] == 0 and body["system"] == "S"


# ── Fetcher: CloudTrail writes-only, log pagination ───────────────────────────

def _ct_event(name: str, resource: str) -> dict:
    return {"EventTime": datetime(2026, 11, 9, tzinfo=UTC), "EventName": name,
            "Username": "u", "Resources": [{"ResourceName": resource}]}


class TestFetcher:
    def _fetcher(self, client):
        from cloudctl.debug.fetcher import DebugFetcher
        session = MagicMock()
        session.client.return_value = client
        return DebugFetcher(session)

    def test_cloudtrail_default_is_one_call_of_50(self):
        ct = MagicMock()
        ct.lookup_events.return_value = {"Events": [_ct_event("GetObject", "b")], "NextToken": "t"}
        self._fetcher(ct).cloudtrail(minutes=60)
        assert ct.lookup_events.call_count == 1
        assert ct.lookup_events.call_args.kwargs["MaxResults"] == 50
        assert "LookupAttributes" not in ct.lookup_events.call_args.kwargs

    def test_cloudtrail_writes_only_filters_and_paginates(self):
        ct = MagicMock()
        ct.lookup_events.side_effect = [
            {"Events": [_ct_event("PutRolePolicy", "orders-role"), _ct_event("UpdateService", "other")],
             "NextToken": "t1"},
            {"Events": [_ct_event("UpdateFunctionConfiguration", "orders-fn")]},
        ]
        evts = self._fetcher(ct).cloudtrail(minutes=60, writes_only=True, resource_name="orders",
                                            max_events=100)
        first = ct.lookup_events.call_args_list[0].kwargs
        assert first["LookupAttributes"] == [{"AttributeKey": "ReadOnly", "AttributeValue": "false"}]
        assert ct.lookup_events.call_args_list[1].kwargs["NextToken"] == "t1"
        assert [e["event"] for e in evts] == ["PutRolePolicy", "UpdateFunctionConfiguration"]

    def test_cloudwatch_logs_default_single_page(self):
        logs = MagicMock()
        logs.filter_log_events.return_value = {"events": [{"timestamp": 0, "message": "a"}], "nextToken": "t"}
        self._fetcher(logs).cloudwatch_logs("lg")
        assert logs.filter_log_events.call_count == 1

    def test_cloudwatch_logs_paginates_and_keeps_newest(self):
        logs = MagicMock()
        logs.filter_log_events.side_effect = [
            {"events": [{"timestamp": i * 1000, "message": f"m{i}"} for i in range(30)], "nextToken": "t1"},
            {"events": [{"timestamp": i * 1000, "message": f"m{i}"} for i in range(30, 60)]},
        ]
        evts = self._fetcher(logs).cloudwatch_logs("lg", max_events=40, max_pages=5)
        assert logs.filter_log_events.call_count == 2
        assert len(evts) == 40 and evts[-1]["event"] == "m59" and evts[0]["event"] == "m20"


# ── Agent mode: fetched-data keys and branch determinism ──────────────────────

class TestFetchedKey:
    def test_distinct_metric_queries_get_distinct_keys(self):
        from cloudctl.mcp.tools.debug import _fetched_key
        a = _fetched_key("query_metrics", {"namespace": "AWS/Lambda", "metric_name": "Errors"})
        b = _fetched_key("query_metrics", {"namespace": "AWS/Lambda", "metric_name": "Duration"})
        assert a != b and a.startswith("query_metrics:Errors#")

    def test_resource_only_calls_keep_their_old_key(self):
        from cloudctl.mcp.tools.debug import _fetched_key
        assert _fetched_key("get_service_config", {"service_type": "lambda", "resource_name": "fn"}) \
            == "get_service_config:fn"
        assert _fetched_key("get_deployment_info", {"resource_name": "fn", "service_type": "lambda"}) \
            .startswith("get_deployment_info")

    def test_identical_calls_share_a_key(self):
        from cloudctl.mcp.tools.debug import _fetched_key
        x = {"resource_hint": "orders", "minutes": 30}
        assert _fetched_key("tail_logs", dict(x)) == _fetched_key("tail_logs", dict(x))


def _tool_turn(*calls):
    return {"stopReason": "tool_use", "output": {"message": {"role": "assistant", "content": [
        {"toolUse": {"toolUseId": f"t{i}", "name": n, "input": inp}} for i, (n, inp) in enumerate(calls)
    ]}}}


def _final_turn(obj: dict):
    return {"stopReason": "end_turn", "output": {"message": {"role": "assistant", "content": [
        {"text": json.dumps(obj)}]}}}


class TestRunBranch:
    def _run(self):
        from cloudctl.ai import graph_agent
        turns = [
            # Phase 1: cover the mandatory tools, query two metrics
            _tool_turn(("list_resources", {"service_type": "lambda"}),
                       ("get_service_config", {"service_type": "lambda", "resource_name": "orders-api"})),
            _tool_turn(("query_metrics", {"namespace": "AWS/Lambda", "metric_name": "Errors",
                                          "dimensions": {"FunctionName": "orders-api"}})),
            _tool_turn(("query_metrics", {"namespace": "AWS/Lambda", "metric_name": "Duration",
                                          "dimensions": {"FunctionName": "orders-api"}}),
                       ("tail_logs", {"resource_hint": "orders-api"})),
            _final_turn({"conclusion": "config fine", "confirmed": False, "phase2_needed": True,
                         "confidence": "LOW", "evidence": []}),
            # Phase 2: confirm, quoting the FIRST metric query
            _final_turn({"conclusion": "errors spiked", "confirmed": True, "confidence": "HIGH",
                         "evidence": ["errors spiked"],
                         "predictions_tested": [{"if_true": "errors rise", "verdict": "CONFIRMED",
                                                 "observed": "orders-api errors 48213"}]}),
        ]
        bedrock = MagicMock()
        bedrock.converse.side_effect = turns
        metric = {
            "Errors":   json.dumps({"metric": "Errors", "resource": "orders-api", "max": 48213}),
            "Duration": json.dumps({"metric": "Duration", "resource": "orders-api", "max": 1200.5}),
        }
        hyp = {"service": "lambda", "reason": "orders-api failing", "focus": "errors",
               "predictions": [{"if_true": "errors rise", "check": "Errors metric", "if_absent": "refutes"}]}
        with patch.object(graph_agent, "_make_bedrock", return_value=bedrock), \
             patch("cloudctl.mcp.tools.debug.list_resources", return_value=json.dumps({"items": ["orders-api"]})), \
             patch("cloudctl.mcp.tools.debug.get_service_config", return_value=json.dumps({"timeout": 3})), \
             patch("cloudctl.mcp.tools.debug.query_metrics",
                   side_effect=lambda **kw: metric[kw["metric_name"]]), \
             patch("cloudctl.mcp.tools.debug.tail_logs", return_value=json.dumps({"lines": ["boom"]})), \
             patch("cloudctl.ai.guardrails.audit_log_tool_call"):
            result = graph_agent._run_branch(hyp, "orders api errors", None, "us-east-1", 30, "sess")
        return result, bedrock

    def test_both_metric_queries_stay_in_the_corpus(self):
        result, _ = self._run()
        metric_keys = [k for k in result.all_fetched if k.startswith("query_metrics:")]
        assert len(metric_keys) == 2

    def test_confirmed_prediction_quoting_earlier_data_is_not_downgraded(self):
        result, _ = self._run()
        assert result.predictions_tested[0]["verdict"] == "CONFIRMED"
        assert result.confirmed is True

    def test_branch_model_calls_use_temperature_zero(self):
        _, bedrock = self._run()
        for call in bedrock.converse.call_args_list:
            assert call.kwargs["inferenceConfig"]["temperature"] == 0
