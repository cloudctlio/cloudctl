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
        assert any(n.startswith("aws.prod.compute:") for n in notes)
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
        from cloudctl.ai.factory import AnthropicAI, AzureFoundryAI, VertexAI
        for cls in (AnthropicAI, VertexAI, AzureFoundryAI):
            obj = self._anthropic_like(cls)
            with patch("cloudctl.ai.factory._anthropic_sdk_major", return_value=0):
                assert obj._invoke("p", system="S", temperature=0) == "ok"
            kw = obj._client.messages.create.call_args.kwargs
            # extra_body, not the keyword: anthropic 1.x removed the keyword
            assert kw["system"] == "S" and kw["extra_body"] == {"temperature": 0}
            assert "temperature" not in kw

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
        f = DebugFetcher(session)
        f._CT_PAGE_DELAY = 0
        f._BACKOFF_BASE = 0
        return f

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

    def test_cloudwatch_logs_single_page_reads_whole_window(self):
        logs = MagicMock()
        logs.filter_log_events.return_value = {"events": [{"timestamp": 0, "message": "a"}], "nextToken": "t"}
        self._fetcher(logs).cloudwatch_logs("lg", minutes=60, max_pages=1)
        assert logs.filter_log_events.call_count == 1
        kw = logs.filter_log_events.call_args.kwargs
        assert kw["endTime"] - kw["startTime"] == 60 * 60 * 1000

    def test_cloudwatch_logs_reads_newest_slice_first(self):
        logs = MagicMock()
        logs.filter_log_events.return_value = {
            "events": [{"timestamp": i * 1000, "message": f"m{i}", "eventId": str(i)} for i in range(30)]}
        self._fetcher(logs).cloudwatch_logs("lg", minutes=160, max_events=30, max_pages=5)
        first = logs.filter_log_events.call_args_list[0].kwargs
        # The first call covers only the last 1/16 of the window
        assert first["endTime"] - first["startTime"] == 160 * 60 * 1000 // 16
        assert logs.filter_log_events.call_count == 1  # 30 lines already: stop

    def test_cloudwatch_logs_walks_back_and_keeps_newest(self):
        logs = MagicMock()
        logs.filter_log_events.side_effect = [
            {"events": [{"timestamp": 900_000 + i, "message": f"new{i}", "eventId": f"n{i}"} for i in range(10)]},
            {"events": [{"timestamp": 500_000 + i, "message": f"mid{i}", "eventId": f"m{i}"} for i in range(10)]},
            {"events": [{"timestamp": 100_000 + i, "message": f"old{i}", "eventId": f"o{i}"} for i in range(10)]},
        ]
        evts = self._fetcher(logs).cloudwatch_logs("lg", max_events=15, max_pages=5)
        msgs = [e["event"] for e in evts]
        assert logs.filter_log_events.call_count == 2
        assert msgs[-1] == "new9" and "old0" not in msgs and len(msgs) == 15
        assert msgs == [f"mid{i}" for i in range(5, 10)] + [f"new{i}" for i in range(10)]

    def test_cloudwatch_logs_splits_an_overfull_slice_newer_half_first(self):
        logs = MagicMock()
        logs.filter_log_events.side_effect = [
            {"events": [{"timestamp": 1, "message": "oldest-of-slice"}], "nextToken": "t"},
            {"events": [{"timestamp": 2, "message": "newer-half", "eventId": "a"}]},
        ]
        evts = self._fetcher(logs).cloudwatch_logs("lg", max_events=1, max_pages=5)
        calls = logs.filter_log_events.call_args_list
        assert calls[1].kwargs["endTime"] == calls[0].kwargs["endTime"]
        assert calls[1].kwargs["startTime"] > calls[0].kwargs["startTime"]
        assert [e["event"] for e in evts] == ["newer-half"]

    def test_cloudwatch_logs_keeps_lines_when_a_later_call_fails(self):
        logs = MagicMock()
        logs.filter_log_events.side_effect = [
            {"events": [{"timestamp": 5, "message": "kept", "eventId": "k"}]},
            RuntimeError("boom"),
        ]
        f = self._fetcher(logs)
        evts = f.cloudwatch_logs("lg", max_events=10, max_pages=5)
        assert [e["event"] for e in evts] == ["kept"]
        assert "older lines missing" in f.errors["cloudwatch_logs:lg"]

    def test_cloudtrail_pauses_between_pages(self):
        ct = MagicMock()
        ct.lookup_events.side_effect = [
            {"Events": [_ct_event("PutRolePolicy", "r")], "NextToken": "t1"},
            {"Events": [_ct_event("UpdateService", "s")]},
        ]
        f = self._fetcher(ct)
        f._CT_PAGE_DELAY = 0.25
        with patch("cloudctl.debug.fetcher.time.sleep") as sleep:
            f.cloudtrail(minutes=60, writes_only=True, max_events=100)
        sleep.assert_called_once_with(0.25)

    def test_cloudtrail_retries_a_throttled_page(self):
        ct = MagicMock()
        ct.lookup_events.side_effect = [
            {"Events": [_ct_event("PutRolePolicy", "r")], "NextToken": "t1"},
            _throttle(),
            {"Events": [_ct_event("UpdateService", "s")]},
        ]
        f = self._fetcher(ct)
        evts = f.cloudtrail(minutes=60, writes_only=True, max_events=100)
        assert [e["event"] for e in evts] == ["PutRolePolicy", "UpdateService"]
        assert "cloudtrail" not in f.errors

    def test_cloudtrail_keeps_earlier_pages_when_throttling_persists(self):
        ct = MagicMock()
        ct.lookup_events.side_effect = [
            {"Events": [_ct_event("PutRolePolicy", "r")], "NextToken": "t1"},
        ] + [_throttle()] * 10
        f = self._fetcher(ct)
        evts = f.cloudtrail(minutes=60, writes_only=True, max_events=100)
        assert [e["event"] for e in evts] == ["PutRolePolicy"]
        assert f.availability["cloudtrail"] is True
        assert f.errors["cloudtrail"].startswith("ThrottlingException after 1 page(s)")

    def test_cloudtrail_first_page_failure_is_recorded(self):
        ct = MagicMock()
        ct.lookup_events.side_effect = [_throttle()] * 10
        f = self._fetcher(ct)
        assert f.cloudtrail(minutes=60) == []
        assert f.availability["cloudtrail"] is False
        assert f.errors["cloudtrail"] == "ThrottlingException"


def _throttle():
    from botocore.exceptions import ClientError
    return ClientError({"Error": {"Code": "ThrottlingException", "Message": "Rate exceeded"}},
                       "LookupEvents")


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


# ── Review fixes: dedup and budget must not lose real data ────────────────────

class TestDedupKeepsResourceAttributes:
    def test_env_vars_with_the_same_name_survive(self):
        ctx = {"aws": {"prod": {"compute": [
            {"name": "fn-a", "env": [{"name": "DB_HOST", "value": "a.db"}]},
            {"name": "fn-b", "env": [{"name": "DB_HOST", "value": "b.db"}]},
        ]}}}
        context_shaper.dedup_nested(ctx)
        fns = ctx["aws"]["prod"]["compute"]
        assert [f["env"][0]["value"] for f in fns] == ["a.db", "b.db"]

    def test_same_name_in_different_lists_is_not_a_duplicate(self):
        ctx = {"aws": {"prod": {
            "compute": [{"name": "api", "type": "lambda"}],
            "network": [{"name": "api", "type": "alb"}],
        }}}
        context_shaper.dedup_nested(ctx)
        assert ctx["aws"]["prod"]["network"] == [{"name": "api", "type": "alb"}]

    def test_same_name_in_two_accounts_is_kept(self):
        ctx = {"aws": {
            "acct-a": {"compute": [{"name": "worker", "state": "running"}]},
            "acct-b": {"compute": [{"name": "worker", "state": "stopped"}]},
        }}
        context_shaper.dedup_nested(ctx)
        assert ctx["aws"]["acct-b"]["compute"] == [{"name": "worker", "state": "stopped"}]

    def test_identical_name_only_copies_and_same_arn_are_dropped(self):
        ctx = {"aws": {
            "p1": {"compute": [{"name": "w", "state": "running"}, {"arn": "arn:x", "state": "ok"}]},
            "p2": {"compute": [{"name": "w", "state": "running"}, {"arn": "arn:x", "state": "ok"}]},
        }}
        context_shaper.dedup_nested(ctx)
        assert ctx["aws"]["p2"]["compute"] == []

    def test_does_not_recurse_into_a_resource(self):
        ctx = {"aws": {"p": {"compute": [
            {"arn": "arn:svc-1", "containers": [{"name": "app"}, {"name": "app"}]},
        ]}}}
        context_shaper.dedup_nested(ctx)
        assert len(ctx["aws"]["p"]["compute"][0]["containers"]) == 2


class TestBudgetTrimsInsideSections:
    def _inventory(self, n=200):
        return {"aws": {"prod": {
            "compute": [{"name": f"i{i}", "pad": "y" * 50} for i in range(n)],
            "database": [{"name": f"d{i}"} for i in range(20)],
        }}}

    def test_barely_over_budget_loses_a_few_items_not_the_section(self):
        ctx = self._inventory()
        limit = len(context_shaper.serialize(ctx)) - 10
        notes = context_shaper.fit_to_budget(ctx, max_chars=limit)
        assert "_summary" not in ctx["aws"]
        assert len(ctx["aws"]["prod"]["compute"]) == 199
        assert len(ctx["aws"]["prod"]["database"]) == 20
        assert notes == ["aws.prod.compute: kept 199 of 200 items to fit the size budget"]
        assert len(context_shaper.serialize(ctx)) <= limit

    def test_largest_inner_list_is_trimmed_first(self):
        ctx = self._inventory()
        context_shaper.fit_to_budget(ctx, max_chars=len(context_shaper.serialize(ctx)) - 2000)
        assert len(ctx["aws"]["prod"]["database"]) == 20

    def test_section_is_summarised_only_as_a_last_resort(self):
        ctx = {"aws": {"prod": {"account": "x" * 5000}}, "audit_logs": [{"event": "e"}]}
        notes = context_shaper.fit_to_budget(ctx, max_chars=200)
        assert ctx["aws"] == {"_summary": "aws omitted to fit the size budget"}
        assert "aws: omitted to fit the size budget" in notes

    def test_unknown_keys_outrank_the_inventory(self):
        assert context_shaper._ordered_keys({"aws": 1, "mystery": 1, "service_logs": 1}) \
            == ["service_logs", "mystery", "aws"]
        ctx = {"mystery": [{"event": f"e{i}"} for i in range(10)], **self._inventory()}
        context_shaper.fit_to_budget(ctx, max_chars=len(context_shaper.serialize(ctx)) - 500)
        assert len(ctx["mystery"]) == 10


# ── Review fixes: audit window and fetch errors in the provider ───────────────

class TestProviderAudit:
    def _run(self, fetcher, minutes=45):
        from cloudctl.providers.aws.provider import AWSProvider
        prov = AWSProvider.__new__(AWSProvider)
        prov._session = MagicMock()
        ctx: dict = {}
        with patch("cloudctl.debug.fetcher.DebugFetcher", return_value=fetcher), \
             patch("cloudctl.debug.planner.plan_sources", return_value=["audit_logs"]), \
             patch("cloudctl.debug.planner.extract_service_hints", return_value=[]):
            try:
                prov.fetch_debug_context("orders erroring", [], ctx, minutes=minutes)
            except Exception:  # noqa: BLE001, S110
                pass  # later fetches on the mock are not under test
        return ctx

    def _fetcher(self, writes, recent, errors=None):
        f = MagicMock()
        f.cloudtrail.side_effect = [writes, recent]
        f.errors = errors or {}
        f.acm_certificates.return_value = {}
        return f

    def test_respects_the_callers_window_and_keeps_failed_reads(self):
        write = {"time": "2026-11-10T10:00:00Z", "event": "PutRolePolicy", "principal": "d",
                 "resource": "r", "error_code": ""}
        denied = {"time": "2026-11-10T10:05:00Z", "event": "GetSecretValue", "principal": "app",
                  "resource": "s", "error_code": "AccessDenied"}
        ok_read = {"time": "2026-11-10T10:06:00Z", "event": "DescribeInstances", "principal": "x",
                   "resource": "", "error_code": ""}
        f = self._fetcher([write], [ok_read, denied, write])
        ctx = self._run(f, minutes=45)
        calls = f.cloudtrail.call_args_list
        assert all(c.kwargs["minutes"] == 45 for c in calls)
        assert calls[0].kwargs.get("writes_only") is True and not calls[1].kwargs.get("writes_only")
        assert [e["event"] for e in ctx["audit_logs"]] == ["GetSecretValue", "PutRolePolicy"]

    def test_fetch_errors_reach_the_context(self):
        f = self._fetcher([], [], errors={"cloudtrail": "ThrottlingException after 2 page(s)"})
        ctx = self._run(f)
        assert ctx["source_errors"] == ["cloudtrail: ThrottlingException after 2 page(s)"]


# ── Review fixes: temperature only where the model and SDK accept it ──────────

class TestTemperatureGate:
    def test_models_that_reject_temperature(self):
        from cloudctl.ai.factory import _claude_accepts_temperature as ok
        for m in ("us.anthropic.claude-opus-4-7-v1:0", "claude-opus-4-8", "claude-opus-5-5",
                  "claude-sonnet-5", "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-2",
                  "claude-opus-4-7@20260101"):
            assert not ok(m), m
        for m in ("us.anthropic.claude-sonnet-4-6", "us.anthropic.claude-sonnet-4-20250514-v1:0",
                  "us.anthropic.claude-haiku-4-5-20251001-v1:0", "claude-opus-4-6@20260101",
                  "claude-sonnet-4-5", "claude-opus-4-20250514", "m"):
            assert ok(m), m

    def test_bedrock_omits_temperature_for_newer_models(self):
        from cloudctl.ai.factory import BedrockAI
        obj = BedrockAI.__new__(BedrockAI)
        obj._model, obj._region, obj._profile = "us.anthropic.claude-opus-4-7-v1:0", "us-east-1", None
        client = MagicMock()
        client.invoke_model.return_value = {"body": MagicMock(read=lambda: json.dumps(
            {"content": [{"text": "ok"}]}).encode())}
        with patch("boto3.Session") as sess:
            sess.return_value.client.return_value = client
            obj._invoke("p", temperature=0)
        assert "temperature" not in json.loads(client.invoke_model.call_args.kwargs["body"])

    def test_sdk_providers_by_sdk_version(self):
        from cloudctl.ai.factory import _claude_sdk_temperature_kwargs as kw
        with patch("cloudctl.ai.factory._anthropic_sdk_major", return_value=1):
            assert kw(0, "claude-sonnet-4-6") == {"extra_body": {"temperature": 0}}
            assert kw(0, "claude-opus-5-5") == {}
            assert kw(None, "claude-sonnet-4-6") == {}
        with patch("cloudctl.ai.factory._anthropic_sdk_major", return_value=2):
            assert kw(0, "claude-sonnet-4-6") == {}  # API 2026-10-21 rejects it on every model

