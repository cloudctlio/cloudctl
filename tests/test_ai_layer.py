"""Tests for AI layer — confidence scoring, prompt builders, factory helpers."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest


# ── confidence.py — pure logic, zero mocking ──────────────────────────────────

class TestConfidenceScore:
    def test_empty_data_is_low(self):
        from cloudctl.ai.confidence import score
        result = score({})
        assert result.level == "LOW"
        assert "No cloud data" in result.reason

    def test_full_data_is_high(self):
        # HIGH requires score >= 5: 4+ sources (+3) + inflection (+2) = 5
        from cloudctl.ai.confidence import score
        result = score(
            {
                "compute":  [{"id": "i-1"}],
                "storage":  [{"name": "b1"}],
                "security": [{"finding": "x"}],
                "database": [{"id": "db-1"}],
            },
            expected_accounts=1,
            has_inflection=True,
        )
        assert result.level == "HIGH"

    def test_missing_required_key_is_low(self):
        # 1 source covered → score penalty → LOW; missing key surfaced in reasons
        from cloudctl.ai.confidence import score
        result = score(
            {"compute": [{"id": "i-1"}]},
            required_keys=["compute", "security"],
        )
        assert result.level == "LOW"
        assert any("security" in r for r in result.reasons)

    def test_zero_data_points_is_low(self):
        from cloudctl.ai.confidence import score
        result = score({"compute": [], "storage": []})
        assert result.level == "LOW"

    def test_partial_accounts_reflected_in_label(self):
        # expected_accounts is stored in accounts_total and shown in label
        from cloudctl.ai.confidence import score
        result = score(
            {"compute": [{"id": "i-1"}]},
            expected_accounts=3,
        )
        assert "1/3" in result.label

    def test_low_historical_accuracy_is_low(self):
        from cloudctl.ai.confidence import score
        result = score(
            {"compute": [{"id": "i-1"}]},
            historical_accuracy=0.3,
        )
        assert result.level == "LOW"
        assert any("30%" in r for r in result.reasons)

    def test_medium_historical_accuracy_reduces_score(self):
        # 0.5–0.8 accuracy is neutral (no score adjustment); 1 source alone is LOW
        from cloudctl.ai.confidence import score
        result = score(
            {"compute": [{"id": "i-1"}]},
            historical_accuracy=0.65,
        )
        assert result.level == "LOW"

    def test_high_historical_accuracy_boosts_score(self):
        # 4+ sources (+3) + inflection (+2) + high accuracy (+1) = 6 → HIGH
        from cloudctl.ai.confidence import score
        result = score(
            {
                "compute":  [{"id": "i-1"}],
                "storage":  [{"name": "b1"}],
                "security": [{"finding": "x"}],
                "database": [{"id": "db-1"}],
            },
            historical_accuracy=0.95,
            expected_accounts=1,
            has_inflection=True,
        )
        assert result.level == "HIGH"

    def test_label_contains_confidence_level(self):
        from cloudctl.ai.confidence import score
        result = score({"compute": [{"id": "i-1"}]}, expected_accounts=1)
        assert "HIGH" in result.label or "MEDIUM" in result.label or "LOW" in result.label

    def test_label_includes_sources(self):
        from cloudctl.ai.confidence import score
        result = score({"compute": [{"id": "i-1"}]}, expected_accounts=1)
        assert "compute" in result.label

    def test_count_items_nested_dict(self):
        from cloudctl.ai.confidence import _count_items
        assert _count_items({"a": [1, 2], "b": [3]}) == 3

    def test_count_items_list(self):
        from cloudctl.ai.confidence import _count_items
        assert _count_items([1, 2, 3]) == 3

    def test_count_items_empty(self):
        from cloudctl.ai.confidence import _count_items
        assert _count_items([]) == 0
        assert _count_items({}) == 0


# ── prompts/ — pure string builders ───────────────────────────────────────────

class TestSecurityPrompts:
    def test_audit_prompt_includes_account(self):
        from cloudctl.ai.prompts.security import audit_prompt
        out = audit_prompt([{"severity": "HIGH", "resource": "sg-1"}], "prod")
        assert "prod" in out
        assert "sg-1" in out

    def test_public_resources_prompt_returns_json(self):
        from cloudctl.ai.prompts.security import public_resources_prompt
        out = public_resources_prompt([{"type": "S3", "id": "my-bucket"}])
        assert "my-bucket" in out
        assert "severity" in out.lower()

    def test_fix_prompt_includes_keys(self):
        from cloudctl.ai.prompts.security import fix_prompt
        out = fix_prompt({"severity": "HIGH", "resource": "sg-1", "issue": "open"})
        assert "steps" in out
        assert "iac_note" in out


class TestCostPrompts:
    def test_summary_prompt_includes_account(self):
        from cloudctl.ai.prompts.cost import summary_prompt
        out = summary_prompt({"total": "$100"}, "prod")
        assert "prod" in out
        assert "savings" in out.lower()

    def test_anomaly_prompt_structure(self):
        from cloudctl.ai.prompts.cost import anomaly_prompt
        out = anomaly_prompt([{"service": "EC2", "expected": 50, "actual": 500}])
        assert "EC2" in out
        assert "action" in out.lower()

    def test_rightsizing_prompt(self):
        from cloudctl.ai.prompts.cost import rightsizing_prompt
        out = rightsizing_prompt([{"instance_id": "i-1", "current_type": "m5.xlarge"}])
        assert "i-1" in out
        assert "suggested_type" in out

    def test_fix_prompt_includes_keys(self):
        from cloudctl.ai.prompts.cost import fix_prompt
        out = fix_prompt({"issue": "High EC2 spend", "resource": "ec2"})
        assert "steps" in out
        assert "iac_note" in out


class TestPipelinePrompts:
    def test_failure_prompt(self):
        from cloudctl.ai.prompts.pipeline import failure_prompt
        out = failure_prompt({"stages": [{"name": "build", "status": "FAILED"}]}, "deploy-prod")
        assert "deploy-prod" in out
        assert "root_cause" in out

    def test_slow_pipeline_prompt(self):
        from cloudctl.ai.prompts.pipeline import slow_pipeline_prompt
        out = slow_pipeline_prompt({"stages": [{"name": "test", "duration": 600}]})
        assert "optimization" in out.lower()


class TestGeneralPrompts:
    def test_question_prompt_includes_data(self):
        from cloudctl.ai.prompts.general import question_prompt
        out = question_prompt("which instances are idle?", {"compute": [{"id": "i-1"}]})
        assert "which instances are idle?" in out
        assert "i-1" in out

    def test_summarize_prompt(self):
        from cloudctl.ai.prompts.general import summarize_prompt
        out = summarize_prompt({"compute": [{"id": "i-1"}]}, focus="cost")
        assert "cost" in out
        assert "concerns" in out

    def test_compare_prompt(self):
        from cloudctl.ai.prompts.general import compare_prompt
        out = compare_prompt({"compute": 3}, {"compute": 5}, "prod", "staging")
        assert "PROD" in out
        assert "STAGING" in out
        assert "only_in_left" in out


# ── ai/factory.py — helpers ────────────────────────────────────────────────────

class TestAIFactoryHelpers:
    def _cfg(self, **settings):
        cfg = MagicMock()
        cfg.get = lambda key, default=None: settings.get(key, default)
        cfg.clouds = list(settings.get("clouds", ["aws"]))
        return cfg

    def test_is_ai_configured_none(self):
        from cloudctl.ai.factory import is_ai_configured
        assert not is_ai_configured(self._cfg(**{"ai.provider": "none"}))

    def test_is_ai_configured_empty(self):
        from cloudctl.ai.factory import is_ai_configured
        assert not is_ai_configured(self._cfg())

    def test_is_ai_configured_bedrock(self):
        from cloudctl.ai.factory import is_ai_configured
        assert is_ai_configured(self._cfg(**{"ai.provider": "bedrock"}))

    def test_is_ai_configured_openai(self):
        from cloudctl.ai.factory import is_ai_configured
        assert is_ai_configured(self._cfg(**{"ai.provider": "openai"}))

    def test_is_ai_configured_auto_with_aws(self):
        from cloudctl.ai.factory import is_ai_configured
        cfg = self._cfg(**{"ai.provider": "auto", "clouds": ["aws"]})
        assert is_ai_configured(cfg)

    def test_is_ai_configured_auto_no_clouds(self):
        from cloudctl.ai.factory import is_ai_configured
        cfg = self._cfg(**{"ai.provider": "auto", "clouds": []})
        assert not is_ai_configured(cfg)

    def test_auto_detect_aws_returns_bedrock(self):
        from cloudctl.ai.factory import _auto_detect_provider
        cfg = MagicMock()
        cfg.clouds = ["aws"]
        assert _auto_detect_provider(cfg) == "bedrock"

    def test_auto_detect_gcp_returns_vertex(self):
        from cloudctl.ai.factory import _auto_detect_provider
        cfg = MagicMock()
        cfg.clouds = ["gcp"]
        assert _auto_detect_provider(cfg) == "vertex"

    def test_auto_detect_azure_returns_azure(self):
        from cloudctl.ai.factory import _auto_detect_provider
        cfg = MagicMock()
        cfg.clouds = ["azure"]
        assert _auto_detect_provider(cfg) == "azure"

    def test_auto_detect_aws_beats_gcp(self):
        from cloudctl.ai.factory import _auto_detect_provider
        cfg = MagicMock()
        cfg.clouds = ["gcp", "aws"]
        assert _auto_detect_provider(cfg) == "bedrock"

    def test_auto_detect_no_clouds_returns_none(self):
        from cloudctl.ai.factory import _auto_detect_provider
        cfg = MagicMock()
        cfg.clouds = []
        assert _auto_detect_provider(cfg) is None

    def test_get_ai_status_bedrock(self):
        from cloudctl.ai.factory import get_ai_status
        cfg = self._cfg(**{"ai.provider": "bedrock", "ai.tier": "sonnet", "ai.bedrock_region": "us-east-1"})
        status = get_ai_status(cfg)
        assert status["provider"] == "bedrock"
        assert status["region"] == "us-east-1"

    def test_get_ai_status_masks_api_key(self):
        from cloudctl.ai.factory import get_ai_status
        cfg = self._cfg(**{
            "ai.provider": "anthropic",
            "ai.anthropic_api_key": "sk-ant-1234567890abcdef",
        })
        status = get_ai_status(cfg)
        assert "sk-a" in status["api_key"]
        assert "cdef" in status["api_key"]
        assert "1234567890" not in status["api_key"]

    def test_get_ai_status_short_key_masked(self):
        from cloudctl.ai.factory import get_ai_status
        cfg = self._cfg(**{"ai.provider": "anthropic", "ai.anthropic_api_key": "short"})
        status = get_ai_status(cfg)
        assert status["api_key"] == "***"

    def test_get_ai_status_ollama(self):
        from cloudctl.ai.factory import get_ai_status
        cfg = self._cfg(**{
            "ai.provider": "ollama",
            "ai.ollama_host": "http://localhost:11434",
            "ai.ollama_model": "llama3",
        })
        status = get_ai_status(cfg)
        assert status["host"] == "http://localhost:11434"
        assert status["model"] == "llama3"

    def test_get_ai_unknown_provider_raises(self):
        from cloudctl.ai.factory import get_ai
        cfg = self._cfg(**{"ai.provider": "unknown_xyz"})
        with pytest.raises(ValueError, match="not supported"):
            get_ai(cfg)

    def test_parse_json_response_clean(self):
        from cloudctl.ai.factory import _parse_json_response
        result = _parse_json_response('{"key": "value"}')
        assert result == {"key": "value"}

    def test_parse_json_response_strips_fences(self):
        from cloudctl.ai.factory import _parse_json_response
        result = _parse_json_response('```json\n{"key": "value"}\n```')
        assert result == {"key": "value"}

    def test_parse_json_response_invalid_returns_raw(self):
        from cloudctl.ai.factory import _parse_json_response
        result = _parse_json_response("not json at all")
        assert "raw" in result


# ── ai/context.py ─────────────────────────────────────────────────────────────

class TestContextTrim:
    def test_trim_truncates_long_lists(self):
        from cloudctl.ai.context import trim_context
        ctx = {"compute": list(range(100))}
        result = trim_context(ctx, max_items_per_key=10)
        assert len(result["compute"]) == 10
        assert result["_compute_truncated"] == 90

    def test_trim_short_list_unchanged(self):
        from cloudctl.ai.context import trim_context
        ctx = {"compute": [1, 2, 3]}
        result = trim_context(ctx, max_items_per_key=10)
        assert result["compute"] == [1, 2, 3]
        assert "_compute_truncated" not in result

    def test_trim_nested_dict(self):
        from cloudctl.ai.context import trim_context
        ctx = {"aws": {"compute": list(range(100))}}
        result = trim_context(ctx, max_items_per_key=5)
        assert len(result["aws"]["compute"]) == 5

    def test_trim_preserves_scalars(self):
        from cloudctl.ai.context import trim_context
        ctx = {"total_cost": "$100", "accounts": 3}
        result = trim_context(ctx)
        assert result["total_cost"] == "$100"
        assert result["accounts"] == 3


# ── ai_cmd.py CLI ─────────────────────────────────────────────────────────────

class TestAICmdStatus:
    """
    ai_cmd imports helpers inline (inside functions), so patch at the factory
    module level rather than as attributes on ai_cmd.
    """

    def test_status_not_configured(self):
        from typer.testing import CliRunner
        from cloudctl.main import app
        runner = CliRunner()
        cfg = MagicMock()
        cfg.is_initialized = True

        with patch("cloudctl.commands.ai_cmd.require_init", return_value=cfg), \
             patch("cloudctl.ai.factory.is_ai_configured", return_value=False):
            result = runner.invoke(app, ["ai", "status"])
        assert result.exit_code == 0

    def test_status_configured(self):
        from typer.testing import CliRunner
        from cloudctl.main import app
        runner = CliRunner()
        cfg = MagicMock()
        cfg.is_initialized = True

        with patch("cloudctl.commands.ai_cmd.require_init", return_value=cfg), \
             patch("cloudctl.ai.factory.is_ai_configured", return_value=True), \
             patch("cloudctl.ai.factory.get_ai_status", return_value={"provider": "bedrock", "tier": "sonnet"}):
            result = runner.invoke(app, ["ai", "status"])
        assert result.exit_code == 0
        assert "bedrock" in result.output

    def test_ask_without_ai_exits_1(self):
        from typer.testing import CliRunner
        from cloudctl.main import app
        runner = CliRunner()
        cfg = MagicMock()
        cfg.is_initialized = True

        # _get_ai raises typer.Exit(1) when AI is not configured
        import typer as _typer
        with patch("cloudctl.commands.ai_cmd.require_init", return_value=cfg), \
             patch("cloudctl.commands.ai_cmd._get_ai", side_effect=_typer.Exit(1)):
            result = runner.invoke(app, ["ai", "ask", "which instances are running?"])
        assert result.exit_code == 1

    def test_ask_with_ai_calls_ask_method(self):
        from typer.testing import CliRunner
        from cloudctl.main import app
        runner = CliRunner()
        cfg = MagicMock()
        cfg.is_initialized = True

        mock_ai = MagicMock()
        mock_ai.ask.return_value = {
            "answer": "You have 3 running instances.",
            "confidence": "HIGH",
            "sources": ["CloudWatch"],
        }

        with patch("cloudctl.commands.ai_cmd.require_init", return_value=cfg), \
             patch("cloudctl.commands.ai_cmd._get_ai", return_value=mock_ai), \
             patch("cloudctl.commands.ai_cmd._fetch_context", return_value={}):
            result = runner.invoke(app, ["ai", "ask", "which instances are running?"])
        assert result.exit_code == 0
        assert "3 running instances" in result.output

    def test_models_not_supported(self):
        from typer.testing import CliRunner
        from cloudctl.main import app
        runner = CliRunner()
        cfg = MagicMock()
        cfg.is_initialized = True

        mock_ai = MagicMock(spec=[])  # spec=[] means no list_models attribute
        with patch("cloudctl.commands.ai_cmd.require_init", return_value=cfg), \
             patch("cloudctl.commands.ai_cmd._get_ai", return_value=mock_ai):
            result = runner.invoke(app, ["ai", "models"])
        assert result.exit_code == 0
        assert "not supported" in result.output
