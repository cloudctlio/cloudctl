"""Tests for cloudctl.debug package — planner, correlator, renderer, resolver."""
from __future__ import annotations

import pytest


# ─── planner ────────────────────────────────────────────────────────────────

class TestPlanner:
    def test_502_includes_alb_and_ecs(self):
        from cloudctl.debug.planner import plan_sources
        sources = plan_sources("payments returning 502s")
        assert "alb_logs" in sources
        assert "ecs_events" in sources

    def test_default_sources_always_present(self):
        from cloudctl.debug.planner import plan_sources
        sources = plan_sources("something completely unrelated xyz")
        assert "cloudwatch_metrics" in sources
        assert "cloudtrail" in sources

    def test_database_symptom(self):
        from cloudctl.debug.planner import plan_sources
        sources = plan_sources("database connection pool exhausted")
        assert "rds_events" in sources

    def test_deploy_symptom(self):
        from cloudctl.debug.planner import plan_sources
        sources = plan_sources("after the deploy things broke")
        assert "codepipeline" in sources

    def test_permission_symptom(self):
        from cloudctl.debug.planner import plan_sources
        sources = plan_sources("access denied when calling S3")
        assert "iam_simulation" in sources

    def test_extract_service_hints_hyphenated(self):
        from cloudctl.debug.planner import extract_service_hints
        hints = extract_service_hints("the payments-api is returning 502s")
        assert "payments-api" in hints

    def test_extract_service_hints_quoted(self):
        from cloudctl.debug.planner import extract_service_hints
        hints = extract_service_hints('"checkout" service is timing out')
        assert "checkout" in hints

    def test_extract_service_hints_capped(self):
        from cloudctl.debug.planner import extract_service_hints
        hints = extract_service_hints("a b c d e f g h i j k service")
        assert len(hints) <= 5

    def test_no_duplicate_sources(self):
        from cloudctl.debug.planner import plan_sources
        sources = plan_sources("502 timeout error latency slow")
        assert len(sources) == len(set(sources))


# ─── correlator ─────────────────────────────────────────────────────────────

class TestCorrelator:
    def _make_events(self):
        return [
            {"time": "2024-01-15T15:03:00Z", "source": "ALB", "event": "5xx spike"},
            {"time": "2024-01-15T14:52:00Z", "source": "ECS", "event": "deploy registered"},
            {"time": "2024-01-15T15:01:00Z", "source": "RDS", "event": "connections 98/100"},
        ]

    def test_timeline_sorted(self):
        from cloudctl.debug.correlator import build_timeline
        tl = build_timeline(self._make_events())
        times = [e.time for e in tl]
        assert times == sorted(times)

    def test_inflection_marked(self):
        from cloudctl.debug.correlator import build_timeline
        tl = build_timeline(self._make_events())
        inf_events = [e for e in tl if e.is_inflection]
        assert len(inf_events) >= 1

    def test_find_inflection_point(self):
        from cloudctl.debug.correlator import build_timeline, find_inflection_point
        tl = build_timeline(self._make_events())
        point = find_inflection_point(tl)
        assert point is not None
        assert point.is_inflection

    def test_summarise_returns_dicts(self):
        from cloudctl.debug.correlator import build_timeline, summarise
        tl = build_timeline(self._make_events())
        summary = summarise(tl)
        assert isinstance(summary, list)
        assert all(isinstance(e, dict) for e in summary)
        assert all("time" in e for e in summary)

    def test_empty_timeline(self):
        from cloudctl.debug.correlator import build_timeline, find_inflection_point
        tl = build_timeline([])
        assert tl == []
        assert find_inflection_point(tl) is None


# ─── resolver ───────────────────────────────────────────────────────────────

class TestResolver:
    def test_cdk_steps(self):
        from cloudctl.debug.resolver import build_steps
        steps = build_steps("cdk", ["Revert DB_POOL_SIZE"])
        assert any("cdk deploy" in s.lower() or "codepipeline" in s.lower() for s in steps)

    def test_terraform_steps(self):
        from cloudctl.debug.resolver import build_steps
        steps = build_steps("terraform", ["Fix the config"])
        assert any("terraform" in s.lower() for s in steps)

    def test_unknown_method(self):
        from cloudctl.debug.resolver import build_steps
        steps = build_steps("unknown", [])
        assert len(steps) >= 1

    def test_ai_steps_come_first(self):
        from cloudctl.debug.resolver import build_steps
        ai = ["STEP A", "STEP B"]
        steps = build_steps("pulumi", ai)
        assert steps[0] == "STEP A"
        assert steps[1] == "STEP B"


# ─── deployment_detector ────────────────────────────────────────────────────

class TestDeploymentDetector:
    def test_terraform_tags(self):
        from cloudctl.debug.deployment_detector import detect
        method = detect(session=None, resource_tags={"terraform": "true"})
        assert method == "terraform"

    def test_pulumi_tags(self):
        from cloudctl.debug.deployment_detector import detect
        method = detect(session=None, resource_tags={"pulumi:project": "infra"})
        assert method == "pulumi"

    def test_managed_by_terraform(self):
        from cloudctl.debug.deployment_detector import detect
        method = detect(session=None, resource_tags={"managed-by": "terraform"})
        assert method == "terraform"

    def test_no_tags_unknown(self):
        from cloudctl.debug.deployment_detector import detect
        method = detect(session=None, resource_tags={})
        assert method == "unknown"

    def test_iac_drift_warning_cdk(self):
        from cloudctl.debug.deployment_detector import iac_drift_warning
        warning = iac_drift_warning("cdk")
        assert warning is not None
        assert "cdk deploy" in warning.lower()

    def test_iac_drift_warning_unknown(self):
        from cloudctl.debug.deployment_detector import iac_drift_warning
        assert iac_drift_warning("unknown") is None


# ─── renderer (smoke — no assertions on output content) ──────────────────────

class TestRenderer:
    def test_functions_callable(self):
        from cloudctl.debug import renderer
        # Should not raise
        renderer.fetch_start("test")
        renderer.fetch_item("test", 5)
        renderer.fetch_skipped("test", "no perms")
        renderer.fetch_error("test", "boom")
        renderer.section_header("Test Section")
        renderer.confidence_note("low confidence")
        renderer.incident_saved("/tmp/test.md")
        renderer.no_data_found(["compute", "cost"])
        renderer.missing_source_warning("CloudTrail", "enable it")

    def test_affected_resources_empty(self):
        from cloudctl.debug.renderer import affected_resources
        affected_resources([])  # Should not raise

    def test_remediation_steps_empty(self):
        from cloudctl.debug.renderer import remediation_steps
        remediation_steps([])  # Should not raise

    def test_evidence_table_empty(self):
        from cloudctl.debug.renderer import evidence_table
        evidence_table([])  # Should not raise
