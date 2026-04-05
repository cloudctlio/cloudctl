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

    def test_bicep_steps(self):
        from cloudctl.debug.resolver import build_steps
        steps = build_steps("bicep", [])
        assert any("bicep" in s.lower() for s in steps)
        assert any("az deployment" in s.lower() for s in steps)

    def test_arm_steps(self):
        from cloudctl.debug.resolver import build_steps
        steps = build_steps("arm", [])
        assert any("arm" in s.lower() for s in steps)

    def test_azure_devops_steps(self):
        from cloudctl.debug.resolver import build_steps
        steps = build_steps("azure-devops", [])
        assert any("azure devops" in s.lower() for s in steps)

    def test_deployment_manager_steps(self):
        from cloudctl.debug.resolver import build_steps
        steps = build_steps("deployment-manager", [])
        assert any("deployment-manager" in s.lower() for s in steps)

    def test_config_connector_steps(self):
        from cloudctl.debug.resolver import build_steps
        steps = build_steps("config-connector", [])
        # Config Connector — must say to edit the Kubernetes CR, not the GCP resource
        full_text = " ".join(steps).lower()
        assert "kubectl" in full_text or "kubernetes" in full_text

    def test_cloud_build_steps(self):
        from cloudctl.debug.resolver import build_steps
        steps = build_steps("cloud-build", [])
        assert any("cloud build" in s.lower() for s in steps)

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
    # ── AWS tag detection ──────────────────────────────────────────────────
    def test_aws_terraform_tags(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("aws", resource_tags={"terraform": "true"}) == "terraform"

    def test_aws_pulumi_tags(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("aws", resource_tags={"pulumi:project": "infra"}) == "pulumi"

    def test_aws_managed_by_terraform(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("aws", resource_tags={"managed-by": "terraform"}) == "terraform"

    def test_aws_no_tags_unknown(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("aws", resource_tags={}) == "unknown"

    # ── Azure tag detection ────────────────────────────────────────────────
    def test_azure_bicep_tag(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("azure", resource_tags={"bicep-file": "main.bicep"}) == "bicep"

    def test_azure_arm_tag(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("azure", resource_tags={"arm-template": "true"}) == "arm"

    def test_azure_devops_tag(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("azure", resource_tags={"azure-devops": "pipeline-123"}) == "azure-devops"

    def test_azure_managed_by_bicep(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("azure", resource_tags={"managed-by": "bicep"}) == "bicep"

    def test_azure_managed_by_arm(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("azure", resource_tags={"managed-by": "arm"}) == "arm"

    def test_azure_terraform_crosscloud(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("azure", resource_tags={"terraform": "true"}) == "terraform"

    def test_azure_no_tags_unknown(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("azure", resource_tags={}) == "unknown"

    # ── GCP label detection ────────────────────────────────────────────────
    def test_gcp_config_connector_label(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("gcp", gcp_labels={"cnrm.cloud.google.com/managed-by-kcc": "true"}) == "config-connector"

    def test_gcp_config_connector_managed_by(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("gcp", gcp_labels={"managed-by": "config-connector"}) == "config-connector"

    def test_gcp_deployment_manager_label(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("gcp", gcp_labels={"dm-name": "my-deployment"}) == "deployment-manager"

    def test_gcp_deployment_manager_managed_by(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("gcp", gcp_labels={"managed-by": "deployment-manager"}) == "deployment-manager"

    def test_gcp_cloud_build_label(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("gcp", gcp_labels={"cloud-build-id": "abc123"}) == "cloud-build"

    def test_gcp_terraform_crosscloud(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("gcp", gcp_labels={"terraform": "true"}) == "terraform"

    def test_gcp_no_labels_unknown(self):
        from cloudctl.debug.deployment_detector import detect
        assert detect("gcp", gcp_labels={}) == "unknown"

    # ── Drift warnings ────────────────────────────────────────────────────
    def test_drift_warning_cdk(self):
        from cloudctl.debug.deployment_detector import iac_drift_warning
        w = iac_drift_warning("cdk")
        assert w is not None and "cdk deploy" in w.lower()

    def test_drift_warning_bicep(self):
        from cloudctl.debug.deployment_detector import iac_drift_warning
        w = iac_drift_warning("bicep")
        assert w is not None and "bicep" in w.lower()

    def test_drift_warning_arm(self):
        from cloudctl.debug.deployment_detector import iac_drift_warning
        w = iac_drift_warning("arm")
        assert w is not None and "arm" in w.lower()

    def test_drift_warning_azure_devops(self):
        from cloudctl.debug.deployment_detector import iac_drift_warning
        w = iac_drift_warning("azure-devops")
        assert w is not None and "azure devops" in w.lower()

    def test_drift_warning_deployment_manager(self):
        from cloudctl.debug.deployment_detector import iac_drift_warning
        w = iac_drift_warning("deployment-manager")
        assert w is not None and "deployment-manager" in w.lower()

    def test_drift_warning_config_connector(self):
        from cloudctl.debug.deployment_detector import iac_drift_warning
        w = iac_drift_warning("config-connector")
        assert w is not None and "config connector" in w.lower()

    def test_drift_warning_cloud_build(self):
        from cloudctl.debug.deployment_detector import iac_drift_warning
        w = iac_drift_warning("cloud-build")
        assert w is not None and "cloud build" in w.lower()

    def test_drift_warning_codepipeline_is_none(self):
        # CodePipeline and GitHub Actions are CI/CD — no drift warning needed
        from cloudctl.debug.deployment_detector import iac_drift_warning
        assert iac_drift_warning("codepipeline") is None

    def test_drift_warning_unknown_is_none(self):
        from cloudctl.debug.deployment_detector import iac_drift_warning
        assert iac_drift_warning("unknown") is None

    def test_all_known_methods_have_resolver_steps(self):
        """Every non-unknown known method should have resolver steps."""
        from cloudctl.debug.deployment_detector import KNOWN_METHODS
        from cloudctl.debug.resolver import _STEPS
        for method in KNOWN_METHODS:
            if method == "unknown":
                continue
            assert method in _STEPS, f"Missing resolver steps for '{method}'"


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
