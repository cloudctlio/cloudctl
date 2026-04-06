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

    # ── PATCH 1: CDK detected via template body (CDKMetadata) ─────────────
    def test_aws_cfn_cdk_via_cdkmetadata(self):
        """CDK stack identified from CDKMetadata resource in template, not stack tags."""
        from unittest.mock import MagicMock
        from cloudctl.debug.deployment_detector import _aws_cfn_registry
        import json

        cf = MagicMock()
        cf.describe_stack_resources.return_value = {
            "StackResources": [{"StackName": "MyStack"}]
        }
        cf.describe_stacks.return_value = {"Stacks": [{"Tags": []}]}
        cf.get_template.return_value = {
            "TemplateBody": json.dumps({
                "Resources": {
                    "CDKMetadata": {"Type": "AWS::CDK::Metadata"},
                    "MyBucketABCD1234": {"Type": "AWS::S3::Bucket"},
                }
            })
        }
        session = MagicMock()
        session.client.return_value = cf
        assert _aws_cfn_registry(session, "arn:aws:s3:::my-bucket") == "cdk"

    def test_aws_cfn_cdk_via_logical_id_pattern(self):
        """CDK detected from >50% of logical IDs matching the 8-hex-char suffix pattern."""
        from unittest.mock import MagicMock
        from cloudctl.debug.deployment_detector import _aws_cfn_registry
        import json

        cf = MagicMock()
        cf.describe_stack_resources.return_value = {
            "StackResources": [{"StackName": "MyStack"}]
        }
        cf.describe_stacks.return_value = {"Stacks": [{"Tags": []}]}
        cf.get_template.return_value = {
            "TemplateBody": json.dumps({
                "Resources": {
                    "ServiceRoleABCDEF12": {"Type": "AWS::IAM::Role"},
                    "FunctionABCDEF34": {"Type": "AWS::Lambda::Function"},
                    "BucketABCDEF56": {"Type": "AWS::S3::Bucket"},
                }
            })
        }
        session = MagicMock()
        session.client.return_value = cf
        assert _aws_cfn_registry(session, "arn:aws:lambda:::function:test") == "cdk"

    def test_aws_cfn_raw_cloudformation(self):
        """Plain CF stack with human-chosen IDs returns cloudformation (CDKToolkit absent)."""
        from unittest.mock import MagicMock
        from cloudctl.debug.deployment_detector import _aws_cfn_registry
        import json

        cf = MagicMock()
        cf.describe_stack_resources.return_value = {
            "StackResources": [{"StackName": "MyStack"}]
        }
        cf.get_template.return_value = {
            "TemplateBody": json.dumps({
                "Resources": {
                    "MyBucket": {"Type": "AWS::S3::Bucket"},
                    "MyRole": {"Type": "AWS::IAM::Role"},
                }
            })
        }
        # CDKToolkit not present — makes the bootstrap check fail
        cf.describe_stacks.side_effect = Exception("Stack not found")
        session = MagicMock()
        session.client.return_value = cf
        assert _aws_cfn_registry(session, "arn:aws:s3:::my-bucket") == "cloudformation"

    # ── PATCH 2: CloudTrail userAgent ─────────────────────────────────────
    def test_aws_cloudtrail_useragent_terraform(self):
        """Terraform detected from HashiCorp userAgent in CloudTrail event detail."""
        import json
        from unittest.mock import MagicMock
        from cloudctl.debug.deployment_detector import _aws_cloudtrail

        ct = MagicMock()
        ct.lookup_events.return_value = {
            "Events": [{
                "Username": "ci-deploy-role",
                "CloudTrailEvent": json.dumps({
                    "userAgent": "HashiCorp Terraform/1.7.0 (+https://www.terraform.io)"
                }),
            }]
        }
        session = MagicMock()
        session.client.return_value = ct
        assert _aws_cloudtrail(session, "arn:aws:s3:::my-bucket") == "terraform"

    def test_aws_cloudtrail_useragent_pulumi(self):
        """Pulumi detected from userAgent even when Username gives no hint."""
        import json
        from unittest.mock import MagicMock
        from cloudctl.debug.deployment_detector import _aws_cloudtrail

        ct = MagicMock()
        ct.lookup_events.return_value = {
            "Events": [{
                "Username": "deploy-sa",
                "CloudTrailEvent": json.dumps({
                    "userAgent": "pulumi/3.0 go1.21 linux/amd64"
                }),
            }]
        }
        session = MagicMock()
        session.client.return_value = ct
        assert _aws_cloudtrail(session, "arn:aws:s3:::my-bucket") == "pulumi"

    # ── PATCH 3: Azure Activity Log HTTP userAgent ────────────────────────
    def test_azure_activity_log_http_useragent_terraform(self):
        """Terraform detected from HTTP userAgent in Activity Log even with generic caller."""
        import sys
        from unittest.mock import MagicMock
        from cloudctl.debug.deployment_detector import _azure_activity_log

        event = MagicMock()
        event.caller = "ci-runner@tenant.com"
        event.http_request = MagicMock()
        event.http_request.__str__ = lambda self: "HashiCorp Terraform/1.7.0 azurerm/3.0"

        mock_monitor_client = MagicMock()
        mock_monitor_client.activity_logs.list.return_value = [event]
        mock_monitor_module = MagicMock()
        mock_monitor_module.MonitorManagementClient.return_value = mock_monitor_client

        sys.modules["azure"] = MagicMock()
        sys.modules["azure.mgmt"] = MagicMock()
        sys.modules["azure.mgmt.monitor"] = mock_monitor_module

        try:
            result = _azure_activity_log(MagicMock(), "sub-123", "/subscriptions/sub-123/res")
        finally:
            for mod in ("azure", "azure.mgmt", "azure.mgmt.monitor"):
                sys.modules.pop(mod, None)

        assert result == "terraform"

    # ── PATCH 4: GCP callerSuppliedUserAgent ──────────────────────────────
    def test_gcp_audit_logs_caller_useragent_terraform(self):
        """Terraform detected from callerSuppliedUserAgent even with opaque principalEmail."""
        import sys
        from unittest.mock import MagicMock
        from cloudctl.debug.deployment_detector import _gcp_audit_logs

        entry = MagicMock()
        entry.payload = {
            "requestMetadata": {
                "callerSuppliedUserAgent": "HashiCorp Terraform/1.7.0"
            },
            "authenticationInfo": {
                "principalEmail": "deploy@project.iam.gserviceaccount.com"
            },
        }

        mock_logging_client = MagicMock()
        mock_logging_client.list_entries.return_value = [entry]
        mock_logging_module = MagicMock()
        mock_logging_module.Client.return_value = mock_logging_client

        # Inject mock modules so the optional import inside _gcp_audit_logs succeeds.
        # The function does: from google.cloud import logging as gcp_logging
        # so we must set it as an attribute on the google.cloud mock AND in sys.modules.
        mock_google_cloud = MagicMock()
        mock_google_cloud.logging = mock_logging_module
        sys.modules["google"] = MagicMock()
        sys.modules["google.cloud"] = mock_google_cloud
        sys.modules["google.cloud.logging"] = mock_logging_module

        try:
            result = _gcp_audit_logs("my-project", "my-resource")
        finally:
            for mod in ("google", "google.cloud", "google.cloud.logging"):
                sys.modules.pop(mod, None)

        assert result == "terraform"

    # ── PATCH 5: Expanded tag patterns ────────────────────────────────────
    def test_goog_terraform_provisioned_label(self):
        """GCP goog-terraform-provisioned label is recognised."""
        from cloudctl.debug.deployment_detector import detect
        assert detect("gcp", gcp_labels={"goog-terraform-provisioned": "true"}) == "terraform"

    def test_terraform_workspace_tag(self):
        """terraform-workspace tag is recognised on AWS."""
        from cloudctl.debug.deployment_detector import detect
        assert detect("aws", resource_tags={"terraform-workspace": "prod"}) == "terraform"

    def test_iac_tool_tag_terraform(self):
        """iac-tool=terraform tag is recognised."""
        from cloudctl.debug.deployment_detector import detect
        assert detect("aws", resource_tags={"iac-tool": "terraform"}) == "terraform"

    def test_iac_tool_tag_pulumi(self):
        """iac-tool=pulumi tag is recognised."""
        from cloudctl.debug.deployment_detector import detect
        assert detect("aws", resource_tags={"iac-tool": "pulumi"}) == "pulumi"

    def test_pulumi_stack_tag(self):
        """pulumi:stack tag is recognised."""
        from cloudctl.debug.deployment_detector import detect
        assert detect("aws", resource_tags={"pulumi:stack": "prod"}) == "pulumi"

    def test_managed_by_terraform_cloud(self):
        """managed-by=terraform-cloud is recognised."""
        from cloudctl.debug.deployment_detector import detect
        assert detect("aws", resource_tags={"managed-by": "terraform-cloud"}) == "terraform"

    # ── PATCH 6: ARM false-positive prevention ────────────────────────────
    def test_azure_arm_deployments_skips_terraform_named_deployment(self):
        """Deployment with 'terraform' in the name is not misidentified as arm."""
        import sys
        from unittest.mock import MagicMock
        from cloudctl.debug.deployment_detector import _azure_arm_deployments

        dep = MagicMock()
        dep.name = "terraform-20240101"
        dep.properties = MagicMock()
        dep.properties.template = None

        mock_rm_client = MagicMock()
        mock_rm_client.deployments.list_by_resource_group.return_value = [dep]
        mock_rm_client.deployments.get.return_value = dep
        mock_resource_module = MagicMock()
        mock_resource_module.ResourceManagementClient.return_value = mock_rm_client

        sys.modules["azure"] = MagicMock()
        sys.modules["azure.mgmt"] = MagicMock()
        sys.modules["azure.mgmt.resource"] = mock_resource_module

        try:
            result = _azure_arm_deployments(MagicMock(), "sub-123", "my-rg", None)
        finally:
            for mod in ("azure", "azure.mgmt", "azure.mgmt.resource"):
                sys.modules.pop(mod, None)

        assert result == "unknown"


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
