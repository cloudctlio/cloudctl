"""Tests for cloudctl.debug package — planner, correlator, renderer, resolver."""
from __future__ import annotations

import pytest


# ─── planner ────────────────────────────────────────────────────────────────

class TestPlanner:
    def test_always_returns_all_sources(self):
        from cloudctl.debug.planner import plan_sources, ALL_SOURCES
        sources = plan_sources("payments returning 502s")
        assert sources == ALL_SOURCES

    def test_default_sources_always_present(self):
        from cloudctl.debug.planner import plan_sources
        sources = plan_sources("something completely unrelated xyz")
        assert "service_logs" in sources
        assert "audit_logs" in sources
        assert "network_context" in sources

    def test_any_symptom_returns_all_sources(self):
        from cloudctl.debug.planner import plan_sources, ALL_SOURCES
        for symptom in [
            "database connection pool exhausted",
            "after the deploy things broke",
            "access denied when calling S3",
        ]:
            assert plan_sources(symptom) == ALL_SOURCES

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


# ─── ACM certificate fetcher ────────────────────────────────────────────────

class TestAcmCertificates:
    def _make_session(self, certs: list[dict]):
        """Return a mock boto3 session whose ACM client returns the given certs."""
        from unittest.mock import MagicMock  # noqa: PLC0415
        from datetime import datetime, timezone, timedelta  # noqa: PLC0415

        acm = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"CertificateSummaryList": [
            {"CertificateArn": c["arn"]} for c in certs
        ]}]
        acm.get_paginator.return_value = paginator

        def _describe(CertificateArn):  # noqa: N803
            cert = next(c for c in certs if c["arn"] == CertificateArn)
            return {"Certificate": {
                "DomainName":               cert["domain"],
                "SubjectAlternativeNames":  cert.get("sans", []),
                "Type":                     cert["type"],
                "NotAfter":                 cert.get("expiry"),
                "InUseBy":                  cert.get("in_use_by", []),
            }}

        acm.describe_certificate.side_effect = _describe
        session = MagicMock()
        session.client.return_value = acm
        return session

    def test_expired_cert_flagged(self):
        from datetime import datetime, timezone, timedelta  # noqa: PLC0415
        from cloudctl.debug.fetcher import DebugFetcher  # noqa: PLC0415
        past = datetime.now(timezone.utc) - timedelta(days=5)
        session = self._make_session([{
            "arn": "arn:aws:acm:us-east-1:123:certificate/abc",
            "domain": "api.example.com",
            "type": "IMPORTED",
            "expiry": past,
            "in_use_by": ["arn:aws:elasticloadbalancing:::loadbalancer/app/payments-alb/x"],
        }])
        result = DebugFetcher(session).acm_certificates()
        assert result["has_issues"] is True
        assert len(result["expired"]) == 1
        assert result["expired"][0]["domain"] == "api.example.com"
        assert result["expired"][0]["status"] == "EXPIRED"

    def test_expiring_soon_cert_flagged(self):
        from datetime import datetime, timezone, timedelta  # noqa: PLC0415
        from cloudctl.debug.fetcher import DebugFetcher  # noqa: PLC0415
        soon = datetime.now(timezone.utc) + timedelta(days=10)
        session = self._make_session([{
            "arn": "arn:aws:acm:us-east-1:123:certificate/def",
            "domain": "checkout.example.com",
            "type": "AMAZON_ISSUED",
            "expiry": soon,
            "in_use_by": [],
        }])
        result = DebugFetcher(session).acm_certificates()
        assert result["has_issues"] is True
        assert len(result["expiring_soon"]) == 1
        assert result["expiring_soon"][0]["status"] == "EXPIRING_SOON"

    def test_imported_not_expiring_flagged_as_no_auto_renew(self):
        from datetime import datetime, timezone, timedelta  # noqa: PLC0415
        from cloudctl.debug.fetcher import DebugFetcher  # noqa: PLC0415
        future = datetime.now(timezone.utc) + timedelta(days=200)
        session = self._make_session([{
            "arn": "arn:aws:acm:us-east-1:123:certificate/ghi",
            "domain": "internal.example.com",
            "type": "IMPORTED",
            "expiry": future,
            "in_use_by": [],
        }])
        result = DebugFetcher(session).acm_certificates()
        assert result["has_issues"] is False   # not expiring, not expired
        assert len(result["imported_no_auto"]) == 1
        assert result["imported_no_auto"][0]["status"] == "IMPORTED_NO_AUTO_RENEW"
        assert result["imported_no_auto"][0]["auto_renew"] is False

    def test_amazon_issued_valid_cert_ok(self):
        from datetime import datetime, timezone, timedelta  # noqa: PLC0415
        from cloudctl.debug.fetcher import DebugFetcher  # noqa: PLC0415
        future = datetime.now(timezone.utc) + timedelta(days=300)
        session = self._make_session([{
            "arn": "arn:aws:acm:us-east-1:123:certificate/jkl",
            "domain": "www.example.com",
            "type": "AMAZON_ISSUED",
            "expiry": future,
            "in_use_by": ["arn:aws:cloudfront::123:distribution/ABC"],
        }])
        result = DebugFetcher(session).acm_certificates()
        assert result["has_issues"] is False
        assert result["all"][0]["status"] == "OK"
        assert result["all"][0]["auto_renew"] is True

    def test_no_session_returns_empty(self):
        from cloudctl.debug.fetcher import DebugFetcher  # noqa: PLC0415
        result = DebugFetcher(None).acm_certificates()
        assert result["has_issues"] is False
        assert result["total"] == 0

    def test_acm_expiry_check_in_all_sources(self):
        from cloudctl.debug.planner import ALL_SOURCES  # noqa: PLC0415
        assert "acm_expiry_check" in ALL_SOURCES


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

    def test_aws_cfn_cdk_short_name_fallback(self):
        """When full ARN returns no stacks, retry with short function name (last colon segment)."""
        from unittest.mock import MagicMock, call
        from cloudctl.debug.deployment_detector import _aws_cfn_registry
        import json

        cf = MagicMock()
        # First call (full ARN) returns empty — CloudFormation physical IDs are names not ARNs
        # Second call (short name) returns the stack
        cf.describe_stack_resources.side_effect = [
            {"StackResources": []},
            {"StackResources": [{"StackName": "LambdaCrashStack"}]},
        ]
        cf.describe_stacks.return_value = {"Stacks": [{"Tags": []}]}
        cf.get_template.return_value = {
            "TemplateBody": json.dumps({
                "Resources": {
                    "CDKMetadata": {"Type": "AWS::CDK::Metadata"},
                    "PaymentsFn08FA78A0": {"Type": "AWS::Lambda::Function"},
                }
            })
        }
        session = MagicMock()
        session.client.return_value = cf

        fn_arn = "arn:aws:lambda:us-east-1:123456789012:function:LambdaCrashStack-PaymentsFn08FA78A0-Y60RENQ9YHrY"
        assert _aws_cfn_registry(session, fn_arn) == "cdk"
        # First lookup used full ARN, second used short function name
        calls = cf.describe_stack_resources.call_args_list
        assert calls[0] == call(PhysicalResourceId=fn_arn)
        assert calls[1] == call(PhysicalResourceId="LambdaCrashStack-PaymentsFn08FA78A0-Y60RENQ9YHrY")

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

    def test_aws_cloudtrail_elb_arn_extracts_name_segment(self):
        """ELB target group ARN: name segment extracted from 'targetgroup/name/hex-id'."""
        import json
        from unittest.mock import MagicMock, call
        from cloudctl.debug.deployment_detector import _aws_cloudtrail

        tg_arn = "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/my-service-tg/abcdef1234567890"

        ct = MagicMock()
        # First two lookups (full ARN + "targetgroup/name/hex-id") return nothing.
        # Third lookup (name segment "my-service-tg") returns a Terraform event.
        empty = {"Events": []}
        terraform_event = {"Events": [{
            "Username": "ci",
            "CloudTrailEvent": json.dumps({"userAgent": "HashiCorp Terraform/1.9.0"}),
        }]}
        ct.lookup_events.side_effect = [empty, empty, terraform_event]

        session = MagicMock()
        session.client.return_value = ct
        assert _aws_cloudtrail(session, tg_arn) == "terraform"

        # Confirm the third call used the clean name segment
        calls = ct.lookup_events.call_args_list
        looked_up_names = [c.kwargs["LookupAttributes"][0]["AttributeValue"] for c in calls]
        assert "my-service-tg" in looked_up_names

    def test_aws_cloudtrail_alb_arn_extracts_name_segment(self):
        """ALB ARN: name segment extracted from 'loadbalancer/app/name/hex-id'."""
        import json
        from unittest.mock import MagicMock
        from cloudctl.debug.deployment_detector import _aws_cloudtrail

        alb_arn = "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abcdef1234567890"

        ct = MagicMock()
        empty = {"Events": []}
        terraform_event = {"Events": [{
            "Username": "ci",
            "CloudTrailEvent": json.dumps({"userAgent": "HashiCorp Terraform/1.9.0"}),
        }]}
        # First two lookups return nothing, "my-alb" lookup succeeds
        ct.lookup_events.side_effect = [empty, empty, terraform_event]

        session = MagicMock()
        session.client.return_value = ct
        assert _aws_cloudtrail(session, alb_arn) == "terraform"

        calls = ct.lookup_events.call_args_list
        looked_up_names = [c.kwargs["LookupAttributes"][0]["AttributeValue"] for c in calls]
        assert "my-alb" in looked_up_names

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
            result = _azure_arm_deployments(MagicMock(), "sub-123", "my-rg")
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


# ─── debug_cmd --dry-run / --explain ─────────────────────────────────────────

class TestDebugCmdFlags:
    def _invoke_dry_run(self, symptom):
        from unittest.mock import MagicMock, patch
        from typer.testing import CliRunner
        from cloudctl.main import app

        runner = CliRunner()
        with patch("cloudctl.commands.debug_cmd.require_init", return_value=MagicMock()):
            return runner.invoke(app, ["debug", symptom, "--dry-run"])

    def test_dry_run_no_aws_calls(self):
        """--dry-run exits before touching AWS and prints the planned sources."""
        result = self._invoke_dry_run("payments returning 502s")
        assert result.exit_code == 0
        assert "DRY RUN" in result.output
        assert "service_logs" in result.output
        assert "audit_logs" in result.output
        # must NOT make any real AWS / AI calls — if it did, it would raise without mocks

    def test_dry_run_shows_hints(self):
        """--dry-run prints the extracted resource hints."""
        result = self._invoke_dry_run("payments-api returning 502s")
        assert result.exit_code == 0
        assert "payments-api" in result.output

    def test_dry_run_shows_no_changes_message(self):
        """--dry-run footer says run without --dry-run to execute."""
        result = self._invoke_dry_run("lambda timeout")
        assert result.exit_code == 0
        assert "without --dry-run" in result.output

    def test_dry_run_network_symptom_includes_network_context(self):
        """Network-related symptom plans network_context in dry-run."""
        result = self._invoke_dry_run("vpc nat gateway not routing traffic")
        assert result.exit_code == 0
        assert "network_context" in result.output


# ─── fetcher: cloudtrail lag warning ─────────────────────────────────────────

class TestCloudTrailLagCheck:
    def _fetcher(self):
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher
        return DebugFetcher(MagicMock())

    def test_constant_is_15(self):
        from cloudctl.debug.fetcher import CLOUDTRAIL_LAG_MINUTES
        assert CLOUDTRAIL_LAG_MINUTES == 15

    def test_returns_tuple(self):
        """cloudtrail_with_lag_check always returns (list, bool)."""
        f = self._fetcher()
        f.cloudtrail = lambda **kw: []
        events, warning = f.cloudtrail_with_lag_check(minutes=120)
        assert isinstance(events, list)
        assert isinstance(warning, bool)

    def test_no_warning_without_incident_time(self):
        """No lag warning when incident_time is not provided."""
        f = self._fetcher()
        f.cloudtrail = lambda **kw: []
        _, warning = f.cloudtrail_with_lag_check(minutes=120)
        assert warning is False

    def test_warning_when_incident_is_recent(self):
        """Lag warning is True when incident_time is within the lag window."""
        from datetime import datetime, timezone, timedelta
        f = self._fetcher()
        f.cloudtrail = lambda **kw: []
        recent = datetime.now(timezone.utc) - timedelta(minutes=5)
        _, warning = f.cloudtrail_with_lag_check(minutes=30, incident_time=recent)
        assert warning is True

    def test_no_warning_when_incident_is_old(self):
        """No lag warning when incident_time is well outside the lag window."""
        from datetime import datetime, timezone, timedelta
        f = self._fetcher()
        f.cloudtrail = lambda **kw: []
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        _, warning = f.cloudtrail_with_lag_check(minutes=120, incident_time=old)
        assert warning is False

    def test_events_passed_through(self):
        """Events returned by cloudtrail() are passed through unchanged."""
        f = self._fetcher()
        stub = [{"time": "t1", "source": "CT", "event": "CreateFunction"}]
        f.cloudtrail = lambda **kw: stub
        events, _ = f.cloudtrail_with_lag_check(minutes=120)
        assert events == stub


# ─── fetcher: lambda_report_metrics ──────────────────────────────────────────

class TestLambdaReportMetrics:
    def _fetcher_with_logs(self, raw_events):
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher
        f = DebugFetcher(MagicMock())
        f.cloudwatch_logs = MagicMock(return_value=raw_events)
        return f

    def _report(self, duration, billed, mem_size, mem_used, init=None):
        line = (
            f"REPORT RequestId: abc  Duration: {duration} ms  "
            f"Billed Duration: {billed} ms  Memory Size: {mem_size} MB  "
            f"Max Memory Used: {mem_used} MB"
        )
        if init is not None:
            line += f"  Init Duration: {init} ms"
        return {"time": "2026-01-01T00:00:00", "event": line}

    def test_parses_duration(self):
        f = self._fetcher_with_logs([self._report(1234.56, 1300, 512, 256)])
        results = f.lambda_report_metrics("my-fn")
        assert len(results) == 1
        assert results[0]["duration_ms"] == 1234.56

    def test_parses_memory(self):
        f = self._fetcher_with_logs([self._report(500, 600, 512, 200)])
        results = f.lambda_report_metrics("my-fn")
        assert results[0]["memory_mb"] == 200

    def test_cold_start_detected(self):
        f = self._fetcher_with_logs([self._report(500, 600, 512, 200, init=450.23)])
        results = f.lambda_report_metrics("my-fn")
        assert results[0]["cold_start"] is True

    def test_warm_start_no_cold_start(self):
        f = self._fetcher_with_logs([self._report(500, 600, 512, 200)])
        results = f.lambda_report_metrics("my-fn")
        assert results[0]["cold_start"] is False

    def test_non_report_lines_skipped(self):
        logs = [
            {"time": "t", "event": "START RequestId: abc"},
            {"time": "t", "event": "END RequestId: abc"},
            self._report(300, 400, 256, 128),
        ]
        f = self._fetcher_with_logs(logs)
        results = f.lambda_report_metrics("my-fn")
        assert len(results) == 1

    def test_empty_logs_returns_empty(self):
        f = self._fetcher_with_logs([])
        assert f.lambda_report_metrics("my-fn") == []

    def test_source_field_set(self):
        f = self._fetcher_with_logs([self._report(100, 200, 128, 64)])
        results = f.lambda_report_metrics("my-fn")
        assert results[0]["source"] == "LambdaREPORT/my-fn"


# ─── fetcher: sqs_with_dlq ────────────────────────────────────────────────────

class TestSqsWithDlq:
    def _fetcher(self, queue_urls=None, attrs=None, cw_metrics=None):
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher
        import json

        mock_sqs = MagicMock()
        mock_sqs.list_queues.return_value = {"QueueUrls": queue_urls or []}

        # Default attrs: depth 5, no DLQ
        default_attrs = {
            "ApproximateNumberOfMessages": "5",
            "ApproximateNumberOfMessagesNotVisible": "0",
        }
        mock_sqs.get_queue_attributes.return_value = {"Attributes": attrs or default_attrs}

        mock_cw = MagicMock()
        mock_cw.get_metric_statistics.return_value = {"Datapoints": cw_metrics or []}

        session = MagicMock()
        session.client.side_effect = lambda svc, **kw: mock_sqs if svc == "sqs" else mock_cw

        return DebugFetcher(session)

    def test_no_queues_returns_empty(self):
        f = self._fetcher(queue_urls=[])
        assert f.sqs_with_dlq("my-queue") == []

    def test_queue_depth_event_returned(self):
        f = self._fetcher(
            queue_urls=["https://sqs.us-east-1.amazonaws.com/123/my-queue"],
            attrs={"ApproximateNumberOfMessages": "42", "ApproximateNumberOfMessagesNotVisible": "0"},
        )
        results = f.sqs_with_dlq("my-queue")
        assert any("42" in str(r.get("event", "")) for r in results)

    def test_dlq_depth_event_returned(self):
        import json
        dlq_arn = "arn:aws:sqs:us-east-1:123:my-queue-dlq"
        attrs = {
            "ApproximateNumberOfMessages": "0",
            "ApproximateNumberOfMessagesNotVisible": "0",
            "RedrivePolicy": json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": "3"}),
        }
        dlq_attrs = {"ApproximateNumberOfMessages": "7", "ApproximateNumberOfMessagesNotVisible": "0"}

        from unittest.mock import MagicMock, call
        from cloudctl.debug.fetcher import DebugFetcher

        mock_sqs = MagicMock()
        mock_sqs.list_queues.return_value = {"QueueUrls": ["https://sqs.us-east-1.amazonaws.com/123/my-queue"]}
        mock_sqs.get_queue_url.return_value = {"QueueUrl": "https://sqs.us-east-1.amazonaws.com/123/my-queue-dlq"}
        mock_sqs.get_queue_attributes.side_effect = [
            {"Attributes": attrs},      # main queue
            {"Attributes": dlq_attrs},  # DLQ
        ]
        mock_cw = MagicMock()
        mock_cw.get_metric_statistics.return_value = {"Datapoints": []}
        session = MagicMock()
        session.client.side_effect = lambda svc, **kw: mock_sqs if svc == "sqs" else mock_cw

        f = DebugFetcher(session)
        results = f.sqs_with_dlq("my-queue")
        # DLQ row: source contains "DLQ", event contains dlq_depth=7
        dlq_rows = [r for r in results if "DLQ" in r.get("source", "")]
        assert dlq_rows, f"No DLQ row found in results: {results}"
        assert "7" in dlq_rows[0].get("event", ""), f"DLQ depth 7 not in event: {dlq_rows[0]}"


# ─── fetcher: alb discovery ───────────────────────────────────────────────────

class TestAlbDiscovery:
    def _session(self):
        from unittest.mock import MagicMock
        return MagicMock()

    def test_find_alb_no_ecs_services_returns_none(self):
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher
        mock_ecs = MagicMock()
        mock_ecs.list_clusters.return_value = {"clusterArns": []}
        session = MagicMock()
        session.client.return_value = mock_ecs
        f = DebugFetcher(session)
        assert f.find_alb_for_resource("my-service") is None

    def test_get_alb_log_config_disabled(self):
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher
        mock_elb = MagicMock()
        mock_elb.describe_load_balancer_attributes.return_value = {
            "Attributes": [
                {"Key": "access_logs.s3.enabled", "Value": "false"},
                {"Key": "access_logs.s3.bucket", "Value": ""},
            ]
        }
        session = MagicMock()
        session.client.return_value = mock_elb
        f = DebugFetcher(session)
        result = f.get_alb_log_config("arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc")
        assert result.get("enabled") is False

    def test_get_alb_log_config_enabled(self):
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher
        mock_elb = MagicMock()
        mock_elb.describe_load_balancer_attributes.return_value = {
            "Attributes": [
                {"Key": "access_logs.s3.enabled", "Value": "true"},
                {"Key": "access_logs.s3.bucket", "Value": "my-logs-bucket"},
                {"Key": "access_logs.s3.prefix", "Value": "alb/"},
            ]
        }
        session = MagicMock()
        session.client.return_value = mock_elb
        f = DebugFetcher(session)
        result = f.get_alb_log_config("arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/my-alb/abc")
        assert result.get("enabled") is True
        assert result.get("bucket") == "my-logs-bucket"


# ─── fetcher: ecs_stopped_tasks ───────────────────────────────────────────────

class TestEcsStoppedTasks:
    def test_no_stopped_tasks_returns_empty(self):
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher
        mock_ecs = MagicMock()
        mock_ecs.list_tasks.return_value = {"taskArns": []}
        session = MagicMock()
        session.client.return_value = mock_ecs
        f = DebugFetcher(session)
        assert f.ecs_stopped_tasks("my-cluster", "my-service") == []

    def test_stopped_tasks_with_exit_code(self):
        from datetime import datetime, timezone
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher
        mock_ecs = MagicMock()
        mock_ecs.list_tasks.return_value = {"taskArns": ["arn:aws:ecs:us-east-1:123:task/abc"]}
        mock_ecs.describe_tasks.return_value = {
            "tasks": [{
                "taskArn": "arn:aws:ecs:us-east-1:123:task/abc",
                "stoppedReason": "Essential container exited",
                "stoppedAt": datetime(2026, 1, 1, tzinfo=timezone.utc),
                "containers": [{"name": "app", "exitCode": 1, "reason": "OOMKilled"}],
            }]
        }
        session = MagicMock()
        session.client.return_value = mock_ecs
        f = DebugFetcher(session)
        results = f.ecs_stopped_tasks("my-cluster", "my-service")
        assert len(results) == 1
        assert "OOMKilled" in results[0]["event"]


# ─── fetcher: rds_for_resource ────────────────────────────────────────────────

class TestRdsForResource:
    def test_no_instances_returns_empty(self):
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher
        mock_rds = MagicMock()
        mock_rds.describe_db_instances.return_value = {"DBInstances": []}
        session = MagicMock()
        session.client.return_value = mock_rds
        f = DebugFetcher(session)
        assert f.rds_for_resource("payments-db") == []

    def test_matching_instance_by_name(self):
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher
        mock_rds = MagicMock()
        mock_rds.describe_db_instances.return_value = {
            "DBInstances": [{
                "DBInstanceIdentifier": "payments-db",
                "DBInstanceStatus": "available",
                "Endpoint": {"Address": "payments-db.abc.us-east-1.rds.amazonaws.com", "Port": 5432},
                "Engine": "postgres",
                "DBInstanceClass": "db.t3.micro",
                "VpcSecurityGroups": [],
            }]
        }
        session = MagicMock()
        session.client.return_value = mock_rds
        f = DebugFetcher(session)
        results = f.rds_for_resource("payments-db")
        assert len(results) == 1
        assert "payments-db" in results[0]["event"]


# ─── deployment_detector: generic resource harvest from context ───────────────

class TestGenericResourceHarvest:
    """Verify _detect_deployment_method harvests identifiers from all context sources."""

    def _make_engine(self):
        from unittest.mock import MagicMock
        from cloudctl.ai.debug_engine import DebugEngine
        cfg = MagicMock()
        cfg.accounts = {"aws": [{"name": "test-profile"}]}
        return DebugEngine(cfg)

    def _make_session(self, terraform_resource: str):
        """Return a mock session where CloudTrail finds Terraform for terraform_resource,
        and CloudFormation always raises (resource not in any CF stack)."""
        import json
        from unittest.mock import MagicMock

        empty = {"Events": []}
        terraform_event = {"Events": [{
            "Username": "ci",
            "CloudTrailEvent": json.dumps({"userAgent": "HashiCorp Terraform/1.9.0"}),
        }]}

        mock_ct = MagicMock()
        mock_ct.lookup_events.side_effect = lambda **kw: (
            terraform_event
            if terraform_resource in str(kw.get("LookupAttributes", ""))
            else empty
        )

        mock_cf = MagicMock()
        mock_cf.describe_stack_resources.side_effect = Exception("Stack not found")

        mock_tagger = MagicMock()
        mock_tagger.get_resources.return_value = {"ResourceTagMappingList": []}

        session = MagicMock()
        session.client.side_effect = lambda svc, **kw: {
            "cloudtrail":               mock_ct,
            "cloudformation":           mock_cf,
            "resourcegroupstaggingapi": mock_tagger,
        }.get(svc, MagicMock())
        return session

    def test_network_context_vpc_id_used_for_detection(self):
        """VPC IDs from network_context reach the IaC detector (no /aws/ path needed)."""
        from unittest.mock import patch

        engine = self._make_engine()
        context = {
            "audit_logs": [],
            "network_context": [
                {"time": "—", "source": "VPC/vpc-0abc1234def56789a", "event": "state=available"},
                {"time": "—", "source": "SecurityGroup/sg-0f70105360f3d1326", "event": "ingress port=8080"},
            ],
        }
        session = self._make_session("vpc-0abc1234def56789a")

        with patch("cloudctl.commands._helpers.get_aws_provider") as mock_provider:
            from unittest.mock import MagicMock
            mock_prov = MagicMock()
            mock_prov._session = session
            mock_provider.return_value = mock_prov
            result = engine._detect_deployment_method("aws", "test-profile", None, context)

        assert result == "terraform"

    def test_service_logs_harvested_even_when_audit_logs_present(self):
        """Service log names are harvested even when audit_logs is non-empty."""
        from unittest.mock import MagicMock, patch

        engine = self._make_engine()
        context = {
            "audit_logs": [
                {"resource": "arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/my-tg/abc",
                 "source": "CT", "event": "DescribeTargetHealth"},
            ],
            "service_logs": [
                {"time": "t", "source": "CloudWatch/Logs//aws/lambda/my-fn", "event": "[ERROR] fail"},
            ],
        }
        session = self._make_session("my-fn")

        with patch("cloudctl.commands._helpers.get_aws_provider") as mock_provider:
            mock_prov = MagicMock()
            mock_prov._session = session
            mock_provider.return_value = mock_prov
            result = engine._detect_deployment_method("aws", "test-profile", None, context)

        assert result == "terraform"


# ─── fetcher: bedrock_agent_config ──────────────────────────────────────────

class TestBedrockAgentConfigFetcher:
    """Regression test for a real production miss: bedrock_agent_config
    fetched action_groups but never called list_agent_knowledge_bases, so
    the agent had no way to see a real KB association and twice concluded
    "no KB attached to the agent" when the actual fault was elsewhere
    (a bad S3 data-source prefix, an S3 Vectors permission denial)."""

    def test_includes_knowledge_base_association(self):
        from unittest.mock import MagicMock

        from cloudctl.debug.fetcher import DebugFetcher

        ba = MagicMock()
        ba.list_agents.return_value = {
            "agentSummaries": [{"agentId": "AG123", "agentName": "rag-assistant-agent"}],
        }
        ba.get_agent.return_value = {"agent": {
            "agentName": "rag-assistant-agent", "agentStatus": "PREPARED",
            "foundationModel": "anthropic.claude-3", "instruction": "x",
            "idleSessionTTLInSeconds": 600,
        }}
        ba.list_agent_aliases.return_value = {"agentAliasSummaries": []}
        ba.list_agent_action_groups.return_value = {"actionGroupSummaries": []}
        ba.list_agent_knowledge_bases.return_value = {
            "agentKnowledgeBaseSummaries": [
                {"knowledgeBaseId": "KB456", "knowledgeBaseState": "ENABLED"},
            ],
        }

        session = MagicMock()
        session.client.return_value = ba

        result = DebugFetcher(session).bedrock_agent_config("rag-assistant-agent")

        assert result["knowledge_bases"] == [
            {"knowledge_base_id": "KB456", "state": "ENABLED"},
        ]

    def test_missing_knowledge_base_yields_empty_list(self):
        from unittest.mock import MagicMock

        from cloudctl.debug.fetcher import DebugFetcher

        ba = MagicMock()
        ba.list_agents.return_value = {
            "agentSummaries": [{"agentId": "AG123", "agentName": "rag-assistant-agent"}],
        }
        ba.get_agent.return_value = {"agent": {
            "agentName": "rag-assistant-agent", "agentStatus": "PREPARED",
            "foundationModel": "anthropic.claude-3", "instruction": "x",
            "idleSessionTTLInSeconds": 600,
        }}
        ba.list_agent_aliases.return_value = {"agentAliasSummaries": []}
        ba.list_agent_action_groups.return_value = {"actionGroupSummaries": []}
        ba.list_agent_knowledge_bases.return_value = {"agentKnowledgeBaseSummaries": []}

        session = MagicMock()
        session.client.return_value = ba

        result = DebugFetcher(session).bedrock_agent_config("rag-assistant-agent")

        assert result["knowledge_bases"] == []


class TestLambdaEventSourceMappingsFetcher:
    """Regression test for a real production miss: lambda_function_config
    never fetched event source mappings, so when an MSK/Kafka poller's own
    auth fails, the Lambda is never invoked at all (zero logs, zero
    metrics) and the agent had no tool-visible way to see the real failure
    — it guessed "cluster was recreated" from circumstantial CloudTrail
    timing instead of the actual AccessDenied surfaced in
    StateTransitionReason/LastProcessingResult."""

    def _make_session(self, mappings):
        from unittest.mock import MagicMock

        lmb = MagicMock()
        lmb.list_functions.return_value = {"Functions": [{"FunctionName": "streaming-etl-consumer"}]}
        lmb.get_function_configuration.return_value = {
            "FunctionName": "streaming-etl-consumer", "Runtime": "python3.11",
            "Handler": "handler.handler", "MemorySize": 256, "Timeout": 30,
            "State": "Active",
        }
        lmb.get_function_concurrency.return_value = {}
        lmb.list_event_source_mappings.return_value = {"EventSourceMappings": mappings}

        session = MagicMock()
        session.client.return_value = lmb
        return session

    def test_surfaces_access_denied_state_transition_reason(self):
        from cloudctl.debug.fetcher import DebugFetcher
        session = self._make_session([{
            "UUID": "abc-123",
            "EventSourceArn": "arn:aws:kafka:us-east-1:123:cluster/streaming-etl-cluster/xyz",
            "State": "Enabled",
            "StateTransitionReason": "PROBLEM: AccessDeniedException calling kafka-cluster:Connect",
            "LastProcessingResult": "PROBLEM: KMSAccessDeniedException encountered",
            "LastModified": "2026-06-24T01:00:00Z",
        }])

        result = DebugFetcher(session).lambda_function_config("streaming-etl-consumer")

        assert len(result["event_source_mappings"]) == 1
        esm = result["event_source_mappings"][0]
        assert "AccessDeniedException" in esm["state_transition_reason"]
        assert "AccessDeniedException" in esm["last_processing_result"]

    def test_no_mappings_yields_empty_list(self):
        from cloudctl.debug.fetcher import DebugFetcher
        session = self._make_session([])

        result = DebugFetcher(session).lambda_function_config("streaming-etl-consumer")

        assert result["event_source_mappings"] == []


class TestEventBridgeCustomBusFetcher:
    """Regression test for a real production miss: eventbridge_rule_config
    called list_rules()/list_targets_by_rule() without EventBusName, which
    only searches the DEFAULT bus — a rule on a custom bus is invisible.
    The agent concluded "no rule exists" with HIGH confidence on
    streaming-etl (whose only rule lives on a custom bus), when the rule
    was there all along."""

    def _make_session(self):
        from unittest.mock import MagicMock

        eb = MagicMock()
        eb.list_event_buses.return_value = {"EventBuses": [
            {"Name": "default"}, {"Name": "streaming-etl-bus"},
        ]}

        def _list_rules(NamePrefix=None, EventBusName=None):  # noqa: N803
            if EventBusName == "streaming-etl-bus":
                return {"Rules": [{"Name": "streaming-etl-rule", "State": "ENABLED",
                                   "EventPattern": '{"source":["streaming-etl.app"]}',
                                   "EventBusName": "streaming-etl-bus"}]}
            return {"Rules": []}

        eb.list_rules.side_effect = _list_rules
        eb.list_targets_by_rule.return_value = {"Targets": [
            {"Id": "1", "Arn": "arn:aws:lambda:us-east-1:123:function:streaming-etl-eb-target"},
        ]}

        session = MagicMock()
        session.client.return_value = eb
        return session

    def test_finds_rule_on_custom_bus(self):
        from cloudctl.debug.fetcher import DebugFetcher
        session = self._make_session()

        result = DebugFetcher(session).eventbridge_rule_config("streaming-etl-rule")

        assert result["name"] == "streaming-etl-rule"
        assert result["event_bus"] == "streaming-etl-bus"
        assert len(result["targets"]) == 1

    def test_no_rule_anywhere_yields_empty_dict(self):
        from unittest.mock import MagicMock

        from cloudctl.debug.fetcher import DebugFetcher

        eb = MagicMock()
        eb.list_event_buses.return_value = {"EventBuses": [{"Name": "default"}]}
        eb.list_rules.return_value = {"Rules": []}
        session = MagicMock()
        session.client.return_value = eb

        result = DebugFetcher(session).eventbridge_rule_config("nonexistent-rule")

        assert result == {}


class TestSerialise:
    """Regression test for a real production miss: get_service_config's
    _serialise() helper had no bytes handling, so when waf_web_acl_config
    surfaced a WAF rule's byte_match_statement.search_string (which AWS
    returns as a raw bytes Blob, not str), json.dumps crashed with
    'Object of type bytes is not JSON serializable' — and crashed the
    entire run_incidents.sh batch, not just that one tool call."""

    def test_utf8_bytes_decoded_to_string(self):
        import json

        from cloudctl.mcp.tools.debug import _serialise
        result = _serialise({"search_string": b"v2"})
        assert result == {"search_string": "v2"}
        json.dumps(result)  # must not raise

    def test_non_utf8_bytes_get_a_placeholder_not_a_crash(self):
        import json

        from cloudctl.mcp.tools.debug import _serialise
        result = _serialise({"blob": b"\xff\xfe\x00\x01"})
        assert "not UTF-8" in result["blob"]
        json.dumps(result)  # must not raise

    def test_bytes_nested_in_list_and_dict(self):
        import json

        from cloudctl.mcp.tools.debug import _serialise
        result = _serialise({"rules": [{"statement": {"search_string": b"v2"}}]})
        assert result["rules"][0]["statement"]["search_string"] == "v2"
        json.dumps(result)  # must not raise


class TestCognitoUserPoolConfigFetcher:
    """cognito-auth's user_pool_client_misconfigured incident hinges entirely
    on the App Client's explicit_auth_flows — a config-drift fault with no
    log or metric signal at all. Before this fetcher, cloudctl had zero
    Cognito support anywhere; the agent could see the trigger Lambdas
    themselves but had no way to see which triggers are wired to the pool
    or what auth flows an App Client allows."""

    def _make_session(self, lambda_config=None, explicit_auth_flows=None):
        from unittest.mock import MagicMock

        idp = MagicMock()
        idp.list_user_pools.return_value = {"UserPools": [
            {"Id": "us-east-1_abc123", "Name": "cognito-auth-pool"},
        ]}
        idp.describe_user_pool.return_value = {"UserPool": {
            "Id": "us-east-1_abc123", "Name": "cognito-auth-pool",
            "Arn": "arn:aws:cognito-idp:us-east-1:123:userpool/us-east-1_abc123",
            "Status": "ACTIVE", "MfaConfiguration": "OFF",
            "LambdaConfig": lambda_config or {},
            "AutoVerifiedAttributes": ["email"], "EstimatedNumberOfUsers": 0,
        }}
        idp.list_user_pool_clients.return_value = {"UserPoolClients": [
            {"ClientId": "client123"},
        ]}
        idp.describe_user_pool_client.return_value = {"UserPoolClient": {
            "ClientId": "client123", "ClientName": "cognito-auth-client",
            "ExplicitAuthFlows": explicit_auth_flows or [],
            "AccessTokenValidity": 1, "IdTokenValidity": 1,
        }}
        session = MagicMock()
        session.client.return_value = idp
        return session

    def test_surfaces_lambda_trigger_wiring(self):
        from cloudctl.debug.fetcher import DebugFetcher
        session = self._make_session(lambda_config={
            "PreAuthentication": "arn:aws:lambda:us-east-1:123:function:cognito-auth-pre-auth",
            "PostConfirmation": "arn:aws:lambda:us-east-1:123:function:cognito-auth-post-confirmation",
        })

        result = DebugFetcher(session).cognito_user_pool_config("cognito-auth-pool")

        assert result["lambda_config"]["PreAuthentication"].endswith("cognito-auth-pre-auth")
        assert result["lambda_config"]["PostConfirmation"].endswith("cognito-auth-post-confirmation")

    def test_surfaces_app_client_auth_flows(self):
        from cloudctl.debug.fetcher import DebugFetcher
        session = self._make_session(explicit_auth_flows=["ALLOW_REFRESH_TOKEN_AUTH"])

        result = DebugFetcher(session).cognito_user_pool_config("cognito-auth-pool")

        flows = result["app_clients"][0]["explicit_auth_flows"]
        assert "ALLOW_USER_PASSWORD_AUTH" not in flows
        assert "ALLOW_REFRESH_TOKEN_AUTH" in flows

    def test_no_pool_found_yields_empty_dict(self):
        from unittest.mock import MagicMock

        from cloudctl.debug.fetcher import DebugFetcher

        idp = MagicMock()
        idp.list_user_pools.return_value = {"UserPools": []}
        session = MagicMock()
        session.client.return_value = idp

        result = DebugFetcher(session).cognito_user_pool_config("nonexistent-pool")

        assert result == {}


class TestAppsyncApiConfigFetcher:
    """appsync-graphql's resolver_misconfigured incident is a response
    mapping template bug that returns a wrong-but-valid value (silent data
    corruption, not an error) — AppSync produces zero log signal for this
    unless field-level logging is explicitly enabled. The agent's only way
    to find it is reading the actual mapping template text via this
    fetcher; before this, cloudctl had zero AppSync support."""

    def _make_session(self, response_mapping_template=None, auth_type="API_KEY",
                       additional_auth=None):
        from unittest.mock import MagicMock

        appsync = MagicMock()
        appsync.list_graphql_apis.return_value = {"graphqlApis": [
            {"apiId": "abc123", "name": "appsync-graphql-api", "authenticationType": auth_type,
             "additionalAuthenticationProviders": additional_auth or []},
        ]}
        appsync.list_data_sources.return_value = {"dataSources": [
            {"name": "ItemsDataSource", "type": "AMAZON_DYNAMODB",
             "serviceRoleArn": "arn:aws:iam::123:role/appsync-ds-role",
             "dynamodbConfig": {"tableName": "appsync-graphql-items"}},
        ]}

        def _list_resolvers(apiId, typeName):  # noqa: N803
            if typeName == "Query":
                return {"resolvers": [{
                    "fieldName": "getItem", "dataSourceName": "ItemsDataSource",
                    "kind": "UNIT", "requestMappingTemplate": "## req",
                    "responseMappingTemplate": response_mapping_template or "$util.toJson($ctx.result)",
                }]}
            return {"resolvers": []}

        appsync.list_resolvers.side_effect = _list_resolvers
        appsync.list_api_keys.return_value = {"apiKeys": [{"id": "key123", "expires": 1735000000}]}

        session = MagicMock()
        session.client.return_value = appsync
        return session

    def test_surfaces_resolver_response_mapping_template(self):
        from cloudctl.debug.fetcher import DebugFetcher
        session = self._make_session(response_mapping_template="$util.toJson($ctx.result.wrongField)")

        result = DebugFetcher(session).appsync_api_config("appsync-graphql-api")

        query_resolvers = [r for r in result["resolvers"] if r["type_name"] == "Query"]
        assert query_resolvers[0]["response_mapping_template"] == "$util.toJson($ctx.result.wrongField)"

    def test_surfaces_auth_mode_and_additional_providers(self):
        from cloudctl.debug.fetcher import DebugFetcher
        session = self._make_session(auth_type="AMAZON_COGNITO_USER_POOLS",
                                       additional_auth=[{"authenticationType": "API_KEY"}])

        result = DebugFetcher(session).appsync_api_config("appsync-graphql-api")

        assert result["authentication_type"] == "AMAZON_COGNITO_USER_POOLS"
        types = [p["type"] for p in result["additional_authentication_providers"]]
        assert "API_KEY" in types

    def test_no_api_found_yields_empty_dict(self):
        from unittest.mock import MagicMock

        from cloudctl.debug.fetcher import DebugFetcher

        appsync = MagicMock()
        appsync.list_graphql_apis.return_value = {"graphqlApis": []}
        session = MagicMock()
        session.client.return_value = appsync

        result = DebugFetcher(session).appsync_api_config("nonexistent-api")

        assert result == {}


class TestEfsFilesystemConfigFetcher:
    def test_efs_filesystem_config(self):
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher

        efs = MagicMock()
        efs.describe_file_systems.return_value = {"FileSystems": [
            {"FileSystemId": "fs-12345678", "Name": "efs-shared-storage", "LifeCycleState": "available",
             "PerformanceMode": "generalPurpose", "ThroughputMode": "bursting", "Encrypted": True, "NumberOfMountTargets": 1}
        ]}
        efs.describe_mount_targets.return_value = {"MountTargets": [
            {"MountTargetId": "fsmt-12345", "SubnetId": "subnet-abc", "AvailabilityZoneName": "us-east-1a",
             "LifeCycleState": "available", "IpAddress": "10.0.0.5"}
        ]}
        efs.describe_mount_target_security_groups.return_value = {"SecurityGroups": ["sg-123"]}
        efs.describe_access_points.return_value = {"AccessPoints": []}

        ec2 = MagicMock()
        ec2.describe_security_groups.return_value = {"SecurityGroups": [
            {"GroupId": "sg-123", "GroupName": "efs-sg", "IpPermissions": []}
        ]}

        session = MagicMock()
        session.client.side_effect = lambda svc, **kw: {"efs": efs, "ec2": ec2}.get(svc)

        result = DebugFetcher(session).efs_filesystem_config("efs-shared-storage")
        assert result["filesystem_id"] == "fs-12345678"
        assert result["name"] == "efs-shared-storage"
        assert len(result["mount_targets"]) == 1
        assert result["mount_targets"][0]["security_groups"] == ["sg-123"]


class TestBatchConfigFetcher:
    def test_batch_config(self):
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher

        batch = MagicMock()
        batch.describe_compute_environments.return_value = {"computeEnvironments": [
            {"computeEnvironmentName": "batch-compute-env", "computeEnvironmentArn": "arn:aws:batch:us-east-1:123:compute-environment/batch-compute-env",
             "type": "MANAGED", "state": "ENABLED", "status": "VALID", "computeResources": {"subnets": ["subnet-1"]}}
        ]}
        batch.describe_job_queues.return_value = {"jobQueues": [
            {"jobQueueName": "batch-job-queue", "jobQueueArn": "arn:aws:batch:us-east-1:123:job-queue/batch-job-queue",
             "state": "ENABLED", "status": "VALID", "priority": 1, "computeEnvironmentOrder": []}
        ]}
        batch.describe_job_definitions.return_value = {"jobDefinitions": [
            {"jobDefinitionName": "batch-job-def", "jobDefinitionArn": "arn:aws:batch:us-east-1:123:job-definition/batch-job-def:1",
             "revision": 1, "status": "ACTIVE", "type": "container", "containerProperties": {"image": "busybox"}}
        ]}
        batch.list_jobs.return_value = {"jobSummaryList": []}

        session = MagicMock()
        session.client.return_value = batch

        result = DebugFetcher(session).batch_config("batch")
        assert len(result["compute_environments"]) == 1
        assert result["compute_environments"][0]["name"] == "batch-compute-env"
        assert len(result["job_queues"]) == 1
        assert result["job_queues"][0]["name"] == "batch-job-queue"
        assert len(result["job_definitions"]) == 1
        assert result["job_definitions"][0]["name"] == "batch-job-def"


class TestEfsAndBatchListers:
    def test_list_efs(self):
        from unittest.mock import MagicMock
        from cloudctl.mcp.tools.debug import _list_efs

        efs = MagicMock()
        efs.describe_file_systems.return_value = {"FileSystems": [{"FileSystemId": "fs-1234"}]}
        session = MagicMock()
        session.client.return_value = efs

        assert _list_efs(session) == ["fs-1234"]

    def test_list_batch(self):
        from unittest.mock import MagicMock
        from cloudctl.mcp.tools.debug import _list_batch

        batch = MagicMock()
        batch.describe_compute_environments.return_value = {"computeEnvironments": [{"computeEnvironmentName": "env-1"}]}
        batch.describe_job_queues.return_value = {"jobQueues": [{"jobQueueName": "queue-1"}]}
        batch.describe_job_definitions.return_value = {"jobDefinitions": [{"jobDefinitionName": "def-1"}]}
        session = MagicMock()
        session.client.return_value = batch

        assert _list_batch(session) == ["env-1", "queue-1", "def-1"]


class TestGenericResourceFetcher:
    def test_generic_fallback_tagging_and_cloudcontrol(self):
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher

        # Mock tagging client
        tagging = MagicMock()
        tagging.get_resources.return_value = {
            "ResourceTagMappingList": [
                {
                    "ResourceARN": "arn:aws:mq:us-east-1:123456789012:broker:my-broker",
                    "Tags": [{"Key": "Name", "Value": "my-broker"}, {"Key": "Env", "Value": "Prod"}]
                }
            ]
        }

        # Mock cloudcontrol client
        cc = MagicMock()
        cc.get_resource.return_value = {
            "ResourceDescription": {
                "Properties": '{"BrokerName": "my-broker", "EngineType": "ActiveMQ"}'
            }
        }

        session = MagicMock()
        def get_client(service, **kwargs):
            if service == "resourcegroupstaggingapi":
                return tagging
            if service == "cloudcontrol":
                return cc
            return MagicMock()

        session.client.side_effect = get_client

        fetcher = DebugFetcher(session)
        res = fetcher.generic_resource_config("mq", "my-broker")
        assert res["BrokerName"] == "my-broker"
        assert res["EngineType"] == "ActiveMQ"
        assert res["tags"] == {"Name": "my-broker", "Env": "Prod"}
        assert res["_fetch_method"] == "cloudcontrol"

    def test_generic_fallback_boto3_reflection(self):
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher

        # Mock tagging client
        tagging = MagicMock()
        tagging.get_resources.return_value = {
            "ResourceTagMappingList": [
                {
                    "ResourceARN": "arn:aws:mq:us-east-1:123456789012:broker:my-broker",
                    "Tags": [{"Key": "Name", "Value": "my-broker"}]
                }
            ]
        }

        # Cloudcontrol client returns error
        cc = MagicMock()
        cc.get_resource.side_effect = Exception("Not supported")

        # Mock mq client for reflection
        mq = MagicMock()
        mq.meta.service_model.operation_names = ["DescribeBroker"]
        op_model = MagicMock()
        op_model.py_name = "describe_broker"
        input_shape = MagicMock()
        input_shape.members = ["BrokerId"]
        op_model.input_shape = input_shape
        mq.meta.service_model.operation_model.return_value = op_model

        mq.describe_broker.return_value = {
            "BrokerName": "my-broker",
            "BrokerId": "my-broker",
            "EngineType": "RabbitMQ"
        }

        session = MagicMock()
        def get_client(service, **kwargs):
            if service == "resourcegroupstaggingapi":
                return tagging
            if service == "cloudcontrol":
                return cc
            if service == "mq":
                return mq
            return MagicMock()

        session.client.side_effect = get_client

        fetcher = DebugFetcher(session)
        res = fetcher.generic_resource_config("mq", "my-broker")
        assert res["BrokerName"] == "my-broker"
        assert res["EngineType"] == "RabbitMQ"
        assert res["_fetch_method"] == "boto3_reflection"

    def test_generic_fallback_dependency_enrichment(self):
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher

        # Mock tagging client
        tagging = MagicMock()
        tagging.get_resources.return_value = {
            "ResourceTagMappingList": [
                {
                    "ResourceARN": "arn:aws:mq:us-east-1:123456789012:broker:my-broker",
                    "Tags": []
                }
            ]
        }

        # Mock cloudcontrol returning dependency strings
        cc = MagicMock()
        cc.get_resource.return_value = {
            "ResourceDescription": {
                "Properties": (
                    '{"SecurityGroups": ["sg-abc1234"], "RoleArn": "arn:aws:iam::123456789012:role/app-role", '
                    '"SubnetId": "subnet-abc987f", "VpcId": "vpc-111222", '
                    '"KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"}'
                )
            }
        }

        # Mock all the enrichment clients
        ec2 = MagicMock()
        ec2.describe_security_groups.return_value = {
            "SecurityGroups": [{
                "GroupId": "sg-abc1234", "GroupName": "app-sg", "VpcId": "vpc-111222",
                "IpPermissions": [{"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}],
                "IpPermissionsEgress": []
            }]
        }
        ec2.describe_subnets.return_value = {
            "Subnets": [{"SubnetId": "subnet-abc987f", "VpcId": "vpc-111222", "CidrBlock": "10.0.1.0/24"}]
        }
        ec2.describe_vpcs.return_value = {
            "Vpcs": [{"VpcId": "vpc-111222", "CidrBlock": "10.0.0.0/16"}]
        }
        ec2.describe_route_tables.return_value = {"RouteTables": []}

        iam = MagicMock()
        iam.get_role.return_value = {
            "Role": {"RoleName": "app-role", "AssumeRolePolicyDocument": {}}
        }
        iam.list_role_policies.return_value = {"PolicyNames": ["inline-1"]}
        iam.get_role_policy.return_value = {"PolicyDocument": {"Statement": []}}
        iam.list_attached_role_policies.return_value = {"AttachedPolicies": []}

        kms = MagicMock()
        kms.describe_key.return_value = {
            "KeyMetadata": {"KeyId": "12345678-1234-1234-1234-123456789012", "Arn": "arn:aws:kms:...", "Enabled": True}
        }
        kms.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}
        kms.get_key_policy.return_value = {"Policy": "{}"}

        session = MagicMock()
        def get_client(service, **kwargs):
            if service == "resourcegroupstaggingapi":
                return tagging
            if service == "cloudcontrol":
                return cc
            if service == "ec2":
                return ec2
            if service == "iam":
                return iam
            if service == "kms":
                return kms
            return MagicMock()

        session.client.side_effect = get_client

        fetcher = DebugFetcher(session)
        res = fetcher.generic_resource_config("mq", "my-broker")
        assert "_resolved_security_groups" in res
        assert "_resolved_iam_roles" in res
        assert "_resolved_kms_keys" in res
        assert "_resolved_network_resources" in res

        assert res["_resolved_security_groups"]["sg-abc1234"]["group_name"] == "app-sg"
        assert res["_resolved_iam_roles"]["arn:aws:iam::123456789012:role/app-role"]["role_name"] == "app-role"
        assert res["_resolved_network_resources"]["subnet-abc987f"]["cidr_block"] == "10.0.1.0/24"
        assert res["_resolved_network_resources"]["vpc-111222"]["cidr_block"] == "10.0.0.0/16"
        assert res["_resolved_kms_keys"]["arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"]["rotation_enabled"] is True

    def test_generic_fallback_last_resort(self):
        from unittest.mock import MagicMock
        from cloudctl.debug.fetcher import DebugFetcher

        tagging = MagicMock()
        tagging.get_resources.return_value = {
            "ResourceTagMappingList": [
                {
                    "ResourceARN": "arn:aws:mq:us-east-1:123456789012:broker:my-broker",
                    "Tags": [{"Key": "foo", "Value": "bar"}]
                }
            ]
        }

        # CC and Boto3 reflect fail
        cc = MagicMock()
        cc.get_resource.side_effect = Exception("unsupported")

        session = MagicMock()
        def get_client(service, **kwargs):
            if service == "resourcegroupstaggingapi":
                return tagging
            if service == "cloudcontrol":
                return cc
            return MagicMock()

        session.client.side_effect = get_client

        fetcher = DebugFetcher(session)
        res = fetcher.generic_resource_config("mq", "my-broker")
        assert res["resource_arn"] == "arn:aws:mq:us-east-1:123456789012:broker:my-broker"
        assert res["tags"] == {"foo": "bar"}
        assert res["_fetch_method"] == "tagging_api"


class TestDebugToolsFallback:
    def test_get_service_config_unregistered_fallback(self):
        from unittest.mock import MagicMock, patch
        import json
        from cloudctl.mcp.tools.debug import get_service_config

        session = MagicMock()
        with patch("cloudctl.mcp.tools.debug._make_session", return_value=session):
            with patch("cloudctl.debug.fetcher.DebugFetcher.generic_resource_config") as mock_generic:
                mock_generic.return_value = {"BrokerName": "my-broker"}
                
                res_str = get_service_config(
                    service_type="mq",
                    resource_hint="my-broker",
                    profile=None,
                    region="us-east-1"
                )
                res = json.loads(res_str)
                assert res["found"] is True
                assert res["service_type"] == "mq"
                assert res["config"]["BrokerName"] == "my-broker"
                mock_generic.assert_called_once_with(service_type="mq", resource_name="my-broker")

    def test_list_resources_unregistered_fallback(self):
        from unittest.mock import MagicMock, patch
        import json
        from cloudctl.mcp.tools.debug import list_resources

        tagger = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"ResourceTagMappingList": [{"ResourceARN": "arn:aws:mq:us-east-1:123:broker:my-broker"}]}
        ]
        tagger.get_paginator.return_value = paginator

        session = MagicMock()
        session.client.return_value = tagger

        with patch("cloudctl.mcp.tools.debug._make_session", return_value=session):
            res_str = list_resources(
                service_type="mq",
                profile=None,
                region="us-east-1"
            )
            res = json.loads(res_str)
            assert res["service_type"] == "mq"
            assert res["count"] == 1
            assert res["resources"] == ["arn:aws:mq:us-east-1:123:broker:my-broker"]
