"""
Deployment method detector — identifies how a cloud resource is managed.

Detection order (same logic for every cloud):
  1. Tags / Labels        — fastest, no extra API calls
  2. Deployment registry  — cloud-specific service that tracks what deployed a resource
       AWS:   CloudFormation describe_stack_resources + stack CDK tags
       Azure: ARM Deployment history (ResourceManagementClient.deployments)
       GCP:   Deployment Manager API (deploymentmanager.deployments.list)
  3. Audit trail          — who last modified this resource
       AWS:   CloudTrail  lookup_events → userAgent (definitive) + Username (secondary)
       Azure: Activity Log (MonitorManagementClient.activity_logs) → HTTP userAgent + caller
       GCP:   Cloud Audit Logs (google.cloud.logging) → callerSuppliedUserAgent + principalEmail
"""
from __future__ import annotations

from typing import Optional

_TF_UA = "hashicorp terraform"


def _tool_from_useragent(ua: str) -> str:
    """Return IaC tool name detected in an AWS CloudTrail userAgent, or empty string."""
    if _TF_UA in ua:
        return "terraform"
    if "pulumi" in ua:
        return "pulumi"
    if "aws-cdk" in ua:
        return "cdk"
    return ""


def _tool_from_http_useragent(ua: str) -> str:
    """Return IaC tool name from an Azure/GCP HTTP userAgent (no CDK — CDK is AWS-only)."""
    if _TF_UA in ua:
        return "terraform"
    if "pulumi" in ua:
        return "pulumi"
    return ""


def _tool_from_cloudtrail_username(u: str) -> str:
    """Return tool detected in a CloudTrail Username field, or empty string."""
    if "codepipeline" in u:
        return "codepipeline"
    if "github-actions" in u or "github.com" in u:
        return "github-actions"
    if "terraform" in u:
        return "terraform"
    if "pulumi" in u:
        return "pulumi"
    return ""


def _tool_from_azure_caller(caller: str) -> str:
    """Return tool detected in an Azure Activity Log caller field, or empty string."""
    if "vstoken" in caller or "vstfs" in caller or "azure devops" in caller or "azdo" in caller:
        return "azure-devops"
    if "github" in caller or "github-actions" in caller:
        return "github-actions"
    if "terraform" in caller:
        return "terraform"
    if "pulumi" in caller:
        return "pulumi"
    if "bicep" in caller:
        return "bicep"
    return ""


def _tool_from_gcp_email(email: str) -> str:
    """Return tool detected in a GCP principalEmail, or empty string."""
    if "cnrm-controller-manager" in email or "cnrm" in email:
        return "config-connector"
    if "cloudbuild" in email:
        return "cloud-build"
    if "cloudservices" in email:
        return "deployment-manager"
    if "terraform" in email:
        return "terraform"
    if "pulumi" in email:
        return "pulumi"
    if "github" in email:
        return "github-actions"
    return ""


KNOWN_METHODS = [
    # AWS
    "cdk", "cloudformation", "codepipeline",
    # Cross-cloud IaC
    "terraform", "pulumi",
    # Azure
    "bicep", "arm", "azure-devops",
    # GCP
    "deployment-manager", "config-connector", "cloud-build",
    # CI/CD (cloud-agnostic)
    "github-actions",
    "unknown",
]


def detect(
    cloud: str,
    # AWS
    session=None,
    resource_arn: Optional[str] = None,
    resource_tags: Optional[dict] = None,
    # Azure
    azure_credential=None,
    subscription_id: Optional[str] = None,
    resource_id: Optional[str] = None,
    resource_group: Optional[str] = None,
    # GCP
    gcp_project: Optional[str] = None,
    gcp_resource_name: Optional[str] = None,
    gcp_labels: Optional[dict] = None,
) -> str:
    """
    Detect the deployment method for a resource.
    Returns a string from KNOWN_METHODS.
    """
    if cloud == "aws":
        return _detect_aws(session, resource_arn, resource_tags or {})
    if cloud == "azure":
        return _detect_azure(
            resource_tags or {},
            azure_credential, subscription_id,
            resource_id, resource_group,
        )
    if cloud == "gcp":
        return _detect_gcp(gcp_labels or {}, gcp_project, gcp_resource_name)

    # Fallback: tag-only scan for unknown clouds
    return _tags_crosscloud(resource_tags or gcp_labels or {})


# ════════════════════════════════════════════════════════════════════════════
# AWS
# ════════════════════════════════════════════════════════════════════════════

def _detect_aws(session, resource_arn: Optional[str], tags: dict) -> str:
    # 1. Tags (Terraform/Pulumi stamp tags on AWS resources)
    m = _tags_crosscloud(tags)
    if m != "unknown":
        return m

    if not session:
        return "unknown"

    # 2. CloudFormation deployment registry → CDK or raw CF
    if resource_arn:
        m = _aws_cfn_registry(session, resource_arn)
        if m != "unknown":
            return m

    # 3. CloudTrail audit trail → last modifier principal
    if resource_arn:
        m = _aws_cloudtrail(session, resource_arn)
        if m != "unknown":
            return m

    return "unknown"


def _aws_cfn_registry(session, resource_arn: str) -> str:
    """CloudFormation describe_stack_resources + inspect template body for CDK fingerprints."""
    import json  # noqa: PLC0415
    import re    # noqa: PLC0415
    try:
        cf     = session.client("cloudformation")
        resp   = cf.describe_stack_resources(PhysicalResourceId=resource_arn)
        stacks = resp.get("StackResources", [])
        if not stacks:
            return "unknown"
        stack_name = stacks[0]["StackName"]

        # Inspect template body — CDK leaves structural fingerprints inside the
        # template regardless of whether the team added any explicit tags
        try:
            tpl_resp = cf.get_template(StackName=stack_name)
            template = tpl_resp.get("TemplateBody", {})
            if isinstance(template, str):
                template = json.loads(template)
            resources = template.get("Resources", {})

            # CDKMetadata resource — CDK injects this into every stack it generates
            if "CDKMetadata" in resources:
                return "cdk"

            # aws:cdk:path in any resource's Metadata block
            for resource_def in resources.values():
                if "aws:cdk:path" in resource_def.get("Metadata", {}):
                    return "cdk"

            # aws:cdk:path anywhere in the template (belt and suspenders)
            if "aws:cdk:path" in json.dumps(template):
                return "cdk"

            # CDK logical ID pattern: ends with exactly 8 uppercase hex chars
            # e.g. "PaymentsApiServiceD4F8B3A2" — raw CF uses human-chosen IDs
            cdk_id_pattern = re.compile(r"^.+[A-F0-9]{8}$")
            cdk_id_count = sum(1 for k in resources if cdk_id_pattern.match(k))
            if resources and cdk_id_count > len(resources) * 0.5:
                return "cdk"
        except Exception:  # noqa: BLE001
            pass

        # Also check CDKToolkit bootstrap stack — present in every CDK-bootstrapped account
        try:
            cf.describe_stacks(StackName="CDKToolkit")
            return "cdk"
        except Exception:  # noqa: BLE001
            pass

        return "cloudformation"
    except Exception:  # noqa: BLE001
        return "unknown"


def _aws_cloudtrail(session, resource_arn: str) -> str:
    """CloudTrail lookup_events — check userAgent (definitive) then Username (secondary)."""
    import json as _json  # noqa: PLC0415
    from datetime import datetime, timedelta, timezone  # noqa: PLC0415
    try:
        ct    = session.client("cloudtrail")
        end   = datetime.now(timezone.utc)
        resp  = ct.lookup_events(
            LookupAttributes=[{"AttributeKey": "ResourceName", "AttributeValue": resource_arn}],
            StartTime=end - timedelta(hours=24),
            EndTime=end,
            MaxResults=10,
        )
        for ev in resp.get("Events", []):
            # Parse full CloudTrail JSON to get userAgent — IaC tools always set this
            detail = _json.loads(ev.get("CloudTrailEvent", "{}"))
            ua = detail.get("userAgent", "").lower()
            u  = (ev.get("Username") or "").lower()

            # userAgent is definitive — cannot be suppressed by the caller
            tool = _tool_from_useragent(ua) or _tool_from_cloudtrail_username(u)
            if tool:
                return tool
    except Exception:  # noqa: BLE001
        pass
    return "unknown"


# ════════════════════════════════════════════════════════════════════════════
# Azure
# ════════════════════════════════════════════════════════════════════════════

def _detect_azure(
    tags: dict,
    credential,
    subscription_id: Optional[str],
    resource_id: Optional[str],
    resource_group: Optional[str],
) -> str:
    # 1. Tags
    m = _tags_azure(tags)
    if m != "unknown":
        return m

    if not credential or not subscription_id:
        return "unknown"

    # 2. ARM Deployment history — tells us Bicep vs raw ARM vs other tools
    if resource_group:
        m = _azure_arm_deployments(credential, subscription_id, resource_group)
        if m != "unknown":
            return m

    # 3. Activity Log — equivalent of CloudTrail, reveals the caller identity
    if resource_id:
        m = _azure_activity_log(credential, subscription_id, resource_id)
        if m != "unknown":
            return m

    return "unknown"


def _azure_arm_deployments(
    credential, subscription_id: str,
    resource_group: str,
) -> str:
    """
    ARM Deployment history via ResourceManagementClient.deployments.list_by_resource_group().
    Each deployment record includes template metadata; Bicep sets _generator.name = 'bicep'.
    """
    try:
        from azure.mgmt.resource import ResourceManagementClient  # noqa: PLC0415
        client = ResourceManagementClient(credential, subscription_id)
        for dep in client.deployments.list_by_resource_group(resource_group):
            # Get full deployment detail to read template metadata
            detail = client.deployments.get(resource_group, dep.name)
            props  = detail.properties or {}
            # template_hash is present on completed deployments; check _generator in template
            template = getattr(props, "template", None) or {}
            if isinstance(template, dict):
                gen = template.get("metadata", {}).get("_generator", {})
                if isinstance(gen, dict):
                    name = gen.get("name", "").lower()
                    if "bicep" in name:
                        return "bicep"
                    if "arm" in name:
                        return "arm"
                    # Empty/unknown generator — can't conclude from template alone
            # If we can't inspect the template, check the deployment name for hints.
            # Do NOT return "arm" if Terraform created the deployment — Terraform
            # azurerm creates ARM deployments internally; those are caught by
            # _azure_activity_log() via userAgent instead.
            dep_name = (dep.name or "").lower()
            if "bicep" in dep_name:
                return "bicep"
            if dep_name and "terraform" not in dep_name:
                return "arm"
    except Exception:  # noqa: BLE001
        pass
    return "unknown"


def _azure_activity_log(credential, subscription_id: str, resource_id: str) -> str:
    """
    Azure Activity Log via MonitorManagementClient.activity_logs.list().
    The `caller` field reveals who triggered the operation:
      - Azure DevOps service principals appear as vstoken://... or spn:{guid}
        with a display name containing "Azure DevOps" / "ADO"
      - GitHub Actions OIDC shows github.com/... in the caller
      - Terraform Cloud / Terraform Enterprise show up as their service account UPN
    """
    try:
        from azure.mgmt.monitor import MonitorManagementClient  # noqa: PLC0415
        from datetime import datetime, timedelta, timezone  # noqa: PLC0415

        client = MonitorManagementClient(credential, subscription_id)
        end    = datetime.now(timezone.utc)
        f      = (
            f"eventTimestamp ge '{(end - timedelta(hours=24)).isoformat()}' and "
            f"eventTimestamp le '{end.isoformat()}' and "
            f"resourceId eq '{resource_id}'"
        )
        for event in client.activity_logs.list(filter=f, select="caller,operationName,httpRequest"):
            caller       = (getattr(event, "caller", None) or "").lower()
            http_request = getattr(event, "http_request", None)

            # HTTP userAgent is definitive — Terraform azurerm always sets it
            if http_request:
                tool = _tool_from_http_useragent(str(http_request).lower())
                if tool:
                    return tool

            # caller field as secondary signal
            tool = _tool_from_azure_caller(caller)
            if tool:
                return tool
    except Exception:  # noqa: BLE001
        pass
    return "unknown"


def _tags_azure(tags: dict) -> str:
    """Detect Azure deployment method from resource tags."""
    lk = {k.lower(): (v.lower() if isinstance(v, str) else "") for k, v in tags.items()}

    # Bicep — bicep deployments may stamp a bicep-file or _generator tag
    if "bicep-file" in lk or "bicep_template" in lk or "bicep-template" in lk:
        return "bicep"
    if "bicep" in lk.get("_generator", "") or "bicep" in lk.get("deploymenttool", ""):
        return "bicep"

    # ARM — explicit arm-template tag
    if "arm-template" in lk or "arm_template" in lk:
        return "arm"
    if lk.get("deploymenttype", "") in ("arm", "arm-template"):
        return "arm"

    # Azure DevOps Pipelines
    if any(k in lk for k in ("azure-devops", "azdo-pipeline", "ado-pipeline")):
        return "azure-devops"
    if any("devops" in v or "azdo" in v for v in lk.values()):
        return "azure-devops"

    # managed-by catch-all
    mgd = lk.get("managed-by", lk.get("managedby", ""))
    if "bicep" in mgd:
        return "bicep"
    if "arm" in mgd:
        return "arm"
    if "devops" in mgd or "azdo" in mgd:
        return "azure-devops"

    return _tags_crosscloud(tags)


# ════════════════════════════════════════════════════════════════════════════
# GCP
# ════════════════════════════════════════════════════════════════════════════

def _detect_gcp(
    labels: dict,
    project: Optional[str],
    resource_name: Optional[str],
) -> str:
    # 1. Resource labels
    m = _labels_gcp(labels)
    if m != "unknown":
        return m

    if not project:
        return "unknown"

    # 2. Deployment Manager API — list deployments and check if resource is in one
    if resource_name:
        m = _gcp_deployment_manager(project, resource_name)
        if m != "unknown":
            return m

    # 3. Cloud Audit Logs — last modifier principal email reveals the tool
    if resource_name:
        m = _gcp_audit_logs(project, resource_name)
        if m != "unknown":
            return m

    return "unknown"


def _gcp_deployment_manager(project: str, resource_name: str) -> str:
    """
    GCP Deployment Manager API via googleapiclient.
    Lists deployments in the project and checks if the resource name appears
    in any deployment's manifest (resources list).
    """
    try:
        import google.auth  # noqa: PLC0415
        from googleapiclient import discovery  # noqa: PLC0415

        creds, _ = google.auth.default()
        svc      = discovery.build("deploymentmanager", "v2", credentials=creds)
        resp     = svc.deployments().list(project=project).execute()
        for dep in resp.get("deployments", []):
            dep_name = dep.get("name", "")
            # Fetch manifest to check resource list
            manifest_url = dep.get("manifest", "")
            if not manifest_url:
                continue
            manifest_name = manifest_url.split("/")[-1]
            manifest = svc.manifests().get(
                project=project, deployment=dep_name, manifest=manifest_name
            ).execute()
            for res in manifest.get("resources", {}).get("resources", []):
                if resource_name in (res.get("name", "") or ""):
                    return "deployment-manager"
    except Exception:  # noqa: BLE001
        pass
    return "unknown"


def _gcp_audit_logs(project: str, resource_name: str) -> str:
    """
    Cloud Audit Logs via google-cloud-logging.
    authenticationInfo.principalEmail reveals the tool:
      - Config Connector:    cnrm-controller-manager@{project}.iam.gserviceaccount.com
      - Deployment Manager:  {project-number}@cloudservices.gserviceaccount.com
      - Cloud Build:         {project-number}@cloudbuild.gserviceaccount.com
      - Terraform Cloud:     service account name set by user, often contains "terraform"
    """
    try:
        from google.cloud import logging as gcp_logging  # noqa: PLC0415
        from datetime import datetime, timedelta, timezone  # noqa: PLC0415

        client     = gcp_logging.Client(project=project)
        end        = datetime.now(timezone.utc)
        filter_str = (
            f'resource.name="{resource_name}" '
            f'timestamp>="{(end - timedelta(hours=24)).isoformat()}" '
            f'logName="projects/{project}/logs/cloudaudit.googleapis.com%2Factivity"'
        )
        for entry in client.list_entries(filter_=filter_str, max_results=10):
            payload = entry.payload if isinstance(entry.payload, dict) else {}

            # callerSuppliedUserAgent is definitive — always set by IaC tools
            ua = (
                payload.get("requestMetadata", {})
                       .get("callerSuppliedUserAgent", "") or ""
            ).lower()
            tool = _tool_from_http_useragent(ua)
            if tool:
                return tool

            # principalEmail as secondary signal
            email = (
                payload.get("authenticationInfo", {}).get("principalEmail", "") or ""
            ).lower()
            tool = _tool_from_gcp_email(email)
            if tool:
                return tool
    except Exception:  # noqa: BLE001
        pass
    return "unknown"


def _labels_gcp(labels: dict) -> str:
    """Detect GCP deployment method from resource labels."""
    lk = {k.lower(): (v.lower() if isinstance(v, str) else "") for k, v in labels.items()}

    # Config Connector stamps cnrm.cloud.google.com/* labels on every resource it manages
    if any(k.startswith("cnrm.cloud.google.com") for k in lk):
        return "config-connector"
    if lk.get("managed-by") == "config-connector" or lk.get("config-connector") == "true":
        return "config-connector"

    # Deployment Manager stamps dm-name or deployment-manager label
    if "dm-name" in lk or "deployment-manager" in lk or "gcp-deployment-manager" in lk:
        return "deployment-manager"
    if lk.get("managed-by") in ("deployment-manager", "gcp-deployment-manager"):
        return "deployment-manager"

    # Cloud Build — managed resources tagged with build trigger info
    if "cloud-build-id" in lk or lk.get("managed-by") == "cloud-build":
        return "cloud-build"

    return _tags_crosscloud(labels)


# ════════════════════════════════════════════════════════════════════════════
# Cross-cloud
# ════════════════════════════════════════════════════════════════════════════

def _tags_crosscloud(tags: dict) -> str:
    """Detect cross-cloud IaC tools (Terraform, Pulumi) from tags/labels."""
    lk = {k.lower(): (v.lower() if isinstance(v, str) else "") for k, v in tags.items()}

    # Terraform — all known tag/label patterns across providers
    _tf_keys = {
        "terraform",
        "terraform-workspace",
        "tf-workspace",
        "goog-terraform-provisioned",  # GCP google provider default label
    }
    _tf_managed_values = {"terraform", "terraform-cloud", "terraform-enterprise"}

    if any(k in lk for k in _tf_keys):
        return "terraform"
    if lk.get("managed-by", lk.get("managedby", "")) in _tf_managed_values:
        return "terraform"
    if lk.get("provisioner", "") == "terraform":
        return "terraform"
    if lk.get("iac-tool", "") == "terraform":
        return "terraform"

    # Pulumi — all known tag/label patterns
    _pulumi_keys = {"pulumi:project", "pulumi:stack", "pulumi:organization"}

    if any(k in lk for k in _pulumi_keys):
        return "pulumi"
    if lk.get("managed-by", lk.get("managedby", "")) == "pulumi":
        return "pulumi"
    if lk.get("iac-tool", "") == "pulumi":
        return "pulumi"

    return "unknown"


# ════════════════════════════════════════════════════════════════════════════
# IaC drift warnings
# ════════════════════════════════════════════════════════════════════════════

_DRIFT_WARNINGS: dict[str, str] = {
    # AWS
    "cdk":               "Direct changes will be overwritten on the next cdk deploy.",
    "cloudformation":    "Direct changes will be overwritten on the next stack update.",
    # Cross-cloud
    "terraform":         "Direct changes will be overwritten on the next terraform apply.",
    "pulumi":            "Direct changes will be overwritten on the next pulumi up.",
    # Azure
    "bicep":             "Direct changes will be overwritten on the next Bicep deployment (az deployment group create).",
    "arm":               "Direct changes will be overwritten on the next ARM template deployment.",
    "azure-devops":      "Direct changes will be overwritten when the Azure DevOps pipeline runs.",
    # GCP
    "deployment-manager": "Direct changes will be overwritten on the next gcloud deployment-manager deployments update.",
    "config-connector":   "Direct changes will be reconciled back by Config Connector. Edit the Kubernetes CR instead.",
    "cloud-build":        "Direct changes will be overwritten when the Cloud Build trigger runs.",
}


def iac_drift_warning(method: str) -> Optional[str]:
    """Return a calm, factual drift warning or None for CI-only / unknown methods."""
    return _DRIFT_WARNINGS.get(method.lower())
