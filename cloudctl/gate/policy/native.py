"""Native cloud guardrails, read before the gate approves anything.

The gate must never authorize what the organization's own controls deny.
These engines call each cloud's own policy service with the change's scoped
credentials (read-only calls):

AWS
    * IAM Access Analyzer ``ValidatePolicy`` on every IAM / resource policy
      document in the plan (errors and security warnings block).
    * ``iam:SimulatePrincipalPolicy`` for the gate's role on the create/delete
      action of each mapped resource type, in the requested region; a deny that
      comes from AWS Organizations (SCPs) is a CRITICAL finding.

Azure
    * Azure Policy ``checkPolicyRestrictions`` at the environment's resource
      group for each Azure resource: full ARM content for ARM/Bicep plans,
      type and location for Terraform (mapped types).

GCP
    * Organization Policy ``getEffectivePolicy`` on the project for
      ``gcp.resourceLocations``, ``compute.vmExternalIpAccess``,
      ``storage.publicAccessPrevention`` and ``iam.allowedPolicyMemberDomains``,
      checked against the planned resources.

Coverage is partial by nature: these services answer only for what they can
be asked about. Mapped resource types are listed in this module. Anything
the native engine cannot evaluate is reported in the engine run detail, not
silently passed, and the Rego rules and baseline scanners still apply. A
failing API call fails closed.

Required read permissions for the gate's identity: AWS
``access-analyzer:ValidatePolicy``, ``iam:SimulatePrincipalPolicy``; Azure
``Microsoft.PolicyInsights/checkPolicyRestrictions/action``; GCP
``orgpolicy.policy.get`` (Organization Policy Viewer on the project).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

from cloudctl.gate.models import EngineError, Finding, ResourceChange, Severity
from cloudctl.gate.policy.engine import PolicyContext

# ── AWS ──────────────────────────────────────────────────────────────────────

#: Terraform / CloudFormation type → (create action, delete action)
AWS_ACTIONS: dict[str, tuple[str, str]] = {
    "aws_instance": ("ec2:RunInstances", "ec2:TerminateInstances"),
    "AWS::EC2::Instance": ("ec2:RunInstances", "ec2:TerminateInstances"),
    "aws_launch_template": ("ec2:CreateLaunchTemplate", "ec2:DeleteLaunchTemplate"),
    "aws_vpc": ("ec2:CreateVpc", "ec2:DeleteVpc"),
    "AWS::EC2::VPC": ("ec2:CreateVpc", "ec2:DeleteVpc"),
    "aws_subnet": ("ec2:CreateSubnet", "ec2:DeleteSubnet"),
    "aws_security_group": ("ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup"),
    "AWS::EC2::SecurityGroup": ("ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup"),
    "aws_ebs_volume": ("ec2:CreateVolume", "ec2:DeleteVolume"),
    "aws_s3_bucket": ("s3:CreateBucket", "s3:DeleteBucket"),
    "AWS::S3::Bucket": ("s3:CreateBucket", "s3:DeleteBucket"),
    "aws_db_instance": ("rds:CreateDBInstance", "rds:DeleteDBInstance"),
    "AWS::RDS::DBInstance": ("rds:CreateDBInstance", "rds:DeleteDBInstance"),
    "aws_rds_cluster": ("rds:CreateDBCluster", "rds:DeleteDBCluster"),
    "AWS::RDS::DBCluster": ("rds:CreateDBCluster", "rds:DeleteDBCluster"),
    "aws_dynamodb_table": ("dynamodb:CreateTable", "dynamodb:DeleteTable"),
    "AWS::DynamoDB::Table": ("dynamodb:CreateTable", "dynamodb:DeleteTable"),
    "aws_lambda_function": ("lambda:CreateFunction", "lambda:DeleteFunction"),
    "AWS::Lambda::Function": ("lambda:CreateFunction", "lambda:DeleteFunction"),
    "aws_iam_role": ("iam:CreateRole", "iam:DeleteRole"),
    "AWS::IAM::Role": ("iam:CreateRole", "iam:DeleteRole"),
    "aws_iam_user": ("iam:CreateUser", "iam:DeleteUser"),
    "AWS::IAM::User": ("iam:CreateUser", "iam:DeleteUser"),
    "aws_iam_policy": ("iam:CreatePolicy", "iam:DeletePolicy"),
    "aws_iam_access_key": ("iam:CreateAccessKey", "iam:DeleteAccessKey"),
    "aws_kms_key": ("kms:CreateKey", "kms:ScheduleKeyDeletion"),
    "AWS::KMS::Key": ("kms:CreateKey", "kms:ScheduleKeyDeletion"),
    "aws_eks_cluster": ("eks:CreateCluster", "eks:DeleteCluster"),
    "AWS::EKS::Cluster": ("eks:CreateCluster", "eks:DeleteCluster"),
    "aws_ecs_cluster": ("ecs:CreateCluster", "ecs:DeleteCluster"),
    "aws_ecs_service": ("ecs:CreateService", "ecs:DeleteService"),
    "aws_sqs_queue": ("sqs:CreateQueue", "sqs:DeleteQueue"),
    "AWS::SQS::Queue": ("sqs:CreateQueue", "sqs:DeleteQueue"),
    "aws_sns_topic": ("sns:CreateTopic", "sns:DeleteTopic"),
    "AWS::SNS::Topic": ("sns:CreateTopic", "sns:DeleteTopic"),
    "aws_cloudtrail": ("cloudtrail:CreateTrail", "cloudtrail:DeleteTrail"),
    "aws_config_configuration_recorder": ("config:PutConfigurationRecorder",
                                          "config:DeleteConfigurationRecorder"),
    "aws_guardduty_detector": ("guardduty:CreateDetector", "guardduty:DeleteDetector"),
    "aws_cloudwatch_log_group": ("logs:CreateLogGroup", "logs:DeleteLogGroup"),
    "aws_secretsmanager_secret": ("secretsmanager:CreateSecret", "secretsmanager:DeleteSecret"),
}

_IDENTITY_POLICY_TYPES = {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy",
                          "aws_iam_group_policy", "AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}
_RESOURCE_POLICY_TYPES = {
    "aws_s3_bucket_policy": "AWS::S3::Bucket", "aws_sqs_queue_policy": None,
    "aws_sns_topic_policy": None, "aws_kms_key": None, "aws_secretsmanager_secret_policy": None,
    "aws_ecr_repository_policy": None, "AWS::S3::BucketPolicy": "AWS::S3::Bucket",
}
_AA_SEVERITY = {"ERROR": Severity.HIGH, "SECURITY_WARNING": Severity.HIGH,
                "WARNING": Severity.MEDIUM, "SUGGESTION": Severity.LOW}


def _policy_text(change: ResourceChange) -> Optional[str]:
    after = change.after or {}
    v = after.get("policy") if isinstance(after, Mapping) else None
    if v is None and isinstance(after, Mapping):
        v = after.get("PolicyDocument") or after.get("key_policy")
    if isinstance(v, Mapping):
        return json.dumps(v)
    if isinstance(v, str) and v.strip().startswith("{"):
        return v
    return None


@dataclass
class AwsNativeEngine:
    """Access Analyzer + SCP simulation. Needs the change's scoped AWS creds."""

    simulate_scps: bool = True
    validate_policies: bool = True
    name: str = "aws_native"
    last_detail: str = field(default="", init=False)

    @classmethod
    def from_params(cls, params: Mapping[str, Any]) -> "AwsNativeEngine":
        return cls(simulate_scps=bool(params.get("simulate_scps", True)),
                   validate_policies=bool(params.get("validate_policies", True)))

    def applies_to(self, ctx: PolicyContext) -> bool:
        return ctx.env.cloud == "aws" and any(c.cloud == "aws" and c.action.mutates
                                              for c in ctx.plan.changes)

    def evaluate(self, ctx: PolicyContext) -> list[Finding]:
        if ctx.creds is None:
            raise EngineError("aws_native needs the change's scoped credentials")
        session = ctx.creds.client("session")
        findings: list[Finding] = []
        unchecked: list[str] = []
        changes = [c for c in ctx.plan.changes if c.cloud == "aws" and c.action.mutates]
        if self.validate_policies:
            aa = session.client("accessanalyzer")
            for c in changes:
                text = _policy_text(c)
                if text is None or c.action.value == "delete":
                    continue
                kind = "IDENTITY_POLICY" if c.type in _IDENTITY_POLICY_TYPES else (
                    "RESOURCE_POLICY" if c.type in _RESOURCE_POLICY_TYPES else None)
                if kind is None:
                    continue
                findings += self._validate(aa, c, text, kind)
        if self.simulate_scps:
            role_arn = (ctx.env.credentials.params or {}).get("role_arn")
            if role_arn:
                iam = session.client("iam")
                findings += self._simulate(iam, role_arn, changes, ctx.env.scope.get("region", ""), unchecked)
            else:
                unchecked.append("SCP simulation skipped: no role_arn (profile mode)")
        self.last_detail = "; ".join(unchecked[:20])
        return findings

    def _validate(self, aa: Any, c: ResourceChange, text: str, kind: str) -> list[Finding]:
        kw: dict[str, Any] = {"policyDocument": text, "policyType": kind}
        rtype = _RESOURCE_POLICY_TYPES.get(c.type)
        if kind == "RESOURCE_POLICY" and rtype:
            kw["validatePolicyResourceType"] = rtype
        out = []
        try:
            pages = aa.get_paginator("validate_policy").paginate(**kw)
            for page in pages:
                for f in page.get("findings") or []:
                    sev = _AA_SEVERITY.get(str(f.get("findingType")), Severity.MEDIUM)
                    out.append(Finding(
                        rule_id=f"AWS-AA-{f.get('issueCode', 'FINDING')}", severity=sev,
                        message=str(f.get("findingDetails") or f.get("issueCode")),
                        engine="aws_native", resource=c.address,
                        references=(str(f["learnMoreLink"]),) if f.get("learnMoreLink") else (),
                    ))
        except Exception as e:  # noqa: BLE001
            raise EngineError(f"aws_native: Access Analyzer ValidatePolicy failed for {c.address}: {e}") from e
        return out

    def _simulate(self, iam: Any, role_arn: str, changes: Iterable[ResourceChange], region: str,
                  unchecked: list[str]) -> list[Finding]:
        by_region: dict[str, dict[str, list[str]]] = {}
        for c in changes:
            acts = AWS_ACTIONS.get(c.type)
            if not acts:
                unchecked.append(f"no SCP mapping for {c.type}")
                continue
            names = []
            if c.action.value in ("create", "replace"):
                names.append(acts[0])
            if c.action.value in ("delete", "replace"):
                names.append(acts[1])
            if not names:
                continue  # in-place updates: action depends on the attribute; not simulated
            r = c.location or region
            for n in names:
                by_region.setdefault(r, {}).setdefault(n, []).append(c.address)
        out: list[Finding] = []
        for r, acts in sorted(by_region.items()):
            kw: dict[str, Any] = {"PolicySourceArn": role_arn, "ActionNames": sorted(acts)}
            if r:
                kw["ContextEntries"] = [{"ContextKeyName": "aws:RequestedRegion",
                                         "ContextKeyValues": [r], "ContextKeyType": "string"}]
            try:
                pages = iam.get_paginator("simulate_principal_policy").paginate(**kw)
                results = [res for p in pages for res in p.get("EvaluationResults") or []]
            except Exception as e:  # noqa: BLE001
                raise EngineError(f"aws_native: iam:SimulatePrincipalPolicy failed: {e}") from e
            for res in results:
                org = res.get("OrganizationsDecisionDetail") or {}
                action = res.get("EvalActionName", "")
                for addr in acts.get(action, []):
                    if org and org.get("AllowedByOrganizations") is False:
                        out.append(Finding(
                            rule_id="AWS-SCP-DENY", severity=Severity.CRITICAL, engine="aws_native",
                            message=f"An AWS Organizations SCP denies {action} in {r or 'this region'}.",
                            fix_hint="Change the region or resource, or ask the organization admin; "
                                     "the gate never overrides an SCP.",
                            resource=addr))
                    elif res.get("EvalDecision") != "allowed":
                        out.append(Finding(
                            rule_id="AWS-IAM-NOT-ALLOWED", severity=Severity.HIGH, engine="aws_native",
                            message=f"The gate's role is not allowed {action} "
                                    f"({res.get('EvalDecision')}); the apply would fail.",
                            fix_hint="Grant the role the action, or plan under the right environment.",
                            resource=addr))
        return out


# ── Azure ────────────────────────────────────────────────────────────────────

#: Terraform azurerm type → ARM type (for type/location policy checks)
AZURE_TYPES: dict[str, str] = {
    "azurerm_storage_account": "Microsoft.Storage/storageAccounts",
    "azurerm_linux_virtual_machine": "Microsoft.Compute/virtualMachines",
    "azurerm_windows_virtual_machine": "Microsoft.Compute/virtualMachines",
    "azurerm_virtual_machine": "Microsoft.Compute/virtualMachines",
    "azurerm_managed_disk": "Microsoft.Compute/disks",
    "azurerm_virtual_network": "Microsoft.Network/virtualNetworks",
    "azurerm_network_security_group": "Microsoft.Network/networkSecurityGroups",
    "azurerm_public_ip": "Microsoft.Network/publicIPAddresses",
    "azurerm_network_interface": "Microsoft.Network/networkInterfaces",
    "azurerm_key_vault": "Microsoft.KeyVault/vaults",
    "azurerm_kubernetes_cluster": "Microsoft.ContainerService/managedClusters",
    "azurerm_mssql_server": "Microsoft.Sql/servers",
    "azurerm_postgresql_flexible_server": "Microsoft.DBforPostgreSQL/flexibleServers",
    "azurerm_mysql_flexible_server": "Microsoft.DBforMySQL/flexibleServers",
    "azurerm_cosmosdb_account": "Microsoft.DocumentDB/databaseAccounts",
    "azurerm_container_registry": "Microsoft.ContainerRegistry/registries",
    "azurerm_service_plan": "Microsoft.Web/serverfarms",
    "azurerm_linux_web_app": "Microsoft.Web/sites",
    "azurerm_windows_web_app": "Microsoft.Web/sites",
    "azurerm_linux_function_app": "Microsoft.Web/sites",
    "azurerm_redis_cache": "Microsoft.Cache/redis",
    "azurerm_log_analytics_workspace": "Microsoft.OperationalInsights/workspaces",
    "azurerm_servicebus_namespace": "Microsoft.ServiceBus/namespaces",
    "azurerm_eventhub_namespace": "Microsoft.EventHub/namespaces",
}


def azure_resource_content(change: ResourceChange) -> Optional[dict[str, Any]]:
    """Resource content for checkPolicyRestrictions, or None if not mappable."""
    after = change.after if isinstance(change.after, Mapping) else {}
    if change.type.startswith("Microsoft."):
        content = {"type": change.type, "location": after.get("location") or change.location or None}
        for k in ("properties", "sku", "kind", "tags", "identity"):
            if after.get(k) is not None:
                content[k] = after[k]
        return {k: v for k, v in content.items() if v is not None}
    arm = AZURE_TYPES.get(change.type)
    if not arm:
        return None
    content = {"type": arm, "location": after.get("location") or change.location or None}
    if isinstance(after.get("tags"), Mapping):
        content["tags"] = dict(after["tags"])
    return {k: v for k, v in content.items() if v is not None}


@dataclass
class AzureNativeEngine:
    name: str = "azure_native"
    client_factory: Any = None
    last_detail: str = field(default="", init=False)

    @classmethod
    def from_params(cls, params: Mapping[str, Any]) -> "AzureNativeEngine":
        return cls()

    def applies_to(self, ctx: PolicyContext) -> bool:
        return ctx.env.cloud == "azure" and any(c.cloud == "azure" and c.action.value in ("create", "update",
                                                                                            "replace")
                                                for c in ctx.plan.changes)

    def _client(self, ctx: PolicyContext) -> Any:
        if self.client_factory:
            return self.client_factory(ctx)
        try:
            from azure.mgmt.policyinsights import PolicyInsightsClient  # noqa: PLC0415
        except ImportError as e:
            raise EngineError("azure_native needs azure-mgmt-policyinsights (pip install 'cctl[azure]')") from e
        return PolicyInsightsClient(ctx.creds.client("credential"), ctx.env.scope["subscription_id"])

    def evaluate(self, ctx: PolicyContext) -> list[Finding]:
        if ctx.creds is None:
            raise EngineError("azure_native needs the change's scoped credentials")
        client = self._client(ctx)
        rg = ctx.env.scope["resource_group"]
        unchecked: list[str] = []
        out: list[Finding] = []
        for c in ctx.plan.changes:
            if c.cloud != "azure" or c.action.value not in ("create", "update", "replace"):
                continue
            content = azure_resource_content(c)
            if content is None:
                unchecked.append(f"no ARM mapping for {c.type}")
                continue
            body = {"resourceDetails": {"resourceContent": content}}
            try:
                resp = client.policy_restrictions.check_at_resource_group_scope(rg, body)
            except Exception as e:  # noqa: BLE001
                raise EngineError(f"azure_native: checkPolicyRestrictions failed for {c.address}: {e}") from e
            out += _azure_findings(resp, c.address)
        self.last_detail = "; ".join(unchecked[:20])
        return out


def _get(obj: Any, *names: str) -> Any:
    for n in names:
        if obj is None:
            return None
        obj = obj.get(n) if isinstance(obj, Mapping) else getattr(obj, n, None)
    return obj


def _azure_findings(resp: Any, address: str) -> list[Finding]:
    out = []
    evals = _get(resp, "content_evaluation_result", "policy_evaluations") or \
        _get(resp, "contentEvaluationResult", "policyEvaluations") or []
    for ev in evals:
        result = str(_get(ev, "evaluation_result") or _get(ev, "evaluationResult") or "")
        if result.lower() != "noncompliant":
            continue
        info = _get(ev, "policy_info") or _get(ev, "policyInfo") or {}
        pid = _get(info, "policy_definition_id") or _get(info, "policyDefinitionId") or "azure-policy"
        assignment = _get(info, "policy_assignment_id") or _get(info, "policyAssignmentId") or ""
        out.append(Finding(
            rule_id=f"AZURE-POLICY:{str(pid).rsplit('/', 1)[-1]}", severity=Severity.HIGH, engine="azure_native",
            message=f"Azure Policy evaluates this resource as non-compliant (assignment "
                    f"{str(assignment).rsplit('/', 1)[-1] or 'unknown'}); a deny assignment would block it.",
            fix_hint="Change the resource to satisfy the policy or request an exemption; the gate "
                     "never overrides Azure Policy.",
            resource=address))
    for fr in _get(resp, "field_restrictions") or _get(resp, "fieldRestrictions") or []:
        field_name = _get(fr, "field")
        for r in _get(fr, "restrictions") or []:
            if str(_get(r, "result") or "").lower() == "deny":
                vals = _get(r, "values") or []
                out.append(Finding(
                    rule_id="AZURE-POLICY-FIELD", severity=Severity.HIGH, engine="azure_native",
                    message=f"Azure Policy restricts {field_name}" + (f" to {list(vals)[:5]}" if vals else ""),
                    resource=address))
    return out


# ── GCP ──────────────────────────────────────────────────────────────────────

GCP_CONSTRAINTS = ("gcp.resourceLocations", "compute.vmExternalIpAccess",
                   "storage.publicAccessPrevention", "iam.allowedPolicyMemberDomains")
_LOCATION_GROUPS = {"us-locations": ("us-", "us"), "europe-locations": ("europe-", "eu"),
                    "eu-locations": ("europe-", "eu"), "asia-locations": ("asia-", "asia"),
                    "northamerica-locations": ("northamerica-", "us-", "us"),
                    "southamerica-locations": ("southamerica-",), "australia-locations": ("australia-",),
                    "me-locations": ("me-",), "africa-locations": ("africa-",)}


def _rules(policy: Any) -> list[Mapping[str, Any]]:
    spec = (policy or {}).get("spec") or {}
    return list(spec.get("rules") or [])


def _enforced(policy: Any) -> bool:
    return any(r.get("enforce") is True for r in _rules(policy))


def _location_allowed(loc: str, policy: Any) -> Optional[bool]:
    """True/False when decidable, None when a value group is not known."""
    rules = _rules(policy)
    if not rules or any(r.get("allowAll") for r in rules):
        return True
    if any(r.get("denyAll") for r in rules):
        return False
    loc = loc.lower()
    allowed = [v for r in rules for v in ((r.get("values") or {}).get("allowedValues") or [])]
    denied = [v for r in rules for v in ((r.get("values") or {}).get("deniedValues") or [])]

    def match(v: str) -> Optional[bool]:
        v = v.lower()
        if v.startswith("in:"):
            g = v[3:]
            if g == f"{loc}-locations" or g == loc:
                return True
            prefixes = _LOCATION_GROUPS.get(g)
            if prefixes is None:
                return None
            return any(loc == p or loc.startswith(p) for p in prefixes)
        return v == loc or loc.startswith(v + "-")

    for v in denied:
        if match(v):
            return False
    if not allowed:
        return True
    results = [match(v) for v in allowed]
    if any(r is True for r in results):
        return True
    if any(r is None for r in results):
        return None
    return False


@dataclass
class GcpNativeEngine:
    name: str = "gcp_native"
    service_factory: Any = None
    last_detail: str = field(default="", init=False)

    @classmethod
    def from_params(cls, params: Mapping[str, Any]) -> "GcpNativeEngine":
        return cls()

    def applies_to(self, ctx: PolicyContext) -> bool:
        return ctx.env.cloud == "gcp" and any(c.cloud == "gcp" and c.action.mutates for c in ctx.plan.changes)

    def _service(self, ctx: PolicyContext) -> Any:
        if self.service_factory:
            return self.service_factory(ctx)
        try:
            from googleapiclient.discovery import build  # noqa: PLC0415
        except ImportError as e:
            raise EngineError("gcp_native needs google-api-python-client (pip install 'cctl[gcp]')") from e
        return build("orgpolicy", "v2", credentials=ctx.creds.client("credentials"), cache_discovery=False)

    def _policies(self, svc: Any, project: str) -> dict[str, Any]:
        out = {}
        for c in GCP_CONSTRAINTS:
            name = f"projects/{project}/policies/{c}"
            try:
                out[c] = svc.projects().policies().getEffectivePolicy(name=name).execute()
            except Exception as e:  # noqa: BLE001
                status = getattr(getattr(e, "resp", None), "status", None)
                if str(status) == "404":
                    out[c] = {}
                    continue
                raise EngineError(f"gcp_native: getEffectivePolicy {c} failed: {e}") from e
        return out

    def evaluate(self, ctx: PolicyContext) -> list[Finding]:
        if ctx.creds is None:
            raise EngineError("gcp_native needs the change's scoped credentials")
        project = ctx.env.scope["project_id"]
        pol = self._policies(self._service(ctx), project)
        findings: list[Finding] = []
        unknown: list[str] = []
        for c in ctx.plan.changes:
            if c.cloud != "gcp" or not c.action.mutates or c.action.value == "delete":
                continue
            after = c.after if isinstance(c.after, Mapping) else {}
            loc = c.location or str(after.get("location") or after.get("region") or after.get("zone") or "")
            if loc:
                ok = _location_allowed(loc, pol.get("gcp.resourceLocations"))
                if ok is False:
                    findings.append(Finding(
                        rule_id="GCP-ORG-resourceLocations", severity=Severity.CRITICAL, engine="gcp_native",
                        message=f"Organization Policy gcp.resourceLocations does not allow {loc}.",
                        fix_hint="Use an allowed location; the gate never overrides org policy.",
                        resource=c.address))
                elif ok is None:
                    unknown.append(f"{c.address}: location {loc} vs unknown value group")
                    findings.append(Finding(
                        rule_id="GCP-ORG-resourceLocations-UNVERIFIED", severity=Severity.MEDIUM,
                        engine="gcp_native", resource=c.address,
                        message=f"Could not confirm {loc} is allowed by gcp.resourceLocations "
                                "(uses a value group cctl does not expand)."))
            if c.type == "google_compute_instance" and _external_ip(after):
                p = pol.get("compute.vmExternalIpAccess") or {}
                if any(r.get("denyAll") for r in _rules(p)) or _restricted_list(p):
                    findings.append(Finding(
                        rule_id="GCP-ORG-vmExternalIpAccess", severity=Severity.CRITICAL, engine="gcp_native",
                        message="Organization Policy compute.vmExternalIpAccess restricts external IPs; "
                                "this instance requests one.",
                        fix_hint="Remove access_config or use Cloud NAT / IAP.", resource=c.address))
            if _public_member(c) and c.type.startswith("google_storage_bucket_iam") and \
                    _enforced(pol.get("storage.publicAccessPrevention")):
                findings.append(Finding(
                    rule_id="GCP-ORG-publicAccessPrevention", severity=Severity.CRITICAL, engine="gcp_native",
                    message="Organization Policy enforces public access prevention; this public grant "
                            "would be refused.",
                    resource=c.address))
            if _public_member(c) and _restricted_list(pol.get("iam.allowedPolicyMemberDomains") or {}):
                findings.append(Finding(
                    rule_id="GCP-ORG-allowedPolicyMemberDomains", severity=Severity.CRITICAL,
                    engine="gcp_native",
                    message="Organization Policy iam.allowedPolicyMemberDomains limits members to the "
                            "organization's domains; allUsers / allAuthenticatedUsers would be refused.",
                    resource=c.address))
        self.last_detail = "; ".join(unknown[:20])
        return findings


def _restricted_list(policy: Mapping[str, Any]) -> bool:
    rules = _rules(policy)
    if not rules or any(r.get("allowAll") for r in rules):
        return False
    return any(r.get("denyAll") or (r.get("values") or {}).get("allowedValues")
               or (r.get("values") or {}).get("deniedValues") for r in rules)


def _external_ip(after: Mapping[str, Any]) -> bool:
    for ni in after.get("network_interface") or []:
        if isinstance(ni, Mapping) and ni.get("access_config"):
            return True
    return False


def _public_member(c: ResourceChange) -> bool:
    after = c.after if isinstance(c.after, Mapping) else {}
    members = [after.get("member")] + list(after.get("members") or [])
    return any(m in ("allUsers", "allAuthenticatedUsers") for m in members)
