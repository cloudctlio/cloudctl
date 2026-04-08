"""AI debug engine — diagnoses cloud symptoms using real infrastructure data."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from cloudctl.ai import confidence as confidence_mod
from cloudctl.ai.data_fetcher import DataFetcher
from cloudctl.config.manager import ConfigManager


@dataclass
class DebugFinding:
    symptom: str
    root_cause: str
    affected_resources: list[str] = field(default_factory=list)
    remediation_steps: list[str] = field(default_factory=list)
    confidence: Optional[confidence_mod.ConfidenceScore] = None
    confidence_notes: str = ""
    context_summary: dict = field(default_factory=dict)
    deployment_method: str = "unknown"


class DebugEngine:
    """Diagnoses cloud symptoms using real infrastructure data + AI analysis."""

    def __init__(self, cfg: ConfigManager):
        self._cfg = cfg
        self._fetcher = DataFetcher(cfg)

    def debug(
        self,
        symptom: str,
        cloud: str = "all",
        account: Optional[str] = None,
        region: Optional[str] = None,
        include: Optional[list[str]] = None,
    ) -> DebugFinding:
        """
        Fetch real cloud data for the symptom then call AI for root-cause analysis.
        Returns a structured DebugFinding.
        """
        try:
            from cloudctl.ai.factory import get_ai, is_ai_configured  # noqa: PLC0415
        except ImportError:
            return DebugFinding(
                symptom=symptom,
                root_cause="AI module not installed. Run: pip install 'cctl[ai]'",
            )

        if not is_ai_configured(self._cfg):
            return DebugFinding(
                symptom=symptom,
                root_cause="AI not configured. Run: cloudctl config set ai.provider <provider>",
            )

        include = include or ["compute", "cost", "security", "database", "storage"]
        context = self._fetcher.fetch_summary(
            cloud=cloud,
            account=account,
            region=region,
            include=include,
        )

        # Symptom-aware fetching — discover service logs and metrics using planner hints
        if cloud in ("aws", "all"):
            self._fetch_symptom_context_aws(symptom, account, region, context)

        # Detect deployment method from resource tags
        deploy_method = self._detect_deployment_method(cloud, account, region, context)
        if deploy_method:
            context["deployment_method"] = deploy_method

        cs = confidence_mod.score(
            context,
            required_keys=include,
        )

        from cloudctl.ai.factory import _parse_json_response  # noqa: PLC0415
        from cloudctl.ai.prompts.debug import debug_prompt, DEBUG_SYSTEM  # noqa: PLC0415

        ai = get_ai(self._cfg, purpose="analysis")
        prompt = debug_prompt(symptom, context, deploy_method=deploy_method)
        answer_text = ai._invoke(prompt, system=DEBUG_SYSTEM)  # noqa: SLF001
        parsed = _parse_json_response(answer_text)

        return DebugFinding(
            symptom=symptom,
            root_cause=parsed.get("root_cause", answer_text),
            affected_resources=parsed.get("affected_resources", []),
            remediation_steps=parsed.get("remediation_steps", []),
            deployment_method=deploy_method or "unknown",
            confidence=cs,
            confidence_notes=parsed.get("confidence_notes", ""),
            context_summary={k: len(v) if isinstance(v, (list, dict)) else v for k, v in context.items()},
        )

    # Env var key patterns whose values must be redacted before leaving this process
    _SENSITIVE_PATTERNS = (
        "secret", "password", "passwd", "token", "api_key", "apikey",
        "auth", "credential", "private_key", "access_key", "signing_key",
        "encryption_key", "client_secret", "db_pass", "database_pass",
    )

    @classmethod
    def _is_sensitive_key(cls, key: str) -> bool:
        k = key.lower()
        return any(pat in k for pat in cls._SENSITIVE_PATTERNS)

    @classmethod
    def _redact_env_vars(cls, env_vars: dict) -> dict:
        return {k: ("***REDACTED***" if cls._is_sensitive_key(k) else v)
                for k, v in env_vars.items()}

    def _detect_deployment_method(
        self,
        cloud: str,
        account: Optional[str],
        region: Optional[str],
        context: dict,
    ) -> str:
        """Detect IaC deployment method using resource ARNs already in context.

        Generic approach — works for any AWS service, not just Lambda:
        1. Collect resource ARNs from CloudTrail events already fetched.
        2. Use the Resource Groups Tagging API to get tags for those ARNs.
        3. Pass to _detect_aws (tags → CF registry → CloudTrail userAgent).
        4. For CDK/CF stacks, enrich context with template slice.
        """
        from cloudctl.commands._helpers import get_aws_provider  # noqa: PLC0415

        if cloud not in ("aws", "all"):
            return "unknown"

        profiles = self._cfg.accounts.get("aws", [])
        targets  = [p["name"] for p in profiles if not account or p["name"] == account]
        if not targets:
            return "unknown"

        try:
            prov    = get_aws_provider(targets[0], region)
            session = prov._session  # noqa: SLF001

            # Collect resource names/ARNs from whatever is already in context.
            # CloudTrail resource fields may be plain names OR full ARNs — accept both.
            # Log group sources encode the service path (e.g. /aws/lambda/fn, /aws/rds/...).
            resource_names: list[str] = []
            seen: set = set()

            for ev in context.get("cloudtrail_events", [])[:20]:
                for part in ev.get("resource", "").split(", "):
                    part = part.strip()
                    if part and part not in seen:
                        seen.add(part)
                        resource_names.append(part)
                        if len(resource_names) >= 5:
                            break
                if len(resource_names) >= 5:
                    break

            # Fall back to log sources if CloudTrail had nothing useful
            if not resource_names:
                for ev in context.get("service_logs", [])[:10]:
                    src = ev.get("source", "")
                    # "CloudWatch/Logs//aws/lambda/fn" → "fn"
                    # "CloudWatch/Logs//aws/rds/cluster" → "cluster"
                    if "/aws/" in src:
                        name = src.split("/aws/")[-1].split("/")[-1]
                        if name and name not in seen:
                            seen.add(name)
                            resource_names.append(name)
                            if len(resource_names) >= 5:
                                break

            # Tags: only query tagging API when we have full ARNs.
            resource_tags: dict = {}
            arns = [n for n in resource_names if n.startswith("arn:aws:")]
            if arns:
                try:
                    tagger = session.client("resourcegroupstaggingapi")
                    resp   = tagger.get_resources(ResourceARNList=arns[:5])
                    for item in resp.get("ResourceTagMappingList", []):
                        for tag in item.get("Tags", []):
                            resource_tags[tag["Key"]] = tag["Value"]
                except Exception:  # noqa: BLE001
                    pass

            from cloudctl.debug.deployment_detector import _detect_aws  # noqa: PLC0415
            # Try each collected resource name until detection succeeds.
            method = "unknown"
            for candidate in resource_names:
                method = _detect_aws(session, candidate, resource_tags)
                if method != "unknown":
                    break

            # For CDK/CF: enrich context with template slice for affected resources.
            if method in ("cdk", "cloudformation"):
                # Use any ARN we have — CF lookup works for Lambda, ECS, RDS, etc.
                resource_arns = {
                    n.split(":")[-1]: n
                    for n in resource_names
                    if n.startswith("arn:aws:")
                }
                if resource_arns:
                    self._fetch_cf_resource_context(session, resource_arns, resource_tags, context)

            return method
        except Exception:  # noqa: BLE001
            return "unknown"

    def _fetch_cf_resource_context(
        self,
        session,
        fn_arns: dict,
        resource_tags: dict,
        context: dict,
    ) -> None:
        """Fetch CF template slice for affected resources; redact sensitive values."""
        import json  # noqa: PLC0415
        try:
            cf         = session.client("cloudformation")
            stack_name = resource_tags.get("aws:cloudformation:stack-name", "")
            if not stack_name:
                # Fall back: look up by first function ARN
                arn = next(iter(fn_arns.values()), "")
                if not arn:
                    return
                resp = cf.describe_stack_resources(PhysicalResourceId=arn)
                stacks = resp.get("StackResources", [])
                if not stacks:
                    return
                stack_name = stacks[0]["StackName"]

            tpl_body = cf.get_template(StackName=stack_name).get("TemplateBody", "")
            tpl      = json.loads(tpl_body) if isinstance(tpl_body, str) else tpl_body

            # Resolve logical IDs: from tag first, then describe_stack_resources per ARN
            cf_resources = tpl.get("Resources", {})
            logical_ids: set[str] = set()
            tag_lid = resource_tags.get("aws:cloudformation:logical-id", "")
            if tag_lid:
                logical_ids.add(tag_lid)
            for arn in fn_arns.values():
                try:
                    stk = cf.describe_stack_resources(PhysicalResourceId=arn)
                    for r in stk.get("StackResources", []):
                        logical_ids.add(r["LogicalResourceId"])
                except Exception:  # noqa: BLE001
                    pass
            logical_ids.discard("")

            slices: dict = {}
            for lid in logical_ids:
                if lid not in cf_resources:
                    continue
                res   = cf_resources[lid]
                props = dict(res.get("Properties", {}))
                # Redact sensitive env vars regardless of resource type
                env = props.get("Environment", {}).get("Variables", {})
                if env:
                    props["Environment"] = {"Variables": self._redact_env_vars(env)}
                slices[lid] = {
                    "Type":       res.get("Type", ""),
                    "Properties": props,
                }

            if slices:
                context["iac_resource_config"] = {
                    "stack":     stack_name,
                    "resources": slices,
                }
        except Exception:  # noqa: BLE001
            pass

    def _fetch_symptom_context_aws(
        self,
        symptom: str,
        account: Optional[str],
        region: Optional[str],
        context: dict,
    ) -> None:
        """Fetch symptom-specific logs and metrics from AWS, mutates context in place."""
        from cloudctl.debug.planner import plan_sources, extract_service_hints  # noqa: PLC0415
        from cloudctl.debug.fetcher import DebugFetcher  # noqa: PLC0415
        from cloudctl.commands._helpers import get_aws_provider  # noqa: PLC0415

        sources = plan_sources(symptom)
        hints   = extract_service_hints(symptom)

        profiles = self._cfg.accounts.get("aws", [])
        targets  = [p["name"] for p in profiles if not account or p["name"] == account]
        if not targets:
            return

        try:
            prov    = get_aws_provider(targets[0], region)
            fetcher = DebugFetcher(prov._session)
        except Exception:
            return

        # Service logs — discover any CloudWatch log group matching the hints
        if "service_logs" in sources:
            service_logs: list[dict] = []
            for hint in hints[:5]:
                for lg in fetcher.discover_log_groups(hint):
                    evts = fetcher.cloudwatch_logs(
                        log_group=lg,
                        filter_pattern="?ERROR ?WARN ?error ?warn ?5xx ?500",
                        minutes=180,
                    )
                    service_logs.extend(evts)
            if service_logs:
                context["service_logs"] = service_logs


        # CloudTrail
        if "cloudtrail" in sources:
            evts = fetcher.cloudtrail(minutes=120)
            if evts:
                context["cloudtrail_events"] = evts

        # RDS
        if "rds_events" in sources:
            evts = fetcher.rds_events()
            if evts:
                context["rds_events"] = evts

        # CodePipeline
        if "codepipeline" in sources:
            evts = fetcher.codepipeline()
            if evts:
                context["pipeline_executions"] = evts

        # Network context
        if "network_context" in sources:
            evts = fetcher.network_context()
            if evts:
                context["network_context"] = evts
