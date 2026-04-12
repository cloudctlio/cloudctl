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

        from cloudctl.debug.planner import ALL_SOURCES  # noqa: PLC0415
        cs = confidence_mod.score(
            context,
            required_keys=ALL_SOURCES,
        )

        from cloudctl.ai.factory import parse_debug_response  # noqa: PLC0415
        from cloudctl.ai.prompts.debug import debug_prompt, DEBUG_SYSTEM  # noqa: PLC0415

        # ARN dedup — remove duplicate resources that appear under multiple profiles
        self._dedup_arns(context)

        # Tiered pruning — send full JSON only for unhealthy resources;
        # summarize healthy ones so the AI focuses on the signal, not the noise
        self._prune_context(context)

        ai = get_ai(self._cfg, purpose="analysis")
        prompt = debug_prompt(symptom, context, deploy_method=deploy_method)
        answer_text = ai._invoke(prompt, system=DEBUG_SYSTEM)  # noqa: SLF001
        parsed = parse_debug_response(answer_text)

        return DebugFinding(
            symptom=symptom,
            root_cause=parsed.root_cause,
            affected_resources=parsed.affected_resources,
            remediation_steps=[
                f"{s.command}  # {s.explanation}".strip(" #") if s.explanation else s.command
                for s in parsed.remediation_steps
            ],
            deployment_method=deploy_method or "unknown",
            confidence=cs,
            confidence_notes=parsed.confidence_notes,
            context_summary={k: len(v) if isinstance(v, (list, dict)) else v for k, v in context.items()},
        )

    @staticmethod
    def _prune_context(context: dict) -> None:
        """Tier resources by health so the AI sees signal, not noise.

        Tier 1 (full JSON)  — unhealthy: state not running/active, or has errors
        Tier 2 (name+state) — healthy resources in the same list
        Tier 3 (count only) — emitted as a summary string appended to the list

        Only applies to compute/database lists; logs and audit trails are left intact.
        """
        _UNHEALTHY = {"stopped", "stopping", "failed", "error", "degraded",
                      "impaired", "unavailable", "draining", "inactive"}
        _HEALTHY   = {"running", "active", "available", "ok", "healthy", "started"}

        prunable_keys = {"compute", "database"}

        for key in list(context.keys()):
            if key not in prunable_keys:
                continue
            items = context.get(key)
            if not isinstance(items, list) or len(items) <= 5:
                continue  # small lists — no pruning needed

            tier1, tier2 = [], []
            for item in items:
                if not isinstance(item, dict):
                    tier1.append(item)
                    continue
                state = str(item.get("state") or item.get("status") or "").lower()
                if state in _UNHEALTHY or (state and state not in _HEALTHY):
                    tier1.append(item)  # full JSON
                else:
                    tier2.append({  # metadata only
                        "name":  item.get("name") or item.get("id", ""),
                        "state": state or "unknown",
                    })

            healthy_count = len(tier2)
            pruned: list = tier1
            pruned.extend(tier2[:3])  # include up to 3 healthy neighbours for context
            if healthy_count > 3:
                pruned.append({"_summary": f"{healthy_count - 3} additional healthy {key} resources omitted"})
            context[key] = pruned

    @staticmethod
    def _dedup_arns(context: dict) -> None:
        """Remove duplicate resources that appear under multiple profiles/keys.

        Walks every list in context and drops items whose ARN (or id/name) was
        already seen, so the same resource isn't sent twice to the AI.
        """
        seen_arns: set[str] = set()
        for key, value in context.items():
            if not isinstance(value, list):
                continue
            deduped = []
            for item in value:
                if not isinstance(item, dict):
                    deduped.append(item)
                    continue
                arn = (
                    item.get("arn")
                    or item.get("ARN")
                    or item.get("id")
                    or item.get("name")
                    or item.get("source")
                )
                if arn and arn in seen_arns:
                    continue
                if arn:
                    seen_arns.add(arn)
                deduped.append(item)
            context[key] = deduped

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

            for ev in context.get("audit_logs", [])[:20]:
                for part in ev.get("resource", "").split(", "):
                    part = part.strip()
                    if part and part not in seen:
                        seen.add(part)
                        resource_names.append(part)
                        if len(resource_names) >= 5:
                            break
                if len(resource_names) >= 5:
                    break

            # Harvest resource identifiers from all event lists in context.
            # Two source formats exist:
            #   "/aws/service/name"    (Lambda, RDS, ECS log groups)  → extract "name"
            #   "ResourceType/id"      (network_context: VPC, SG, …)  → extract "id"
            # Both yield stable, infrequently-queried identifiers whose CloudTrail
            # create event is more likely to appear within MaxResults than high-volume
            # scheduler events (e.g. ECS DescribeTargetHealth).
            import re as _re  # noqa: PLC0415
            _AWS_ID = _re.compile(r"^(vpc|subnet|sg|rtb|igw|nat|eni|eip|acl)-[0-9a-f]+$")
            for ctx_key, events in context.items():
                if not isinstance(events, list):
                    continue
                for ev in events[:10]:
                    if not isinstance(ev, dict):
                        continue
                    src = ev.get("source", "")
                    if "/aws/" in src:
                        # e.g. "CloudWatch/Logs//aws/lambda/my-fn" → "my-fn"
                        name = src.split("/aws/")[-1].split("/")[-1]
                    elif "/" in src:
                        # e.g. "VPC/vpc-0abc123" or "SecurityGroup/sg-0abc123" → "vpc-0abc123"
                        name = src.split("/")[-1]
                    else:
                        continue
                    if name and name not in seen and (_AWS_ID.match(name) or not name.startswith(("arn:", "http"))):
                        seen.add(name)
                        resource_names.append(name)
                if len(resource_names) >= 10:
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

            # CFN fields that add noise without diagnostic value
            _CFN_STRIP = {"DependsOn", "UpdateReplacePolicy", "DeletionPolicy",
                          "Metadata", "Condition", "CreationPolicy", "UpdatePolicy"}
            # Tag keys that are AWS-internal noise
            _TAG_STRIP  = {"aws:cloudformation:stack-id", "aws:cloudformation:stack-name",
                           "aws:cloudformation:logical-id"}

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
                # Strip noisy tag keys that add no diagnostic signal
                tags = props.get("Tags")
                if isinstance(tags, list):
                    props["Tags"] = [
                        t for t in tags if t.get("Key", "") not in _TAG_STRIP
                    ]
                slices[lid] = {
                    "Type":       res.get("Type", ""),
                    "Properties": props,
                    **{k: res[k] for k in res if k not in _CFN_STRIP and k != "Properties" and k != "Type"},
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

        # Audit logs — fetch first so resource names can seed log discovery
        if "audit_logs" in sources:
            evts = fetcher.cloudtrail(minutes=120)
            if evts:
                context["audit_logs"] = evts
                # Extract Lambda function names and RDS instance IDs from
                # CloudTrail resource fields so their log groups get discovered.
                # CloudTrail stores resource names in ev["resource"] as a
                # comma-separated string of ResourceName values.
                # Lambda log groups: /aws/lambda/<fn-name>
                # RDS log groups:    /aws/rds/instance/<id>/postgresql
                _hint_set = set(hints)
                for ev in evts:
                    for part in ev.get("resource", "").split(","):
                        part = part.strip()
                        if not part:
                            continue
                        # Full ARN → extract function name or RDS instance id
                        if ":function:" in part:
                            name = part.split(":function:")[-1].split(":")[0]
                        elif ":db:" in part:
                            name = part.split(":db:")[-1]
                        else:
                            name = part  # plain resource name (no ARN prefix)
                        if name and len(name) > 4 and name not in _hint_set:
                            _hint_set.add(name)
                            hints.append(name)

        # Network context — fetch before log discovery so target group /
        # ECS service names can seed log discovery
        if "network_context" in sources:
            evts = fetcher.network_context()
            if evts:
                context["network_context"] = evts

        # Service logs — discover log groups using symptom hints PLUS names
        # extracted from already-fetched audit_logs and network_context events.
        # A source like "TargetGroup/cloudctl-complex-e2e-ecs-tg" yields
        # "cloudctl-complex-e2e-ecs-tg", matching /ecs/cloudctl-complex-e2e-nginx.
        if "service_logs" in sources:
            _seen_hints: set[str] = set()
            all_hints: list[str] = []

            for h in hints[:5]:
                if h not in _seen_hints:
                    _seen_hints.add(h)
                    all_hints.append(h)

            # Harvest names from event sources already in context.
            # Two strategies:
            #   1. Full resource name from "Type/name" sources → matches log groups directly
            #   2. Shared name prefix (longest common prefix of resource names) →
            #      catches ECS log groups like /ecs/<stack>-nginx when only
            #      TargetGroup/<stack>-ecs-tg is in network_context
            _SKIP_TYPES = {"aws", "ecs", "rds", "lambda", "ec2", "s3", "CloudWatch",
                           "Logs", "ECS", "VPC", "Subnet", "RouteTable", "SecurityGroup",
                           "NatGateway", "IGW", "NetworkACL", "ElasticIP",
                           "InternetGateway", "VPCFlowLogs"}
            resource_names_seen: list[str] = []
            for ctx_key in ("audit_logs", "network_context"):
                for ev in context.get(ctx_key, [])[:100]:
                    src = ev.get("source", "")
                    if "/" in src:
                        # Take the last segment (the resource name, not the type prefix)
                        name = src.split("/")[-1]
                        if (name and name not in _seen_hints and len(name) > 4
                                and not name.startswith(("arn:", "i-", "sg-", "vpc-",
                                                         "subnet-", "rtb-", "igw-", "nat-",
                                                         "eni-", "acl-", "eipalloc-",
                                                         "tgw-", "pcx-", "pl-", "vpce-"))):
                            _seen_hints.add(name)
                            all_hints.append(name)
                            resource_names_seen.append(name)

            # For each resource name, also add a truncated version with the
            # last 1-2 dash-components stripped — this recovers the stack prefix
            # e.g. "cloudctl-complex-e2e-ecs-tg" → "cloudctl-complex-e2e"
            # which matches /ecs/cloudctl-complex-e2e-nginx via logGroupNamePattern
            for nm in list(resource_names_seen):
                parts = nm.split("-")
                if len(parts) >= 4:
                    # Try dropping last 2 components, then last 1
                    for drop in (2, 1):
                        shorter = "-".join(parts[:-drop])
                        if len(shorter) >= 5 and shorter not in _seen_hints:
                            _seen_hints.add(shorter)
                            all_hints.append(shorter)
                            break

            service_logs: list[dict] = []
            seen_lgs: set[str] = set()
            for hint in all_hints[:20]:
                for lg in fetcher.discover_log_groups(hint, limit=50):
                    if lg not in seen_lgs:
                        seen_lgs.add(lg)
                        evts = fetcher.cloudwatch_logs(
                            log_group=lg,
                            filter_pattern="?ERROR ?WARN ?error ?warn",
                            minutes=180,
                        )
                        if not evts:
                            # Tail last 50 lines unconditionally — catches stack
                            # traces and structured JSON logs that don't contain
                            # ERROR/WARN, regardless of the time window.
                            evts = fetcher.tail_log_group(lg, lines=50)
                        service_logs.extend(evts)

            # Recently-active sweep — fallback only, runs when hint-based
            # discovery found fewer than 2 log groups. Catches custom log
            # groups (/app/payments, /prod/checkout) that hints never match.
            if len(seen_lgs) < 2:
                for lg in fetcher.recently_active_log_groups(minutes=180, limit=30):
                    if lg in seen_lgs:
                        continue
                    seen_lgs.add(lg)
                    evts = fetcher.cloudwatch_logs(
                        log_group=lg,
                        filter_pattern="?ERROR ?WARN ?error ?warn",
                        minutes=180,
                    )
                    service_logs.extend(evts)

            if service_logs:
                context["service_logs"] = service_logs
