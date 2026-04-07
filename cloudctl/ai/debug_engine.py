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

        cs = confidence_mod.score(
            context,
            required_keys=include,
        )

        from cloudctl.ai.factory import _parse_json_response  # noqa: PLC0415

        ai = get_ai(self._cfg, purpose="analysis")
        raw_response = ai.ask(symptom, context=context)

        answer_text = raw_response.get("answer", "")
        parsed = _parse_json_response(answer_text)

        return DebugFinding(
            symptom=symptom,
            root_cause=parsed.get("root_cause", answer_text),
            affected_resources=parsed.get("affected_resources", []),
            remediation_steps=parsed.get("remediation_steps", []),
            confidence=cs,
            confidence_notes=parsed.get("confidence_notes", ""),
            context_summary={k: len(v) if isinstance(v, (list, dict)) else v for k, v in context.items()},
        )

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
        if "lambda_logs" in sources or "alb_logs" in sources:
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

        # Lambda metrics
        if "lambda_logs" in sources:
            for metric in ("Errors", "Duration", "Throttles"):
                evts = fetcher.cloudwatch_metrics(namespace="AWS/Lambda", metric_name=metric)
                if evts:
                    context.setdefault("metrics", []).extend(evts)

        # ALB metrics
        if "alb_logs" in sources:
            for metric in ("HTTPCode_Target_5XX_Count", "HTTPCode_Target_4XX_Count", "TargetResponseTime"):
                evts = fetcher.cloudwatch_metrics(namespace="AWS/ApplicationELB", metric_name=metric)
                if evts:
                    context.setdefault("metrics", []).extend(evts)

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
