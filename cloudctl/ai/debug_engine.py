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

        cs = confidence_mod.score(
            context,
            required_keys=include,
        )

        from cloudctl.ai.prompts.debug import debug_prompt, DEBUG_SYSTEM  # noqa: PLC0415
        from cloudctl.ai.factory import _parse_json_response  # noqa: PLC0415

        ai = get_ai(self._cfg, purpose="analysis")
        prompt = debug_prompt(symptom, context)

        # Override system prompt with debug-specific one
        raw_response = ai.ask(symptom, context=context)

        # Parse structured response
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
