"""CloudAgent — multi-turn agentic queries that iteratively fetch cloud data."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from cloudctl.ai.data_fetcher import DataFetcher
from cloudctl.config.manager import ConfigManager


_ALL_CATEGORIES = ["compute", "storage", "database", "cost", "security"]

# Keywords that hint the AI needs more data
_DATA_NEED_KEYWORDS = {
    "compute":  ["ec2", "vm", "instance", "compute", "server", "ecs", "gce"],
    "storage":  ["s3", "bucket", "blob", "storage", "gcs"],
    "database": ["rds", "database", "sql", "dynamodb", "redis", "cosmos", "mongo"],
    "cost":     ["cost", "billing", "spend", "expense", "budget", "price"],
    "security": ["security", "iam", "role", "permission", "public", "open", "exposed"],
}


@dataclass
class AgentResult:
    answer: str
    rounds: int
    context_categories_used: list[str]
    confidence_level: str = "LOW"


def _merge_context(base: dict, update: dict) -> None:
    """Merge update dict into base, merging nested dicts in place."""
    for k, v in update.items():
        if k not in base:
            base[k] = v
        elif isinstance(v, dict) and isinstance(base[k], dict):
            base[k].update(v)


def _extract_data_needs(answer: str, already_fetched: set[str]) -> list[str]:
    """
    Detect if the AI answer hints it needs more data.
    Returns list of include categories not yet fetched.
    """
    answer_lower = answer.lower()
    needs = []
    for category, keywords in _DATA_NEED_KEYWORDS.items():
        if category in already_fetched:
            continue
        if any(kw in answer_lower for kw in keywords):
            needs.append(category)
    return needs


class CloudAgent:
    """
    Multi-turn agent that fetches cloud data iteratively.
    Starts with a summary, then fetches more if the AI signals it needs it.
    Max 3 rounds to avoid runaway API calls.
    """
    MAX_ROUNDS = 3

    def __init__(self, cfg: ConfigManager):
        self._cfg = cfg
        self._fetcher = DataFetcher(cfg)

    def run(
        self,
        question: str,
        cloud: str = "all",
        account: Optional[str] = None,
        region: Optional[str] = None,
    ) -> AgentResult:
        """
        Run the agentic loop.
        Round 1: fetch compute + cost (most common need)
        Round 2+: fetch what the AI says it needs
        """
        try:
            from cloudctl.ai.factory import get_ai, is_ai_configured  # noqa: PLC0415
        except ImportError:
            return AgentResult(
                answer="AI module not installed. Run: pip install 'cctl[ai]'",
                rounds=0,
                context_categories_used=[],
            )

        if not is_ai_configured(self._cfg):
            return AgentResult(
                answer="AI not configured. Run: cloudctl config set ai.provider <provider>",
                rounds=0,
                context_categories_used=[],
            )

        ai = get_ai(self._cfg, purpose="analysis")
        context: dict = {}
        fetched_categories: set[str] = set()
        response: dict = {}

        for round_num in range(self.MAX_ROUNDS):
            # Round 1: start with compute+cost; later rounds add what's needed
            if round_num == 0:
                to_fetch = ["compute", "cost"]
            else:
                to_fetch = _extract_data_needs(
                    response.get("answer", ""), fetched_categories
                )
                if not to_fetch:
                    break  # AI has what it needs

            new_ctx = self._fetcher.fetch_summary(
                cloud=cloud,
                account=account,
                region=region,
                include=to_fetch,
            )
            for cat in to_fetch:
                fetched_categories.add(cat)

            # Merge new context
            _merge_context(context, new_ctx)

            response = ai.ask(question, context=context)

        from cloudctl.ai import confidence as confidence_mod  # noqa: PLC0415
        cs = confidence_mod.score(context)

        return AgentResult(
            answer=response.get("answer", ""),
            rounds=round_num + 1,
            context_categories_used=list(fetched_categories),
            confidence_level=cs.level,
        )
