"""Cost facts for the policy stage.

* :class:`InfracostEnricher` runs the Infracost CLI (Apache-2.0) over a
  Terraform/OpenTofu plan JSON and records the monthly cost delta. It prices
  AWS, Azure and GCP resources. The CLI needs an ``INFRACOST_API_KEY`` and
  sends resource types and pricing-relevant attributes (not secrets or state)
  to the pricing API; set ``pricing_api_endpoint`` to use a self-hosted
  Cloud Pricing API instead.
* Model spend is read from the request (``context.model_cost_usd``), which
  the callers fill from the AI provider's reported usage, so the gate can
  hold model cost to a per-environment limit (rule CCTL-COST-003).

Rules CCTL-COST-001/002 decide on these facts. If the environment sets a cost
limit and the plan cannot be priced (other IaC tools, enricher disabled), the
change is rejected unless ``cost.allow_unestimated`` is set.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Optional

from cloudctl.gate.models import EngineError
from cloudctl.gate.policy.engine import PolicyContext
from cloudctl.gate.policy.scanners import CliScanner, _common, _load_json, run_scanner, scanner_env


@dataclass
class InfracostEnricher(CliScanner):
    api_key_env: str = "INFRACOST_API_KEY"
    pricing_api_endpoint: Optional[str] = None

    name = "infracost"
    default_binary = "infracost"
    PLATFORMS = {"terraform", "opentofu"}

    @classmethod
    def from_params(cls, params: Mapping[str, Any]) -> "InfracostEnricher":
        return cls(**_common(params), api_key_env=str(params.get("api_key_env", "INFRACOST_API_KEY")),
                   pricing_api_endpoint=params.get("pricing_api_endpoint"))

    def applies_to(self, ctx: PolicyContext) -> bool:
        return ctx.plan.platform in self.PLATFORMS and bool(ctx.plan.artifacts.get("terraform_plan_json"))

    def enrich(self, ctx: PolicyContext) -> None:
        if not self.applies_to(ctx):
            return
        key = os.environ.get(self.api_key_env)
        if not key:
            raise EngineError(f"infracost: ${self.api_key_env} is not set")
        extra = {"INFRACOST_API_KEY": key, "INFRACOST_NO_COLOR": "true",
                 "INFRACOST_SKIP_UPDATE_CHECK": "true"}
        if self.pricing_api_endpoint:
            extra["INFRACOST_PRICING_API_ENDPOINT"] = str(self.pricing_api_endpoint)
        exe = self.binary_path()
        plan_json = Path(ctx.plan.artifacts["terraform_plan_json"])
        p = run_scanner([exe, "breakdown", "--path", str(plan_json), "--format", "json", "--no-color",
                         *self.extra_args],
                        what="infracost breakdown", timeout=self.timeout, env=scanner_env(extra))
        ctx.facts["cost"] = parse_infracost(_load_json(p.stdout, "infracost"))


def _money(v: Any) -> Optional[float]:
    if v in (None, ""):
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        raise EngineError(f"infracost: {v!r} is not a number") from None


def parse_infracost(doc: Any) -> dict[str, Any]:
    if not isinstance(doc, Mapping):
        raise EngineError("infracost: output is not an object")
    diff = _money(doc.get("diffTotalMonthlyCost"))
    total = _money(doc.get("totalMonthlyCost"))
    past = _money(doc.get("pastTotalMonthlyCost"))
    if diff is None and total is not None:
        diff = total - (past or 0.0)
    if diff is None:
        raise EngineError("infracost: no monthly cost in the output")
    currency = str(doc.get("currency") or "USD")
    if currency != "USD":
        # environment limits are in USD; comparing another currency would be wrong
        raise EngineError(f"infracost reported {currency}; set Infracost's currency to USD")
    return {"estimated": True, "monthly_delta_usd": round(diff, 2),
            "monthly_total_usd": total, "currency": currency,
            "source": "infracost"}
