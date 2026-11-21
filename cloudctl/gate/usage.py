"""Model spend for a change, so the gate can hold it to a limit.

cctl is model-agnostic, so it ships no price list. Set the price of the
model in use (USD per million tokens, input and output) with
``CLOUDCTL_MODEL_PRICE_USD_PER_MTOK="3,15"``. Without it the spend is
unknown; an environment with ``cost.max_model_cost_usd`` then rejects the
change unless ``cost.allow_unestimated`` is set (rule CCTL-COST-004).
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Mapping, Optional

PRICE_ENV = "CLOUDCTL_MODEL_PRICE_USD_PER_MTOK"


def model_price() -> Optional[tuple[float, float]]:
    raw = os.environ.get(PRICE_ENV, "").strip()
    if not raw:
        return None
    try:
        a, b = (float(x) for x in raw.split(","))
    except ValueError:
        return None
    if a < 0 or b < 0:
        return None
    return a, b


@dataclass
class ModelUsage:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0

    def add(self, resp: Mapping[str, Any]) -> None:
        u = resp.get("usage") or {}
        self.calls += 1
        self.input_tokens += int(u.get("inputTokens") or 0)
        self.output_tokens += int(u.get("outputTokens") or 0)

    def cost_usd(self) -> Optional[float]:
        price = model_price()
        if price is None:
            return None
        return round((self.input_tokens * price[0] + self.output_tokens * price[1]) / 1_000_000, 4)

    def context(self) -> dict[str, Any]:
        return {"model_calls": self.calls, "model_input_tokens": self.input_tokens,
                "model_output_tokens": self.output_tokens, "model_cost_usd": self.cost_usd()}
