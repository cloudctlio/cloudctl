"""Pluggable model adapter for the control plane.

The control plane needs one thing from a model: text back for a system
prompt and a user message. Any provider cctl supports (Bedrock, Anthropic,
OpenAI-compatible, Gemini) works through :class:`ConverseAdapter`, which
wraps cctl's existing Converse-shaped clients. Tests and other runtimes can
pass anything with a ``complete`` method.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, Protocol


@dataclass(frozen=True)
class ModelReply:
    text: str
    input_tokens: int = 0
    output_tokens: int = 0
    model: str = ""


class ModelAdapter(Protocol):
    def complete(self, system: str, user: str) -> ModelReply: ...


class ConverseAdapter:
    """Adapter over a client exposing ``converse(**kwargs)`` in the Bedrock
    Converse shape (what ``cloudctl.ai.model_providers`` returns)."""

    def __init__(self, client: Any, model_id: str, *, max_tokens: int = 4000,
                 temperature: Optional[float] = 0.0) -> None:
        self.client = client
        self.model_id = model_id
        self.max_tokens = max_tokens
        self.temperature = temperature

    @classmethod
    def from_environment(cls, *, profile: Optional[str] = None, region: str = "us-east-1") -> "ConverseAdapter":
        """Provider from CLOUDCTL_MODEL_PROVIDER, model from CLOUDCTL_MODEL."""
        from cloudctl.ai.model_providers import default_model, make_model_client  # noqa: PLC0415
        return cls(make_model_client(profile, region), default_model())

    def complete(self, system: str, user: str) -> ModelReply:
        cfg: dict[str, Any] = {"maxTokens": self.max_tokens}
        if self.temperature is not None:
            cfg["temperature"] = self.temperature
        resp = self.client.converse(modelId=self.model_id, system=[{"text": system}],
                                    messages=[{"role": "user", "content": [{"text": user}]}],
                                    inferenceConfig=cfg)
        blocks = (((resp or {}).get("output") or {}).get("message") or {}).get("content") or []
        text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict))
        usage = resp.get("usage") or {}
        return ModelReply(text=text, input_tokens=int(usage.get("inputTokens") or 0),
                          output_tokens=int(usage.get("outputTokens") or 0), model=self.model_id)
