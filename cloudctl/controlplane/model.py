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


# ── registry and guard ──────────────────────────────────────────────────────

class ModelAdapterError(Exception):
    pass


_REGISTRY: dict[str, Any] = {}
ENTRY_POINT_GROUP = "cloudctl.model_adapters"


def register_adapter(name: str, factory: Any) -> None:
    """Register ``factory(**settings) -> ModelAdapter`` under *name*."""
    if not name.isidentifier():
        raise ModelAdapterError(f"invalid adapter name {name!r}")
    _REGISTRY[name] = factory


def _converse_factory(**settings: Any) -> ConverseAdapter:
    return ConverseAdapter.from_environment(profile=settings.get("profile"),
                                            region=settings.get("region", "us-east-1"))


register_adapter("converse", _converse_factory)


def load_adapter(name: str = "converse", **settings: Any) -> ModelAdapter:
    """A registered adapter, or one an installed package publishes under the
    ``cloudctl.model_adapters`` entry-point group. Nothing is imported from a
    module path given at run time: only installed, named adapters load."""
    factory = _REGISTRY.get(name)
    if factory is None:
        from importlib.metadata import entry_points  # noqa: PLC0415
        found = [ep for ep in entry_points(group=ENTRY_POINT_GROUP) if ep.name == name]
        if not found:
            known = sorted(set(_REGISTRY) | {ep.name for ep in entry_points(group=ENTRY_POINT_GROUP)})
            raise ModelAdapterError(f"no model adapter {name!r}; installed: {known}")
        factory = found[0].load()
    adapter = factory(**settings)
    if not callable(getattr(adapter, "complete", None)):
        raise ModelAdapterError(f"adapter {name!r} has no complete(system, user) method")
    return adapter


class GuardedAdapter:
    """Wraps any adapter with the limits a shared service needs: a cap on
    prompt size, bounded retries with backoff on errors, and an hourly token
    budget. Every call (and every refusal) goes to *audit*."""

    def __init__(self, inner: ModelAdapter, *, max_prompt_chars: int = 200_000, retries: int = 2,
                 backoff_seconds: float = 2.0, tokens_per_hour: int = 2_000_000,
                 audit: Any = None, sleep: Any = None, clock: Any = None) -> None:
        import threading  # noqa: PLC0415
        import time  # noqa: PLC0415
        self.inner = inner
        self.max_prompt_chars = max_prompt_chars
        self.retries = max(0, min(retries, 5))
        self.backoff = backoff_seconds
        self.tokens_per_hour = tokens_per_hour
        self.audit = audit
        self._sleep = sleep or time.sleep
        self._clock = clock or time.time
        self._window: list[tuple[float, int]] = []
        self._lock = threading.Lock()

    def _used(self, now: float) -> int:
        self._window = [(t, n) for t, n in self._window if now - t < 3600]
        return sum(n for _, n in self._window)

    def _log(self, event: str, data: dict) -> None:
        if self.audit:
            self.audit(event, data)

    def complete(self, system: str, user: str) -> ModelReply:
        size = len(system) + len(user)
        if size > self.max_prompt_chars:
            self._log("model.refused", {"reason": "prompt too large", "chars": size})
            raise ModelAdapterError(f"prompt is {size} characters; the limit is {self.max_prompt_chars}")
        with self._lock:
            if self._used(self._clock()) >= self.tokens_per_hour:
                self._log("model.refused", {"reason": "hourly token budget spent"})
                raise ModelAdapterError("the hourly model token budget is spent")
        last: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            try:
                reply = self.inner.complete(system, user)
            except Exception as e:  # noqa: BLE001 — provider SDKs raise many types
                last = e
                self._log("model.error", {"attempt": attempt + 1, "error": str(e)[:300]})
                if attempt < self.retries:
                    self._sleep(self.backoff * (2 ** attempt))
                continue
            with self._lock:
                self._window.append((self._clock(), reply.input_tokens + reply.output_tokens))
            return reply
        raise ModelAdapterError(f"the model failed after {self.retries + 1} attempts: {last}")
