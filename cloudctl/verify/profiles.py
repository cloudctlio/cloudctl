"""Per-model settings profiles, loaded from profiles.yaml.

Per-model behaviour lives here as data so nothing in discovery, the
primitives or the verifier branches on which model is running. Only the
proposer call (and later the narrative call) reads a profile.

Selection at run time (first match wins):
  CLOUDCTL_VERIFY_PROFILES   path to a profiles file (default: the packaged one)
  CLOUDCTL_VERIFY_PROFILE    a profile name in that file
  otherwise a profile whose model_id equals CLOUDCTL_MODEL, and finally an
  ad-hoc profile for CLOUDCTL_MODEL_PROVIDER / CLOUDCTL_MODEL with the safest
  settings (json_repair, temperature omitted).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import yaml

PROVIDERS = ("bedrock", "anthropic", "openai", "gemini", "openai_compatible")
STRUCTURED_MODES = ("native_schema", "tool_use", "json_repair")
_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "profiles.yaml")


@dataclass
class ModelProfile:
    name: str
    provider: str
    model_id: str
    structured_mode: str = "json_repair"
    temperature: float | None = None
    reasoning: dict = field(default_factory=lambda: {"level": "none"})
    max_output_tokens: int = 2000
    context_window: int | None = None
    price_in: float | None = None
    price_out: float | None = None
    rate_limit: dict = field(default_factory=lambda: {"max_retries": 6, "base_delay_s": 2.0})
    region: str = "us-east-1"
    base_url: str = ""
    pinned: bool = False
    family: str = ""
    size: str = ""
    additional_request_fields: dict = field(default_factory=dict)
    # tool_use only: force the submit tool with toolChoice. Some Bedrock
    # models accept tools but not a forced choice; set false for those.
    force_tool: bool = True

    def validate(self) -> list[str]:
        errs = []
        if self.provider not in PROVIDERS:
            errs.append(f"{self.name}: provider must be one of {PROVIDERS}")
        if self.structured_mode not in STRUCTURED_MODES:
            errs.append(f"{self.name}: structured_mode must be one of {STRUCTURED_MODES}")
        if self.provider == "bedrock" and self.structured_mode == "native_schema":
            errs.append(f"{self.name}: bedrock Converse has no response schema; use tool_use or json_repair")
        if self.provider == "anthropic" and self.structured_mode == "native_schema":
            errs.append(f"{self.name}: the anthropic adapter has no response schema; use tool_use or json_repair")
        if self.provider == "openai_compatible" and not self.base_url:
            errs.append(f"{self.name}: openai_compatible needs base_url")
        if not self.model_id:
            errs.append(f"{self.name}: model_id is required")
        if self.temperature is not None and not isinstance(self.temperature, (int, float)):
            errs.append(f"{self.name}: temperature must be a number or null")
        if not isinstance(self.max_output_tokens, int) or self.max_output_tokens <= 0:
            errs.append(f"{self.name}: max_output_tokens must be a positive integer")
        keys = set(self.reasoning or {})
        if not keys <= {"level", "effort", "budget_tokens"} or len(keys) != 1:
            errs.append(f"{self.name}: reasoning must be one of {{level}}, {{effort}} or {{budget_tokens}}")
        return errs

    def inference_config(self) -> dict:
        cfg: dict = {"maxTokens": self.max_output_tokens}
        if self.temperature is not None:
            cfg["temperature"] = float(self.temperature)
        return cfg

    def cost(self, tokens_in: int, tokens_out: int) -> float | None:
        if self.price_in is None or self.price_out is None:
            return None
        return (tokens_in * self.price_in + tokens_out * self.price_out) / 1_000_000

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in self.__dataclass_fields__}


def load_profiles(path: str | None = None) -> dict[str, ModelProfile]:
    path = path or os.environ.get("CLOUDCTL_VERIFY_PROFILES") or _DEFAULT_PATH
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    defaults = doc.get("defaults") or {}
    out: dict[str, ModelProfile] = {}
    errs: list[str] = []
    for name, raw in (doc.get("profiles") or {}).items():
        merged = {**defaults, **(raw or {})}
        known = set(ModelProfile.__dataclass_fields__)
        unknown = set(merged) - known
        if unknown:
            errs.append(f"{name}: unknown field(s) {sorted(unknown)}")
            continue
        p = ModelProfile(name=name, **{k: v for k, v in merged.items() if k != "name"})
        errs += p.validate()
        out[name] = p
    if errs:
        raise ValueError("invalid model profiles: " + "; ".join(errs))
    return out


def require_pinned(profiles: dict[str, ModelProfile]) -> None:
    """For study runs: every profile must have been checked on run day."""
    bad = sorted(n for n, p in profiles.items()
                 if not p.pinned or p.price_in is None or p.price_out is None
                 or p.model_id.startswith("CHECK-CATALOG"))
    if bad:
        raise ValueError("profiles not pinned for a study run (confirm model id in the "
                         f"provider catalog, fill prices, set pinned: true): {bad}")


def select_profile(profiles: dict[str, ModelProfile] | None = None) -> ModelProfile:
    profiles = profiles if profiles is not None else load_profiles()
    name = os.environ.get("CLOUDCTL_VERIFY_PROFILE", "").strip()
    if name:
        if name not in profiles:
            raise ValueError(f"CLOUDCTL_VERIFY_PROFILE={name!r} not in profiles: {sorted(profiles)}")
        return profiles[name]
    model = os.environ.get("CLOUDCTL_MODEL", "us.anthropic.claude-sonnet-4-6")
    provider = os.environ.get("CLOUDCTL_MODEL_PROVIDER", "bedrock").strip().lower() or "bedrock"
    if provider in ("aws",):
        provider = "bedrock"
    if provider == "google":
        provider = "gemini"
    for p in profiles.values():
        if p.model_id == model and p.provider == provider:
            return p
    p = ModelProfile(name=f"adhoc:{provider}:{model}", provider=provider, model_id=model,
                     structured_mode="json_repair", temperature=None,
                     region=os.environ.get("AWS_REGION", "us-east-1"))
    errs = p.validate()
    if errs:
        raise ValueError("; ".join(errs))
    return p
