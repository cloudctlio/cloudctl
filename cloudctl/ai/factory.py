"""AI provider factory — returns the right AI client based on config."""
from __future__ import annotations

import re
from typing import Any, Optional

from cloudctl.config.manager import ConfigManager


# ── Base class ─────────────────────────────────────────────────────────────────

class BaseAI:
    """Common interface for all AI providers."""

    def ask(self, question: str, context: dict | None = None) -> dict:
        raise NotImplementedError

    def generate_fix(self, issue: dict) -> dict:
        raise NotImplementedError

    def analyze_logs(self, logs: str, context: dict | None = None) -> dict:
        raise NotImplementedError


# ── Model ID tables ────────────────────────────────────────────────────────────

_BEDROCK_MODELS = {
    "opus":   "us.anthropic.claude-opus-4-6-v1:0",
    "sonnet": "us.anthropic.claude-sonnet-4-6-v1:0",
    "haiku":  "us.anthropic.claude-haiku-4-5-20251001-v1:0",
}
_AZURE_MODELS = {
    "opus":   "claude-opus-4-6",
    "sonnet": "claude-sonnet-4-6",
    "haiku":  "claude-haiku-4-5",
}
_VERTEX_MODELS = {
    "opus":   "claude-opus-4-6@20260101",
    "sonnet": "claude-sonnet-4-6@20260101",
    "haiku":  "claude-haiku-4-5@20251001",
}
_ANTHROPIC_MODELS = {
    "opus":   "claude-opus-4-6-20260101",
    "sonnet": "claude-sonnet-4-6-20260101",
    "haiku":  "claude-haiku-4-5-20251001",
}


# ── Prompt helpers ─────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = (
    "You are a senior cloud infrastructure expert. "
    "Answer using ONLY the real data provided. "
    "Cite specific resource names and values. "
    "If the data is insufficient, say so explicitly. "
    "Never guess."
)


def _ask_prompt(question: str, context: dict) -> str:
    import json  # noqa: PLC0415
    parts = [f"REAL DATA FROM CLOUD:\n{json.dumps(context, indent=2)}", f"\nQUESTION: {question}",
             "\nBase your answer strictly on the data above."]
    return "\n".join(parts)


def _parse_json_response(text: str) -> dict:
    """Extract JSON from a model response (strips markdown fences if present)."""
    import json  # noqa: PLC0415
    text = re.sub(r"```(?:json)?\s*", "", text).strip().rstrip("`")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw": text}


# ── AWS Bedrock ────────────────────────────────────────────────────────────────

class BedrockAI(BaseAI):
    def __init__(self, cfg: ConfigManager):
        import boto3  # noqa: PLC0415
        region = cfg.get("ai.bedrock_region") or "us-east-1"
        tier   = cfg.get("ai.tier") or "sonnet"
        self._model = cfg.get("ai.bedrock_model") or _BEDROCK_MODELS.get(tier, _BEDROCK_MODELS["sonnet"])
        self._client = boto3.client("bedrock-runtime", region_name=region)

    def _invoke(self, prompt: str) -> str:
        import json  # noqa: PLC0415
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 4096,
            "system": _SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": prompt}],
        })
        resp = self._client.invoke_model(modelId=self._model, body=body)
        data = json.loads(resp["body"].read())
        return data["content"][0]["text"]

    def ask(self, question: str, context: dict | None = None) -> dict:
        text = self._invoke(_ask_prompt(question, context or {}))
        return {"answer": text, "confidence": "HIGH", "sources": ["AWS Bedrock"]}

    def generate_fix(self, issue: dict) -> dict:
        import json  # noqa: PLC0415
        prompt = f"Generate a JSON fix proposal for this issue. Return valid JSON only, no markdown.\n{json.dumps(issue)}"
        return _parse_json_response(self._invoke(prompt))

    def analyze_logs(self, logs: str, context: dict | None = None) -> dict:
        import json  # noqa: PLC0415
        prompt = f"Analyze these logs and return a JSON summary. No markdown fences.\n\nLOGS:\n{logs}"
        if context:
            prompt += f"\n\nCONTEXT:\n{json.dumps(context)}"
        return _parse_json_response(self._invoke(prompt))


# ── Azure Foundry ──────────────────────────────────────────────────────────────

class AzureFoundryAI(BaseAI):
    def __init__(self, cfg: ConfigManager):
        resource  = cfg.get("ai.azure_foundry_resource") or ""
        tier      = cfg.get("ai.tier") or "sonnet"
        self._model = cfg.get("ai.azure_foundry_model") or _AZURE_MODELS.get(tier, _AZURE_MODELS["sonnet"])
        base_url    = f"https://{resource}.services.ai.azure.com/anthropic"
        api_key     = cfg.get("ai.azure_foundry_api_key")

        if api_key:
            from anthropic import Anthropic  # noqa: PLC0415
            self._client = Anthropic(base_url=base_url, api_key=api_key)
        else:
            from azure.identity import DefaultAzureCredential, get_bearer_token_provider  # noqa: PLC0415
            from anthropic import Anthropic  # noqa: PLC0415
            token_provider = get_bearer_token_provider(
                DefaultAzureCredential(), "https://cognitiveservices.azure.com/.default"
            )
            self._client = Anthropic(
                base_url=base_url,
                default_headers={"Authorization": f"Bearer {token_provider()}"},
                api_key="placeholder",
            )

    def _invoke(self, prompt: str) -> str:
        msg = self._client.messages.create(
            model=self._model,
            max_tokens=4096,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text

    def ask(self, question: str, context: dict | None = None) -> dict:
        text = self._invoke(_ask_prompt(question, context or {}))
        return {"answer": text, "confidence": "HIGH", "sources": ["Azure Foundry"]}

    def generate_fix(self, issue: dict) -> dict:
        import json  # noqa: PLC0415
        return _parse_json_response(self._invoke(
            f"Generate a JSON fix for this issue. No markdown.\n{json.dumps(issue)}"
        ))

    def analyze_logs(self, logs: str, context: dict | None = None) -> dict:
        import json  # noqa: PLC0415
        prompt = f"Analyze logs, return JSON summary. No markdown.\n\nLOGS:\n{logs}"
        if context:
            prompt += f"\n\nCONTEXT:\n{json.dumps(context)}"
        return _parse_json_response(self._invoke(prompt))


# ── GCP Vertex AI ──────────────────────────────────────────────────────────────

class VertexAI(BaseAI):
    def __init__(self, cfg: ConfigManager):
        from anthropic import AnthropicVertex  # noqa: PLC0415
        import google.auth  # noqa: PLC0415
        _, project = google.auth.default()
        region     = cfg.get("ai.vertex_region") or "us-east5"
        tier       = cfg.get("ai.tier") or "sonnet"
        project_id = cfg.get("ai.vertex_project") or project or ""
        self._model  = cfg.get("ai.vertex_model") or _VERTEX_MODELS.get(tier, _VERTEX_MODELS["sonnet"])
        self._client = AnthropicVertex(region=region, project_id=project_id)

    def _invoke(self, prompt: str) -> str:
        msg = self._client.messages.create(
            model=self._model,
            max_tokens=4096,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text

    def ask(self, question: str, context: dict | None = None) -> dict:
        return {"answer": self._invoke(_ask_prompt(question, context or {})), "confidence": "HIGH", "sources": ["Vertex AI"]}

    def generate_fix(self, issue: dict) -> dict:
        import json  # noqa: PLC0415
        return _parse_json_response(self._invoke(f"JSON fix for issue. No markdown.\n{json.dumps(issue)}"))

    def analyze_logs(self, logs: str, context: dict | None = None) -> dict:
        import json  # noqa: PLC0415
        p = f"Analyze logs, return JSON. No markdown.\n\nLOGS:\n{logs}"
        if context:
            p += f"\n\nCONTEXT:\n{json.dumps(context)}"
        return _parse_json_response(self._invoke(p))


# ── Anthropic Direct ───────────────────────────────────────────────────────────

class AnthropicAI(BaseAI):
    def __init__(self, cfg: ConfigManager):
        from anthropic import Anthropic  # noqa: PLC0415
        api_key     = cfg.get("ai.anthropic_api_key") or ""
        tier        = cfg.get("ai.tier") or "sonnet"
        self._model  = cfg.get("ai.anthropic_model") or _ANTHROPIC_MODELS.get(tier, _ANTHROPIC_MODELS["sonnet"])
        self._client = Anthropic(api_key=api_key)

    def _invoke(self, prompt: str) -> str:
        msg = self._client.messages.create(
            model=self._model, max_tokens=4096,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text

    def ask(self, question: str, context: dict | None = None) -> dict:
        return {"answer": self._invoke(_ask_prompt(question, context or {})), "confidence": "HIGH", "sources": ["Anthropic"]}

    def generate_fix(self, issue: dict) -> dict:
        import json  # noqa: PLC0415
        return _parse_json_response(self._invoke(f"JSON fix for issue. No markdown.\n{json.dumps(issue)}"))

    def analyze_logs(self, logs: str, context: dict | None = None) -> dict:
        import json  # noqa: PLC0415
        p = f"Analyze logs, return JSON. No markdown.\n\nLOGS:\n{logs}"
        if context:
            p += f"\n\nCONTEXT:\n{json.dumps(context)}"
        return _parse_json_response(self._invoke(p))


# ── OpenAI ─────────────────────────────────────────────────────────────────────

class OpenAIProvider(BaseAI):
    def __init__(self, cfg: ConfigManager):
        from openai import OpenAI  # noqa: PLC0415
        self._model  = cfg.get("ai.openai_model") or "gpt-4o"
        self._client = OpenAI(api_key=cfg.get("ai.openai_api_key") or "")

    def _invoke(self, prompt: str) -> str:
        resp = self._client.chat.completions.create(
            model=self._model,
            messages=[{"role": "system", "content": _SYSTEM_PROMPT}, {"role": "user", "content": prompt}],
        )
        return resp.choices[0].message.content or ""

    def ask(self, question: str, context: dict | None = None) -> dict:
        return {"answer": self._invoke(_ask_prompt(question, context or {})), "confidence": "HIGH", "sources": ["OpenAI"]}

    def generate_fix(self, issue: dict) -> dict:
        import json  # noqa: PLC0415
        return _parse_json_response(self._invoke(f"JSON fix for issue. No markdown.\n{json.dumps(issue)}"))

    def analyze_logs(self, logs: str, context: dict | None = None) -> dict:
        import json  # noqa: PLC0415
        p = f"Analyze logs, return JSON. No markdown.\n\nLOGS:\n{logs}"
        if context:
            p += f"\n\nCONTEXT:\n{json.dumps(context)}"
        return _parse_json_response(self._invoke(p))


# ── Ollama ─────────────────────────────────────────────────────────────────────

class OllamaAI(BaseAI):
    def __init__(self, cfg: ConfigManager):
        import requests  # noqa: PLC0415
        self._host    = cfg.get("ai.ollama_host") or "http://localhost:11434"
        self._model   = cfg.get("ai.ollama_model") or "llama3"
        self._session = requests.Session()

    def _invoke(self, prompt: str) -> str:
        import json  # noqa: PLC0415
        resp = self._session.post(
            f"{self._host}/api/generate",
            json={"model": self._model, "prompt": f"{_SYSTEM_PROMPT}\n\n{prompt}", "stream": False},
            timeout=120,
        )
        resp.raise_for_status()
        return resp.json().get("response", "")

    def ask(self, question: str, context: dict | None = None) -> dict:
        return {"answer": self._invoke(_ask_prompt(question, context or {})), "confidence": "MEDIUM", "sources": ["Ollama"]}

    def generate_fix(self, issue: dict) -> dict:
        import json  # noqa: PLC0415
        return _parse_json_response(self._invoke(f"JSON fix for issue. No markdown.\n{json.dumps(issue)}"))

    def analyze_logs(self, logs: str, context: dict | None = None) -> dict:
        import json  # noqa: PLC0415
        p = f"Analyze logs, return JSON. No markdown.\n\nLOGS:\n{logs}"
        if context:
            p += f"\n\nCONTEXT:\n{json.dumps(context)}"
        return _parse_json_response(self._invoke(p))


# ── Auto-detect ────────────────────────────────────────────────────────────────

def _auto_detect_provider(cfg: ConfigManager) -> Optional[str]:
    clouds = cfg.clouds if hasattr(cfg, "clouds") else []
    if "aws" in clouds:
        return "bedrock"
    if "gcp" in clouds:
        return "vertex"
    if "azure" in clouds:
        return "azure"
    return None


# ── Public API ─────────────────────────────────────────────────────────────────

_PROVIDER_MAP: dict[str, type] = {
    "bedrock":    BedrockAI,
    "azure":      AzureFoundryAI,
    "vertex":     VertexAI,
    "anthropic":  AnthropicAI,
    "openai":     OpenAIProvider,
    "ollama":     OllamaAI,
}


def get_ai(cfg: ConfigManager, purpose: str = "default") -> BaseAI:
    """Return configured AI provider instance."""
    provider = cfg.get("ai.provider") or "none"
    if provider == "auto":
        provider = _auto_detect_provider(cfg) or "none"
    if purpose == "analysis":
        provider = cfg.get("ai.analysis_provider") or provider
    elif purpose == "fix":
        provider = cfg.get("ai.fix_provider") or provider

    cls = _PROVIDER_MAP.get(provider)
    if not cls:
        raise ValueError(f"AI provider '{provider}' not supported or not configured.")
    return cls(cfg)


def get_analysis_ai(cfg: ConfigManager) -> BaseAI:
    return get_ai(cfg, purpose="analysis")


def get_fix_ai(cfg: ConfigManager) -> BaseAI:
    return get_ai(cfg, purpose="fix")


def is_ai_configured(cfg: ConfigManager) -> bool:
    try:
        provider = cfg.get("ai.provider") or "none"
        if provider in ("none", "", None):
            return False
        if provider == "auto":
            return _auto_detect_provider(cfg) is not None
        return provider in _PROVIDER_MAP
    except Exception:
        return False


def get_ai_status(cfg: ConfigManager) -> dict:
    provider = cfg.get("ai.provider") or "none"
    tier     = cfg.get("ai.tier") or "sonnet"
    status   = {"provider": provider, "tier": tier}

    def _mask(val: Optional[str]) -> str:
        if not val or len(val) < 8:
            return "***"
        return f"{val[:4]}...{val[-4:]}"

    if provider == "bedrock":
        status["region"] = cfg.get("ai.bedrock_region") or "us-east-1"
    elif provider == "azure":
        status["resource"] = cfg.get("ai.azure_foundry_resource") or "—"
        key = cfg.get("ai.azure_foundry_api_key")
        if key:
            status["api_key"] = _mask(key)
    elif provider == "vertex":
        status["region"]  = cfg.get("ai.vertex_region") or "us-east5"
        status["project"] = cfg.get("ai.vertex_project") or "—"
    elif provider == "anthropic":
        status["api_key"] = _mask(cfg.get("ai.anthropic_api_key"))
    elif provider == "openai":
        status["api_key"] = _mask(cfg.get("ai.openai_api_key"))
        status["model"]   = cfg.get("ai.openai_model") or "gpt-4o"
    elif provider == "ollama":
        status["host"]  = cfg.get("ai.ollama_host") or "http://localhost:11434"
        status["model"] = cfg.get("ai.ollama_model") or "llama3"

    return status
