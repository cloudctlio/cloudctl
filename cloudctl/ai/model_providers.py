"""Model-provider abstraction — run VERDICT's reasoning on any backend.

The whole graph speaks the Bedrock **Converse** shape: it calls
`client.converse(modelId=, system=, messages=, toolConfig=, inferenceConfig=)`
and reads `resp["output"]["message"]["content"]`, `resp["stopReason"]`,
`resp["usage"]`. Rather than rewrite every node, each provider exposes that SAME
`converse(**kwargs)` method and translates to/from its own SDK internally, so it
is a drop-in — `RecordingBedrock` and the usage accounting wrap it unchanged.

Select the backend with `CLOUDCTL_MODEL_PROVIDER` (default `bedrock`); pick the
model with `CLOUDCTL_MODEL`. Credentials come from the provider's usual env var
(`AWS_PROFILE`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`).

Adding a provider = implement one `converse(**kwargs)` returning the Converse
shape and register it in `make_model_client`.
"""
from __future__ import annotations

import os


class _ThrottlingException(Exception):
    """Uniform rate-limit type so callers that catch throttling work across
    providers (the graph catches generic Exception, but this keeps parity with
    boto3's client.exceptions.ThrottlingException)."""


class _Exceptions:
    ThrottlingException = _ThrottlingException


# ── Converse <-> generic translation helpers (pure; unit-tested) ───────────────

def system_to_text(system) -> str:
    """Converse system is a list of {"text": ...} blocks (plus cachePoint dicts).
    Flatten to a single system string."""
    if isinstance(system, str):
        return system
    parts = []
    for blk in system or []:
        if isinstance(blk, dict) and "text" in blk:
            parts.append(blk["text"])
    return "\n\n".join(parts)


def messages_to_generic(messages) -> list[dict]:
    """Converse messages -> a provider-neutral shape close to the Anthropic
    Messages format: role + content blocks of type text | tool_use | tool_result.
    cachePoint markers are dropped (they are a Bedrock caching hint only)."""
    out = []
    for msg in messages or []:
        role = msg.get("role", "user")
        blocks = []
        for c in msg.get("content", []):
            if not isinstance(c, dict):
                continue
            if "text" in c:
                blocks.append({"type": "text", "text": c["text"]})
            elif "toolUse" in c:
                tu = c["toolUse"]
                blocks.append({"type": "tool_use", "id": tu.get("toolUseId"),
                               "name": tu.get("name"), "input": tu.get("input", {})})
            elif "toolResult" in c:
                tr = c["toolResult"]
                text = " ".join(
                    b.get("text", "") for b in tr.get("content", []) if isinstance(b, dict)
                )
                blocks.append({"type": "tool_result",
                               "tool_use_id": tr.get("toolUseId"), "content": text})
            # cachePoint / unknown -> skip
        if blocks:
            out.append({"role": role, "content": blocks})
    return out


def tools_to_generic(tool_config) -> list[dict]:
    """Converse toolConfig -> [{name, description, input_schema}]."""
    out = []
    for t in (tool_config or {}).get("tools", []):
        spec = t.get("toolSpec") if isinstance(t, dict) else None
        if not spec:
            continue
        out.append({
            "name": spec.get("name"),
            "description": spec.get("description", ""),
            "input_schema": (spec.get("inputSchema") or {}).get("json", {}),
        })
    return out


_STOP_MAP = {
    "end_turn": "end_turn", "stop": "end_turn", "stop_sequence": "end_turn",
    "tool_use": "tool_use", "tool_calls": "tool_use", "function_call": "tool_use",
    "max_tokens": "max_tokens", "length": "max_tokens",
}


def to_converse_response(content_blocks: list[dict], stop_reason: str,
                         in_tokens: int, out_tokens: int) -> dict:
    """Assemble a Bedrock-Converse-shaped response from neutral content blocks.
    content_blocks items: {"type":"text","text":..} or
    {"type":"tool_use","id":..,"name":..,"input":..}."""
    conv = []
    for b in content_blocks:
        if b.get("type") == "text":
            conv.append({"text": b.get("text", "")})
        elif b.get("type") == "tool_use":
            conv.append({"toolUse": {"toolUseId": b.get("id"),
                                     "name": b.get("name"),
                                     "input": b.get("input", {})}})
    return {
        "output": {"message": {"role": "assistant", "content": conv}},
        "stopReason": _STOP_MAP.get(stop_reason, "end_turn"),
        "usage": {"inputTokens": in_tokens or 0, "outputTokens": out_tokens or 0},
    }


# ── Providers ─────────────────────────────────────────────────────────────────

class AnthropicConverseClient:
    """Anthropic Messages API behind the Converse interface. Needs
    ANTHROPIC_API_KEY; no AWS required."""

    exceptions = _Exceptions()

    def __init__(self):
        import anthropic  # lazy: only when this provider is selected
        self._client = anthropic.Anthropic()

    def converse(self, **kwargs) -> dict:
        infer = kwargs.get("inferenceConfig") or {}
        req = dict(
            model=kwargs["modelId"],
            system=system_to_text(kwargs.get("system")),
            messages=messages_to_generic(kwargs.get("messages")),
            max_tokens=int(infer.get("maxTokens", 2000)),
            temperature=float(infer.get("temperature", 0)),
        )
        tools = tools_to_generic(kwargs.get("toolConfig"))
        if tools:
            req["tools"] = tools
        try:
            resp = self._client.messages.create(**req)
        except Exception as e:  # normalize throttling across SDK versions
            if "RateLimit" in type(e).__name__:
                raise _ThrottlingException(str(e)) from e
            raise
        blocks = []
        for b in resp.content:
            if b.type == "text":
                blocks.append({"type": "text", "text": b.text})
            elif b.type == "tool_use":
                blocks.append({"type": "tool_use", "id": b.id,
                               "name": b.name, "input": b.input})
        return to_converse_response(
            blocks, resp.stop_reason,
            getattr(resp.usage, "input_tokens", 0),
            getattr(resp.usage, "output_tokens", 0),
        )


class OpenAIConverseClient:
    """OpenAI Chat Completions behind the Converse interface. Needs
    OPENAI_API_KEY."""

    exceptions = _Exceptions()

    def __init__(self):
        import openai  # lazy
        self._client = openai.OpenAI()

    def _to_openai_messages(self, system_text, generic_msgs):
        msgs = [{"role": "system", "content": system_text}] if system_text else []
        for m in generic_msgs:
            texts = [b["text"] for b in m["content"] if b["type"] == "text"]
            tool_uses = [b for b in m["content"] if b["type"] == "tool_use"]
            tool_results = [b for b in m["content"] if b["type"] == "tool_result"]
            if m["role"] == "assistant" and tool_uses:
                msgs.append({
                    "role": "assistant",
                    "content": " ".join(texts) or None,
                    "tool_calls": [
                        {"id": t["id"], "type": "function",
                         "function": {"name": t["name"],
                                      "arguments": _json_dumps(t["input"])}}
                        for t in tool_uses
                    ],
                })
            elif tool_results:
                for tr in tool_results:
                    msgs.append({"role": "tool", "tool_call_id": tr["tool_use_id"],
                                 "content": tr["content"]})
            else:
                msgs.append({"role": m["role"], "content": " ".join(texts)})
        return msgs

    def converse(self, **kwargs) -> dict:
        infer = kwargs.get("inferenceConfig") or {}
        generic = messages_to_generic(kwargs.get("messages"))
        req = dict(
            model=kwargs["modelId"],
            messages=self._to_openai_messages(
                system_to_text(kwargs.get("system")), generic),
            max_completion_tokens=int(infer.get("maxTokens", 2000)),
        )
        tools = tools_to_generic(kwargs.get("toolConfig"))
        if tools:
            req["tools"] = [
                {"type": "function", "function": {
                    "name": t["name"], "description": t["description"],
                    "parameters": t["input_schema"]}}
                for t in tools
            ]
        try:
            resp = self._client.chat.completions.create(**req)
        except Exception as e:
            if "RateLimit" in type(e).__name__:
                raise _ThrottlingException(str(e)) from e
            raise
        choice = resp.choices[0]
        blocks = []
        if choice.message.content:
            blocks.append({"type": "text", "text": choice.message.content})
        for tc in (choice.message.tool_calls or []):
            blocks.append({"type": "tool_use", "id": tc.id,
                           "name": tc.function.name,
                           "input": _json_loads(tc.function.arguments)})
        usage = getattr(resp, "usage", None)
        return to_converse_response(
            blocks, choice.finish_reason,
            getattr(usage, "prompt_tokens", 0),
            getattr(usage, "completion_tokens", 0),
        )


class GeminiConverseClient:
    """Google Gemini (google-genai) behind the Converse interface. Needs
    GEMINI_API_KEY (or GOOGLE_API_KEY). NOTE: Gemini has no tool-call IDs — it
    matches a function_response to a function_call by NAME — so we key tool
    results by the tool name; a branch calling the same tool twice in one turn is
    the one case that can't be perfectly disambiguated."""

    exceptions = _Exceptions()

    def __init__(self):
        from google import genai  # lazy
        self._client = genai.Client()

    def _to_contents(self, generic_msgs):
        id2name = {b["id"]: b["name"]
                   for m in generic_msgs for b in m["content"]
                   if b["type"] == "tool_use"}
        contents = []
        for m in generic_msgs:
            role = "model" if m["role"] == "assistant" else "user"
            parts = []
            for b in m["content"]:
                if b["type"] == "text":
                    parts.append({"text": b["text"]})
                elif b["type"] == "tool_use":
                    parts.append({"function_call": {"name": b["name"],
                                                    "args": b["input"]}})
                elif b["type"] == "tool_result":
                    name = id2name.get(b["tool_use_id"], b["tool_use_id"])
                    parts.append({"function_response": {
                        "name": name, "response": {"result": b["content"]}}})
            if parts:
                contents.append({"role": role, "parts": parts})
        return contents

    def converse(self, **kwargs) -> dict:
        infer = kwargs.get("inferenceConfig") or {}
        generic = messages_to_generic(kwargs.get("messages"))
        config = {
            "max_output_tokens": int(infer.get("maxTokens", 2000)),
            "temperature": float(infer.get("temperature", 0)),
        }
        sys_text = system_to_text(kwargs.get("system"))
        if sys_text:
            config["system_instruction"] = sys_text
        tools = tools_to_generic(kwargs.get("toolConfig"))
        if tools:
            config["tools"] = [{"function_declarations": [
                {"name": t["name"], "description": t["description"],
                 "parameters": t["input_schema"]} for t in tools]}]
        try:
            resp = self._client.models.generate_content(
                model=kwargs["modelId"],
                contents=self._to_contents(generic),
                config=config,
            )
        except Exception as e:
            if any(s in type(e).__name__ for s in ("ResourceExhausted", "RateLimit")):
                raise _ThrottlingException(str(e)) from e
            raise
        blocks = []
        for p in resp.candidates[0].content.parts:
            if getattr(p, "text", None):
                blocks.append({"type": "text", "text": p.text})
            fc = getattr(p, "function_call", None)
            if fc:
                blocks.append({"type": "tool_use", "id": fc.name, "name": fc.name,
                               "input": dict(fc.args) if fc.args else {}})
        stop = "tool_use" if any(b["type"] == "tool_use" for b in blocks) else "end_turn"
        um = getattr(resp, "usage_metadata", None)
        return to_converse_response(
            blocks, stop,
            getattr(um, "prompt_token_count", 0),
            getattr(um, "candidates_token_count", 0),
        )


def _json_dumps(o):
    import json
    return json.dumps(o)


def _json_loads(s):
    import json
    try:
        return json.loads(s)
    except Exception:
        return {}


def _bedrock_client(profile: str | None, region: str):
    from botocore.config import Config as _BotoConfig
    from cloudctl.mcp.tools.debug import _make_session
    session = _make_session(profile, region)
    return session.client(
        "bedrock-runtime", region_name=region,
        config=_BotoConfig(retries={"mode": "adaptive", "max_attempts": 10},
                           connect_timeout=10, read_timeout=120),
    )


def make_model_client(profile: str | None, region: str):
    """Return a client exposing converse(**kwargs) in the Converse shape, chosen
    by CLOUDCTL_MODEL_PROVIDER (default 'bedrock')."""
    provider = os.environ.get("CLOUDCTL_MODEL_PROVIDER", "bedrock").strip().lower()
    if provider in ("", "bedrock", "aws"):
        return _bedrock_client(profile, region)
    if provider == "anthropic":
        return AnthropicConverseClient()
    if provider == "openai":
        return OpenAIConverseClient()
    if provider in ("gemini", "google"):
        return GeminiConverseClient()
    raise ValueError(
        f"unknown CLOUDCTL_MODEL_PROVIDER={provider!r}; "
        "supported: bedrock, anthropic, openai, gemini"
    )
