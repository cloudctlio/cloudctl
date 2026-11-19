"""Provider adapters: what each one sends for the verify proposer's request
fields (temperature, forced tool, response schema, reasoning). Fake SDK
objects only; no network."""
from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from cloudctl.ai import model_providers as MP
from cloudctl.verify.profiles import ModelProfile

TOOLCFG = {"tools": [{"toolSpec": {"name": "submit", "description": "d",
                                   "inputSchema": {"json": {"type": "object", "title": "t",
                                                            "additionalProperties": False,
                                                            "properties": {"a": {"type": "object",
                                                                                 "additionalProperties": False}}}}}}],
           "toolChoice": {"tool": {"name": "submit"}}}


def _anthropic(capture):
    c = MP.AnthropicConverseClient.__new__(MP.AnthropicConverseClient)

    def create(**kw):
        capture.update(kw)
        return SimpleNamespace(content=[], stop_reason="end_turn",
                               usage=SimpleNamespace(input_tokens=0, output_tokens=0))
    c._client = SimpleNamespace(messages=SimpleNamespace(create=create))
    return c


def test_anthropic_omits_temperature_when_absent_and_forces_tool(monkeypatch):
    cap = {}
    _anthropic(cap).converse(modelId="claude-sonnet-4-6", system=[], messages=[],
                             inferenceConfig={"maxTokens": 10}, toolConfig=TOOLCFG,
                             reasoning={"budget_tokens": 1024})
    assert "temperature" not in cap and "extra_body" not in cap
    assert cap["tool_choice"] == {"type": "tool", "name": "submit"}
    assert cap["thinking"] == {"type": "enabled", "budget_tokens": 1024}


def test_anthropic_temperature_goes_through_the_sdk_aware_helper(monkeypatch):
    from cloudctl.ai import factory
    monkeypatch.setattr(factory, "_claude_sdk_temperature_kwargs",
                        lambda t, m: {"extra_body": {"temperature": t}})
    cap = {}
    _anthropic(cap).converse(modelId="m", system=[], messages=[], inferenceConfig={"temperature": 0})
    assert cap["extra_body"] == {"temperature": 0.0} and "temperature" not in cap


def _openai(capture, send_temperature=False):
    c = MP.OpenAIConverseClient.__new__(MP.OpenAIConverseClient)
    c._send_temperature = send_temperature

    def create(**kw):
        capture.update(kw)
        msg = SimpleNamespace(content="{}", tool_calls=None)
        return SimpleNamespace(choices=[SimpleNamespace(message=msg, finish_reason="stop")],
                               usage=SimpleNamespace(prompt_tokens=1, completion_tokens=1))
    c._client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    return c


def test_openai_drops_temperature_by_default_and_sends_schema_and_effort():
    cap = {}
    schema = {"title": "hypotheses", "type": "object"}
    _openai(cap).converse(modelId="gpt", system=[{"text": "s"}], messages=[],
                          inferenceConfig={"maxTokens": 10, "temperature": 0},
                          responseSchema=schema, reasoning={"effort": "low"})
    assert "temperature" not in cap
    assert cap["response_format"] == {"type": "json_schema", "json_schema": {
        "name": "hypotheses", "strict": True, "schema": schema}}
    assert cap["reasoning_effort"] == "low" and cap["max_completion_tokens"] == 10


def test_openai_sends_temperature_when_profile_asks_and_forces_tool():
    cap = {}
    _openai(cap, send_temperature=True).converse(modelId="m", system=[], messages=[],
                                                 inferenceConfig={"temperature": 0.2}, toolConfig=TOOLCFG)
    assert cap["temperature"] == 0.2
    assert cap["tool_choice"] == {"type": "function", "function": {"name": "submit"}}


def test_openai_base_url_reaches_sdk(monkeypatch):
    seen = {}

    class FakeOpenAI:
        def __init__(self, **kw):
            seen.update(kw)
    monkeypatch.setitem(sys.modules, "openai", SimpleNamespace(OpenAI=FakeOpenAI))
    MP.OpenAIConverseClient(base_url="http://localhost:8000/v1")
    assert seen == {"base_url": "http://localhost:8000/v1"}
    seen.clear()
    c = MP.OpenAIConverseClient()
    assert seen == {} and c._send_temperature is False


def _gemini(capture):
    c = MP.GeminiConverseClient.__new__(MP.GeminiConverseClient)

    def gen(**kw):
        capture.update(kw)
        part = SimpleNamespace(text="{}", function_call=None)
        return SimpleNamespace(candidates=[SimpleNamespace(content=SimpleNamespace(parts=[part]))],
                               usage_metadata=SimpleNamespace(prompt_token_count=1, candidates_token_count=1))
    c._client = SimpleNamespace(models=SimpleNamespace(generate_content=gen))
    return c


def test_gemini_strips_schema_keywords_and_sets_thinking():
    cap = {}
    schema = TOOLCFG["tools"][0]["toolSpec"]["inputSchema"]["json"]
    _gemini(cap).converse(modelId="g", system=[], messages=[], inferenceConfig={"maxTokens": 10},
                          responseSchema=schema, reasoning={"budget_tokens": 0}, toolConfig=TOOLCFG)
    cfg = cap["config"]
    assert "temperature" not in cfg
    assert cfg["response_mime_type"] == "application/json"
    assert cfg["response_schema"] == {"type": "object", "properties": {"a": {"type": "object"}}}
    assert cfg["thinking_config"] == {"thinking_budget": 0}
    assert cfg["tools"][0]["function_declarations"][0]["parameters"] == cfg["response_schema"]
    assert cfg["tool_config"]["function_calling_config"]["allowed_function_names"] == ["submit"]


def test_tool_choice_name():
    assert MP.tool_choice_name(TOOLCFG) == "submit"
    assert MP.tool_choice_name({"tools": []}) == "" and MP.tool_choice_name(None) == ""


def test_make_model_client_for_dispatches_on_profile(monkeypatch):
    monkeypatch.setattr(MP, "_bedrock_client", lambda p, r: ("bedrock", p, r))
    monkeypatch.setattr(MP, "AnthropicConverseClient", lambda: "anthropic")
    monkeypatch.setattr(MP, "GeminiConverseClient", lambda: "gemini")
    monkeypatch.setattr(MP, "OpenAIConverseClient", lambda **kw: ("openai", kw))
    mk = lambda **kw: ModelProfile(name="x", model_id="m", **kw)
    assert MP.make_model_client_for(mk(provider="bedrock", region="us-west-2"), "prof") == (
        "bedrock", "prof", "us-west-2")
    assert MP.make_model_client_for(mk(provider="anthropic")) == "anthropic"
    assert MP.make_model_client_for(mk(provider="gemini")) == "gemini"
    assert MP.make_model_client_for(mk(provider="openai_compatible", base_url="http://h", temperature=0.1)) == (
        "openai", {"base_url": "http://h", "send_temperature": True})
    assert MP.make_model_client_for(mk(provider="openai")) == (
        "openai", {"base_url": None, "send_temperature": False})
    with pytest.raises(ValueError):
        MP.make_model_client_for(mk(provider="toaster"))
