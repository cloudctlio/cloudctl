"""Model-provider abstraction — the Converse<->provider translation is what lets
VERDICT run on Bedrock, Anthropic, or OpenAI unchanged. Pure translation + a
fake-SDK round trip, so no API keys or network are needed."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from cloudctl.ai import model_providers as MP


# ── pure translation ──────────────────────────────────────────────────────────
def test_system_to_text_flattens_and_drops_cachepoint():
    system = [{"text": "you are an SRE"}, {"cachePoint": {"type": "default"}},
              {"text": "be precise"}]
    assert MP.system_to_text(system) == "you are an SRE\n\nbe precise"
    assert MP.system_to_text("already a string") == "already a string"


def test_messages_to_generic_maps_text_tooluse_toolresult():
    messages = [
        {"role": "user", "content": [{"text": "hi"}, {"cachePoint": {}}]},
        {"role": "assistant", "content": [
            {"toolUse": {"toolUseId": "t1", "name": "list_resources",
                         "input": {"service_type": "ecs"}}}]},
        {"role": "user", "content": [
            {"toolResult": {"toolUseId": "t1", "content": [{"text": "3 clusters"}]}}]},
    ]
    g = MP.messages_to_generic(messages)
    assert g[0]["content"][0] == {"type": "text", "text": "hi"}
    assert len(g[0]["content"]) == 1                      # cachePoint dropped
    assert g[1]["content"][0]["type"] == "tool_use"
    assert g[1]["content"][0]["name"] == "list_resources"
    assert g[2]["content"][0] == {"type": "tool_result",
                                  "tool_use_id": "t1", "content": "3 clusters"}


def test_tools_to_generic():
    tc = {"tools": [
        {"toolSpec": {"name": "tail_logs", "description": "read logs",
                      "inputSchema": {"json": {"type": "object"}}}},
        {"cachePoint": {"type": "default"}},
    ]}
    tools = MP.tools_to_generic(tc)
    assert tools == [{"name": "tail_logs", "description": "read logs",
                      "input_schema": {"type": "object"}}]


def test_to_converse_response_shape_and_stop_map():
    blocks = [{"type": "text", "text": "root cause X"},
              {"type": "tool_use", "id": "a1", "name": "query_metrics", "input": {"m": 1}}]
    r = MP.to_converse_response(blocks, "tool_calls", 100, 42)
    assert r["stopReason"] == "tool_use"                 # openai 'tool_calls' -> converse
    assert r["usage"] == {"inputTokens": 100, "outputTokens": 42}
    content = r["output"]["message"]["content"]
    assert content[0] == {"text": "root cause X"}
    assert content[1]["toolUse"]["toolUseId"] == "a1"
    assert MP.to_converse_response([], "length", 0, 0)["stopReason"] == "max_tokens"


# ── Anthropic round trip via a fake SDK client ────────────────────────────────
def _anthropic_client(fake_resp):
    c = MP.AnthropicConverseClient.__new__(MP.AnthropicConverseClient)
    c._client = SimpleNamespace(
        messages=SimpleNamespace(create=lambda **kw: fake_resp))
    return c


def test_anthropic_converse_normalizes_to_converse_shape():
    fake = SimpleNamespace(
        content=[SimpleNamespace(type="text", text="it was the IAM policy")],
        stop_reason="end_turn",
        usage=SimpleNamespace(input_tokens=10, output_tokens=5),
    )
    c = _anthropic_client(fake)
    out = c.converse(modelId="claude-x", system=[{"text": "sys"}],
                     messages=[{"role": "user", "content": [{"text": "why?"}]}],
                     inferenceConfig={"maxTokens": 50, "temperature": 0})
    assert out["output"]["message"]["content"][0] == {"text": "it was the IAM policy"}
    assert out["stopReason"] == "end_turn"
    assert out["usage"]["inputTokens"] == 10


def test_anthropic_converse_maps_tool_use():
    fake = SimpleNamespace(
        content=[SimpleNamespace(type="tool_use", id="tu1", name="tail_logs",
                                 input={"resource_hint": "svc"})],
        stop_reason="tool_use",
        usage=SimpleNamespace(input_tokens=1, output_tokens=1),
    )
    out = _anthropic_client(fake).converse(
        modelId="claude-x", messages=[], system=[{"text": "s"}])
    tu = out["output"]["message"]["content"][0]["toolUse"]
    assert tu == {"toolUseId": "tu1", "name": "tail_logs",
                  "input": {"resource_hint": "svc"}}
    assert out["stopReason"] == "tool_use"


def test_anthropic_ratelimit_normalized():
    class RateLimitError(Exception):
        pass

    def boom(**kw):
        raise RateLimitError("slow down")
    c = MP.AnthropicConverseClient.__new__(MP.AnthropicConverseClient)
    c._client = SimpleNamespace(messages=SimpleNamespace(create=boom))
    with pytest.raises(MP._ThrottlingException):
        c.converse(modelId="x", messages=[], system=[])


# ── OpenAI round trip via a fake SDK client ───────────────────────────────────
def test_openai_converse_text_and_tool_calls():
    msg = SimpleNamespace(
        content="checking",
        tool_calls=[SimpleNamespace(
            id="c1", function=SimpleNamespace(name="query_metrics",
                                              arguments='{"namespace":"AWS/ECS"}'))],
    )
    fake = SimpleNamespace(
        choices=[SimpleNamespace(message=msg, finish_reason="tool_calls")],
        usage=SimpleNamespace(prompt_tokens=7, completion_tokens=3),
    )
    c = MP.OpenAIConverseClient.__new__(MP.OpenAIConverseClient)
    c._client = SimpleNamespace(
        chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **kw: fake)))
    out = c.converse(modelId="gpt-x", system=[{"text": "s"}],
                     messages=[{"role": "user", "content": [{"text": "go"}]}])
    content = out["output"]["message"]["content"]
    assert content[0] == {"text": "checking"}
    assert content[1]["toolUse"]["name"] == "query_metrics"
    assert content[1]["toolUse"]["input"] == {"namespace": "AWS/ECS"}
    assert out["stopReason"] == "tool_use"
    assert out["usage"] == {"inputTokens": 7, "outputTokens": 3}


# ── Gemini round trip via a fake SDK client ───────────────────────────────────
def _gemini_client(fake_resp):
    c = MP.GeminiConverseClient.__new__(MP.GeminiConverseClient)
    c._client = SimpleNamespace(
        models=SimpleNamespace(generate_content=lambda **kw: fake_resp))
    return c


def test_gemini_converse_text():
    part = SimpleNamespace(text="the KMS key was disabled", function_call=None)
    fake = SimpleNamespace(
        candidates=[SimpleNamespace(content=SimpleNamespace(parts=[part]))],
        usage_metadata=SimpleNamespace(prompt_token_count=9, candidates_token_count=4),
    )
    out = _gemini_client(fake).converse(
        modelId="gemini-x", system=[{"text": "s"}],
        messages=[{"role": "user", "content": [{"text": "why?"}]}])
    assert out["output"]["message"]["content"][0] == {"text": "the KMS key was disabled"}
    assert out["stopReason"] == "end_turn"
    assert out["usage"] == {"inputTokens": 9, "outputTokens": 4}


def test_gemini_converse_function_call_maps_to_tooluse():
    fc = SimpleNamespace(name="get_service_config", args={"service_type": "kms"})
    part = SimpleNamespace(text=None, function_call=fc)
    fake = SimpleNamespace(
        candidates=[SimpleNamespace(content=SimpleNamespace(parts=[part]))],
        usage_metadata=SimpleNamespace(prompt_token_count=1, candidates_token_count=1),
    )
    out = _gemini_client(fake).converse(modelId="gemini-x", system=[], messages=[])
    tu = out["output"]["message"]["content"][0]["toolUse"]
    assert tu["name"] == "get_service_config"
    assert tu["input"] == {"service_type": "kms"}
    assert out["stopReason"] == "tool_use"


def test_gemini_tool_result_keyed_by_name():
    # a tool_result must be routed back to the function NAME (Gemini has no ids)
    c = MP.GeminiConverseClient.__new__(MP.GeminiConverseClient)
    generic = MP.messages_to_generic([
        {"role": "assistant", "content": [
            {"toolUse": {"toolUseId": "abc", "name": "tail_logs", "input": {}}}]},
        {"role": "user", "content": [
            {"toolResult": {"toolUseId": "abc", "content": [{"text": "no errors"}]}}]},
    ])
    contents = c._to_contents(generic)
    fr = contents[1]["parts"][0]["function_response"]
    assert fr["name"] == "tail_logs"                 # mapped id->name
    assert fr["response"] == {"result": "no errors"}


# ── factory ───────────────────────────────────────────────────────────────────
def test_factory_unknown_provider_raises(monkeypatch):
    monkeypatch.setenv("CLOUDCTL_MODEL_PROVIDER", "llama-on-toaster")
    with pytest.raises(ValueError):
        MP.make_model_client(None, "us-east-1")


def test_factory_default_is_bedrock(monkeypatch):
    monkeypatch.delenv("CLOUDCTL_MODEL_PROVIDER", raising=False)
    called = {}

    def fake_bedrock(p, r):
        called["bedrock"] = (p, r)
        return "BEDROCK"
    monkeypatch.setattr(MP, "_bedrock_client", fake_bedrock)
    assert MP.make_model_client("prof", "us-east-1") == "BEDROCK"
    assert called["bedrock"] == ("prof", "us-east-1")
