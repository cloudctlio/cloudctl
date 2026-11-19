"""Model profiles and the proposer call (one prompt, one schema, per-model
differences only in the profile)."""
from __future__ import annotations

import json

import pytest

from cloudctl.verify import proposer as PR
from cloudctl.verify.evidence import Incident
from cloudctl.verify.profiles import (
    ModelProfile,
    load_profiles,
    require_pinned,
    select_profile,
)
from tests.verify_support import END, FN, T, orders_model

# ── profiles ─────────────────────────────────────────────────────────────────

def test_packaged_profiles_load_and_are_all_unpinned():
    profs = load_profiles()
    assert {"claude-mid", "openai-mid", "gemini-mid", "llama-mid", "qwen-mid"} <= set(profs)
    assert all(not p.pinned for p in profs.values())
    assert all(p.max_output_tokens == profs["claude-mid"].max_output_tokens for p in profs.values())
    assert profs["openai-mid"].temperature is None
    with pytest.raises(ValueError, match="not pinned"):
        require_pinned(profs)


def test_require_pinned_accepts_a_checked_profile():
    p = ModelProfile(name="x", provider="bedrock", model_id="m", pinned=True, price_in=1.0, price_out=2.0)
    require_pinned({"x": p})
    assert p.cost(1_000_000, 500_000) == pytest.approx(2.0)
    assert ModelProfile(name="y", provider="bedrock", model_id="m").cost(1, 1) is None


@pytest.mark.parametrize("kw,needle", [
    ({"provider": "bedrock", "structured_mode": "native_schema"}, "no response schema"),
    ({"provider": "anthropic", "structured_mode": "native_schema"}, "no response schema"),
    ({"provider": "openai_compatible"}, "needs base_url"),
    ({"provider": "nope"}, "provider must be"),
    ({"provider": "openai", "reasoning": {"effort": "low", "level": "none"}}, "reasoning must be"),
    ({"provider": "openai", "max_output_tokens": 0}, "positive integer"),
])
def test_profile_validation(kw, needle):
    p = ModelProfile(name="p", model_id="m", **kw)
    assert any(needle in e for e in p.validate())


def test_load_profiles_rejects_unknown_fields(tmp_path):
    f = tmp_path / "p.yaml"
    f.write_text("defaults: {max_output_tokens: 100}\nprofiles:\n  a: {provider: bedrock, model_id: m, colour: red}\n")
    with pytest.raises(ValueError, match="unknown field"):
        load_profiles(str(f))
    f.write_text("defaults: {max_output_tokens: 100}\nprofiles:\n  a: {provider: bedrock, model_id: m}\n")
    assert load_profiles(str(f))["a"].max_output_tokens == 100


def test_select_profile_order(monkeypatch):
    profs = load_profiles()
    monkeypatch.setenv("CLOUDCTL_VERIFY_PROFILE", "gemini-mid")
    assert select_profile(profs).name == "gemini-mid"
    monkeypatch.setenv("CLOUDCTL_VERIFY_PROFILE", "ghost")
    with pytest.raises(ValueError):
        select_profile(profs)
    monkeypatch.delenv("CLOUDCTL_VERIFY_PROFILE")
    monkeypatch.setenv("CLOUDCTL_MODEL", profs["claude-mid"].model_id)
    monkeypatch.setenv("CLOUDCTL_MODEL_PROVIDER", "aws")
    assert select_profile(profs).name == "claude-mid"
    monkeypatch.setenv("CLOUDCTL_MODEL", "some-new-model")
    monkeypatch.setenv("CLOUDCTL_MODEL_PROVIDER", "google")
    p = select_profile(profs)
    assert p.name == "adhoc:gemini:some-new-model" and p.structured_mode == "json_repair"
    assert p.temperature is None


def test_inference_config_omits_null_temperature():
    assert ModelProfile(name="a", provider="openai", model_id="m").inference_config() == {"maxTokens": 2000}
    assert ModelProfile(name="b", provider="bedrock", model_id="m", temperature=0).inference_config() == {
        "maxTokens": 2000, "temperature": 0.0}


# ── schema and prompt ───────────────────────────────────────────────────────

def _walk(obj):
    yield obj
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)


def test_schema_is_the_common_subset():
    s = PR.build_schema(["b", "a"])
    banned = {"oneOf", "anyOf", "allOf", "$ref", "patternProperties"}
    for node in _walk(s):
        if isinstance(node, dict):
            assert not (banned & set(node))
            assert not isinstance(node.get("type"), list)
            if node.get("type") == "object":
                assert node["additionalProperties"] is False
                assert sorted(node["required"]) == sorted(node["properties"])
    hyp = s["properties"]["hypotheses"]["items"]
    assert hyp["properties"]["node"]["enum"] == ["a", "b"]
    pred = hyp["properties"]["predictions"]["items"]["properties"]
    assert pred["args_json"] == {"type": "string"}
    assert len(pred["primitive"]["enum"]) == 9
    # too many nodes: the enum is dropped, code still validates
    assert "enum" not in PR.build_schema([str(i) for i in range(501)])["properties"]["hypotheses"][
        "items"]["properties"]["node"]


def test_extract_json_handles_fences_prose_and_braces_in_strings():
    assert PR.extract_json('here:\n```json\n{"hypotheses": []}\n```') == {"hypotheses": []}
    assert PR.extract_json('x {bad} then {"a": "}{", "b": {"c": 1}} tail') == {"a": "}{", "b": {"c": 1}}
    assert PR.extract_json("no json") is None
    assert PR.extract_json("") is None


def _request(model=None):
    m = model or orders_model()
    return {"round": 2, "graph": m.summary(), "anchor": FN, "incident": Incident(T, END).to_dict(),
            "previous": [{"hypothesis": {"id": "h1", "node": FN, "property": "p"},
                          "rules": {"predictions_hold": {"ok": False, "why": "x failed"}},
                          "results": [{"primitive": "signal", "expect": "PASS", "status": "FAIL",
                                       "reason": "r" * 500}]}],
            "repair": ["hypotheses[0]: 'ghost' is not a node"]}


def test_user_message_carries_graph_previous_and_repair():
    msg = PR.build_user_message(_request(), "orders failing", {"observation": {"x": 1}})
    assert "orders failing" in msg and FN in msg and "Round 2" in msg
    assert "x failed" in msg and "r" * 161 not in msg
    assert "- hypotheses[0]: 'ghost' is not a node" in msg


# ── the call per structured mode ────────────────────────────────────────────

class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def converse(self, **kw):
        self.calls.append(kw)
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def _resp(content, i=10, o=5):
    return {"output": {"message": {"content": content}}, "usage": {"inputTokens": i, "outputTokens": o}}


def test_tool_use_mode_forces_tool_and_returns_its_input():
    prof = ModelProfile(name="c", provider="bedrock", model_id="claude", structured_mode="tool_use",
                        temperature=0, additional_request_fields={"x": 1}, price_in=3, price_out=15)
    c = FakeClient([_resp([{"text": "thinking"}, {"toolUse": {"name": PR.TOOL_NAME, "input": {"hypotheses": [1]}}}])])
    p = PR.Proposer(c, prof, "symptom")
    assert p(_request()) == {"hypotheses": [1]}
    kw = c.calls[0]
    assert kw["toolConfig"]["toolChoice"] == {"tool": {"name": PR.TOOL_NAME}}
    assert kw["toolConfig"]["tools"][0]["toolSpec"]["inputSchema"]["json"]["required"] == ["hypotheses"]
    assert kw["inferenceConfig"] == {"maxTokens": 2000, "temperature": 0.0}
    assert kw["additionalModelRequestFields"] == {"x": 1}
    assert "At most 5 hypotheses" in kw["system"][0]["text"]
    assert p.usage == {"calls": 1, "input_tokens": 10, "output_tokens": 5}
    assert p.cost() == pytest.approx((10 * 3 + 5 * 15) / 1e6)


def test_tool_use_without_forced_choice():
    prof = ModelProfile(name="l", provider="bedrock", model_id="llama", structured_mode="tool_use",
                        force_tool=False)
    c = FakeClient([_resp([{"text": '{"hypotheses": []}'}])])
    assert PR.Proposer(c, prof, "s")(_request()) == {"hypotheses": []}   # fell back to text JSON
    assert "toolChoice" not in c.calls[0]["toolConfig"]


def test_native_schema_mode_and_reasoning_for_non_bedrock():
    prof = ModelProfile(name="o", provider="openai", model_id="gpt", structured_mode="native_schema",
                        reasoning={"effort": "low"})
    c = FakeClient([_resp([{"text": '{"hypotheses": []}'}])])
    PR.Proposer(c, prof, "s")(_request())
    kw = c.calls[0]
    assert kw["responseSchema"]["title"] == "hypotheses" and "toolConfig" not in kw
    assert kw["reasoning"] == {"effort": "low"} and "temperature" not in kw["inferenceConfig"]


def test_json_repair_mode_returns_raw_text_when_unparseable():
    prof = ModelProfile(name="j", provider="bedrock", model_id="small", reasoning={"level": "none"})
    c = FakeClient([_resp([{"text": "I think it is the role"}])])
    out = PR.Proposer(c, prof, "s")(_request())
    assert out == "I think it is the role"
    assert "toolConfig" not in c.calls[0] and "responseSchema" not in c.calls[0]
    assert "reasoning" not in c.calls[0]


def test_backoff_retries_throttling_only():
    class ThrottlingException(Exception):
        pass
    slept = []
    prof = ModelProfile(name="b", provider="bedrock", model_id="m",
                        rate_limit={"max_retries": 2, "base_delay_s": 1.0})
    c = FakeClient([ThrottlingException("x"), ThrottlingException("x"), _resp([{"text": "{}"}])])
    assert PR.Proposer(c, prof, "s", sleep=slept.append)(_request()) == {}
    assert slept == [1.0, 2.0]
    c2 = FakeClient([ThrottlingException("x")] * 3)
    with pytest.raises(ThrottlingException):
        PR.Proposer(c2, prof, "s", sleep=slept.append)(_request())
    c3 = FakeClient([ValueError("bad request")])
    with pytest.raises(ValueError):
        PR.Proposer(c3, prof, "s", sleep=slept.append)(_request())
    assert len(c3.calls) == 1


def test_every_profile_builds_a_request_with_the_same_prompt_and_schema():
    """Fairness: only profile-driven fields differ between models."""
    req = _request()
    seen = set()
    for prof in load_profiles().values():
        c = FakeClient([_resp([{"text": "{}"}])])
        PR.Proposer(c, prof, "s")(req)
        kw = c.calls[0]
        schema = (kw.get("responseSchema")
                  or ((kw.get("toolConfig") or {}).get("tools") or [{}])[0].get("toolSpec", {})
                  .get("inputSchema", {}).get("json"))
        seen.add(json.dumps([kw["system"], kw["messages"], schema or PR.build_schema(
            [n["id"] for n in req["graph"]["nodes"]])], sort_keys=True))
    assert len(seen) == 1
