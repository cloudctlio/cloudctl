"""NATIVE-FIRST reproduction: exercise a discovered operation SERVER-SIDE
through the AWS control plane (pure evaluate / documented test APIs) using
cloudctl's own IAM role — no network path, no separate auth, side-effect-free.

These tests pin the discipline:
  * the primitive returns the RAW produced result (incl. the "resolver produces
    null fields" class) — mocked AWS clients, NEVER live;
  * native-first SELECTION picks the primitive by resource type and falls back
    cleanly (unavailable signal, never an exception) when none applies / the
    inputs are missing / IAM denies;
  * SAFETY — no side-effecting invoke is ever called (test-invoke is restricted
    to read-only methods; no lambda:Invoke, no mutating client method);
  * HINT-FREE — the native code encodes no expected value / scenario, and
    behaves identically on an invented resource type;
  * the CLOUDCTL_PROBE_AUTO=approve fix — auto-approve now actually approves on
    a non-TTY shell even with the CLI consent handler registered.
"""
from __future__ import annotations

import inspect
import json

import pytest

from cloudctl.mcp.tools import probe as P


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    P.reset_probe_budget()
    P.set_consent_handler(None)
    monkeypatch.setenv("CLOUDCTL_ENABLE_PROBES", "1")
    monkeypatch.setenv("CLOUDCTL_PROBE_AUTO", "approve")   # unattended auto-consent
    yield
    P.reset_probe_budget()
    P.set_consent_handler(None)


def _obj(out: str) -> dict:
    return json.loads(out)


# ── mocked AWS control plane (no live AWS, ever) ───────────────────────────────

# Any method whose invocation would have a SIDE EFFECT. If a primitive ever
# touches one of these the safety test fails loudly.
_FORBIDDEN_METHODS = {
    "invoke", "invoke_async", "invoke_endpoint", "start_execution",
    "start_sync_execution", "put_events", "publish", "send_message",
    "create_resolver", "update_resolver", "delete_resolver",
    "put_rest_api", "create_deployment", "update_stage",
}


class _RecordingClient:
    """A fake boto client: only the whitelisted evaluate/test methods answer;
    every other attribute (esp. a side-effecting one) raises, proving the
    primitive never reaches for it."""

    def __init__(self, responses: dict, service: str):
        self._responses = responses
        self._service = service
        self.calls: list = []

    def __getattr__(self, name):
        def _method(**kwargs):
            self.calls.append((name, kwargs))
            if name in _FORBIDDEN_METHODS:
                raise AssertionError(
                    f"SIDE-EFFECTING method {self._service}.{name} was called")
            if name not in self._responses:
                raise AssertionError(
                    f"unexpected method call {self._service}.{name}")
            outcome = self._responses[name]
            if isinstance(outcome, Exception):
                raise outcome
            return outcome
        return _method


class _FakeSession:
    def __init__(self, clients: dict):
        self._clients = clients
        self.requested: list = []

    def client(self, service):
        self.requested.append(service)
        if service not in self._clients:
            raise AssertionError(f"unexpected client requested: {service}")
        return self._clients[service]


def _install_session(monkeypatch, clients: dict) -> _FakeSession:
    sess = _FakeSession(clients)
    monkeypatch.setattr(P, "_native_session", lambda profile, region: sess)
    return sess


def _client_error(code="AccessDeniedException", msg="not authorized"):
    from botocore.exceptions import ClientError
    return ClientError({"Error": {"Code": code, "Message": msg}}, "Op")


# ── 1. native primitive returns the RAW result ────────────────────────────────

def test_appsync_evaluate_mapping_returns_raw_null_field_output(monkeypatch):
    # the exact class this whole pillar exists for: the resolver's response
    # mapping evaluates to a payload with NULL fields — server-side, verbatim.
    raw_output = '{"id":null,"name":null}'
    appsync = _RecordingClient(
        {"evaluate_mapping_template": {"evaluationResult": raw_output,
                                       "error": None, "logs": []}},
        "appsync")
    _install_session(monkeypatch, {"appsync": appsync})

    out = _obj(P.native_reproduce_gated(
        service_type="appsync",
        params={"template": "$util.toJson($ctx.result)",
                "context": {"result": {"wrong": 1}}},
        profile=None, region="us-east-1", reason="reproduce resolver output"))

    assert out["reproduced_via"] == "appsync:EvaluateMappingTemplate"
    assert out["evaluation_result"] == raw_output
    assert out["side_effect_free"] is True
    assert out["_reproduction"].startswith("cloudctl-executed")
    assert out["probes_used"] == 1
    # context dict was serialized to a JSON string for the API
    assert appsync.calls[0][0] == "evaluate_mapping_template"
    assert isinstance(appsync.calls[0][1]["context"], str)


def test_appsync_evaluate_code_path(monkeypatch):
    appsync = _RecordingClient(
        {"evaluate_code": {"evaluationResult": '{"ok":true}', "error": None,
                           "logs": ["line"]}},
        "appsync")
    _install_session(monkeypatch, {"appsync": appsync})

    out = _obj(P.native_reproduce_gated(
        service_type="appsync",
        params={"code": "export function request(ctx){return {}}",
                "context": '{"arguments":{}}'},
        profile=None, region="us-east-1", reason="r"))
    assert out["reproduced_via"] == "appsync:EvaluateCode"
    assert out["evaluation_result"] == '{"ok":true}'
    assert appsync.calls[0][0] == "evaluate_code"


def test_apigateway_test_invoke_returns_raw_status_body_log(monkeypatch):
    apigw = _RecordingClient(
        {"test_invoke_method": {"status": 200, "body": '{"data":null}',
                                "headers": {"x": "y"}, "log": "exec log",
                                "latency": 42}},
        "apigateway")
    _install_session(monkeypatch, {"apigateway": apigw})

    out = _obj(P.native_reproduce_gated(
        service_type="apigateway",
        params={"rest_api_id": "abc123", "resource_id": "r1",
                "http_method": "GET", "path": "/thing"},
        profile=None, region="us-east-1", reason="r"))
    assert out["reproduced_via"] == "apigateway:test-invoke-method"
    assert out["status"] == 200
    assert out["body"] == '{"data":null}'
    assert out["log"] == "exec log"
    assert out["latency_ms"] == 42


# ── 2. native-first SELECTION + clean fallback ────────────────────────────────

def test_selection_by_type():
    assert P.native_primitive_available("appsync")
    assert P.native_primitive_available("apigateway")
    assert P.native_primitive_available("aws:appsync")     # composite token
    assert not P.native_primitive_available("dynamodb")
    assert not P.native_primitive_available("")


def test_no_primitive_returns_unavailable_not_exception(monkeypatch):
    # invented / unsupported type → structured 'unavailable', caller falls back
    _install_session(monkeypatch, {})
    out = _obj(P.native_reproduce_gated(
        service_type="zqwibblewotsit", params={}, profile=None,
        region="us-east-1", reason="r"))
    assert out["native_reproduction"] == "unavailable"
    assert "no side-effect-free" in out["reason"]
    assert P.probes_used() == 0                 # nothing was exercised


def test_missing_inputs_returns_unavailable(monkeypatch):
    _install_session(monkeypatch, {"appsync": _RecordingClient({}, "appsync")})
    out = _obj(P.native_reproduce_gated(
        service_type="appsync", params={"context": "{}"},   # no template/code
        profile=None, region="us-east-1", reason="r"))
    assert out["native_reproduction"] == "unavailable"
    assert "template" in out["reason"].lower()


def test_access_denied_degrades_gracefully(monkeypatch):
    appsync = _RecordingClient(
        {"evaluate_mapping_template": _client_error("AccessDeniedException")},
        "appsync")
    _install_session(monkeypatch, {"appsync": appsync})
    out = _obj(P.native_reproduce_gated(
        service_type="appsync",
        params={"template": "t", "context": "{}"},
        profile=None, region="us-east-1", reason="r"))
    assert out["native_reproduction"] == "unavailable"
    assert out["access_denied"] is True
    assert "access denied" in out["reason"].lower()


def test_apigateway_access_denied_degrades(monkeypatch):
    apigw = _RecordingClient(
        {"test_invoke_method": _client_error("UnauthorizedException")},
        "apigateway")
    _install_session(monkeypatch, {"apigateway": apigw})
    out = _obj(P.native_reproduce_gated(
        service_type="apigateway",
        params={"rest_api_id": "a", "resource_id": "r", "http_method": "GET"},
        profile=None, region="us-east-1", reason="r"))
    assert out["native_reproduction"] == "unavailable"
    assert out["access_denied"] is True


def test_unexpected_error_is_structured_not_raised(monkeypatch):
    appsync = _RecordingClient(
        {"evaluate_mapping_template": RuntimeError("boom")}, "appsync")
    _install_session(monkeypatch, {"appsync": appsync})
    out = _obj(P.native_reproduce_gated(
        service_type="appsync", params={"template": "t", "context": "{}"},
        profile=None, region="us-east-1", reason="r"))
    assert out["native_reproduction"] == "unavailable"
    assert "failed" in out["reason"].lower()


# ── 3. SAFETY — no side-effecting invoke, ever ────────────────────────────────

def test_test_invoke_refuses_non_read_only_method(monkeypatch):
    apigw = _RecordingClient({"test_invoke_method": {"status": 200}}, "apigateway")
    _install_session(monkeypatch, {"apigateway": apigw})
    for method in ("POST", "PUT", "DELETE", "PATCH"):
        out = _obj(P.native_reproduce_gated(
            service_type="apigateway",
            params={"rest_api_id": "a", "resource_id": "r",
                    "http_method": method},
            profile=None, region="us-east-1", reason="r"))
        assert out["native_reproduction"] == "unavailable"
        assert out["unsafe_method"] is True
    assert apigw.calls == []                    # test-invoke NEVER ran


def test_primitives_touch_only_safe_eval_apis(monkeypatch):
    # exercise both primitives and assert NO forbidden (side-effecting) method
    # was ever called on the mocked clients
    appsync = _RecordingClient(
        {"evaluate_mapping_template": {"evaluationResult": "{}"}}, "appsync")
    apigw = _RecordingClient({"test_invoke_method": {"status": 200}}, "apigateway")
    _install_session(monkeypatch, {"appsync": appsync, "apigateway": apigw})

    P.native_reproduce_gated("appsync", {"template": "t", "context": "{}"},
                             None, "us-east-1", "r")
    P.reset_probe_budget()
    P.native_reproduce_gated("apigateway",
                             {"rest_api_id": "a", "resource_id": "r",
                              "http_method": "GET"}, None, "us-east-1", "r")

    called = {c[0] for c in appsync.calls} | {c[0] for c in apigw.calls}
    assert called <= {"evaluate_mapping_template", "test_invoke_method"}
    assert not (called & _FORBIDDEN_METHODS)


def test_disabled_when_probes_off(monkeypatch):
    monkeypatch.delenv("CLOUDCTL_ENABLE_PROBES", raising=False)
    out = _obj(P.native_reproduce_gated("appsync", {"template": "t",
                                                    "context": "{}"},
                                        None, "us-east-1", "r"))
    assert "disabled" in out["probe_error"]


def test_declined_when_consent_skips(monkeypatch):
    monkeypatch.delenv("CLOUDCTL_PROBE_AUTO", raising=False)
    P.set_consent_handler(lambda plan: {"decision": "skip", "reason": "no"})
    called = _install_session(monkeypatch,
                              {"appsync": _RecordingClient({}, "appsync")})
    out = _obj(P.native_reproduce_gated("appsync",
                                        {"template": "t", "context": "{}"},
                                        None, "us-east-1", "r"))
    assert out["probe_declined"] is True
    assert P.probes_used() == 0
    assert called.requested == []               # never even made a client


def test_native_plan_shows_control_plane_safety(monkeypatch):
    seen = {}
    P.set_consent_handler(lambda plan: seen.update(plan) or {"decision": "skip"})
    P.native_reproduce_gated("appsync", {"template": "t", "context": "{}"},
                             None, "us-east-1", "reproduce mapping")
    assert seen["action"] == "reproduce-native"
    assert seen["service_type"] == "appsync"
    assert "side-effect-free" in seen["safety"]
    assert "no network path" in seen["safety"]


# ── 4. hint-freeness / generic behaviour ──────────────────────────────────────

# The native code may name the SERVICE (how to exercise a type is allowed, like
# a fetcher) but must NOT encode expected VALUES, scenario/incident names, or a
# "what the correct result looks like" judgement.
_FORBIDDEN_HINTS = [
    # scenario / incident vocabulary
    "resolver_misconfigured", "auth_mode_mismatch", "scenario", "incident",
    # expected-value / correctness judgement
    "should be", "should equal", "expected value", "correct value",
    "is wrong", "is correct", "fabricat",
    # enumerated service field names (the reverted-attempt smell)
    "rotationenabled", "rotationlambdaarn", "price_cents",
]


def test_native_code_encodes_no_expected_value_or_scenario():
    src = "".join(
        inspect.getsource(fn)
        for fn in (P._native_appsync, P._native_apigateway,
                   P._select_native_primitive, P.native_reproduce_gated,
                   P._native_result, P._native_reason)
    ).lower()
    hits = [w for w in _FORBIDDEN_HINTS if w in src]
    assert hits == [], f"native code leaked hints: {hits}"


def test_registry_maps_types_to_callables_only():
    # the registry is a capability map (type -> how-to-exercise), never data
    for key, fn in P._NATIVE_PRIMITIVES.items():
        assert isinstance(key, str) and callable(fn)


def test_generic_behaviour_on_invented_types(monkeypatch):
    # two unrelated invented, unsupported types get identical structured
    # fallback — the routing is keyed on the type token, nothing scenario-specific
    _install_session(monkeypatch, {})
    a = _obj(P.native_reproduce_gated("flarnblat", {}, None, "us-east-1", "r"))
    b = _obj(P.native_reproduce_gated("gromulon-9", {}, None, "us-east-1", "r"))
    assert a["native_reproduction"] == b["native_reproduction"] == "unavailable"
    assert set(a) == set(b)


# ── 5. the CLOUDCTL_PROBE_AUTO=approve fix (real bug) ─────────────────────────

def test_probe_auto_approve_honored_on_non_tty(monkeypatch):
    """With the CLI consent handler registered AND a non-TTY stdin,
    CLOUDCTL_PROBE_AUTO=approve must now auto-approve instead of declining."""
    from cloudctl.commands import debug_cmd

    monkeypatch.setenv("CLOUDCTL_PROBE_AUTO", "approve")
    # _probe_consent imports sys locally; patch the real stdin.isatty so the
    # non-TTY branch would decline UNLESS the auto-approve fix takes precedence.
    import sys as _s
    monkeypatch.setattr(_s.stdin, "isatty", lambda: False)

    decision = debug_cmd._probe_consent({
        "method": "GET", "url": "http://x/y", "reason": "r",
        "safety": "read-only",
    })
    assert decision["decision"] == "approve"


def test_probe_consent_still_declines_non_tty_without_auto(monkeypatch):
    from cloudctl.commands import debug_cmd
    monkeypatch.delenv("CLOUDCTL_PROBE_AUTO", raising=False)
    import sys as _s
    monkeypatch.setattr(_s.stdin, "isatty", lambda: False)
    decision = debug_cmd._probe_consent({
        "method": "GET", "url": "http://x/y", "reason": "r",
        "safety": "read-only",
    })
    assert decision["decision"] == "skip"


# ── 6. native result captured into the observation, like an HTTP probe ─────────

class _ScriptedBedrock:
    def __init__(self, script):
        self.script = list(script)
        self.seen_tool_configs: list = []

    def converse(self, **kw):
        self.seen_tool_configs.append(kw.get("toolConfig") or {})
        return self.script.pop(0)


def _tool_use(name, tool_input, tid="t1"):
    return {"stopReason": "tool_use",
            "output": {"message": {"role": "assistant", "content": [
                {"toolUse": {"toolUseId": tid, "name": name, "input": tool_input}}]}}}


def _end_turn(text):
    return {"stopReason": "end_turn",
            "output": {"message": {"role": "assistant",
                                   "content": [{"text": text}]}}}


def test_observe_node_captures_native_result(monkeypatch):
    from cloudctl.ai import graph_agent as g

    appsync = _RecordingClient(
        {"evaluate_mapping_template": {"evaluationResult": '{"id":null}',
                                       "error": None, "logs": []}},
        "appsync")
    _install_session(monkeypatch, {"appsync": appsync})

    fake = _ScriptedBedrock([
        _tool_use("native_reproduce", {
            "service_type": "appsync",
            "params": {"template": "t", "context": "{}"},
            "reason": "reproduce the resolver mapping",
        }),
        _end_turn(json.dumps({
            "symptom_observable_now": True, "onset_estimate": "unknown",
            "affected_scope": "the resolver", "unaffected_scope": "unknown",
            "reproduction": "mapping evaluated to null id",
            "measurements": ["null id from evaluation"],
        })),
    ])
    monkeypatch.setattr(g, "_make_bedrock", lambda *a, **k: fake)

    out = g.observe_node({
        "symptom": "query returns null fields", "profile": None,
        "region": "us-east-1", "minutes": 60, "session_id": "sess-test",
    })
    rep = out["observation"]["reproduction_observed"][0]
    assert rep["via"] == "native"
    assert rep["service_type"] == "appsync"
    assert rep["response"]["reproduced_via"] == "appsync:EvaluateMappingTemplate"
    assert rep["response"]["evaluation_result"] == '{"id":null}'
    # native_reproduce is offered to the model when reproduction is enabled
    tool_names = {t["toolSpec"]["name"]
                  for t in fake.seen_tool_configs[0]["tools"] if "toolSpec" in t}
    assert "native_reproduce" in tool_names
