"""REPRODUCTION: exercise the discovered user-facing entry point and capture
the CONCRETE response (status, body, timing), so specific-cause reasoning is
grounded in what actually happened instead of fabricated from config.

These tests pin the four discipline requirements:
  1. concrete-response capture (status/body/timing/auth-honesty) — mocked HTTP,
     never live;
  2. graceful degradation (unreachable / timeout / no auth / bad payload →
     structured "could not reproduce", NEVER an exception);
  3. safety — a mutating request is impossible in code (bare POST, mutation/
     subscription payloads, PUT/DELETE/PATCH all rejected before any bytes go
     out);
  4. hint-freeness — behaviour is keyed on the HTTP interaction pattern only:
     identical for invented endpoints, and the reproduction code carries no
     service literals.
Plus the reproduce-first wiring in the observe node (opt-in, deterministically
captured, and byte-identical passive behaviour when reproduction is off).
"""
from __future__ import annotations

import inspect
import io
import json
import socket
import urllib.error
import urllib.request
from email.message import Message

import pytest

from cloudctl.mcp.tools import probe as P


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    P.reset_probe_budget()
    P.set_consent_handler(None)
    monkeypatch.setenv("CLOUDCTL_ENABLE_PROBES", "1")
    monkeypatch.delenv("CLOUDCTL_PROBE_AUTO", raising=False)
    yield
    P.reset_probe_budget()
    P.set_consent_handler(None)


def _obj(out: str) -> dict:
    return json.loads(out)


# ── mocked HTTP plumbing (no live network, ever) ───────────────────────────────

class _FakeResponse:
    def __init__(self, status=200, body=b"", url="https://x/", content_type="application/json"):
        self.status = status
        self.url = url
        self._body = body
        self.headers = Message()
        self.headers["Content-Type"] = content_type

    def read(self, n=-1):
        return self._body if n is None or n < 0 else self._body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class _FakeOpener:
    def __init__(self, outcome):
        self.outcome = outcome
        self.requests: list = []

    def open(self, req, timeout=None):
        self.requests.append(req)
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


@pytest.fixture
def fake_net(monkeypatch):
    """Install a fake HTTP layer: bypass DNS-based host checks for invented
    hostnames and route the request to a canned outcome. Returns an installer
    taking the outcome (a _FakeResponse or an Exception to raise)."""
    monkeypatch.setattr(P, "_host_is_blocked", lambda host: (False, ""))

    def _install(outcome):
        opener = _FakeOpener(outcome)
        monkeypatch.setattr(P.urllib.request, "build_opener", lambda *h: opener)
        return opener

    return _install


def _http_error(code=401, body=b'{"message":"denied"}'):
    return urllib.error.HTTPError(
        "https://entrypoint.invented.example/op", code, "err",
        Message(), io.BytesIO(body),
    )


# ── 1. concrete response capture ───────────────────────────────────────────────

def test_reproduction_returns_concrete_response(fake_net):
    fake_net(_FakeResponse(status=200, body=b'{"data":{"answer":42}}'))
    out = _obj(P.probe_http("https://entrypoint.invented.example/op"))
    assert out["status"] == 200
    assert out["body"] == '{"data":{"answer":42}}'
    assert isinstance(out["elapsed_ms"], int) and out["elapsed_ms"] >= 0
    assert out["auth_sent"] is False
    assert out["probes_used"] == 1


def test_success_with_null_fields_body_returned_verbatim(fake_net):
    # the class of fault reproduction exists for: HTTP 200 whose payload is
    # wrong/empty — only the concrete body can show it. Content is invented.
    body = b'{"data":{"getThing":{"id":null,"name":null}}}'
    fake_net(_FakeResponse(status=200, body=body))
    out = _obj(P.probe_http("https://entrypoint.invented.example/op"))
    assert out["status"] == 200
    assert out["body"] == body.decode()


def test_discovered_credential_marks_auth_sent(fake_net):
    opener = fake_net(_FakeResponse(status=200, body=b"ok"))
    out = _obj(P.probe_http("https://entrypoint.invented.example/op",
                            headers={"x-api-key": "discovered-key-1"}))
    assert out["auth_sent"] is True
    req = opener.requests[0]
    assert req.get_header("X-api-key") == "discovered-key-1"


def test_error_status_is_captured_not_raised(fake_net):
    fake_net(_http_error(401))
    out = _obj(P.probe_http("https://entrypoint.invented.example/op",
                            headers={"authorization": "discovered-token"}))
    assert out["status"] == 401
    assert out["body"] == '{"message":"denied"}'
    assert out["auth_sent"] is True
    assert "elapsed_ms" in out
    assert "note" not in out          # credential WAS sent — rejection stands as observed


def test_auth_rejection_without_credential_is_flagged_inconclusive(fake_net):
    # auth honesty: no discoverable credential → the probe still reports the
    # concrete response but flags that the rejection may only reflect the
    # missing credential — the engine must not treat it as the proven fault.
    fake_net(_http_error(401))
    out = _obj(P.probe_http("https://entrypoint.invented.example/op"))
    assert out["status"] == 401
    assert out["auth_sent"] is False
    assert "no credential" in out["note"].lower()


# ── 2. graceful degradation — never an exception ───────────────────────────────

def test_timeout_is_structured_could_not_reproduce(fake_net):
    fake_net(socket.timeout("timed out"))
    out = _obj(P.probe_http("https://entrypoint.invented.example/op"))
    assert "could not reproduce" in out["probe_error"]
    assert out["timed_out"] is True
    assert "elapsed_ms" in out


def test_unreachable_is_structured_could_not_reproduce(fake_net):
    fake_net(urllib.error.URLError(ConnectionRefusedError("refused")))
    out = _obj(P.probe_http("https://entrypoint.invented.example/op"))
    assert "could not reproduce" in out["probe_error"]
    assert out["timed_out"] is False


def test_unresolvable_host_is_structured(monkeypatch):
    def _no_dns(*a, **k):
        raise socket.gaierror("no such host")
    monkeypatch.setattr(P.socket, "getaddrinfo", _no_dns)
    out = _obj(P.probe_http("https://no-such-entrypoint.invented.example/op"))
    assert "does not resolve" in out["probe_error"]


# ── 3. safety — a mutating request is impossible in code ───────────────────────

def test_bare_post_still_blocked(fake_net):
    opener = fake_net(_FakeResponse())
    out = _obj(P.probe_http("https://entrypoint.invented.example/op", method="POST"))
    assert "read-only" in out["probe_error"]
    assert opener.requests == []
    assert P.probes_used() == 0


def test_mutation_payload_blocked(fake_net):
    opener = fake_net(_FakeResponse())
    body = json.dumps({"query": "mutation { zapThing(id: 1) { id } }"})
    out = _obj(P.probe_http("https://entrypoint.invented.example/op",
                            method="POST", body=body))
    assert "mutation" in out["probe_error"]
    assert opener.requests == []           # not one byte was sent
    assert P.probes_used() == 0


def test_subscription_payload_blocked(fake_net):
    opener = fake_net(_FakeResponse())
    body = json.dumps({"query": "subscription { onThing { id } }"})
    out = _obj(P.probe_http("https://entrypoint.invented.example/op",
                            method="POST", body=body))
    assert "probe_error" in out
    assert opener.requests == []


def test_unprovable_payloads_blocked(fake_net):
    opener = fake_net(_FakeResponse())
    unprovable = [
        "not json at all",
        json.dumps(["a", "list"]),
        json.dumps({"query": "{ a }", "extension_field": 1}),   # unknown key
        json.dumps({"query": ""}),
        json.dumps({"query": "q".ljust(9000, "x")}),            # oversize doc
        json.dumps({"query": "please delete everything"}),      # not a query doc
    ]
    for body in unprovable:
        out = _obj(P.probe_http("https://entrypoint.invented.example/op",
                                method="POST", body=body))
        assert "probe_error" in out, body
    assert opener.requests == []
    assert P.probes_used() == 0


def test_other_mutating_methods_blocked_even_with_query_body(fake_net):
    opener = fake_net(_FakeResponse())
    body = json.dumps({"query": "query Q { thing { id } }"})
    for m in ("PUT", "DELETE", "PATCH"):
        out = _obj(P.probe_http("https://entrypoint.invented.example/op",
                                method=m, body=body))
        assert "read-only" in out["probe_error"]
    assert opener.requests == []


def test_body_on_get_blocked(fake_net):
    opener = fake_net(_FakeResponse())
    out = _obj(P.probe_http("https://entrypoint.invented.example/op",
                            method="GET",
                            body=json.dumps({"query": "{ a }"})))
    assert "probe_error" in out
    assert opener.requests == []


def test_read_only_query_post_allowed(fake_net):
    opener = fake_net(_FakeResponse(status=200, body=b'{"data":{"thing":null}}'))
    body = json.dumps({"query": "query GetThing { thing { id name } }",
                       "variables": {"id": "t-1"}})
    out = _obj(P.probe_http("https://entrypoint.invented.example/op",
                            method="POST", body=body,
                            headers={"x-api-key": "k"}))
    assert out["status"] == 200
    req = opener.requests[0]
    assert req.get_method() == "POST"
    assert req.data == body.encode()
    assert req.get_header("Content-type") == "application/json"


def test_anonymous_query_shorthand_allowed(fake_net):
    fake_net(_FakeResponse(status=200, body=b"{}"))
    out = _obj(P.probe_http("https://entrypoint.invented.example/op",
                            method="POST",
                            body=json.dumps({"query": "{ thing { id } }"})))
    assert out["status"] == 200


def test_keyword_inside_string_literal_does_not_false_block(fake_net):
    # stripping string literals: the WORD "mutation" as data is not an operation
    fake_net(_FakeResponse(status=200, body=b"{}"))
    doc = 'query Q { search(text: "mutation drill") { id } }'
    out = _obj(P.probe_http("https://entrypoint.invented.example/op",
                            method="POST", body=json.dumps({"query": doc})))
    assert out["status"] == 200


# ── consent gate carries the payload transparently ─────────────────────────────

def test_gated_shows_body_in_plan_and_passes_it_through(fake_net, monkeypatch):
    seen_plan: dict = {}
    seen_call: dict = {}
    body = json.dumps({"query": "query Q { thing { id } }"})

    def _fake_probe(url, method="GET", headers=None, body=None):
        seen_call.update(url=url, method=method, body=body)
        return json.dumps({"status": 200, "body": "{}"})

    monkeypatch.setattr(P, "probe_http", _fake_probe)
    P.set_consent_handler(lambda plan: seen_plan.update(plan) or {"decision": "approve"})
    out = _obj(P.probe_http_gated("https://entrypoint.invented.example/op",
                                  method="POST", body=body, reason="reproduce op"))
    assert out["status"] == 200
    assert seen_plan["body"] == body           # operator saw exactly what runs
    assert "read-only" in seen_plan["safety"]
    assert seen_call["body"] == body


def test_gated_rejects_unprovable_body_before_asking_consent():
    asked = {"n": 0}
    P.set_consent_handler(lambda plan: asked.__setitem__("n", asked["n"] + 1)
                          or {"decision": "approve"})
    out = _obj(P.probe_http_gated(
        "https://entrypoint.invented.example/op", method="POST",
        body=json.dumps({"query": "mutation { zap }"}), reason="r"))
    assert "rejected before consent" in out["probe_error"]
    assert asked["n"] == 0                     # never prompted a human for it


def test_gated_without_body_keeps_legacy_signature(monkeypatch):
    # regression: approve path must still work with probe_http implementations
    # (and recordings) that predate the body parameter
    monkeypatch.setattr(P, "probe_http",
                        lambda url, method="GET", headers=None:
                        json.dumps({"status": 204, "body": ""}))
    P.set_consent_handler(lambda plan: {"decision": "approve"})
    out = _obj(P.probe_http_gated("https://entrypoint.invented.example/op", reason="r"))
    assert out["status"] == 204


# ── 4. hint-freeness / service-agnosticism ──────────────────────────────────────

_SERVICE_LITERALS = [
    "appsync", "apigateway", "api gateway", "amazonaws", "cognito",
    "dynamodb", "lambda", "cloudfront", "elasticloadbalancing", "alb ",
    "resolver", "vtl", "$util",
]


def test_reproduction_code_names_no_service():
    # every function on the reproduction path: keyed on the HTTP interaction
    # pattern only, no service names, no expected-response vocabulary
    src = "".join(
        inspect.getsource(fn)
        for fn in (P.probe_http, P.probe_http_gated,
                   P._body_is_read_only_query, P._strip_query_noise)
    ).lower()
    hits = [w for w in _SERVICE_LITERALS if w in src]
    assert hits == [], f"reproduction code leaked service literals: {hits}"


def test_identical_behaviour_on_invented_endpoints(fake_net):
    # keyed on the interaction pattern only: two unrelated invented hosts get
    # byte-identical treatment (same result shape, same fields)
    fake_net(_FakeResponse(status=200, body=b"A"))
    a = _obj(P.probe_http("https://svc-one.invented.example/x"))
    fake_net(_FakeResponse(status=200, body=b"A"))
    b = _obj(P.probe_http("https://totally-other.fictional.example/y?z=1"))
    assert set(a) == set(b)
    assert a["status"] == b["status"] == 200


# ── observe-node wiring: reproduce-first, opt-in, deterministic capture ────────

class _ScriptedBedrock:
    def __init__(self, script):
        self.script = list(script)
        self.seen_tool_configs: list = []
        self.seen_systems: list = []

    def converse(self, **kw):
        self.seen_tool_configs.append(kw.get("toolConfig") or {})
        self.seen_systems.append(kw.get("system") or [])
        return self.script.pop(0)


def _tool_use(name, tool_input, tid="t1"):
    return {
        "stopReason": "tool_use",
        "output": {"message": {"role": "assistant", "content": [
            {"toolUse": {"toolUseId": tid, "name": name, "input": tool_input}},
        ]}},
    }


def _end_turn(text):
    return {
        "stopReason": "end_turn",
        "output": {"message": {"role": "assistant",
                               "content": [{"text": text}]}},
    }


_OBS_JSON = json.dumps({
    "symptom_observable_now": True,
    "onset_estimate": "unknown",
    "affected_scope": "the probed operation",
    "unaffected_scope": "unknown",
    "reproduction": "status 200 with null payload fields",
    "measurements": ["probe returned 200 with null fields"],
})


def test_observe_node_reproduces_and_captures_concrete_response(monkeypatch):
    from cloudctl.ai import graph_agent as g

    monkeypatch.setenv("CLOUDCTL_ENABLE_PROBES", "1")
    monkeypatch.setenv("CLOUDCTL_PROBE_AUTO", "approve")   # CI auto-consent
    canned = json.dumps({"status": 200,
                         "body": '{"data":{"thing":{"id":null}}}',
                         "elapsed_ms": 12, "auth_sent": True})
    monkeypatch.setattr(P, "probe_http",
                        lambda url, method="GET", headers=None, body=None: canned)

    fake = _ScriptedBedrock([
        _tool_use("probe_http", {
            "url": "https://entrypoint.invented.example/op",
            "method": "POST",
            "body": json.dumps({"query": "query Q { thing { id } }"}),
            "reason": "exercise the reported operation",
        }),
        _end_turn(_OBS_JSON),
    ])
    monkeypatch.setattr(g, "_make_bedrock", lambda *a, **k: fake)

    out = g.observe_node({
        "symptom": "user-facing operation returns wrong data",
        "profile": None, "region": "us-east-1", "minutes": 60,
        "session_id": "sess-test",
    })
    obs = out["observation"]
    # the CONCRETE response is attached deterministically, verbatim —
    # independent of how the model summarized it
    rep = obs["reproduction_observed"]
    assert rep[0]["url"] == "https://entrypoint.invented.example/op"
    assert rep[0]["method"] == "POST"
    assert rep[0]["response"]["status"] == 200
    assert rep[0]["response"]["body"] == '{"data":{"thing":{"id":null}}}'
    assert rep[0]["response"]["_reproduction"].startswith("cloudctl-executed")
    # the model's own summary also parsed
    assert obs["symptom_observable_now"] is True


def test_observe_node_probe_failure_captured_not_raised(monkeypatch):
    from cloudctl.ai import graph_agent as g

    monkeypatch.setenv("CLOUDCTL_ENABLE_PROBES", "1")
    monkeypatch.setenv("CLOUDCTL_PROBE_AUTO", "approve")
    monkeypatch.setattr(
        P, "probe_http",
        lambda url, method="GET", headers=None, body=None:
        json.dumps({"probe_error": "could not reproduce: URLError: refused",
                    "timed_out": False, "elapsed_ms": 3, "probes_used": 1}))

    fake = _ScriptedBedrock([
        _tool_use("probe_http", {"url": "https://gone.invented.example/op",
                                 "reason": "reproduce"}),
        _end_turn(json.dumps({
            "symptom_observable_now": False, "onset_estimate": "unknown",
            "affected_scope": "unknown", "unaffected_scope": "unknown",
            "reproduction": "not possible: endpoint unreachable",
            "measurements": [],
        })),
    ])
    monkeypatch.setattr(g, "_make_bedrock", lambda *a, **k: fake)

    out = g.observe_node({
        "symptom": "operation failing", "profile": None,
        "region": "us-east-1", "minutes": 60, "session_id": "sess-test",
    })
    rep = out["observation"]["reproduction_observed"][0]
    assert "could not reproduce" in rep["response"]["probe_error"]


def test_observe_node_unchanged_when_reproduction_disabled(monkeypatch):
    from cloudctl.ai import graph_agent as g

    monkeypatch.delenv("CLOUDCTL_ENABLE_PROBES", raising=False)
    fake = _ScriptedBedrock([_end_turn(json.dumps({
        "symptom_observable_now": False, "onset_estimate": "unknown",
        "affected_scope": "?", "unaffected_scope": "?", "measurements": [],
    }))])
    monkeypatch.setattr(g, "_make_bedrock", lambda *a, **k: fake)

    out = g.observe_node({
        "symptom": "something failing", "profile": None,
        "region": "us-east-1", "minutes": 60, "session_id": "sess-test",
    })
    # no reproduction key, passive toolset only, passive prompt only
    assert "reproduction_observed" not in out["observation"]
    tool_names = {t["toolSpec"]["name"]
                  for t in fake.seen_tool_configs[0]["tools"]
                  if "toolSpec" in t}
    assert "probe_http" not in tool_names
    assert "aws_read" not in tool_names
    system_text = "".join(b.get("text", "") for b in fake.seen_systems[0])
    assert "REPRODUCE FIRST" not in system_text


def test_observe_node_offers_reproduction_tools_when_enabled(monkeypatch):
    from cloudctl.ai import graph_agent as g

    monkeypatch.setenv("CLOUDCTL_ENABLE_PROBES", "1")
    fake = _ScriptedBedrock([_end_turn(json.dumps({
        "symptom_observable_now": False, "onset_estimate": "unknown",
        "affected_scope": "?", "unaffected_scope": "?", "measurements": [],
    }))])
    monkeypatch.setattr(g, "_make_bedrock", lambda *a, **k: fake)

    g.observe_node({
        "symptom": "something failing", "profile": None,
        "region": "us-east-1", "minutes": 60, "session_id": "sess-test",
    })
    tool_names = {t["toolSpec"]["name"]
                  for t in fake.seen_tool_configs[0]["tools"]
                  if "toolSpec" in t}
    assert {"probe_http", "aws_read"} <= tool_names
    system_text = "".join(b.get("text", "") for b in fake.seen_systems[0])
    assert "REPRODUCE FIRST" in system_text


# ── grounding: prompts carry the generic consistency principle, hint-free ──────

def test_synthesis_prompt_has_reproduced_response_consistency_rule():
    from cloudctl.ai import graph_agent as g
    assert "REPRODUCED RESPONSE CONSISTENCY" in g._SYNTHESIZE_PROMPT
    # the rule reasons over the observed response, not any service's config
    low = " ".join(g._SYNTHESIZE_PROMPT.lower().split())
    for phrase in ("would have produced a different concrete response",
                   "do not invent what the response"):
        assert phrase in low


def test_discriminate_prompt_weighs_reproduced_response():
    from cloudctl.ai import graph_agent as g
    assert "reproduced" in g._DISCRIMINATE_SYSTEM.lower()
    assert "reproduction_observed" in g._DISCRIMINATE_SYSTEM


def test_new_prompt_guidance_is_hint_free():
    """The reproduce-first addendum and the consistency rule must name no
    service, no resource type, and no scenario — only the interaction pattern
    and universal HTTP semantics."""
    from cloudctl.ai import graph_agent as g
    blocklist = [
        "appsync", "graphql", "api gateway", "apigateway", "cognito",
        "dynamodb", "lambda", "s3", "vtl", "$util", "resolver",
        "cloudfront", "alb", "sqs", "sns", "kms",
    ]
    for text in (g._OBSERVE_REPRODUCE_ADDENDUM,):
        low = text.lower()
        hits = [w for w in blocklist if w in low]
        assert hits == [], f"addendum leaked hint literals: {hits}"
    # the synthesize rule block specifically
    block = g._SYNTHESIZE_PROMPT.split("REPRODUCED RESPONSE CONSISTENCY", 1)[1]
    block = block.split("Select the hypothesis", 1)[0].lower()
    hits = [w for w in blocklist if w in block]
    assert hits == [], f"consistency rule leaked hint literals: {hits}"
