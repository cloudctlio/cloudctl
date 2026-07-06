"""The consent gate makes active reproduction opt-in AND per-probe approved.
Even when probing is enabled, NOTHING runs until a human decides. These tests
pin the three decisions (approve / paste / skip), decline-by-default, and that
parallel branches can't prompt over each other."""
from __future__ import annotations

import json
import threading
import time

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


# ── opt-in master switch ──────────────────────────────────────────────────────
def test_gate_disabled_when_probes_off(monkeypatch):
    monkeypatch.delenv("CLOUDCTL_ENABLE_PROBES", raising=False)
    out = _obj(P.probe_http_gated("https://svc.internal/x", reason="r"))
    assert "disabled" in out.get("probe_error", "")


# ── decline-by-default: enabled but nobody wired to consent → never probe ──────
def test_no_handler_declines_never_probes(monkeypatch):
    called = {"probe": False}
    monkeypatch.setattr(P, "probe_http", lambda *a, **k: called.__setitem__("probe", True) or "{}")
    out = _obj(P.probe_http_gated("https://svc.internal/x", reason="r"))
    assert out.get("probe_declined") is True
    assert called["probe"] is False          # crucial: no silent probe
    assert P.probes_used() == 0


# ── approve → cloudctl runs it, result is passed through + tagged ──────────────
def test_approve_runs_and_tags(monkeypatch):
    monkeypatch.setattr(P, "probe_http",
                        lambda url, method="GET", headers=None:
                        json.dumps({"status": 200, "body": '{"price_cents": 0}'}))
    P.set_consent_handler(lambda plan: {"decision": "approve"})
    out = _obj(P.probe_http_gated("http://alb/catalog/SKU-1", reason="check body"))
    assert out["status"] == 200
    assert out["body"] == '{"price_cents": 0}'
    assert out["_reproduction"].startswith("cloudctl-executed")


# ── paste → operator ran it elsewhere, we ingest their response ────────────────
def test_paste_ingests_operator_response(monkeypatch):
    probed = {"n": 0}
    monkeypatch.setattr(P, "probe_http",
                        lambda *a, **k: probed.__setitem__("n", probed["n"] + 1) or "{}")
    P.set_consent_handler(lambda plan: {"decision": "paste",
                                        "pasted": '{"price_cents": 0}'})
    out = _obj(P.probe_http_gated("http://private-alb/catalog/SKU-1", reason="r"))
    assert out["observed_response"] == '{"price_cents": 0}'
    assert out["_reproduction"].startswith("operator-executed")
    assert probed["n"] == 0                   # cloudctl did NOT make the request
    assert P.probes_used() == 1               # but it counts against the budget


# ── skip → declined, and the agent is told not to claim verification ───────────
def test_skip_declines_with_verify_note():
    P.set_consent_handler(lambda plan: {"decision": "skip", "reason": "not now"})
    out = _obj(P.probe_http_gated("http://alb/x", reason="r"))
    assert out["probe_declined"] is True
    assert "do not claim" in out["note"].lower()
    assert P.probes_used() == 0


def test_unrecognized_decision_is_treated_as_skip():
    P.set_consent_handler(lambda plan: {"decision": "banana"})
    out = _obj(P.probe_http_gated("http://alb/x", reason="r"))
    assert out["probe_declined"] is True


# ── the plan the operator sees carries what/why/safety ────────────────────────
def test_plan_presented_to_handler_has_context():
    seen = {}
    P.set_consent_handler(lambda plan: seen.update(plan) or {"decision": "skip"})
    P.probe_http_gated("http://alb/catalog/SKU-1", method="get",
                       reason="telemetry clean, suspect response body")
    assert seen["url"] == "http://alb/catalog/SKU-1"
    assert seen["method"] == "GET"
    assert seen["reason"] == "telemetry clean, suspect response body"
    assert "read-only" in seen["safety"]


# ── deterministic auto-mode (CI/replay) only when explicitly set ──────────────
def test_auto_approve_env_when_no_handler(monkeypatch):
    monkeypatch.setenv("CLOUDCTL_PROBE_AUTO", "approve")
    monkeypatch.setattr(P, "probe_http",
                        lambda *a, **k: json.dumps({"status": 200, "body": "ok"}))
    out = _obj(P.probe_http_gated("http://alb/x", reason="r"))
    assert out["status"] == 200
    assert out["_reproduction"].startswith("cloudctl-executed")


# ── parallel branches cannot prompt over each other (gate is serialized) ──────
def test_consent_gate_is_serialized(monkeypatch):
    monkeypatch.setattr(P, "probe_http",
                        lambda *a, **k: json.dumps({"status": 200}))
    state = {"inside": 0, "overlap": False}

    def handler(plan):
        state["inside"] += 1
        if state["inside"] > 1:
            state["overlap"] = True
        time.sleep(0.02)          # widen the window for a race to show
        state["inside"] -= 1
        return {"decision": "approve"}

    P.set_consent_handler(handler)
    threads = [threading.Thread(target=P.probe_http_gated,
                                args=("http://alb/x",), kwargs={"reason": "r"})
               for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert state["overlap"] is False
