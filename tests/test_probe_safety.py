"""The active-reproduction probe must make unsafe requests impossible in CODE,
independent of the model. These tests exercise every guard."""
from __future__ import annotations

import json

import pytest

from cloudctl.mcp.tools import probe as P


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    P.reset_probe_budget()
    monkeypatch.setenv("CLOUDCTL_ENABLE_PROBES", "1")
    yield
    P.reset_probe_budget()


def _reason(out: str) -> str:
    return json.loads(out).get("probe_error", "")


def test_disabled_by_default(monkeypatch):
    monkeypatch.delenv("CLOUDCTL_ENABLE_PROBES", raising=False)
    assert "disabled" in _reason(P.probe_http("https://example.com"))


def test_metadata_endpoint_blocked():
    # the classic SSRF target — must never be reachable
    out = P.probe_http("http://169.254.169.254/latest/meta-data/iam/")
    assert "blocked" in _reason(out)


def test_loopback_blocked():
    for url in ("http://127.0.0.1:8080/", "http://localhost/admin"):
        assert "blocked" in _reason(P.probe_http(url))


def test_non_http_scheme_blocked():
    for url in ("file:///etc/passwd", "gopher://x/", "ftp://h/"):
        assert "not allowed" in _reason(P.probe_http(url))


def test_mutating_method_blocked():
    for m in ("POST", "PUT", "DELETE", "PATCH"):
        assert "read-only" in _reason(P.probe_http("https://example.com", method=m))


def test_private_ranges_allowed_by_guard():
    # the user's own internal endpoints are legitimate targets — the host guard
    # must NOT block them (only loopback/link-local/metadata are blocked)
    for host in ("10.0.0.5", "172.16.3.4", "192.168.1.10"):
        blocked, _ = P._host_is_blocked(host)
        assert not blocked, f"{host} should be allowed"


def test_metadata_and_loopback_flagged_by_guard():
    for host in ("169.254.169.254", "127.0.0.1", "0.0.0.0"):
        blocked, _ = P._host_is_blocked(host)
        assert blocked, f"{host} must be blocked"


def test_probe_budget_enforced():
    # exhaust the budget on rejected-but-admitted probes, then confirm the cap
    P._PROBE_STATS["used"] = P._MAX_PROBES_PER_INVESTIGATION
    out = P.probe_http("https://example.com")
    assert "budget" in _reason(out)


def test_budget_resets():
    P._PROBE_STATS["used"] = 3
    P.reset_probe_budget()
    assert P.probes_used() == 0
