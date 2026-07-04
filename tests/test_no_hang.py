"""No-hang guarantee: every tool-plane AWS client carries bounded timeouts and
capped retries, so a single unresponsive call can never stall an investigation
(a boto read once hung a run for 40 minutes, 2026-07-04)."""
from __future__ import annotations

from botocore.config import Config

from cloudctl.mcp.tools.debug import _make_session, _tool_boto_config


def test_clients_have_bounded_timeouts():
    c = _make_session(None, "us-east-1").client("cloudwatch")
    cfg = c.meta.config
    assert cfg.connect_timeout == 8
    assert cfg.read_timeout == 30
    # retries capped (max_attempts=3 → total_max_attempts=4, adaptive)
    assert cfg.retries["total_max_attempts"] <= 4


def test_caller_config_overrides_but_timeouts_persist():
    s = _make_session(None, "us-east-1")
    c = s.client("logs", config=Config(read_timeout=60))
    assert c.meta.config.read_timeout == 60      # caller wins
    assert c.meta.config.connect_timeout == 8    # default still applied


def test_tool_boto_config_shape():
    cfg = _tool_boto_config()
    assert cfg.connect_timeout and cfg.read_timeout
    assert cfg.retries["max_attempts"] <= 3


def test_budget_ceiling_raises_and_propagates(monkeypatch):
    from cloudctl.mcp.tools import recorder as rec
    rec.reset_usage_stats()
    rec._accumulate_usage({"usage": {"inputTokens": 10000, "outputTokens": 1000}}, 1.0)
    monkeypatch.setenv("CLOUDCTL_INVESTIGATION_BUDGET_USD", "0.01")
    import pytest
    with pytest.raises(rec.BudgetExceededError):
        rec._check_budget()
    # BaseException so it propagates past branch-level `except Exception`
    assert issubclass(rec.BudgetExceededError, BaseException)
    assert not issubclass(rec.BudgetExceededError, Exception)
    monkeypatch.setenv("CLOUDCTL_INVESTIGATION_BUDGET_USD", "100")
    rec._check_budget()  # under budget: no raise


def test_no_budget_set_never_raises(monkeypatch):
    from cloudctl.mcp.tools import recorder as rec
    rec.reset_usage_stats()
    rec._accumulate_usage({"usage": {"inputTokens": 10_000_000, "outputTokens": 1}}, 1.0)
    monkeypatch.delenv("CLOUDCTL_INVESTIGATION_BUDGET_USD", raising=False)
    rec._check_budget()  # no cap → never raises regardless of spend
