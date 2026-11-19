"""Agent mode must not raise confidence from past y/n answers.

Before this change, a keyword pattern confirmed 3+ times in ~/.cloudctl
promoted a MEDIUM verdict to HIGH and appended a "confidence promoted" line to
the evidence list, with no new evidence fetched. Confidence now comes only from
the verdict pipeline.
"""
from __future__ import annotations

import json

from typer.testing import CliRunner

import cloudctl.ai.graph_agent as ga
import cloudctl.ai.live_learner as ll
import cloudctl.commands.debug_cmd as dc
from cloudctl.main import app


def test_confirmed_keyword_pattern_does_not_promote_confidence(tmp_path, monkeypatch):
    # A pattern the old code would have matched: same symptom tokens, confirmed
    # 5x, data sources that the agent run below also fetched.
    base = tmp_path / ".cloudctl"
    (base / "patterns").mkdir(parents=True)
    (base / "patterns" / "patterns.json").write_text(json.dumps([{
        "pattern_id": "resource_limit-payments-returning",
        "pattern_type": "resource_limit",
        "symptom_tokens": ["payments", "returning", "502s"],
        "data_sources": ["get_metrics"],
        "evidence_shape": "",
        "confirmed_count": 5,
        "last_seen": "2026-11-01T00:00:00+00:00",
        "account_ids": ["xxxx1234"],
    }]), encoding="utf-8")
    monkeypatch.setattr(ll, "_BASE", base)

    agent_out = {
        "root_cause": "connection pool exhausted on orders-db",
        "evidence": ["DatabaseConnections at 100 of max 100"],
        "confidence": "MEDIUM",
        "severity": "HIGH",
    }
    monkeypatch.setattr(dc, "require_init", lambda: object())
    monkeypatch.setattr(ga, "debug_incident_graph",
                        lambda **_k: (json.dumps(agent_out), {"get_metrics:orders-db": {"v": 1}}))
    monkeypatch.setattr(dc, "_render_agent_result", lambda *_a, **_k: None)

    out_file = tmp_path / "out.json"
    result = CliRunner().invoke(app, [
        "debug", "payments returning 502s", "--agent",
        "--verdict", "skip", "--json-out", str(out_file),
    ])
    assert result.exit_code == 0, result.output

    d = json.loads(out_file.read_text(encoding="utf-8"))
    assert d["confidence"] == "MEDIUM"
    assert not any("confidence promoted" in e for e in d["evidence"])


def test_best_pattern_match_is_gone():
    assert not hasattr(ll, "best_pattern_match")
