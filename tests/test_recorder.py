"""Tests for the record/replay layer, session cache, and dual-plane model
recording (exact-mode neutrality proofs, pinned-mode divergence attribution)."""
from __future__ import annotations

import json
import os

import pytest
from unittest.mock import MagicMock

from cloudctl.mcp.tools import recorder as rec


@pytest.fixture(autouse=True)
def _clean_state(tmp_path, monkeypatch):
    for var in ("CLOUDCTL_RECORD", "CLOUDCTL_REPLAY", "CLOUDCTL_REPLAY_MODEL"):
        monkeypatch.delenv(var, raising=False)
    rec.reset_replay_state()
    yield
    rec.reset_replay_state()


def _fixture(tmp_path) -> str:
    return str(tmp_path / "fixture.jsonl")


# ── tool plane ────────────────────────────────────────────────────────────────

class TestToolPlane:
    def test_record_then_exact_replay(self, tmp_path, monkeypatch):
        path = _fixture(tmp_path)
        calls = {"n": 0}

        @rec.recordable("mytool")
        def mytool(resource_name, profile, region):
            calls["n"] += 1
            return json.dumps({"value": f"live-{resource_name}"})

        monkeypatch.setenv("CLOUDCTL_RECORD", path)
        assert "live-db1" in mytool("db1", "p", "r")

        monkeypatch.delenv("CLOUDCTL_RECORD")
        monkeypatch.setenv("CLOUDCTL_REPLAY", path)
        rec.reset_replay_state()
        assert "live-db1" in mytool("db1", "other-profile", "r")
        assert calls["n"] == 1                       # replay never ran the tool
        assert rec.replay_fidelity()["exact"] == 1

    def test_miss_is_explicit(self, tmp_path, monkeypatch):
        path = _fixture(tmp_path)
        open(path, "w").close()

        @rec.recordable("never_recorded")
        def never_recorded(resource_name, profile, region):
            return json.dumps({"value": "x"})

        monkeypatch.setenv("CLOUDCTL_REPLAY", path)
        out = json.loads(never_recorded("a", "p", "r"))
        assert out["replay_miss"] is True
        assert rec.replay_fidelity()["miss"] == 1

    def test_session_cache_dedupes_but_not_errors(self, monkeypatch):
        calls = {"n": 0}

        @rec.recordable("cachetool")
        def cachetool(resource_name, profile, region):
            calls["n"] += 1
            if resource_name == "bad":
                return json.dumps({"error": "boom"})
            return json.dumps({"value": calls["n"]})

        assert cachetool("x", "p", "r") == cachetool("x", "p", "r")
        assert calls["n"] == 1
        cachetool("bad", "p", "r"); cachetool("bad", "p", "r")
        assert calls["n"] == 3                       # errors never cached


# ── model plane (dual-plane recording) ────────────────────────────────────────

def _resp(text):
    return {"stopReason": "end_turn",
            "output": {"message": {"content": [{"text": text}]}},
            "usage": {"inputTokens": 1}}


REQ_CACHED = dict(
    system=[{"text": "SYS"}, {"cachePoint": {"type": "default"}}],
    messages=[{"role": "user", "content": [{"text": "hello"},
                                           {"cachePoint": {"type": "default"}}]}],
)
REQ_PLAIN = dict(
    system=[{"text": "SYS"}],
    messages=[{"role": "user", "content": [{"text": "hello"}]}],
)
REQ_MUTATED = dict(
    system=[{"text": "SYS CHANGED"}],
    messages=[{"role": "user", "content": [{"text": "hello"}]}],
)


class TestModelPlane:
    def test_passthrough_when_no_env(self):
        client = MagicMock()
        client.converse.return_value = _resp("live")
        w = rec.RecordingBedrock(client)
        out = w.converse(**REQ_PLAIN)
        assert out["output"]["message"]["content"][0]["text"] == "live"
        assert client.converse.call_count == 1
        # attribute delegation stays transparent
        client.some_other_api.return_value = 42
        assert w.some_other_api() == 42

    def test_cachepoint_excluded_from_hash(self):
        assert rec._request_hash(REQ_CACHED) == rec._request_hash(REQ_PLAIN)
        assert rec._request_hash(REQ_PLAIN) != rec._request_hash(REQ_MUTATED)

    def _record_one(self, tmp_path, monkeypatch, request, text="verdict A"):
        path = _fixture(tmp_path)
        monkeypatch.setenv("CLOUDCTL_RECORD", path)
        client = MagicMock()
        client.converse.return_value = _resp(text)
        rec.RecordingBedrock(client).converse(**request)
        monkeypatch.delenv("CLOUDCTL_RECORD")
        return path

    def test_exact_replay_serves_recorded_response(self, tmp_path, monkeypatch):
        path = self._record_one(tmp_path, monkeypatch, REQ_CACHED)
        monkeypatch.setenv("CLOUDCTL_REPLAY", path)
        monkeypatch.setenv("CLOUDCTL_REPLAY_MODEL", "exact")
        rec.reset_replay_state()
        live = MagicMock()
        out = rec.RecordingBedrock(live).converse(**REQ_PLAIN)   # no cachePoints
        assert out["output"]["message"]["content"][0]["text"] == "verdict A"
        assert live.converse.call_count == 0
        assert rec.MODEL_STATS["served"] == 1

    def test_exact_replay_rejects_mutated_request(self, tmp_path, monkeypatch):
        path = self._record_one(tmp_path, monkeypatch, REQ_PLAIN)
        monkeypatch.setenv("CLOUDCTL_REPLAY", path)
        monkeypatch.setenv("CLOUDCTL_REPLAY_MODEL", "exact")
        rec.reset_replay_state()
        with pytest.raises(RuntimeError, match="NOT behavior-neutral"):
            rec.RecordingBedrock(MagicMock()).converse(**REQ_MUTATED)

    def test_pinned_replay_goes_live_at_divergence(self, tmp_path, monkeypatch):
        path = self._record_one(tmp_path, monkeypatch, REQ_PLAIN)
        monkeypatch.setenv("CLOUDCTL_REPLAY", path)
        monkeypatch.setenv("CLOUDCTL_REPLAY_MODEL", "pinned")
        rec.reset_replay_state()
        live = MagicMock()
        live.converse.return_value = _resp("live-after-divergence")
        w = rec.RecordingBedrock(live)
        served = w.converse(**REQ_PLAIN)
        diverged = w.converse(**REQ_MUTATED)
        assert served["output"]["message"]["content"][0]["text"] == "verdict A"
        assert diverged["output"]["message"]["content"][0]["text"] == "live-after-divergence"
        assert live.converse.call_count == 1
        assert rec.MODEL_STATS["diverged_at"] is not None

    def test_live_mode_records_model_plane(self, tmp_path, monkeypatch):
        path = self._record_one(tmp_path, monkeypatch, REQ_PLAIN)
        records = [json.loads(l) for l in open(path, encoding="utf-8")]
        model_recs = [r for r in records if r["tool"] == "_model"]
        assert len(model_recs) == 1
        assert model_recs[0]["input"]["hash"] == rec._request_hash(REQ_PLAIN)
        stored = json.loads(model_recs[0]["output"])
        assert stored["output"]["message"]["content"][0]["text"] == "verdict A"
