"""Tests for cloudctl.agent.session — SessionState and persistence."""
from __future__ import annotations

import json
import pytest
from pathlib import Path
from unittest.mock import patch


class TestSessionState:
    def test_add_turn(self):
        from cloudctl.agent.session import SessionState
        s = SessionState(session_id="test123")
        s.add_turn("user", "hello")
        s.add_turn("assistant", "hi there")
        assert len(s.turns) == 2
        assert s.turns[0].role == "user"
        assert s.turns[1].content == "hi there"

    def test_history_text(self):
        from cloudctl.agent.session import SessionState
        s = SessionState(session_id="test123")
        s.add_turn("user", "what is the cost?")
        s.add_turn("assistant", "about $50")
        text = s.history_text()
        assert "USER: what is the cost?" in text
        assert "ASSISTANT: about $50" in text

    def test_history_text_max_turns(self):
        from cloudctl.agent.session import SessionState
        s = SessionState(session_id="test123")
        for i in range(20):
            s.add_turn("user", f"q{i}")
        text = s.history_text(max_turns=5)
        assert "q19" in text
        assert "q0" not in text

    def test_merge_context_new_key(self):
        from cloudctl.agent.session import SessionState
        s = SessionState(session_id="test123")
        s.merge_context({"compute": [{"name": "i-123"}]})
        assert "compute" in s.context_cache

    def test_merge_context_extend_list(self):
        from cloudctl.agent.session import SessionState
        s = SessionState(session_id="test123")
        s.merge_context({"items": [1, 2]})
        s.merge_context({"items": [3, 4]})
        assert s.context_cache["items"] == [1, 2, 3, 4]

    def test_merge_context_update_dict(self):
        from cloudctl.agent.session import SessionState
        s = SessionState(session_id="test123")
        s.merge_context({"meta": {"a": 1}})
        s.merge_context({"meta": {"b": 2}})
        assert s.context_cache["meta"] == {"a": 1, "b": 2}

    def test_created_at_auto_set(self):
        from cloudctl.agent.session import SessionState
        s = SessionState(session_id="test123")
        assert s.created_at != ""

    def test_turn_timestamp_auto_set(self):
        from cloudctl.agent.session import Turn
        t = Turn(role="user", content="hello")
        assert t.timestamp != ""


class TestSessionPersistence:
    def test_save_and_load(self, tmp_path):
        from cloudctl.agent.session import SessionState, save, load

        with patch("cloudctl.agent.session._SESSIONS_DIR", tmp_path):
            s = SessionState(session_id="sess001", cloud="aws")
            s.add_turn("user", "why is prod slow?")
            save(s)
            loaded = load("sess001")

        assert loaded is not None
        assert loaded.session_id == "sess001"
        assert loaded.cloud == "aws"
        assert len(loaded.turns) == 1
        assert loaded.turns[0].content == "why is prod slow?"

    def test_load_missing_returns_none(self, tmp_path):
        from cloudctl.agent.session import load
        with patch("cloudctl.agent.session._SESSIONS_DIR", tmp_path):
            result = load("nonexistent")
        assert result is None

    def test_new_session_creates_and_saves(self, tmp_path):
        from cloudctl.agent.session import new_session, load

        with patch("cloudctl.agent.session._SESSIONS_DIR", tmp_path):
            s = new_session(cloud="azure")
            loaded = load(s.session_id)

        assert loaded is not None
        assert loaded.cloud == "azure"

    def test_list_sessions(self, tmp_path):
        from cloudctl.agent.session import new_session, list_sessions

        with patch("cloudctl.agent.session._SESSIONS_DIR", tmp_path):
            new_session(cloud="aws")
            new_session(cloud="gcp")
            sessions = list_sessions()

        assert len(sessions) == 2
        clouds = {s["cloud"] for s in sessions}
        assert clouds == {"aws", "gcp"}
