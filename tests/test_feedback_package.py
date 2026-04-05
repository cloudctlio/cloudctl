"""Tests for cloudctl.feedback package — store, processor, applier."""
from __future__ import annotations

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


# ─── store ──────────────────────────────────────────────────────────────────

class TestFeedbackStore:
    def test_append_and_read(self, tmp_path):
        from cloudctl.feedback.store import FeedbackEntry, append, read_all
        feedback_file = tmp_path / "feedback.jsonl"

        with patch("cloudctl.feedback.store._JSONL_FILE", feedback_file), \
             patch("cloudctl.feedback.store._DIR", tmp_path):
            entry = FeedbackEntry(
                question="why is prod slow?",
                answer="DB connection exhaustion",
                rating=5,
                cloud="aws",
                account="prod",
                provider="bedrock",
            )
            append(entry)
            records = read_all()

        assert len(records) == 1
        assert records[0]["question"] == "why is prod slow?"
        assert records[0]["rating"] == 5

    def test_read_empty(self, tmp_path):
        from cloudctl.feedback.store import read_all
        fake_file = tmp_path / "feedback.jsonl"
        with patch("cloudctl.feedback.store._JSONL_FILE", fake_file):
            assert read_all() == []

    def test_read_limit(self, tmp_path):
        from cloudctl.feedback.store import FeedbackEntry, append, read_all

        feedback_file = tmp_path / "feedback.jsonl"
        with patch("cloudctl.feedback.store._JSONL_FILE", feedback_file), \
             patch("cloudctl.feedback.store._DIR", tmp_path):
            for i in range(5):
                append(FeedbackEntry(
                    question=f"q{i}", answer=f"a{i}", rating=3,
                    cloud="aws", account="", provider="bedrock",
                ))
            records = read_all(limit=3)

        assert len(records) == 3

    def test_load_patterns_missing(self, tmp_path):
        from cloudctl.feedback.store import load_patterns
        fake = tmp_path / "patterns.yaml"
        with patch("cloudctl.feedback.store._PATTERNS_FILE", fake):
            assert load_patterns() == {}

    def test_save_and_load_patterns(self, tmp_path):
        from cloudctl.feedback.store import save_patterns, load_patterns
        fake = tmp_path / "patterns.yaml"
        with patch("cloudctl.feedback.store._PATTERNS_FILE", fake), \
             patch("cloudctl.feedback.store._DIR", tmp_path):
            save_patterns({"cloud_accuracy": {"aws": 0.8}})
            loaded = load_patterns()
        assert loaded["cloud_accuracy"]["aws"] == pytest.approx(0.8)


# ─── processor ──────────────────────────────────────────────────────────────

class TestFeedbackProcessor:
    def test_positive_text(self):
        from cloudctl.feedback.processor import classify_text
        assert classify_text("that was correct and exactly right") == 5

    def test_negative_text(self):
        from cloudctl.feedback.processor import classify_text
        assert classify_text("totally wrong, incorrect answer") == 1

    def test_neutral_text(self):
        from cloudctl.feedback.processor import classify_text
        assert classify_text("hmm interesting") == 3

    def test_extract_signals_empty(self):
        from cloudctl.feedback.processor import extract_signals
        signals = extract_signals([])
        assert signals["total_records"] == 0
        assert signals["cloud_accuracy"] == {}

    def test_extract_signals_cloud_accuracy(self):
        from cloudctl.feedback.processor import extract_signals
        records = [
            {"rating": 5, "cloud": "aws",   "question": "why is prod slow"},
            {"rating": 5, "cloud": "aws",   "question": "cost analysis"},
            {"rating": 1, "cloud": "azure", "question": "vm status"},
        ]
        signals = extract_signals(records)
        assert "aws" in signals["cloud_accuracy"]
        assert signals["cloud_accuracy"]["aws"] > signals["cloud_accuracy"]["azure"]


# ─── applier ────────────────────────────────────────────────────────────────

class TestFeedbackApplier:
    def test_no_patterns_returns_base(self, tmp_path):
        from cloudctl.feedback.applier import adjust_confidence
        fake = tmp_path / "patterns.yaml"
        with patch("cloudctl.feedback.applier.load_patterns", return_value={}):
            result = adjust_confidence(0.6, "why is prod slow?", "aws")
        assert result == pytest.approx(0.6)

    def test_positive_cloud_nudges_up(self, tmp_path):
        from cloudctl.feedback.applier import adjust_confidence
        patterns = {"cloud_accuracy": {"aws": 1.0}, "keyword_accuracy": {}}
        with patch("cloudctl.feedback.applier.load_patterns", return_value=patterns):
            result = adjust_confidence(0.6, "anything", "aws")
        assert result > 0.6

    def test_negative_cloud_nudges_down(self, tmp_path):
        from cloudctl.feedback.applier import adjust_confidence
        patterns = {"cloud_accuracy": {"aws": 0.0}, "keyword_accuracy": {}}
        with patch("cloudctl.feedback.applier.load_patterns", return_value=patterns):
            result = adjust_confidence(0.6, "anything", "aws")
        assert result < 0.6

    def test_clamped_to_0_1(self):
        from cloudctl.feedback.applier import adjust_confidence
        patterns = {"cloud_accuracy": {"aws": 0.0}, "keyword_accuracy": {}}
        with patch("cloudctl.feedback.applier.load_patterns", return_value=patterns):
            result = adjust_confidence(0.0, "anything", "aws")
        assert 0.0 <= result <= 1.0
