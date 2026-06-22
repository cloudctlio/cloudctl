"""
live_learner.py — The harness learning loop that runs on real user data.

Called from debug_cmd.py after user confirms y/n on an agent result.
No manual intervention needed.

Two paths:
  Confirmed correct ("y")      -> save fixture + extract pattern
  Confirmed wrong ("n/partial") -> save failure + generate correction

Everything is local. Nothing is sent anywhere.
Stored at ~/.cloudctl/
  fixtures/   — replay corpus (grows with every "y")
  failures/   — failure cases (grows with every "n")
  patterns/   — incident patterns (extracted from "y" outcomes)
  prompt_lib/ — correction examples (extracted from "n" outcomes)
"""
from __future__ import annotations

import json
import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path


# ── Storage paths ──────────────────────────────────────────────────────────────

_BASE = Path.home() / ".cloudctl"


# ── Data structures ────────────────────────────────────────────────────────────

@dataclass
class IncidentFixture:
    fixture_id:   str
    ts:           str
    query:        str
    account_id:   str        # anonymised — only last 4 digits
    region:       str
    fetched_data: dict       # sanitised (secrets already redacted)
    agent_output: dict
    ground_truth: dict       # confirmed correct answer
    turns_used:   int
    pattern_type: str


@dataclass
class IncidentPattern:
    pattern_id:      str
    pattern_type:    str
    symptom_tokens:  list[str]
    data_sources:    list[str]
    evidence_shape:  str
    confirmed_count: int
    last_seen:       str
    account_ids:     list[str]


@dataclass
class FailureCase:
    failure_id:       str
    ts:               str
    query:            str
    agent_output:     dict
    user_correction:  str
    fetched_data:     dict
    hallucinations:   list[str]
    missed_signals:   list[str]
    correction_rules: list[str]


# ── Entry points ───────────────────────────────────────────────────────────────

def on_confirmed_correct(
    query:        str,
    fetched_data: dict,
    agent_output: dict,
    account_id:   str,
    region:       str,
    turns_used:   int = 0,
) -> None:
    """Called when user confirms 'y'. Silent — no output to user."""
    fixture_id   = _make_id(query)
    pattern_type = _classify_root_cause(agent_output.get("root_cause", ""))

    fixture = IncidentFixture(
        fixture_id=fixture_id,
        ts=datetime.now(timezone.utc).isoformat(),
        query=query,
        account_id=_anonymise_account(account_id),
        region=region,
        fetched_data=fetched_data,
        agent_output=agent_output,
        ground_truth={
            "root_cause": agent_output.get("root_cause"),
            "evidence":   agent_output.get("evidence", []),
            "severity":   agent_output.get("severity"),
        },
        turns_used=turns_used,
        pattern_type=pattern_type,
    )
    _save_fixture(fixture)

    pattern = _extract_pattern(fixture)
    if pattern:
        _upsert_pattern(pattern)

    _append_prompt_library({
        "type":         "correct_example",
        "fixture_id":   fixture_id,
        "query":        query,
        "root_cause":   agent_output.get("root_cause"),
        "pattern_type": pattern_type,
        "key_evidence": agent_output.get("evidence", [])[:2],
        "turns_used":   turns_used,
    })


def on_confirmed_wrong(
    query:           str,
    fetched_data:    dict,
    agent_output:    dict,
    user_correction: str,
    account_id:      str,
) -> None:
    """Called when user says 'n' or 'partial'. Silent — no output to user."""
    from cloudctl.ai.guardrails import detect_hallucinations

    failure_id = _make_id(query, prefix="fail")
    hal        = detect_hallucinations(agent_output, fetched_data)
    missed     = _find_missed_signals(agent_output, fetched_data, user_correction)
    rules      = _generate_correction_rules(query, agent_output, hal, missed, user_correction)

    case = FailureCase(
        failure_id=failure_id,
        ts=datetime.now(timezone.utc).isoformat(),
        query=query,
        agent_output=agent_output,
        user_correction=user_correction,
        fetched_data=fetched_data,
        hallucinations=hal.unsupported,
        missed_signals=missed,
        correction_rules=rules,
    )
    _save_failure(case)

    if rules:
        _append_prompt_library({
            "type":            "correction",
            "failure_id":      failure_id,
            "query":           query,
            "wrong_answer":    agent_output.get("root_cause", ""),
            "hallucinations":  hal.unsupported[:3],
            "missed_signals":  missed[:3],
            "rules":           rules,
            "user_correction": user_correction,
        })
        # Also append as lessons to corrections.jsonl for layer 3 injection.
        # Use an O_EXCL lock file to serialise concurrent writers.
        corrections_path = _BASE / "prompt_lib" / "corrections.jsonl"
        corrections_path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = corrections_path.with_suffix(".jsonl.lock")
        _deadline = time.monotonic() + 5.0
        _acquired = False
        while time.monotonic() < _deadline:
            try:
                _fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.close(_fd)
                _acquired = True
                break
            except FileExistsError:
                time.sleep(0.05)
        try:
            with open(corrections_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"lessons": rules}) + "\n")
        finally:
            if _acquired:
                try:
                    lock_path.unlink(missing_ok=True)
                except Exception:
                    pass


def get_investigation_hints(query: str) -> list[str]:
    """
    Return investigation hints from confirmed past patterns.
    Only patterns confirmed >= 2 times are used.
    Injected into the first user message to the agent.
    """
    patterns     = _load_patterns()
    query_tokens = set(_tokenise(query))
    hints        = []

    for p in sorted(patterns, key=lambda x: x.get("confirmed_count", 0), reverse=True):
        if p.get("confirmed_count", 0) < 2:
            continue
        overlap = len(query_tokens & set(p.get("symptom_tokens", [])))
        if overlap >= 1:
            hints.append(
                f"Past incidents matching this symptom pattern "
                f"({p['confirmed_count']}x confirmed): "
                f"check {', '.join(p.get('data_sources', [])[:2])} first. "
                f"Pattern type: {p['pattern_type']}."
            )

    return hints[:3]


def best_pattern_match(query: str) -> dict | None:
    """
    Return the most-confirmed pattern whose symptom tokens overlap the query, or None.

    Used by the agent verdict pipeline to bump confidence on recurring incidents:
    if a pattern has been confirmed N times and matches the current symptom, the
    model's self-rated confidence can be promoted (MEDIUM -> HIGH at N >= 3).
    """
    patterns     = _load_patterns()
    query_tokens = set(_tokenise(query))
    best         = None
    best_score   = 0

    for p in patterns:
        overlap = len(query_tokens & set(p.get("symptom_tokens", [])))
        if overlap == 0:
            continue
        # Score = overlap * confirmed_count -- prefer broad token overlap on
        # frequently-confirmed patterns, but a single strong token match on a
        # 10x-confirmed pattern still beats a 3-token match on a 1x pattern.
        s = overlap * max(1, p.get("confirmed_count", 0))
        if s > best_score:
            best_score = s
            best       = p

    return best


# ── Pattern extraction ─────────────────────────────────────────────────────────

def _extract_pattern(fixture: IncidentFixture) -> IncidentPattern | None:
    symptom_tokens = _tokenise(fixture.query)
    contributing   = _find_contributing_sources(fixture.agent_output, fixture.fetched_data)
    if not contributing:
        return None

    return IncidentPattern(
        pattern_id=f"{fixture.pattern_type}-{'-'.join(symptom_tokens[:2])}",
        pattern_type=fixture.pattern_type,
        symptom_tokens=symptom_tokens,
        data_sources=contributing,
        evidence_shape=_templatise(fixture.agent_output.get("evidence", [])),
        confirmed_count=1,
        last_seen=fixture.ts,
        account_ids=[fixture.account_id],
    )


def _upsert_pattern(new: IncidentPattern) -> None:
    patterns = _load_patterns()
    existing = next((p for p in patterns if p["pattern_id"] == new.pattern_id), None)
    if existing:
        existing["confirmed_count"] += 1
        existing["last_seen"] = new.last_seen
        if new.account_ids[0] not in existing.get("account_ids", []):
            existing.setdefault("account_ids", []).append(new.account_ids[0])
    else:
        patterns.append({
            "pattern_id":      new.pattern_id,
            "pattern_type":    new.pattern_type,
            "symptom_tokens":  new.symptom_tokens,
            "data_sources":    new.data_sources,
            "evidence_shape":  new.evidence_shape,
            "confirmed_count": new.confirmed_count,
            "last_seen":       new.last_seen,
            "account_ids":     new.account_ids,
        })
    _save_patterns(patterns)


# ── Correction rule generation ─────────────────────────────────────────────────

def _generate_correction_rules(
    query:           str,
    agent_output:    dict,
    hal,
    missed:          list[str],
    user_correction: str,
) -> list[str]:
    rules        = []
    symptom_type = _classify_symptom(query)

    for claim in hal.unsupported[:2]:
        rules.append(
            f"Do NOT claim '{claim[:80]}' without finding it explicitly "
            f"in the fetched data. Verify in CloudWatch or logs first."
        )

    for source in missed[:2]:
        rules.append(
            f"When diagnosing '{symptom_type}' symptoms, "
            f"ALWAYS check {source} — "
            f"a past incident showed the signal was there but was missed."
        )

    correction_lower = user_correction.lower()
    if "dlq" in correction_lower or "dead letter" in correction_lower:
        rules.append(
            "When Lambda errors are elevated, ALWAYS check the associated "
            "SQS DLQ depth — errors may be silently accumulating there."
        )
    if "security group" in correction_lower or " sg " in correction_lower:
        rules.append(
            "For connectivity failures, check security group rules on BOTH "
            "the source and destination — not just one side."
        )
    if "wrong service" in correction_lower or "wrong resource" in correction_lower:
        rules.append(
            f"For '{symptom_type}' symptoms, verify you are investigating "
            f"the correct service before fetching metrics."
        )
    if "nat" in correction_lower:
        rules.append(
            "For Lambda timeout issues in VPC, check the route table for "
            "NAT Gateway — private subnets without NAT cannot reach AWS APIs."
        )

    return rules


# ── Storage helpers ────────────────────────────────────────────────────────────

def _save_fixture(f: IncidentFixture) -> None:
    d = _BASE / "fixtures"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / f"{f.fixture_id}.json", "w", encoding="utf-8") as fp:
        json.dump(f.__dict__, fp, indent=2, default=str)


def _save_failure(f: FailureCase) -> None:
    d = _BASE / "failures"
    d.mkdir(parents=True, exist_ok=True)
    with open(d / f"{f.failure_id}.json", "w", encoding="utf-8") as fp:
        json.dump(f.__dict__, fp, indent=2, default=str)


def _append_prompt_library(entry: dict) -> None:
    p = _BASE / "prompt_lib" / "library.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


_MAX_JSONL_FILE_BYTES = 5 * 1024 * 1024   # 5 MB — reject files larger than this
_MAX_JSONL_LINE_BYTES = 64 * 1024          # 64 KB per line — reject oversized entries


def _load_prompt_library() -> list[dict]:
    p = _BASE / "prompt_lib" / "library.jsonl"
    if not p.exists():
        return []
    if p.stat().st_size > _MAX_JSONL_FILE_BYTES:
        return []  # DoS protection: refuse to load abnormally large files
    entries = []
    for line in p.read_text(encoding="utf-8").strip().splitlines():
        if not line or len(line) > _MAX_JSONL_LINE_BYTES:
            continue
        try:
            entry = json.loads(line)
            if isinstance(entry, dict):  # Reject non-dict entries
                entries.append(entry)
        except Exception:
            pass
    return entries


def _load_patterns() -> list[dict]:
    p = _BASE / "patterns" / "patterns.json"
    if not p.exists():
        return []
    if p.stat().st_size > _MAX_JSONL_FILE_BYTES:
        return []  # DoS protection
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_patterns(patterns: list[dict]) -> None:
    p = _BASE / "patterns" / "patterns.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(patterns, indent=2), encoding="utf-8")


def _make_id(query: str, prefix: str = "fix") -> str:
    ts   = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    slug = re.sub(r'[^a-z0-9]+', '-', query.lower())[:25]
    return f"{prefix}-{ts}-{slug}"


def _anonymise_account(account_id: str) -> str:
    return f"xxxx{account_id[-4:]}" if len(account_id) >= 4 else "xxxx"


def _tokenise(text: str) -> list[str]:
    stop = {"is", "are", "the", "a", "an", "and", "or", "in", "on",
            "at", "to", "for", "of", "my", "our", "we", "i", "it"}
    return [
        w for w in re.findall(r'\b[a-z0-9]+\b', text.lower())
        if w not in stop and len(w) > 2
    ]


def _classify_root_cause(text: str) -> str:
    text = text.lower()
    if any(w in text for w in ["pool", "limit", "exhausted", "max_connections"]):
        return "resource_limit"
    if any(w in text for w in ["nat", "subnet", "route", "vpc endpoint"]):
        return "network"
    if any(w in text for w in ["access denied", "permission", "iam", "kms"]):
        return "iam"
    if any(w in text for w in ["certificate", "expired", "ssl", "tls"]):
        return "cert"
    if any(w in text for w in ["security group", "port", " sg "]):
        return "sg_mismatch"
    if any(w in text for w in ["throttl", "concurrency", "reserved"]):
        return "throttling"
    if any(w in text for w in ["dlq", "dead letter", "queue"]):
        return "queue_failure"
    return "other"


def _classify_symptom(query: str) -> str:
    q = query.lower()
    if any(c in q for c in ["502", "503", "504", "5xx"]):
        return "5xx errors"
    if any(c in q for c in ["timeout", "slow", "latency"]):
        return "timeout/latency"
    if "dlq" in q or "queue" in q:
        return "queue backup"
    if "lambda" in q:
        return "Lambda failure"
    return "infrastructure"


def _templatise(evidence: list[str]) -> str:
    if not evidence:
        return ""
    return re.sub(r'\b\d+\b', '{N}', evidence[0])


def _find_contributing_sources(agent_output: dict, fetched_data: dict) -> list[str]:
    evidence_text = " ".join(agent_output.get("evidence", [])).lower()
    contributing  = []
    for source_name, source_data in fetched_data.items():
        if not source_data:
            continue
        source_str     = json.dumps(source_data, default=str).lower()
        evidence_words = set(re.findall(r'\b[a-z0-9]{4,}\b', evidence_text))
        source_words   = set(re.findall(r'\b[a-z0-9]{4,}\b', source_str))
        if len(evidence_words & source_words) >= 2:
            contributing.append(source_name)
    return contributing


def _find_missed_signals(
    agent_output:    dict,
    fetched_data:    dict,
    user_correction: str,
) -> list[str]:
    agent_text       = (
        agent_output.get("root_cause", "") +
        " ".join(agent_output.get("evidence", []))
    ).lower()
    correction_lower = user_correction.lower()
    missed           = []

    for source_name, source_data in fetched_data.items():
        if not source_data:
            continue
        source_simple = source_name.replace("_", " ").lower()
        if (
            any(w in correction_lower for w in source_simple.split())
            and source_simple not in agent_text
        ):
            missed.append(source_name)

    return missed
