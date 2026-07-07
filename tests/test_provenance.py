"""Provenance/citation trail.

Every reported claim (evidence item / root_cause sentence) is deterministically
mapped to the all_fetched entries — keyed by _evidence_key, the existing
per-tool-call citation ids — whose stored value actually contains the claim's
facts. Claims with verifiable specifics that trace to ZERO sources land in
unsourced_claims and WEAKEN confidence by one step (a weight, never a hard cap:
a fully-sourced report keeps the level its analysis earned, HIGH included).

All fixtures use MADE-UP service/tool/resource names on purpose: the matching
is purely token-shape based (identifiers, numbers appearing verbatim in the
stored data), with zero service- or scenario-specific vocabulary.
"""
from __future__ import annotations

from cloudctl.ai.graph_agent import (
    _build_report_provenance,
    _evidence_key,
    _salient_tokens,
)
from cloudctl.ai.guardrails import detect_hallucinations, enforce_confidence


def _corpus():
    """A fetched-data corpus keyed exactly the way the graph agent keys it —
    via _evidence_key(tool_name, tool_input). Names are invented."""
    k_cfg = _evidence_key(
        "get_service_config", {"resource_name": "vexlar-node-12"}
    )
    k_met = _evidence_key(
        "query_metrics",
        {"namespace": "ZX/Quorbix", "metric_name": "FlumeDepth",
         "dimensions": {"FlumeId": "quorbix-flume-7"}},
    )
    k_logs = _evidence_key(
        "tail_logs", {"resource_hint": "vexlar-node-12"}
    )
    return {
        k_cfg: {"resource": "vexlar-node-12", "state": "degraded",
                "connection_limit": 250},
        k_met: {"datapoints": [{"value": 8231, "unit": "Count"}],
                "resource": "quorbix-flume-7"},
        k_logs: {"events": ["ERR-4913: flume saturation on quorbix-flume-7"]},
    }, k_cfg, k_met, k_logs


# ── (a) verbatim fact → cited with the correct evidence_key ───────────────────

def test_evidence_item_cited_with_correct_key():
    corpus, k_cfg, k_met, _ = _corpus()
    report = {
        "root_cause": "Saturation.",  # prose only — exercised elsewhere
        "evidence": [
            "quorbix-flume-7 FlumeDepth reached 8231",
            "vexlar-node-12 connection_limit is 250",
        ],
    }
    prov, unsourced = _build_report_provenance(report, corpus)
    assert unsourced == []
    by_claim = {p["claim"]: p for p in prov}

    metric_entry = by_claim["quorbix-flume-7 FlumeDepth reached 8231"]
    assert k_met in metric_entry["evidence_keys"]
    assert metric_entry["quote"]  # short verbatim snippet from the source value

    cfg_entry = by_claim["vexlar-node-12 connection_limit is 250"]
    assert k_cfg in cfg_entry["evidence_keys"]


# ── (b) fabricated claim → flagged AND weakens (never hard-caps) ──────────────

def test_fabricated_claim_flagged_and_weakens_confidence():
    corpus, *_ = _corpus()
    report = {
        # ≥10 words + traceable specifics so no unrelated downgrade path fires
        "root_cause": ("The resource vexlar-node-12 reached its configured "
                       "connection_limit of 250, saturating quorbix-flume-7."),
        "evidence": [
            "vexlar-node-12 connection_limit is 250",
            "quorbix-flume-7 FlumeDepth reached 8231",
            # Fabricated: prose words appear in the corpus, but the specific
            # identifier and value exist nowhere in any fetched entry.
            "resource state degraded on frobnak-queue-3 with value 9944",
        ],
        "confidence": "HIGH",
    }
    prov, unsourced = _build_report_provenance(report, corpus)
    assert any("frobnak-queue-3" in u for u in unsourced)
    # sourced claims are still cited — one bad claim doesn't poison the trail
    assert len(prov) >= 2

    report["provenance"] = prov
    report["unsourced_claims"] = unsourced
    hal = detect_hallucinations(report, corpus)
    out = enforce_confidence(report, corpus, hal)

    assert out["confidence"] == "MEDIUM"          # measurably weakened…
    assert out["confidence"] != "LOW"             # …one step, not slammed down
    assert "traced" in out["confidence_override_reason"]


def test_fully_sourced_report_is_not_capped():
    """Grounding is a floor-check, not a ceiling: with every specific claim
    sourced, HIGH survives untouched."""
    corpus, *_ = _corpus()
    report = {
        "root_cause": ("The resource vexlar-node-12 reached its configured "
                       "connection_limit of 250, saturating quorbix-flume-7."),
        "evidence": [
            "vexlar-node-12 connection_limit is 250",
            "quorbix-flume-7 FlumeDepth reached 8231",
            "log event ERR-4913 shows flume saturation on quorbix-flume-7",
        ],
        "confidence": "HIGH",
    }
    prov, unsourced = _build_report_provenance(report, corpus)
    assert unsourced == []
    report["provenance"] = prov
    report["unsourced_claims"] = unsourced
    hal = detect_hallucinations(report, corpus)
    out = enforce_confidence(report, corpus, hal)
    assert out["confidence"] == "HIGH"
    assert "confidence_override_reason" not in out


def test_weaken_is_one_step_from_medium_too():
    corpus, *_ = _corpus()
    report = {
        "root_cause": ("The resource vexlar-node-12 reached its configured "
                       "connection_limit of 250 causing the observed errors."),
        "evidence": [
            "vexlar-node-12 connection_limit is 250",
            "resource state degraded on frobnak-queue-3 with value 9944",
        ],
        "confidence": "MEDIUM",
    }
    prov, unsourced = _build_report_provenance(report, corpus)
    report["provenance"] = prov
    report["unsourced_claims"] = unsourced
    out = enforce_confidence(
        report, corpus, detect_hallucinations(report, corpus)
    )
    assert out["confidence"] == "LOW"   # one step down from MEDIUM


# ── (c) citation keys round-trip to real corpus entries ───────────────────────

def test_cited_keys_round_trip_to_corpus():
    corpus, *_ = _corpus()
    report = {
        "root_cause": ("vexlar-node-12 hit its connection_limit of 250 and "
                       "quorbix-flume-7 backed up to a FlumeDepth of 8231."),
        "evidence": [
            "vexlar-node-12 connection_limit is 250",
            "quorbix-flume-7 FlumeDepth reached 8231",
            "log event ERR-4913 recorded flume saturation",
        ],
    }
    prov, _ = _build_report_provenance(report, corpus)
    assert prov
    for entry in prov:
        for key in entry["evidence_keys"]:
            assert key in corpus, f"cited key {key!r} is not a real corpus entry"


# ── (d) matching is generic — a wholly invented service works unchanged ───────

def test_generic_matching_needs_no_service_literals():
    """A never-seen tool + service, invented for this test, grounds exactly the
    same way — proving the matcher carries no service/scenario vocabulary."""
    key = _evidence_key(
        "scan_gronkulator", {"gronk_id": "zzq-gronk-0042", "plane": "flarn"}
    )
    corpus = {key: {"gronk": "zzq-gronk-0042", "warp_factor": 77123,
                    "status": "misaligned"}}
    report = {
        "root_cause": "Misalignment.",
        "evidence": ["zzq-gronk-0042 reports warp_factor 77123"],
    }
    prov, unsourced = _build_report_provenance(report, corpus)
    assert unsourced == []
    assert len(prov) == 1
    assert prov[0]["evidence_keys"] == [key]
    assert "77123" in prov[0]["quote"] or "zzq-gronk-0042" in prov[0]["quote"]


# ── conservative edges ────────────────────────────────────────────────────────

def test_pure_prose_claim_is_neither_cited_nor_flagged():
    """A claim with no verifiable specific (no identifier, no value) has nothing
    fabricatable to check — it must not be punished for being prose."""
    corpus, *_ = _corpus()
    report = {
        "root_cause": "Something is saturated somewhere.",
        "evidence": ["the system appears heavily saturated under load"],
    }
    prov, unsourced = _build_report_provenance(report, corpus)
    assert prov == []
    assert unsourced == []


def test_empty_corpus_flags_nothing():
    """With nothing fetched, an unmatched claim is indistinguishable from a
    missing fetch — do not manufacture unsourced flags."""
    report = {
        "root_cause": "vexlar-node-12 failed.",
        "evidence": ["vexlar-node-12 connection_limit is 250"],
    }
    prov, unsourced = _build_report_provenance(report, {})
    assert prov == []
    assert unsourced == []


def test_salient_tokens_ignore_sentence_punctuation():
    """A prose word made 'structural' only by its sentence period is not a
    verifiable fact; real identifiers and numbers are."""
    toks = _salient_tokens("Connections were exhausted. Limit 12,000 hit on ab-cd-99.")
    assert "exhausted" not in toks
    assert not any(t.startswith("exhausted") for t in toks)
    assert "12000" in toks
    assert "ab-cd-99" in toks
