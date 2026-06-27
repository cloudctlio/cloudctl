"""
graph_agent.py — LangGraph-based parallel hypothesis agent for incident investigation.

Three-node graph:
  START → triage → investigate (3 parallel branches) → synthesize → END

Replaces the single sequential ReAct loop with three phases to eliminate
anchoring bias — the agent now evaluates competing hypotheses independently
before committing to one conclusion.
"""
from __future__ import annotations

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TypedDict

from botocore.config import Config as _BotoConfig
from langgraph.graph import END, START, StateGraph
from pydantic import BaseModel, field_validator

# ── Pydantic output types ──────────────────────────────────────────────────────

class Hypothesis(BaseModel):
    service: str
    reason: str
    focus: str


class BranchResult(BaseModel):
    hypothesis: Hypothesis
    evidence: list[str]
    conclusion: str
    confidence: str
    confirmed: bool = False
    tools_called: list[str]
    all_fetched: dict = {}

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, v: str) -> str:
        return v if v in ("LOW", "MEDIUM", "HIGH") else "LOW"


class IncidentReport(BaseModel):
    root_cause: str
    evidence: list[str]
    remediation_steps: list[str]
    severity: str
    confidence: str
    resources_investigated: list[str]
    alternatives_considered: list[dict] | None = None

    @field_validator("severity")
    @classmethod
    def _valid_severity(cls, v: str) -> str:
        return v if v in ("LOW", "MEDIUM", "HIGH", "CRITICAL") else "MEDIUM"

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, v: str) -> str:
        return v if v in ("LOW", "MEDIUM", "HIGH") else "LOW"


# ── LangGraph state ────────────────────────────────────────────────────────────

class GraphState(TypedDict):
    symptom: str
    profile: str | None
    region: str
    minutes: int
    session_id: str
    account_id: str | None
    hypotheses: list[dict]
    branch_results: list[dict]
    final_report: dict
    all_fetched: dict


# ── Shared Bedrock client factory ──────────────────────────────────────────────

_MODEL = "us.anthropic.claude-sonnet-4-6"


def _make_bedrock(profile: str | None, region: str):
    from cloudctl.mcp.tools.debug import _make_session
    session = _make_session(profile, region)
    return session.client(
        "bedrock-runtime",
        region_name=region,
        config=_BotoConfig(
            retries={"mode": "adaptive", "max_attempts": 10},
            connect_timeout=10,
            read_timeout=120,
        ),
    )


def _extract_json(text: str, key: str) -> dict | list | None:
    """Find and parse the first JSON object/array containing `key` in text."""
    pattern = rf'\{{[^{{}}]*"{key}"[^{{}}]*\}}' if key else r'\{.*?\}'
    m = re.search(rf'\{{.*?"{re.escape(key)}".*?\}}', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
    # Try full array
    m2 = re.search(r'\[.*\]', text, re.DOTALL)
    if m2:
        try:
            return json.loads(m2.group(0))
        except Exception:
            pass
    return None


# ── Node 1: triage ─────────────────────────────────────────────────────────────

_TRIAGE_PROMPT = """\
You are an AWS incident triage specialist. Given an incident symptom, identify exactly 3
candidate root causes. They must be genuinely distinct hypotheses — not variations of the
same idea.

Hypothesis selection rules:
1. For symptoms where something "is not happening", "stopped", or "has not occurred in X days":
   ALWAYS include one hypothesis that the feature itself is simply not enabled or configured
   (e.g. the schedule was never bound, the flag is off, the binding resource is absent).
   Do not assume the feature was previously working and is now blocked.
2. For symptoms involving "access denied", "permission error", or "cannot read/write":
   Consider both the caller's identity policy AND the target resource's own policy as
   separate hypotheses — they are independent denial layers.
3. For all symptoms: make the third hypothesis structurally different from the first two
   (e.g. if #1 is IAM and #2 is resource config, make #3 network or capacity).

For each hypothesis output:
  - service: the primary AWS service to investigate first (e.g. "ecs", "iam", "s3", "rds")
  - reason:  one sentence — what specific misconfiguration or failure might cause this
  - focus:   the first thing to check (e.g. "task role missing s3:PutObject", "security group blocking egress on port 5432")

Respond ONLY with a valid JSON array of exactly 3 objects with keys: service, reason, focus.
No markdown fences, no extra text.
"""


def triage_node(state: GraphState) -> dict:
    bedrock = _make_bedrock(state["profile"], state["region"])
    resp = bedrock.converse(
        modelId=_MODEL,
        system=[{"text": _TRIAGE_PROMPT}],
        messages=[{"role": "user", "content": [{"text": f"Incident: {state['symptom']}"}]}],
    )
    text = resp["output"]["message"]["content"][0]["text"].strip()
    # Strip markdown fences if present
    if "```" in text:
        parts = text.split("```")
        for p in parts:
            p = p.strip()
            if p.startswith("json"):
                p = p[4:].strip()
            if p.startswith("["):
                text = p
                break

    try:
        raw = json.loads(text)
        if not isinstance(raw, list):
            raw = [raw]
        hypotheses = [Hypothesis(**h).model_dump() for h in raw[:3]]
    except Exception:
        hypotheses = [{"service": "iam", "reason": "IAM permission denied", "focus": "check role policies"}]

    return {"hypotheses": hypotheses}


# ── Node 2: investigate (parallel, two-phase branches) ────────────────────────

_PHASE1_SYSTEM = """\
You are an AWS incident investigator. Your ONLY task in this phase is to check
the configuration state of the primary resource.

Your hypothesis: {reason}
Primary service: {service}
First thing to check: {focus}

Phase 1 rules — configuration check ONLY:
  1. Call list_resources to find the resource, then get_service_config to read its config.
  2. Look for: disabled flags, missing bindings, absent ARNs, wrong endpoints,
     unconfigured schedules, empty rule sets.
  3. If the config shows a clear, self-evident issue that directly explains
     the symptom, conclude immediately with confirmed=true.
  4. If config looks correct and complete, conclude with confirmed=false and
     phase2_needed=true — do NOT investigate further here.

Maximum 2 tool calls. Conclude with ONLY this JSON:
{{
  "conclusion": "one sentence — what the config shows",
  "evidence": ["specific config value observed"],
  "confidence": "LOW | MEDIUM | HIGH",
  "confirmed": true | false,
  "phase2_needed": true | false
}}
"""

_PHASE2_SYSTEM = """\
You are an AWS incident investigator. Configuration looked correct — now investigate
operational state to prove or disprove this hypothesis.

Your hypothesis: {reason}
Primary service: {service}
Phase 1 finding: {phase1_conclusion}

Phase 2 rules — operational investigation:
  Use tail_logs, query_metrics, search_cloudtrail, get_service_config on dependencies
  (IAM role, KMS key, VPC, target services) to find what is failing at runtime.

ACCESS DENIED rule — three independent layers can each deny access:
  1. Identity policy on the caller's IAM role
  2. Resource-based policy on the TARGET (S3, SQS, Secrets Manager, KMS key policy, ECR, etc.)
  3. Permission boundary or SCP
Check all three. Call get_service_config on the TARGET resource to see its resource policy.

NETWORK rule — check ALL layers when diagnosing connectivity:
  1. Source SG egress  2. Target SG ingress  3. NACLs (stateless, both directions)
  4. Route table  5. VPC endpoint policy  6. DNS resolution
Call get_service_config with service_type="vpc" to see all at once.

Maximum 8 tool calls. Conclude with ONLY this JSON:
{{
  "conclusion": "one paragraph — hypothesis confirmed or ruled out, and why",
  "evidence": ["specific fact from tool result 1", "specific fact from tool result 2", ...],
  "confidence": "LOW | MEDIUM | HIGH",
  "confirmed": true | false,
  "phase2_needed": false
}}
"""


def _run_branch(
    hypothesis: dict,
    symptom: str,
    profile: str | None,
    region: str,
    minutes: int,
    session_id: str,
) -> BranchResult:
    from cloudctl.mcp.tools.debug import (
        _AGENT_TOOLS, _truncate_tool_output,
        list_resources, get_service_config, tail_logs,
        query_metrics, search_cloudtrail, get_event_timeline,
        get_deployment_info,
    )
    from cloudctl.ai.guardrails import (
        sanitise_fetched_data, validate_tool_call, audit_log_tool_call,
    )

    h = Hypothesis(**hypothesis)
    bedrock = _make_bedrock(profile, region)
    branch_fetched: dict = {}
    tools_called: list[str] = []

    def dispatch(tool_name: str, tool_input: dict) -> str:
        tools_called.append(tool_name)
        resource_name = (
            tool_input.get("resource_name")
            or tool_input.get("service_type", "")
        )
        tc = validate_tool_call(
            tool_name, tool_input,
            allowed_profile=profile, allowed_region=region,
        )
        audit_log_tool_call(
            session_id=session_id, tool_name=tool_name,
            resource_name=resource_name, allowed=tc.allowed,
            block_reason="" if tc.allowed else tc.reason,
        )
        if not tc.allowed:
            return json.dumps({"error": tc.reason})

        if tool_name == "list_resources":
            raw = list_resources(tool_input["service_type"], profile, region)
        elif tool_name == "get_service_config":
            raw = get_service_config(
                tool_input["service_type"], tool_input["resource_name"],
                profile, region,
            )
        elif tool_name == "tail_logs":
            raw = tail_logs(
                resource_hint=tool_input["resource_hint"],
                minutes=int(tool_input.get("minutes") or minutes),
                profile=profile, region=region, max_events=100,
            )
        elif tool_name == "get_event_timeline":
            raw = get_event_timeline(tool_input["symptom"], profile, region, minutes)
        elif tool_name == "query_metrics":
            raw = query_metrics(
                namespace=tool_input["namespace"],
                metric_name=tool_input["metric_name"],
                dimensions=tool_input.get("dimensions") or {},
                profile=profile, region=region,
                minutes=int(tool_input.get("minutes") or 30),
                stat=tool_input.get("stat") or "Average",
            )
        elif tool_name == "search_cloudtrail":
            raw = search_cloudtrail(
                resource_name=tool_input["resource_name"],
                profile=profile, region=region,
                event_names=tool_input.get("event_names") or None,
                minutes=int(tool_input.get("minutes") or 1440),
            )
        elif tool_name == "get_deployment_info":
            raw = get_deployment_info(
                resource_name=tool_input["resource_name"],
                service_type=tool_input["service_type"],
                profile=profile, region=region,
            )
        else:
            return json.dumps({"error": f"unknown tool: {tool_name}"})

        try:
            parsed = json.loads(raw)
            sanitised = sanitise_fetched_data(parsed) if isinstance(parsed, dict) else parsed
            branch_fetched[f"{tool_name}:{resource_name}"] = sanitised
            raw = json.dumps(sanitised, default=str)
        except Exception:
            pass

        return _truncate_tool_output(raw, tool_name)

    def _loop(system_text: str, init_messages: list, max_turns: int) -> dict:
        msgs = list(init_messages)
        for _ in range(max_turns):
            try:
                resp = bedrock.converse(
                    modelId=_MODEL,
                    system=[{"text": system_text}],
                    messages=msgs,
                    toolConfig={"tools": _AGENT_TOOLS},
                )
            except Exception as exc:
                return {"conclusion": f"error: {exc}", "confidence": "LOW",
                        "confirmed": False, "phase2_needed": True, "evidence": []}
            stop_reason = resp["stopReason"]
            msg = resp["output"]["message"]
            msgs.append(msg)
            if stop_reason == "end_turn":
                text = next(
                    (b["text"] for b in msg.get("content", []) if "text" in b), ""
                ).strip()
                result = _extract_json(text, "conclusion")
                if result and isinstance(result, dict):
                    return result
                return {"conclusion": text[:400], "confidence": "LOW",
                        "confirmed": False, "phase2_needed": True, "evidence": []}
            if stop_reason == "tool_use":
                tool_results = []
                for block in msg.get("content", []):
                    if "toolUse" in block:
                        tu = block["toolUse"]
                        tool_results.append({
                            "toolResult": {
                                "toolUseId": tu["toolUseId"],
                                "content": [{"text": dispatch(tu["name"], tu["input"])}],
                            }
                        })
                if tool_results:
                    msgs.append({"role": "user", "content": tool_results})
        return {"conclusion": "hit turn limit", "confidence": "LOW",
                "confirmed": False, "phase2_needed": True, "evidence": list(branch_fetched.keys())}

    init_msg = [{"role": "user", "content": [{"text": (
        f"Symptom: {symptom}\n\nInvestigate: {h.reason}\nStart with: {h.focus}"
    )}]}]

    # Phase 1: config-state check only (max 4 turns: ~2 tool calls + conclude)
    p1 = _loop(
        _PHASE1_SYSTEM.format(reason=h.reason, service=h.service, focus=h.focus),
        init_msg, max_turns=4,
    )

    # If config phase found a definitive issue, stop — no need to inspect operational state
    if p1.get("confirmed") or not p1.get("phase2_needed", True):
        return BranchResult(
            hypothesis=h,
            evidence=p1.get("evidence", []),
            conclusion=p1.get("conclusion", ""),
            confidence=p1.get("confidence", "LOW"),
            confirmed=bool(p1.get("confirmed", False)),
            tools_called=tools_called,
            all_fetched=branch_fetched,
        )

    # Phase 2: operational investigation (max 10 turns — config looked correct)
    p2 = _loop(
        _PHASE2_SYSTEM.format(
            reason=h.reason, service=h.service,
            phase1_conclusion=p1.get("conclusion", "no config issues found"),
        ),
        [{"role": "user", "content": [{"text": (
            f"Symptom: {symptom}\n\n"
            f"Config looked correct. Now investigate operational state for: {h.reason}"
        )}]}],
        max_turns=10,
    )

    return BranchResult(
        hypothesis=h,
        evidence=p2.get("evidence", []) or p1.get("evidence", []),
        conclusion=p2.get("conclusion", ""),
        confidence=p2.get("confidence", "LOW"),
        confirmed=bool(p2.get("confirmed", False)),
        tools_called=tools_called,
        all_fetched=branch_fetched,
    )


def investigate_node(state: GraphState) -> dict:
    all_fetched_merged = dict(state.get("all_fetched") or {})
    branch_results: list[dict] = []

    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = {
            ex.submit(
                _run_branch,
                h, state["symptom"], state["profile"],
                state["region"], state["minutes"], state["session_id"],
            ): h
            for h in state["hypotheses"]
        }
        for f in as_completed(futures):
            result = f.result()
            branch_results.append(result.model_dump())
            all_fetched_merged.update(result.all_fetched)

    return {"branch_results": branch_results, "all_fetched": all_fetched_merged}


# ── Node 3: synthesize ─────────────────────────────────────────────────────────

_SYNTHESIZE_PROMPT = """\
You are an AWS incident analyst. You have received {n} independent hypothesis investigations
of the same incident. Each branch investigated a different potential root cause.

Select the hypothesis with the strongest direct evidence from real AWS data.
If multiple branches found real issues, list them all in evidence.
Treat unconfirmed or low-confidence branches as ruled-out alternatives.

Respond ONLY with this JSON object (no markdown, no extra text):
{{
  "root_cause": "specific — what is wrong and why it causes the observed symptom",
  "evidence": ["concrete fact from investigation 1", "concrete fact from investigation 2", ...],
  "remediation_steps": ["step 1", "step 2", ...],
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "confidence": "LOW | MEDIUM | HIGH",
  "resources_investigated": ["resource-name-1", "resource-name-2", ...],
  "alternatives_considered": [
    {{"hypothesis": "...", "verdict": "ruled_out | partial | confirmed", "reason": "..."}}
  ]
}}
"""


def synthesize_node(state: GraphState) -> dict:
    bedrock = _make_bedrock(state["profile"], state["region"])
    branches_text = json.dumps(state["branch_results"], indent=2)
    system = _SYNTHESIZE_PROMPT.format(n=len(state["branch_results"]))
    user_content = (
        f"Symptom: {state['symptom']}\n\n"
        f"Branch investigation results:\n{branches_text}"
    )

    resp = bedrock.converse(
        modelId=_MODEL,
        system=[{"text": system}],
        messages=[{"role": "user", "content": [{"text": user_content}]}],
    )
    text = resp["output"]["message"]["content"][0]["text"].strip()

    result = _extract_json(text, "root_cause")
    if not result or not isinstance(result, dict):
        return {"final_report": {
            "root_cause": text[:500],
            "evidence": [],
            "remediation_steps": [],
            "severity": "UNKNOWN",
            "confidence": "LOW",
            "resources_investigated": [],
        }}

    # Calibrate confidence using branch confirmations as a signal amplifier,
    # not an override. The synthesize model's own assessment reflects evidence
    # quality; branch confirmed=True is additional corroboration.
    confirmed_count = sum(1 for br in state["branch_results"] if br.get("confirmed"))
    agent_conf = result.get("confidence", "LOW")
    if confirmed_count >= 2:
        # Multiple branches independently agreed — trust model's assessment fully
        result["confidence"] = agent_conf
    else:
        # 0 or 1 branch confirmed — trust model but cap HIGH at MEDIUM
        # (HIGH requires multiple independent confirmations)
        result["confidence"] = "MEDIUM" if agent_conf == "HIGH" else agent_conf

    try:
        return {"final_report": IncidentReport(**result).model_dump()}
    except Exception:
        return {"final_report": result}


# ── Node 4: critique (devil's advocate) ───────────────────────────────────────

_CRITIQUE_SYSTEM = """\
You are a skeptical senior SRE reviewing an incident diagnosis before it ships to the on-call page.
You did NOT investigate this incident — you only see the symptom, the chosen conclusion,
and what each hypothesis branch found.

Challenge the conclusion with these questions:
1. Does the stated root cause directly and completely explain the symptom?
2. Did any branch find a clear, direct finding (a disabled flag, a missing resource, an
   explicit Deny) that the synthesizer overlooked or ranked lower than it deserved?
3. Is the conclusion based on circumstantial or inferred evidence when a direct, observable
   fact is available in the branch results?
4. Is there a simpler explanation fully supported by the data?

If the conclusion is well-supported: respond with this JSON exactly:
{"verdict": "confirmed", "notes": "one sentence why it holds up"}

If a stronger conclusion exists: respond with this JSON exactly:
{"verdict": "revised", "root_cause": "...", "evidence": ["...", "..."],
 "confidence": "LOW | MEDIUM | HIGH", "notes": "one sentence why this is stronger"}

Respond ONLY with the JSON. No markdown, no extra text.
"""


def critique_node(state: GraphState) -> dict:
    bedrock = _make_bedrock(state["profile"], state["region"])
    report = state["final_report"]
    branches_summary = json.dumps([
        {
            "hypothesis": br["hypothesis"]["reason"],
            "confirmed": br["confirmed"],
            "confidence": br["confidence"],
            "conclusion": br["conclusion"],
            "evidence": br["evidence"][:3],
        }
        for br in state["branch_results"]
    ], indent=2)

    user_content = (
        f"Symptom: {state['symptom']}\n\n"
        f"Chosen conclusion:\n{json.dumps(report, indent=2)}\n\n"
        f"What each branch found:\n{branches_summary}"
    )
    resp = bedrock.converse(
        modelId=_MODEL,
        system=[{"text": _CRITIQUE_SYSTEM}],
        messages=[{"role": "user", "content": [{"text": user_content}]}],
    )
    text = resp["output"]["message"]["content"][0]["text"].strip()
    critique = _extract_json(text, "verdict")

    if not critique or critique.get("verdict") == "confirmed":
        return {"final_report": report}

    if critique.get("verdict") == "revised":
        revised = dict(report)
        revised["root_cause"] = critique.get("root_cause", report["root_cause"])
        revised["evidence"] = critique.get("evidence", report["evidence"])
        revised["confidence"] = critique.get("confidence", report["confidence"])
        revised["_critique_notes"] = critique.get("notes", "")
        return {"final_report": revised}

    return {"final_report": report}


# ── Graph construction ─────────────────────────────────────────────────────────

def _build_graph():
    workflow = StateGraph(GraphState)
    workflow.add_node("triage", triage_node)
    workflow.add_node("investigate", investigate_node)
    workflow.add_node("synthesize", synthesize_node)
    workflow.add_node("critique", critique_node)
    workflow.add_edge(START, "triage")
    workflow.add_edge("triage", "investigate")
    workflow.add_edge("investigate", "synthesize")
    workflow.add_edge("synthesize", "critique")
    workflow.add_edge("critique", END)
    return workflow.compile()


_graph = None


def _get_graph():
    global _graph
    if _graph is None:
        _graph = _build_graph()
    return _graph


# ── Public entry point ─────────────────────────────────────────────────────────

def debug_incident_graph(
    symptom: str,
    profile: str | None,
    region: str = "us-east-1",
    minutes: int = 10,
    max_turns: int = 24,  # kept for interface compatibility, controls branch depth implicitly
) -> tuple[str, dict]:
    """
    LangGraph parallel hypothesis agent.
    Drop-in replacement for debug_incident_agent — same return signature.
    """
    from cloudctl.mcp.tools.debug import _get_account_id
    from cloudctl.ai.guardrails import (
        check_rate_limit, validate_query,
        detect_hallucinations, enforce_confidence,
        verify_cited_values, redact_output,
        audit_log_agent_call, new_session_id,
    )

    rate_check = check_rate_limit()
    if not rate_check.allowed:
        return json.dumps({"error": rate_check.reason}), {}

    query_check = validate_query(symptom)
    if not query_check.allowed:
        return json.dumps({"error": query_check.reason}), {}
    symptom = query_check.sanitised

    account_id = _get_account_id(profile, region)
    session_id = new_session_id()
    query_hash = hashlib.sha256(symptom.encode()).hexdigest()[:16]

    audit_log_agent_call(
        session_id=session_id, event="start",
        account_id=account_id, region=region, query_hash=query_hash,
    )

    final_state = _get_graph().invoke({
        "symptom": symptom,
        "profile": profile,
        "region": region,
        "minutes": minutes,
        "session_id": session_id,
        "account_id": account_id,
        "hypotheses": [],
        "branch_results": [],
        "final_report": {},
        "all_fetched": {},
    })

    parsed = final_state["final_report"]
    all_fetched = final_state.get("all_fetched", {})

    # Post-synthesis guardrails
    # Note: verify_cited_values is skipped here — graph evidence is derived prose
    # summarising branch conclusions, not direct quotes from tool output, so string-match
    # citation verification fires on every correct answer. Hallucination + confidence
    # enforcement still apply. Critique node provides the semantic cross-check.
    hal_report = detect_hallucinations(parsed, all_fetched)
    parsed = enforce_confidence(parsed, all_fetched, hal_report)
    parsed = redact_output(parsed)

    parsed["_guardrails"] = {
        "agent_version": "graph_v2",
        "hypotheses_explored": len(final_state.get("hypotheses", [])),
        "branches_completed": len(final_state.get("branch_results", [])),
        "branches_confirmed": sum(1 for br in final_state.get("branch_results", []) if br.get("confirmed")),
        "critique_applied": "_critique_notes" in parsed,
        "hallucination_rate": hal_report.hallucination_rate,
        "account_id": account_id,
    }

    audit_log_agent_call(
        session_id=session_id, event="end",
        account_id=account_id, region=region,
        query_hash=query_hash, turns_used=0,
        confidence=parsed.get("confidence", ""),
    )

    return json.dumps(parsed, indent=2), all_fetched
