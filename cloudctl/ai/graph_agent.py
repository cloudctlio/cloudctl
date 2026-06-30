"""
graph_agent.py — LangGraph-based parallel hypothesis agent for incident investigation.

Graph topology:
  START → triage → investigate → synthesize → critique
  critique → [needs_reinvestigation AND round<1] → reinvestigate → synthesize → critique → END
  critique → [confirmed | revised | round≥1] → END

Four accuracy features:
  1. Critique → re-investigate feedback loop: when critique flags insufficient evidence
     it sets investigation_focus; reinvestigate_node runs a targeted branch and feeds
     the result back into a second synthesize → critique pass (capped at 1 retry).
  2. Mandatory alternative hypothesis testing: synthesize_node re-runs if the output
     doesn't enumerate ≥2 alternatives with explicit ruling-out reasoning.
  3. Evidence-conclusion grounding check: applied post-synthesis in debug_incident_graph;
     downgrades confidence when the conclusion names resources absent from evidence.
  4. Branch disagreement escalation: if ≥2 branches confirm contradicting root causes,
     synthesize_node spawns a 4th arbitration branch that re-investigates with all
     contradicting findings in context before the final synthesis.
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
    critique_round: int    # Feature 1: how many reinvestigation cycles have run
    critique_feedback: str # Feature 1: investigation_focus from critique node


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
    m = re.search(rf'\{{.*?"{re.escape(key)}".*?\}}', text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            pass
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
  3. When the config shows that this resource depends on other named resources
     (a role ARN, a model name, a function name, a secret, a target, a certificate),
     call get_service_config on the most suspicious dependency before concluding.
  4. Only set confirmed=true if you have found a STRUCTURAL absence: the resource
     does not exist, the feature is explicitly disabled, or the required binding
     is entirely missing. For any other anomaly — unusual values, unexpected config,
     mismatched settings — set confirmed=false and phase2_needed=true so operational
     evidence can confirm or rule out the hypothesis.
  5. If config looks correct and complete, conclude with confirmed=false and
     phase2_needed=true — do NOT investigate further here.

Maximum 3 tool calls. Conclude with ONLY this JSON:
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

# Feature 4: arbitration branch prompt
_ARBITRATION_SYSTEM = """\
You are a senior AWS incident investigator. Two or more parallel investigation branches
have each found confirmed evidence pointing to DIFFERENT root causes for the same incident.
Your task: re-investigate the disputed resources using tool calls to determine which is
the actual primary cause — or whether both are genuinely contributing.

Original symptom: {symptom}

Contradicting branch findings:
{findings}

Steps:
1. Call get_service_config on the resource from whichever branch seems less directly
   connected to the observed symptom.
2. Call tail_logs to check for the most recent error pattern.
3. Use search_cloudtrail to find what changed closest to symptom onset.
4. Determine: which cause most directly explains the symptom? Are both real? Is one
   causing the other?

Conclude with ONLY this JSON:
{{
  "primary_cause": "the single most direct cause of the symptom",
  "secondary_causes": ["any real but non-primary issues"],
  "resolution": "one paragraph: why this cause is primary over the alternative(s)",
  "evidence": ["specific fact that resolves the contradiction"],
  "confirmed": true,
  "confidence": "LOW | MEDIUM | HIGH"
}}
"""


def _detect_contradiction(branch_results: list[dict]) -> tuple[bool, list[dict]]:
    """Feature 4: identify when ≥2 branches independently confirmed different services."""
    confirmed = [br for br in branch_results if br.get("confirmed") and br.get("evidence")]
    if len(confirmed) < 2:
        return False, []
    services = {br["hypothesis"]["service"] for br in confirmed}
    return len(services) > 1, confirmed


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

    # Phase 1: config-state check (max 6 turns: up to 3 tool calls + conclude)
    p1 = _loop(
        _PHASE1_SYSTEM.format(reason=h.reason, service=h.service, focus=h.focus),
        init_msg, max_turns=6,
    )

    # Only exit early for structural absence AND only if all mandatory tools have
    # been called. If Phase 1 found a structural absence but never called tail_logs
    # or query_metrics, proceed to Phase 2 so the mandatory tools run first.
    from cloudctl.ai.guardrails import verify_tool_coverage
    p1_cov = verify_tool_coverage(symptom, set(tools_called))
    if (p1.get("confirmed") or not p1.get("phase2_needed", True)) and p1_cov.satisfied:
        return BranchResult(
            hypothesis=h,
            evidence=p1.get("evidence", []),
            conclusion=p1.get("conclusion", ""),
            confidence=p1.get("confidence", "LOW"),
            confirmed=bool(p1.get("confirmed", False)),
            tools_called=tools_called,
            all_fetched=branch_fetched,
        )

    # Phase 2: operational investigation (max 10 turns)
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

    # Enforce mandatory tool coverage — if required tools weren't called, force a
    # short pass before concluding.
    cov = verify_tool_coverage(symptom, set(tools_called))
    if not cov.satisfied:
        p3 = _loop(
            _PHASE2_SYSTEM.format(
                reason=h.reason, service=h.service,
                phase1_conclusion=p2.get("conclusion") or p1.get("conclusion", "see prior phases"),
            ),
            [{"role": "user", "content": [{"text": (
                f"Symptom: {symptom}\n\n"
                f"MANDATORY COVERAGE: Before finalizing you must call "
                f"{', '.join(cov.missing_tools)}. You have not called "
                f"{'them' if len(cov.missing_tools) > 1 else 'it'} yet. "
                f"Call {'them' if len(cov.missing_tools) > 1 else 'it'} now, "
                f"then output your final JSON conclusion."
            )}]}],
            max_turns=4,
        )
        if p3.get("evidence"):
            p2 = {
                **p2,
                "evidence": (p2.get("evidence") or []) + p3.get("evidence", []),
                "conclusion": p3.get("conclusion") or p2.get("conclusion"),
                "confidence": p3.get("confidence") or p2.get("confidence"),
                "confirmed": p3.get("confirmed") or p2.get("confirmed"),
            }

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

REQUIRED: You MUST populate alternatives_considered with every hypothesis that was
investigated but ruled out. Each entry MUST have both a "hypothesis" and "reason" field
explaining why it was not the primary cause. At least 2 alternatives are required for
MEDIUM or HIGH confidence.

Respond ONLY with this JSON object (no markdown, no extra text):
{{
  "root_cause": "specific — what is wrong and why it causes the observed symptom",
  "evidence": ["concrete fact from investigation 1", "concrete fact from investigation 2", ...],
  "remediation_steps": ["step 1", "step 2", ...],
  "severity": "LOW | MEDIUM | HIGH | CRITICAL",
  "confidence": "LOW | MEDIUM | HIGH",
  "resources_investigated": ["resource-name-1", "resource-name-2", ...],
  "alternatives_considered": [
    {{"hypothesis": "...", "reason": "why this was ruled out", "verdict": "ruled_out | partial"}}
  ]
}}
"""


def synthesize_node(state: GraphState) -> dict:
    meaningful = [br for br in state["branch_results"] if br.get("evidence")]
    if not meaningful:
        return {"final_report": {
            "root_cause": "Investigation failed: all branches returned empty evidence. "
                          "Check agent logs for tool errors and retry.",
            "evidence": [],
            "remediation_steps": ["Retry the investigation", "Check CloudWatch agent logs for errors"],
            "severity": "UNKNOWN",
            "confidence": "LOW",
            "resources_investigated": [],
        }}

    bedrock = _make_bedrock(state["profile"], state["region"])
    all_branch_results = list(state["branch_results"])
    all_fetched_merged = dict(state.get("all_fetched") or {})
    arbitration_note = ""

    # Feature 4: Branch disagreement escalation
    # If ≥2 branches independently confirmed contradicting root causes, spawn a
    # targeted 4th arbitration branch that re-investigates with all findings in
    # context before the final synthesis.
    has_contradiction, contradicting = _detect_contradiction(state["branch_results"])
    if has_contradiction:
        findings = json.dumps([
            {
                "service": br["hypothesis"]["service"],
                "conclusion": br["conclusion"],
                "evidence": br["evidence"],
            }
            for br in contradicting
        ], indent=2)
        arb_hypothesis = {
            "service": contradicting[0]["hypothesis"]["service"],
            "reason": (
                f"Contradiction: multiple branches confirmed different causes. "
                f"Re-investigate to determine primary: "
                + " vs ".join(br["hypothesis"]["service"] for br in contradicting[:2])
            ),
            "focus": f"Resolve which of these findings directly causes the symptom: {findings[:300]}",
        }
        try:
            arb_result = _run_branch(
                arb_hypothesis,
                state["symptom"],
                state["profile"],
                state["region"],
                state["minutes"],
                state["session_id"],
            )
            all_branch_results.append(arb_result.model_dump())
            all_fetched_merged.update(arb_result.all_fetched)
            arbitration_note = (
                f"\n\nARBITRATION: A 4th branch re-investigated the contradiction. "
                f"It found: {arb_result.conclusion[:300]}"
            )
        except Exception:
            pass

    system = _SYNTHESIZE_PROMPT.format(n=len(all_branch_results))
    branches_text = json.dumps(all_branch_results, indent=2)
    user_content = (
        f"Symptom: {state['symptom']}\n\n"
        f"Branch investigation results:\n{branches_text}"
        f"{arbitration_note}"
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

    # Feature 2: Mandatory alternative hypothesis testing
    # Re-run synthesize if alternatives_considered doesn't enumerate ≥2 ruled-out
    # hypotheses with explicit reasoning. Catches the case where the agent concludes
    # without explaining what it ruled out and why.
    from cloudctl.ai.guardrails import verify_alternatives_considered
    alt_check = verify_alternatives_considered(result)
    if not alt_check.satisfied:
        retry_msg = (
            f"Your response is missing alternatives_considered with at least 2 entries. "
            f"Re-submit the SAME conclusion JSON but ensure 'alternatives_considered' "
            f"lists every hypothesis branch that was investigated and not chosen as the "
            f"primary cause, with a 'hypothesis' string and 'reason' string for each. "
            f"Do not change the root_cause or evidence — only fill in alternatives_considered."
        )
        resp2 = bedrock.converse(
            modelId=_MODEL,
            system=[{"text": system}],
            messages=[
                {"role": "user", "content": [{"text": user_content}]},
                {"role": "assistant", "content": [{"text": text}]},
                {"role": "user", "content": [{"text": retry_msg}]},
            ],
        )
        text2 = resp2["output"]["message"]["content"][0]["text"].strip()
        result2 = _extract_json(text2, "root_cause")
        if result2 and isinstance(result2, dict):
            result = result2

    # Calibrate confidence using branch confirmations as a signal amplifier.
    confirmed_count = sum(1 for br in all_branch_results if br.get("confirmed"))
    agent_conf = result.get("confidence", "LOW")
    if confirmed_count >= 2:
        result["confidence"] = agent_conf
    else:
        result["confidence"] = "MEDIUM" if agent_conf == "HIGH" else agent_conf

    # Propagate arbitration fetched data back into state
    if all_fetched_merged != state.get("all_fetched"):
        try:
            return {"final_report": IncidentReport(**result).model_dump(),
                    "all_fetched": all_fetched_merged,
                    "branch_results": all_branch_results}
        except Exception:
            return {"final_report": result, "all_fetched": all_fetched_merged,
                    "branch_results": all_branch_results}

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

If a stronger conclusion exists in the branch data: respond with this JSON exactly:
{"verdict": "revised", "root_cause": "...", "evidence": ["...", "..."],
 "confidence": "LOW | MEDIUM | HIGH", "notes": "one sentence why this is stronger"}

If the evidence is genuinely insufficient to reach any conclusion — every evidence item
says "not found", "no data", "no logs returned", or is pure inference with no direct
AWS fact — and you can identify a specific investigation that would resolve the ambiguity:
{"verdict": "needs_reinvestigation",
 "investigation_focus": "call [specific tool] on [specific resource] to find [what] — be precise",
 "notes": "one sentence: why current evidence cannot support any conclusion"}

Use needs_reinvestigation sparingly — only when evidence is empty or entirely negative.
Not for disagreement with the conclusion ranking.

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
            "evidence": br["evidence"],
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
        return {"final_report": report, "critique_feedback": ""}

    if critique.get("verdict") == "revised":
        revised = dict(report)
        revised["root_cause"] = critique.get("root_cause", report["root_cause"])
        revised["evidence"] = critique.get("evidence", report["evidence"])
        revised["confidence"] = critique.get("confidence", report["confidence"])
        revised["_critique_notes"] = critique.get("notes", "")
        return {"final_report": revised, "critique_feedback": ""}

    # Feature 1: needs_reinvestigation — set critique_feedback to trigger
    # reinvestigate_node via conditional routing (only if round 0).
    if critique.get("verdict") == "needs_reinvestigation":
        focus = critique.get("investigation_focus", "")
        if focus and state.get("critique_round", 0) < 1:
            return {
                "final_report": report,
                "critique_feedback": focus,
            }

    return {"final_report": report, "critique_feedback": ""}


# ── Node 5: reinvestigate (Feature 1 — critique feedback loop) ────────────────

def reinvestigate_node(state: GraphState) -> dict:
    """
    Feature 1: Targeted re-investigation when critique flags insufficient evidence.
    Runs a single branch with the critique's investigation_focus as the hypothesis,
    appends the result to branch_results, then routes back to synthesize → critique
    for one final pass (critique_round incremented to prevent infinite looping).
    """
    focus = state.get("critique_feedback", "")
    if not focus:
        return {
            "critique_round": state.get("critique_round", 0) + 1,
            "critique_feedback": "",
        }

    try:
        result = _run_branch(
            hypothesis={
                "service": "aws",
                "reason": focus,
                "focus": focus,
            },
            symptom=state["symptom"],
            profile=state["profile"],
            region=state["region"],
            minutes=state["minutes"],
            session_id=state["session_id"],
        )
        new_branches = list(state["branch_results"]) + [result.model_dump()]
        new_fetched = {**state.get("all_fetched", {}), **result.all_fetched}
    except Exception:
        new_branches = list(state["branch_results"])
        new_fetched = dict(state.get("all_fetched", {}))

    return {
        "branch_results": new_branches,
        "all_fetched": new_fetched,
        "critique_round": state.get("critique_round", 0) + 1,
        "critique_feedback": "",
    }


# ── Graph construction ─────────────────────────────────────────────────────────

def _after_critique(state: GraphState) -> str:
    """Route after critique: reinvestigate once if critique flagged insufficient evidence."""
    if state.get("critique_round", 0) >= 1:
        return END
    if state.get("critique_feedback", ""):
        return "reinvestigate"
    return END


def _build_graph():
    workflow = StateGraph(GraphState)
    workflow.add_node("triage", triage_node)
    workflow.add_node("investigate", investigate_node)
    workflow.add_node("synthesize", synthesize_node)
    workflow.add_node("critique", critique_node)
    workflow.add_node("reinvestigate", reinvestigate_node)
    workflow.add_edge(START, "triage")
    workflow.add_edge("triage", "investigate")
    workflow.add_edge("investigate", "synthesize")
    workflow.add_edge("synthesize", "critique")
    workflow.add_conditional_edges(
        "critique", _after_critique,
        {"reinvestigate": "reinvestigate", END: END},
    )
    workflow.add_edge("reinvestigate", "synthesize")
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
    max_turns: int = 24,  # kept for interface compatibility
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
        check_evidence_grounding,
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
        "critique_round": 0,
        "critique_feedback": "",
    })

    parsed = final_state["final_report"]
    all_fetched = final_state.get("all_fetched", {})

    hal_report = detect_hallucinations(parsed, all_fetched)
    parsed = enforce_confidence(parsed, all_fetched, hal_report)

    # Feature 3: Evidence-conclusion grounding check
    # Downgrades confidence when the conclusion names specific resources or
    # identifiers that don't appear in any evidence item — catches conclusions
    # that are plausible but not supported by what the agent actually found.
    grounding = check_evidence_grounding(
        parsed.get("root_cause", ""),
        parsed.get("evidence", []),
        all_fetched,
    )
    if not grounding.grounded and parsed.get("confidence") in ("HIGH", "MEDIUM"):
        parsed["confidence"] = "LOW"
        parsed["confidence_override_reason"] = (
            f"Confidence downgraded: conclusion references identifiers not found "
            f"in evidence — {grounding.reason}"
        )

    parsed = redact_output(parsed)

    reinvestigated = final_state.get("critique_round", 0) > 0
    parsed["_guardrails"] = {
        "agent_version": "graph_v2",
        "hypotheses_explored": len(final_state.get("hypotheses", [])),
        "branches_completed": len(final_state.get("branch_results", [])),
        "branches_confirmed": sum(1 for br in final_state.get("branch_results", []) if br.get("confirmed")),
        "critique_applied": "_critique_notes" in parsed,
        "reinvestigated": reinvestigated,
        "hallucination_rate": hal_report.hallucination_rate,
        "grounding_issues": grounding.ungrounded_claims if not grounding.grounded else [],
        "account_id": account_id,
    }

    audit_log_agent_call(
        session_id=session_id, event="end",
        account_id=account_id, region=region,
        query_hash=query_hash, turns_used=0,
        confidence=parsed.get("confidence", ""),
    )

    return json.dumps(parsed, indent=2), all_fetched
