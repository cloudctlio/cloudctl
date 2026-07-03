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
    # VERDICT: falsifiable predictions — what MUST be observable if this
    # hypothesis is true. Each: {"if_true": str, "check": str, "if_absent": "refutes"|"weakens"}
    predictions: list[dict] = []


class BranchResult(BaseModel):
    hypothesis: Hypothesis
    evidence: list[str]
    conclusion: str
    confidence: str
    confirmed: bool = False
    tools_called: list[str]
    all_fetched: dict = {}
    # VERDICT: per-prediction test outcomes from the investigation
    predictions_tested: list[dict] = []

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
    log_insights: dict     # PRISM: Haiku log analysis (runs parallel with investigate)
    discrimination: dict   # PRISM: causal category verdict before synthesis
    observation: dict      # VERDICT: measured symptom (onset, observable-now, scope)


# ── Shared Bedrock client factory ──────────────────────────────────────────────

_MODEL = "us.anthropic.claude-sonnet-4-6"

# Prompt caching. A cachePoint marks a prefix boundary Bedrock may reuse across
# calls; it does NOT change the tokens the model sees, so at temperature 0 the
# generated output is byte-identical with or without it. We cache only content
# that repeats verbatim across many calls: the tool schema (sent on every
# tool-use turn, identical everywhere) and static system prompts.
_CACHE_POINT = {"cachePoint": {"type": "default"}}


def _sys(text: str) -> list[dict]:
    """System block with a trailing cache point (for STATIC prompts only)."""
    return [{"text": text}, _CACHE_POINT]


def _cached_tools(tools: list[dict]) -> dict:
    """toolConfig whose (large, invariant) tool schema is cached."""
    return {"tools": list(tools) + [_CACHE_POINT]}


def _conv(msgs: list[dict]) -> list[dict]:
    """Return a shallow copy of the conversation with a rolling cache point at
    the end of the latest message. Within a multi-turn tool loop the transcript
    grows and is otherwise re-sent in full every turn; marking the tail lets
    turn K reuse turn K-1's cached prefix and pay only for new tokens. The
    marker is applied to a copy (never persisted into the stored history), so
    exactly one conversation breakpoint exists per call. Behavior-neutral: the
    model conditions on the identical token sequence."""
    if not msgs:
        return msgs
    out = list(msgs)
    last = dict(out[-1])
    content = list(last.get("content", []))
    if content and content[-1] != _CACHE_POINT:
        last["content"] = content + [_CACHE_POINT]
        out[-1] = last
    return out


def _make_bedrock(profile: str | None, region: str):
    from cloudctl.mcp.tools.debug import _make_session
    from cloudctl.mcp.tools.recorder import RecordingBedrock
    session = _make_session(profile, region)
    client = session.client(
        "bedrock-runtime",
        region_name=region,
        config=_BotoConfig(
            retries={"mode": "adaptive", "max_attempts": 10},
            connect_timeout=10,
            read_timeout=120,
        ),
    )
    # Dual-plane recording/replay: records model requests+responses alongside
    # tool I/O; serves them back in exact/pinned replay modes. Live behavior
    # is unchanged when the recorder env vars are unset.
    return RecordingBedrock(client)


def _extract_json(text: str, key: str) -> dict | list | None:
    """Find and parse the first JSON object/array containing `key` in text.

    Uses JSONDecoder.raw_decode so nested objects parse correctly — a regex
    with a non-greedy close brace truncates any JSON containing nested dicts
    (e.g. alternatives_considered), silently degrading the whole report.
    """
    # Strip markdown fences if present
    if "```" in text:
        for part in text.split("```"):
            part = part.strip().lstrip("json").strip()
            if part.startswith(("{", "[")):
                text = part
                break

    dec = json.JSONDecoder()
    # Try each '{' as a potential JSON start; raw_decode handles nesting.
    for m in re.finditer(r"\{", text):
        try:
            obj, _ = dec.raw_decode(text[m.start():])
        except Exception:
            continue
        if isinstance(obj, dict) and key in obj:
            return obj
    # Fall back to the first parseable array
    for m in re.finditer(r"\[", text):
        try:
            obj, _ = dec.raw_decode(text[m.start():])
        except Exception:
            continue
        if isinstance(obj, list):
            return obj
    return None


# ── VERDICT Node 0: observe (quantify the symptom before hypothesizing) ────────
#
# Every wrong diagnosis so far shares one root error: the agent reasoned from the
# symptom TEXT, never from a measurement of the symptom itself. This node runs
# first and establishes three facts the rest of the graph must respect:
#   1. Is the symptom observable right now, in real data?
#   2. When did it start (onset)? Root-cause events must precede onset.
#   3. What exactly is affected (scope)?
# If the symptom cannot be observed, the honest answer is "cannot reproduce" —
# not a narrative built from unrelated anomalies.

_OBSERVE_SYSTEM = """\
You are an incident measurement specialist. Do NOT hypothesize about causes.
Your ONLY job is to measure the reported symptom in real data before any
investigation begins.

Determine three things:
  1. OBSERVABLE — can you see the reported symptom in actual metrics or logs
     right now / within the investigation window? Quote the exact data.
  2. ONSET — the earliest timestamp at which the symptom appears in data.
  3. SCOPE — precisely what is affected (which endpoint, operation, metric
     dimension) and what is demonstrably NOT affected.

Rules:
  - Use list_resources first if you need to find resource names.
  - Use query_metrics and tail_logs to measure. 3-5 tool calls maximum.
  - Report only what the data shows. If you cannot find the symptom in any
    data, say symptom_observable_now=false — that is a valid, important result.
  - ONSET is the MOST RECENT step-change consistent with the reported symptom.
    Older anomalies in the window belong to previous states of the system
    (earlier incidents, deployments, tests) — do not report them as onset.
  - Never speculate about causes.

Conclude with ONLY this JSON:
{
  "symptom_observable_now": true | false,
  "onset_estimate": "ISO timestamp or 'unknown'",
  "affected_scope": "what is affected, from data",
  "unaffected_scope": "what is measurably fine",
  "measurements": ["exact metric/log fact with timestamp", ...]
}
"""


def observe_node(state: GraphState) -> dict:
    from cloudctl.mcp.tools.debug import (
        _AGENT_TOOLS, _truncate_tool_output,
        list_resources, tail_logs, query_metrics, get_event_timeline,
    )
    from cloudctl.ai.guardrails import validate_tool_call, audit_log_tool_call

    bedrock = _make_bedrock(state["profile"], state["region"])
    allowed = {"list_resources", "tail_logs", "query_metrics", "get_event_timeline"}

    def _dispatch(tool_name: str, tool_input: dict) -> str:
        tc = validate_tool_call(
            tool_name, tool_input,
            allowed_profile=state["profile"], allowed_region=state["region"],
        )
        audit_log_tool_call(
            session_id=state["session_id"], tool_name=tool_name,
            resource_name=str(tool_input.get("resource_hint")
                              or tool_input.get("service_type")
                              or tool_input.get("metric_name") or ""),
            allowed=tc.allowed,
            block_reason="" if tc.allowed else tc.reason,
        )
        if not tc.allowed:
            return json.dumps({"error": tc.reason})
        try:
            if tool_name == "list_resources":
                raw = list_resources(tool_input["service_type"],
                                     state["profile"], state["region"])
            elif tool_name == "tail_logs":
                raw = tail_logs(
                    resource_hint=tool_input["resource_hint"],
                    minutes=int(tool_input.get("minutes") or state["minutes"]),
                    profile=state["profile"], region=state["region"], max_events=50,
                )
            elif tool_name == "query_metrics":
                raw = query_metrics(
                    namespace=tool_input["namespace"],
                    metric_name=tool_input["metric_name"],
                    dimensions=tool_input.get("dimensions") or {},
                    profile=state["profile"], region=state["region"],
                    minutes=int(tool_input.get("minutes") or 30),
                    stat=tool_input.get("stat") or "Average",
                    baseline_offset_hours=int(tool_input.get("baseline_offset_hours") or 0),
                )
            elif tool_name == "get_event_timeline":
                raw = get_event_timeline(tool_input["symptom"],
                                         state["profile"], state["region"],
                                         state["minutes"])
            else:
                return json.dumps({"error": f"tool not allowed here: {tool_name}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})
        return _truncate_tool_output(raw, tool_name)

    tools = [t for t in _AGENT_TOOLS if t["toolSpec"]["name"] in allowed]
    msgs = [{"role": "user", "content": [{"text": (
        f"Reported symptom: {state['symptom']}\n\n"
        f"Measure this symptom in real data now."
    )}]}]
    observation: dict = {}
    for _ in range(8):
        try:
            resp = bedrock.converse(
                modelId=_MODEL,
                system=_sys(_OBSERVE_SYSTEM),
                messages=_conv(msgs),
                toolConfig=_cached_tools(tools),
                inferenceConfig={"maxTokens": 700, "temperature": 0},
            )
        except Exception as exc:
            # Never fail silently — an empty observation that hides its cause
            # is how the PRISM no-op went unnoticed for three runs.
            observation = {"_error": f"{type(exc).__name__}: {exc}"[:300]}
            break
        msg = resp["output"]["message"]
        msgs.append(msg)
        if resp["stopReason"] == "max_tokens":
            msgs.append({"role": "user", "content": [{"text": (
                "Your response was cut off. Respond again with ONLY the JSON, "
                "shorter measurement strings."
            )}]})
            continue
        if resp["stopReason"] == "end_turn":
            text = next((b["text"] for b in msg.get("content", []) if "text" in b), "")
            observation = _extract_json(text, "symptom_observable_now") or {}
            if not isinstance(observation, dict):
                observation = {"_error": f"unparseable observe output: {text[:200]}"}
            break
        if resp["stopReason"] == "tool_use":
            tool_results = []
            for block in msg.get("content", []):
                if "toolUse" in block:
                    tu = block["toolUse"]
                    tool_results.append({
                        "toolResult": {
                            "toolUseId": tu["toolUseId"],
                            "content": [{"text": _dispatch(tu["name"], tu["input"])}],
                        }
                    })
            if tool_results:
                msgs.append({"role": "user", "content": tool_results})

    return {"observation": observation}


# ── Node 1: triage (agentic resource discovery) ───────────────────────────────

_TRIAGE_SYSTEM = """\
You are an AWS incident triage specialist. Your job is to:
  1. Use list_resources to discover what is actually deployed in this account/region.
     Call it for whatever service categories the symptom suggests might be involved.
     You decide which services to enumerate — follow the symptom, not a checklist.
     get_dependency_graph returns the real wiring between deployed resources
     (env references, triggers, roles, event sources) — call it once when the
     symptom involves an operation whose dependencies you'd otherwise guess.
  2. Once you know what exists, identify exactly 3 candidate root causes. Each hypothesis
     MUST name a specific resource from what you discovered. Hypotheses should
     cover the operation's actual dependency chain, not just the obvious layer.

list_resources rules:
  - Call it for services the symptom directly implicates (a slow operation → what
    does that operation depend on? a growing backlog → what consumes it?).
  - Do NOT call it for services the symptom gives no reason to suspect.
  - 2-4 list_resources calls is enough. Stop when you have the resources you need.

Hypothesis rules:
  1. Each hypothesis must name a specific resource by name (table, queue, cluster,
     function, key) and describe the failure mode on that resource.
  2. Deployment side-effects (instance or container replacement, connection
     draining, image pulls) are almost NEVER the root cause — they are symptoms
     of routine change. Do not use them as a primary hypothesis.
  3. Cover structurally distinct layers: the data layer, the compute layer,
     and the permissions/configuration layer.
  4. For silent failures (service running but producing wrong output): the
     hypothesis must explain the silence itself — a cause that would have left
     errors or crash traces contradicts the observed absence of them.
  5. If the symptom quotes an explicit error or exception name, work out which
     component raises that error, and make one hypothesis target that
     component's own configuration — not just the callers around it. A request
     rejected at its source runs no downstream code, so it can leave no logs
     and no metrics anywhere; reading configuration is the only way to observe
     that class of fault.

Falsifiability rule (mandatory):
  Every hypothesis must include 1-2 PREDICTIONS: concrete observations that MUST
  exist in real data if the hypothesis is true. A prediction names what to look
  for and where. If a prediction would also be true under the other hypotheses,
  it is useless — pick predictions that DISCRIMINATE between your hypotheses.
  A hypothesis whose predictions cannot be checked with the available tools is
  a bad hypothesis — replace it.

After your tool calls, respond with ONLY a JSON array of exactly 3 objects:
[
  {"service": "aws-service-name", "reason": "one sentence",
   "focus": "resource-name — first thing to check",
   "predictions": [
     {"if_true": "what MUST be observable in real data",
      "check": "which tool on which resource would show it",
      "if_absent": "refutes"}
   ]},
  ...
]
No markdown fences, no extra text outside the JSON array.
"""


def triage_node(state: GraphState) -> dict:
    from cloudctl.mcp.tools.debug import _AGENT_TOOLS, list_resources
    from cloudctl.ai.guardrails import validate_tool_call, audit_log_tool_call

    bedrock = _make_bedrock(state["profile"], state["region"])
    discovered: dict = {}

    def _dispatch_list(tool_name: str, tool_input: dict) -> str:
        svc = tool_input.get("service_type", "")
        tc = validate_tool_call(
            tool_name, tool_input,
            allowed_profile=state["profile"], allowed_region=state["region"],
        )
        audit_log_tool_call(
            session_id=state["session_id"], tool_name=tool_name,
            resource_name=svc, allowed=tc.allowed,
            block_reason="" if tc.allowed else tc.reason,
        )
        if not tc.allowed:
            return json.dumps({"error": tc.reason})
        try:
            if tool_name == "get_dependency_graph":
                from cloudctl.mcp.tools.debug import get_dependency_graph
                raw = get_dependency_graph(state["profile"], state["region"])
                discovered["_dependency_graph"] = json.loads(raw)
                return raw
            raw = list_resources(svc, state["profile"], state["region"])
            parsed = json.loads(raw)
            discovered[svc] = parsed
            return raw
        except Exception as exc:
            return json.dumps({"error": str(exc)})

    # Agentic loop: LLM calls list_resources for whatever services it judges relevant.
    # Capped at 6 turns (up to 4 tool calls + final answer).
    obs = state.get("observation") or {}
    obs_text = (
        f"\n\nMEASURED OBSERVATION (from real data, trust over the symptom text):\n"
        f"{json.dumps(obs, indent=2)}"
        if obs else ""
    )
    msgs = [{"role": "user", "content": [{"text": f"Symptom: {state['symptom']}{obs_text}"}]}]
    hypotheses = []
    for _ in range(6):
        resp = bedrock.converse(
            modelId=_MODEL,
            system=_sys(_TRIAGE_SYSTEM),
            messages=_conv(msgs),
            toolConfig=_cached_tools([t for t in _AGENT_TOOLS
                                  if t["toolSpec"]["name"] in ("list_resources", "get_dependency_graph")]),
            inferenceConfig={"maxTokens": 1000, "temperature": 0},
        )
        stop_reason = resp["stopReason"]
        msg = resp["output"]["message"]
        msgs.append(msg)

        if stop_reason == "max_tokens":
            # Conversation must end with a user message — nudge for a shorter reply.
            msgs.append({"role": "user", "content": [{"text": (
                "Your response was cut off at the token limit. Respond again with "
                "ONLY the JSON array, more concisely — shorter reason/prediction strings."
            )}]})
            continue

        if stop_reason == "end_turn":
            text = next(
                (b["text"] for b in msg.get("content", []) if "text" in b), ""
            ).strip()
            if "```" in text:
                for p in text.split("```"):
                    p = p.strip().lstrip("json").strip()
                    if p.startswith("["):
                        text = p
                        break
            try:
                raw = json.loads(text)
                if not isinstance(raw, list):
                    raw = [raw]
                hypotheses = [Hypothesis(**h).model_dump() for h in raw[:3]]
            except Exception:
                pass
            break

        if stop_reason == "tool_use":
            tool_results = []
            for block in msg.get("content", []):
                if "toolUse" in block:
                    tu = block["toolUse"]
                    tool_results.append({
                        "toolResult": {
                            "toolUseId": tu["toolUseId"],
                            "content": [{"text": _dispatch_list(tu["name"], tu["input"])}],
                        }
                    })
            if tool_results:
                msgs.append({"role": "user", "content": tool_results})

    if not hypotheses:
        hypotheses = [{"service": "iam", "reason": "permission denied", "focus": "check role policies"}]

    return {
        "hypotheses": hypotheses,
        "all_fetched": {**state.get("all_fetched", {}), "_discovery": discovered},
    }


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

FALSIFIABLE PREDICTIONS — if this hypothesis is true, these MUST be observable:
{predictions}

You MUST test every prediction above with tool calls before concluding. A
prediction is CONFIRMED only by directly observed data you can quote, REFUTED
if you looked in the right place and the predicted observation is absent, and
UNTESTED only if no available tool could check it. You may not set
confirmed=true unless at least one prediction is CONFIRMED and none is REFUTED.

Phase 2 rules — operational investigation:
  Use tail_logs, query_metrics, search_cloudtrail, and get_service_config on the
  resource's dependencies — its permissions layer, encryption layer, network
  path, and downstream services — to find what is failing at runtime.
  For permission predictions, probe_permission tests an action deterministically
  via the policy simulator — a REFUTED/CONFIRMED permission needs no log evidence.
  When the dedicated tools don't go deep enough for the service under
  investigation, use aws_read to call the service's own read-only APIs directly —
  you know which operations reveal its configuration, status, limits, and
  policies. Go as deep as the hypothesis requires; do not stop at generic
  config when a service-specific API would confirm or refute a prediction.

ACCESS DENIED rule — three independent layers can each deny access:
  1. Identity policy on the caller's IAM role
  2. Resource-based policy attached to the TARGET resource itself
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
  "predictions_tested": [
    {{"prediction": "the if_true text", "verdict": "CONFIRMED | REFUTED | UNTESTED",
      "observed": "exact data you saw, or what was absent where you looked"}}
  ],
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
        get_deployment_info, probe_permission, get_dependency_graph, aws_read,
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
                profile=profile, region=region, max_events=50,
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
                baseline_offset_hours=int(tool_input.get("baseline_offset_hours") or 0),
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
        elif tool_name == "probe_permission":
            raw = probe_permission(
                role=tool_input["role"],
                action=tool_input["action"],
                resource_arn=tool_input.get("resource_arn", ""),
                profile=profile, region=region,
            )
        elif tool_name == "get_dependency_graph":
            raw = get_dependency_graph(profile=profile, region=region)
        elif tool_name == "aws_read":
            raw = aws_read(
                service=tool_input["service"],
                operation=tool_input["operation"],
                params=tool_input.get("params") or {},
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
                    system=_sys(system_text),
                    messages=_conv(msgs),
                    toolConfig=_cached_tools(_AGENT_TOOLS),
                )
            except Exception as exc:
                return {"conclusion": f"error: {exc}", "confidence": "LOW",
                        "confirmed": False, "phase2_needed": True, "evidence": []}
            stop_reason = resp["stopReason"]
            msg = resp["output"]["message"]
            msgs.append(msg)
            if stop_reason == "max_tokens":
                msgs.append({"role": "user", "content": [{"text": (
                    "Your response was cut off at the token limit. Respond again "
                    "with ONLY the conclusion JSON, more concisely."
                )}]})
                continue
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

    predictions_text = "\n".join(
        f"  {i+1}. IF TRUE: {p.get('if_true', '?')}\n"
        f"     CHECK: {p.get('check', '?')}  (absence {p.get('if_absent', 'weakens')})"
        for i, p in enumerate(h.predictions)
    ) or "  (none stated — derive one falsifiable prediction yourself and test it)"

    # Phase 2: operational investigation (max 7 turns — was 10)
    p2 = _loop(
        _PHASE2_SYSTEM.format(
            reason=h.reason, service=h.service,
            phase1_conclusion=p1.get("conclusion", "no config issues found"),
            predictions=predictions_text,
        ),
        [{"role": "user", "content": [{"text": (
            f"Symptom: {symptom}\n\n"
            f"Config looked correct. Now investigate operational state for: {h.reason}"
        )}]}],
        max_turns=7,
    )

    # Enforce mandatory tool coverage — if required tools weren't called, force a
    # short pass before concluding.
    cov = verify_tool_coverage(symptom, set(tools_called))
    if not cov.satisfied:
        p3 = _loop(
            _PHASE2_SYSTEM.format(
                reason=h.reason, service=h.service,
                phase1_conclusion=p2.get("conclusion") or p1.get("conclusion", "see prior phases"),
                predictions=predictions_text,
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
                "predictions_tested": p3.get("predictions_tested") or p2.get("predictions_tested") or [],
            }

    # VERDICT enforcement — confirmed requires ≥1 CONFIRMED prediction and no
    # REFUTED ones. Enforced in code, not prompt: a branch that never tested its
    # predictions cannot claim confirmation, and a refuted prediction is a veto.
    preds = [p for p in (p2.get("predictions_tested") or []) if isinstance(p, dict)]

    # Anti-fabrication check: a CONFIRMED verdict must quote data that actually
    # exists in this branch's fetched corpus. A model can hallucinate the test
    # result just as confidently as a diagnosis — so the quote is verified
    # deterministically, and an untraceable "observation" downgrades to UNTESTED
    # (which the veto below then treats as no confirmation).
    corpus = json.dumps(branch_fetched, default=str).lower()
    for p in preds:
        if p.get("verdict") != "CONFIRMED":
            continue
        tokens = re.findall(r"[a-z0-9][a-z0-9_.\-:/]{4,}", str(p.get("observed", "")).lower())
        matched = sum(1 for t in tokens if t in corpus)
        if not tokens or matched * 2 < len(tokens):
            p["verdict"] = "UNTESTED"
            p["_downgraded"] = (
                "observed text not traceable to fetched data "
                f"({matched}/{len(tokens)} tokens found)"
            )
    n_confirmed = sum(1 for p in preds if p.get("verdict") == "CONFIRMED")
    n_refuted   = sum(1 for p in preds if p.get("verdict") == "REFUTED")
    confirmed   = bool(p2.get("confirmed", False))
    if confirmed and (n_confirmed == 0 or n_refuted > 0):
        confirmed = False

    return BranchResult(
        hypothesis=h,
        evidence=p2.get("evidence", []) or p1.get("evidence", []),
        conclusion=p2.get("conclusion", ""),
        confidence=p2.get("confidence", "LOW"),
        confirmed=confirmed,
        tools_called=tools_called,
        all_fetched=branch_fetched,
        predictions_tested=preds,
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


# ── PRISM Node A: log_intelligence (runs parallel with investigate) ────────────
#
# Uses a lightweight model (Haiku) to analyze raw log content without any
# hardcoded heuristics. The LLM reasons freely over whatever fields exist —
# no field names, no thresholds, no incident-specific logic.
#
# Key insight it's asked to produce: behavioral_consistency.
#   uniform  = same anomaly on ALL service instances → application code
#   partial  = anomaly on SOME instances only       → infrastructure
# This one signal is often enough to discriminate the cause category.

_LOG_INTEL_SYSTEM = """\
You are a log analysis specialist for distributed services. You receive raw
application log lines from a production system during an incident.

Your ONLY job is to identify patterns in the logs that reveal the root cause
CATEGORY — not the specific fix. Specifically determine:

(a) BEHAVIORAL CONSISTENCY
    - "uniform": Every service instance (host/task/pod) shows the SAME anomaly.
      This is the signature of application-code behavior — code runs identically
      on all replicas so all replicas misbehave identically.
    - "partial": Only SOME instances show the anomaly. This is the signature of
      infrastructure failure — a network, capacity, permission, or encryption
      resource that affects only part of the fleet.
    - "single_request": One request/session generates far more log lines than
      others. This is the signature of a log flood, tight loop, or retry storm
      inside application code.

(b) CAUSE CATEGORY
    - "application_code": Bug or intentional behavior in the application
    - "infrastructure": AWS resource failure, throttle, or unavailability
    - "configuration": Wrong setting, flag, or permission policy
    - "dependency": Downstream service returning errors

Return ONLY this JSON (no markdown):
{
  "behavioral_consistency": "uniform | partial | single_request | unclear",
  "log_volume_anomaly": true | false,
  "cause_category": "application_code | infrastructure | configuration | dependency | unclear",
  "cause_confidence": "LOW | MEDIUM | HIGH",
  "key_observations": [
    "specific pattern observed, phrased as a fact not a conclusion"
  ],
  "reasoning": "2-3 sentences explaining what in the logs led to this classification"
}
"""


def log_intelligence_node(state: GraphState) -> dict:
    """Analyze raw logs with an AI to classify root cause category.

    Runs in parallel with investigate_node after triage. Produces cause_category
    signals (uniform vs partial behavior) that constrain the discriminate node.
    """
    from cloudctl.mcp.tools.debug import _make_session
    from cloudctl.debug.fetcher import DebugFetcher

    # Independent survey: read every log group with recent activity, not just
    # the resources triage hypothesized about. Triage can anchor on
    # infrastructure and never look at the service whose logs hold the real
    # signal — this node exists to catch exactly that, so it must not inherit
    # triage's blind spots. Log groups are the universal substrate: anything
    # that logs, logs here, regardless of what compute runs it.
    from cloudctl.mcp.tools.recorder import recorded

    def _survey() -> dict:
        from cloudctl.mcp.tools.debug import _mine_log_templates
        events_out: list[str] = []
        raw_events: list[dict] = []
        grps: list[str] = []
        err = ""
        try:
            session = _make_session(state["profile"], state["region"])
            fetcher = DebugFetcher(session)
            grps = fetcher.recently_active_log_groups(minutes=state["minutes"], limit=8)
            for grp in grps:
                events = fetcher.cloudwatch_logs(log_group=grp, minutes=state["minutes"])
                if not events:
                    events = fetcher.tail_log_group(grp, lines=30)
                short = grp.rsplit("/", 1)[-1]
                for evt in events:
                    evt["_group"] = short
                raw_events.extend(events)
                for evt in events[:20]:
                    msg = evt.get("event", "").strip()
                    if msg:
                        ts = evt.get("time", "")
                        events_out.append(f"[{ts}] [{short}] {msg[:300]}")
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"[:300]
        # Frequency view over everything fetched — the per-group line sample
        # can miss a flood entirely; template counts cannot.
        templates = [
            f"count={t['count']} :: {t['template'][:160]}"
            for t in _mine_log_templates(raw_events)
        ]
        return {"events": events_out, "groups": grps, "templates": templates, "error": err}

    survey = recorded("log_survey", {"minutes": state["minutes"]}, _survey)
    if not isinstance(survey, dict):
        survey = {"events": [], "groups": [], "error": "unreplayable survey record"}
    all_events = survey.get("events", [])
    groups = survey.get("groups", [])
    survey_error = survey.get("error", "")

    if not all_events:
        # Explain the empty result — an unexplained {} hid the survey bug for runs.
        return {"log_insights": {
            "_error": survey_error or (
                f"no log events in window; {len(groups)} recently-active "
                f"log groups found: {groups[:8]}"
            ),
        }}

    log_text = "\n".join(all_events[:80])
    template_text = "\n".join(survey.get("templates", [])[:12])
    bedrock = _make_bedrock(state["profile"], state["region"])

    try:
        resp = bedrock.converse(
            modelId="us.anthropic.claude-haiku-4-5-20251001",
            system=_sys(_LOG_INTEL_SYSTEM),
            messages=[{"role": "user", "content": [{"text": (
                f"INCIDENT SYMPTOM: {state['symptom']}\n\n"
                f"LINE-SHAPE FREQUENCIES (count per structural template, all "
                f"fetched lines):\n{template_text or '(none)'}\n\n"
                f"LOG LINES ({len(all_events)} total):\n{log_text}"
            )}]}],
            inferenceConfig={"maxTokens": 800, "temperature": 0},
        )
        text = resp["output"]["message"]["content"][0]["text"].strip()
        insights = _extract_json(text, "behavioral_consistency") or {}
        if not isinstance(insights, dict):
            insights = {"_error": f"unparseable log-intel output: {text[:200]}"}
    except Exception as exc:
        insights = {"_error": f"{type(exc).__name__}: {exc}"[:300]}

    return {"log_insights": insights}


# ── PRISM Node B: discriminate (causal discrimination before synthesis) ─────────
#
# Merges evidence from all investigation branches + log intelligence and
# determines the root cause CATEGORY with explicit reasoning. Produces a
# binding constraint ("investigation_constraint") that synthesize_node must
# follow. This prevents the most common reasoning error: attributing uniform
# application-code behavior to an AWS infrastructure cause.

_DISCRIMINATE_SYSTEM = """\
You are a causal reasoning specialist for AWS incident diagnosis. You receive:
  1. Three parallel investigation branches, each examining a different hypothesis
  2. Log analysis from the affected services (behavioral_consistency, cause_category)

Your task: determine the ROOT CAUSE CATEGORY and produce a constraint for the
synthesis step that prevents incorrect conclusions.

CORE REASONING RULES — apply these in order:

Rule -1 — Prediction test (a veto, apply first):
  Each branch reports predictions_tested. A hypothesis with any REFUTED
  prediction is ELIMINATED — no amount of circumstantial evidence revives it.
  A hypothesis with zero CONFIRMED predictions cannot be the primary cause;
  it is at best "untested". Prefer the hypothesis with the most CONFIRMED
  discriminating predictions.
  A CONFIRMED prediction only counts if it is CAUSALLY RELEVANT:
    - A permanent property of the system — one that was equally true while
      the system was working — cannot be the cause of a new incident. If the
      cited defect predates onset and the operation demonstrably worked after
      the defect existed, the confirmation is void.
    - A missing capability matters only if the failing operation actually
      exercises it. Verify the failing path uses what is missing before
      treating its absence as the cause.

Rule 0 — Temporal filtering (apply before all other rules):
  A MEASURED OBSERVATION may be provided with an onset_estimate for when the
  symptom actually began in data. Events before onset caused by deployment
  activity cannot be the root cause. If symptom_observable_now is false, say
  so: the correct output is that the symptom could not be reproduced in data —
  do NOT construct a cause from unrelated anomalies.
  The symptom may also include a [HH:MM UTC] timestamp indicating when the incident
  was FIRST OBSERVED. Branch evidence may include get_deployment_info results
  with a last_changed_at field indicating the most recent deployment.
  If error events in the evidence have timestamps BEFORE or AT the same time as
  last_changed_at, those errors were caused by the deployment itself (instance
  or container replacement, image pulls, routing re-registration) — not by the
  incident.
  Only evidence with timestamps AFTER the deployment settled (last_changed_at
  + ~5 minutes) is valid incident evidence. Discard earlier events as
  deployment artifacts before applying rules 1-3.

Rule 1 — Behavioral consistency test (highest weight):
  If behavioral_consistency = "uniform": every service replica shows the SAME
  anomaly. Identical replicas with identical infra cannot behave differently
  due to infra — they share the same network rules, the same permissions, the
  same runtime definition.
  Therefore: uniform anomaly → cause is APPLICATION CODE, not infrastructure.

  If behavioral_consistency = "partial": only some replicas are affected.
  Infrastructure failures (capacity, network, permissions, encryption) can affect a subset.
  Therefore: partial anomaly → cause may be INFRASTRUCTURE.

  If behavioral_consistency = "single_request": one request generates vastly
  more log lines than others. Infrastructure failures do not cause this.
  Therefore: single_request → APPLICATION CODE (loop, log flood, retry burst).

Rule 2 — Evidence quality test:
  Prefer evidence from direct observation (log line content, metric value)
  over inferences. "The data shows X" is observation; "X COULD mean Y" is
  inference — an inference never outweighs a direct observation.

Rule 3 — Parsimony:
  The simplest explanation consistent with ALL observations is preferred.

Return ONLY this JSON:
{
  "evidence_classifications": [
    {
      "evidence": "quote from branch result or log analysis",
      "category": "application_code | infrastructure | configuration | dependency",
      "rule_applied": "1 | 2 | 3",
      "reasoning": "one sentence"
    }
  ],
  "cause_category": "application_code | infrastructure | configuration | dependency",
  "cause_category_confidence": "LOW | MEDIUM | HIGH",
  "investigation_constraint": "One binding sentence for synthesis, e.g.: The anomaly is uniform across all replicas with identical infrastructure — the root cause is application code behavior, not an AWS service failure."
}
"""


def discriminate_node(state: GraphState) -> dict:
    """Classify root cause category from branch evidence + log insights.

    This node prevents the most common agent error: attributing a uniform
    application-code behavior to an infrastructure cause.
    """
    branch_summary = "\n\n".join(
        f"Branch {i+1} ({br.get('hypothesis', {}).get('service', '?')}):\n"
        f"  Evidence: {chr(10).join(f'  - {e}' for e in br.get('evidence', []))}\n"
        f"  Predictions tested: {json.dumps(br.get('predictions_tested', []))}\n"
        f"  Conclusion: {br.get('conclusion', 'none')}\n"
        f"  Confirmed: {br.get('confirmed', False)}"
        for i, br in enumerate(state.get("branch_results", []))
    )

    log_insights = state.get("log_insights") or {}
    log_summary = json.dumps(log_insights, indent=2) if log_insights else "(no log analysis available)"

    bedrock = _make_bedrock(state["profile"], state["region"])

    try:
        # Sonnet: discriminate needs full reasoning power — wrong category = wrong diagnosis
        resp = bedrock.converse(
            modelId=_MODEL,
            system=_sys(_DISCRIMINATE_SYSTEM),
            messages=[{"role": "user", "content": [{"text": (
                f"SYMPTOM: {state['symptom']}\n\n"
                f"MEASURED OBSERVATION:\n"
                f"{json.dumps(state.get('observation') or {}, indent=2) or '(none)'}\n\n"
                f"LOG INTELLIGENCE:\n{log_summary}\n\n"
                f"INVESTIGATION BRANCHES:\n{branch_summary}"
            )}]}],
            inferenceConfig={"maxTokens": 800, "temperature": 0},
        )
        text = resp["output"]["message"]["content"][0]["text"].strip()
        discrimination = _extract_json(text, "cause_category") or {}
        if not isinstance(discrimination, dict):
            discrimination = {"_error": f"unparseable discriminate output: {text[:200]}"}
    except Exception as exc:
        discrimination = {"_error": f"{type(exc).__name__}: {exc}"[:300]}

    return {"discrimination": discrimination}


# ── VERDICT Node: clarify (human-in-the-loop, only when evidence dead-ends) ────

def clarify_node(state: GraphState) -> dict:
    """Ask the operator one targeted question when no hypothesis survived
    prediction testing — an SRE often knows context the data doesn't show
    (recent changes, affected scope, exact timing). Interactive mode only
    (CLOUDCTL_INTERACTIVE=1); otherwise a no-op. Uses LangGraph interrupt,
    so the investigation checkpoint survives while waiting for the answer.
    """
    import os
    if not os.environ.get("CLOUDCTL_INTERACTIVE"):
        return {}
    brs = state.get("branch_results", [])
    if any(br.get("confirmed") for br in brs):
        return {}
    try:
        from langgraph.types import interrupt
        ruled_out = [
            br.get("hypothesis", {}).get("focus", "?") for br in brs
        ]
        answer = interrupt({
            "question": (
                "No hypothesis survived prediction testing. Investigated and "
                f"ruled out: {ruled_out}. Is there context the data doesn't "
                "show (recent changes, exact onset time, affected scope)?"
            ),
        })
        if answer and isinstance(answer, str) and answer.strip():
            return {"symptom": state["symptom"]
                    + f"\n\nOPERATOR CLARIFICATION: {answer.strip()}"}
    except Exception:  # noqa: BLE001
        pass
    return {}


# ── Node 3: synthesize ─────────────────────────────────────────────────────────

_SYNTHESIZE_PROMPT = """\
You are an AWS incident analyst. You have received {n} independent hypothesis investigations
of the same incident. Each branch investigated a different potential root cause.

{discrimination_constraint}

VERDICT rules (binding):
  1. A hypothesis with a REFUTED prediction cannot be the root cause.
  2. The root cause must have at least one CONFIRMED prediction backed by
     directly observed data. If no hypothesis meets this bar, say exactly that:
     root_cause = what was ruled out and what observation is still needed,
     confidence = LOW. An honest "not proven" beats a constructed narrative.
  3. If the measured observation says symptom_observable_now=false, state that
     the reported symptom could not be reproduced in current data and anchor
     the report on that fact.
  4. Root-cause events must precede the measured onset. Events from our own
     deployment activity before onset are not causes.

Select the hypothesis with the strongest direct evidence from real AWS data.
If multiple branches found real issues, list them all in evidence.
Treat unconfirmed or low-confidence branches as ruled-out alternatives.

REQUIRED: You MUST populate alternatives_considered with every hypothesis that was
investigated but ruled out. Each entry MUST have both a "hypothesis" and "reason" field
explaining why it was not the primary cause. At least 2 alternatives are required for
MEDIUM or HIGH confidence.

Respond ONLY with this JSON object (no markdown, no extra text).
Keep root_cause under 80 words and each evidence item under 30 words — the JSON
must fit well within the response limit or it will be truncated and discarded:
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

    # PRISM: inject discrimination constraint so synthesis is category-constrained
    discrimination = state.get("discrimination") or {}
    if not isinstance(discrimination, dict):
        discrimination = {}
    constraint = discrimination.get("investigation_constraint", "")
    category = discrimination.get("cause_category", "")
    category_conf = discrimination.get("cause_category_confidence", "")
    if constraint:
        discrimination_block = (
            f"CAUSAL DISCRIMINATION RESULT (cause_category={category}, "
            f"confidence={category_conf}):\n"
            f"BINDING CONSTRAINT: {constraint}\n"
            f"You MUST respect this constraint when selecting the root cause. "
            f"Do not attribute an application_code cause to an AWS infrastructure "
            f"resource, and vice versa."
        )
    else:
        discrimination_block = ""

    system = _SYNTHESIZE_PROMPT.format(
        n=len(all_branch_results),
        discrimination_constraint=discrimination_block,
    )
    # Strip all_fetched + tools_called before synthesis — they can be 20-30K tokens
    # of raw tool responses that synthesize never uses. Only evidence + conclusion matter.
    branches_slim = [
        {
            "hypothesis": br.get("hypothesis", {}),
            "evidence":   br.get("evidence", []),
            "predictions_tested": br.get("predictions_tested", []),
            "conclusion": br.get("conclusion", ""),
            "confidence": br.get("confidence", "LOW"),
            "confirmed":  br.get("confirmed", False),
        }
        for br in all_branch_results
    ]
    branches_text = json.dumps(branches_slim, indent=2)
    obs = state.get("observation") or {}
    user_content = (
        f"Symptom: {state['symptom']}\n\n"
        f"Measured observation (real data, gathered before investigation):\n"
        f"{json.dumps(obs, indent=2) if obs else '(measurement unavailable)'}\n\n"
        f"Branch investigation results:\n{branches_text}"
        f"{arbitration_note}"
    )

    resp = bedrock.converse(
        modelId=_MODEL,
        system=_sys(system),
        messages=[{"role": "user", "content": [{"text": user_content}]}],
        inferenceConfig={"maxTokens": 2500, "temperature": 0},
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
            system=_sys(system),
            messages=[
                {"role": "user", "content": [{"text": user_content}]},
                {"role": "assistant", "content": [{"text": text}]},
                {"role": "user", "content": [{"text": retry_msg}]},
            ],
            inferenceConfig={"maxTokens": 2500, "temperature": 0},
        )
        text2 = resp2["output"]["message"]["content"][0]["text"].strip()
        result2 = _extract_json(text2, "root_cause")
        if result2 and isinstance(result2, dict):
            result = result2

    # VERDICT confidence calibration — confidence follows prediction outcomes,
    # not branch agreement. In a correct investigation exactly ONE branch should
    # confirm (the true cause); the old ≥2-branches rule punished the design
    # working as intended and produced LOW on conclusively-evidenced answers.
    def _pred_stats(br: dict) -> tuple[int, int]:
        preds = [p for p in br.get("predictions_tested", []) if isinstance(p, dict)]
        return (
            sum(1 for p in preds if p.get("verdict") == "CONFIRMED"),
            sum(1 for p in preds if p.get("verdict") == "REFUTED"),
        )

    _order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    confirmed_branches = [br for br in all_branch_results if br.get("confirmed")]
    agent_conf = result.get("confidence", "LOW")

    if len(confirmed_branches) == 1:
        n_conf, _ = _pred_stats(confirmed_branches[0])
        alternatives_dead = all(
            _pred_stats(br)[1] > 0 or _pred_stats(br)[0] == 0
            for br in all_branch_results if br is not confirmed_branches[0]
        )
        floor = "HIGH" if (n_conf >= 1 and alternatives_dead) else "MEDIUM"
        if _order.get(agent_conf, 0) < _order[floor]:
            result["confidence"] = floor
            result["confidence_calibration"] = (
                f"raised from {agent_conf}: winning hypothesis has {n_conf} confirmed "
                f"prediction(s) and every alternative is refuted or unconfirmed"
            )
    elif not confirmed_branches:
        # Nothing survived prediction testing — never report above LOW.
        result["confidence"] = "LOW"
    else:
        # ≥2 confirmed branches contradict each other — stay conservative.
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
1. SPECIFICITY TEST — Does the root cause explain the exact SHAPE of the symptom?
   The symptom's selectivity is itself evidence:
   - If some operations fail while others stay healthy, the cause must live in
     something only the failing operations depend on.
   - If a stable fraction of requests is affected, the cause must explain that
     exact partition — a shared-infrastructure cause would affect all of them.
   - If work accumulates with no errors anywhere, the cause must explain silence,
     not point to a crash or restart (those leave traces).
   A root cause that would affect more, less, or different things than the
   symptom shows is WRONG regardless of how much evidence supports it.

2. DEPLOYMENT NOISE TEST — Is the conclusion anchored to events caused by our OWN
   infrastructure management (deploys, rollouts, instance or container replacement,
   image updates, routing re-registration) rather than a real fault? These events
   appear after EVERY deployment and are almost never the actual root cause.
   KEY RULE: Compare evidence timestamps against get_deployment_info's last_changed_at.
   If the error events happened at the same time as the last deployment AND the symptom
   first_observed timestamp is AFTER those events, the errors are deployment artifacts,
   not the incident cause. The incident started after deployment settled.

3. DEPENDENCY COVERAGE TEST — For the operation the symptom describes, did any
   branch investigate each resource that operation depends on (its datastore,
   cache, queue, encryption key, downstream service)? If a dependency was never
   examined, flag needs_reinvestigation naming that specific resource.

4. Did any branch find a direct finding (throttle event, explicit Deny, disabled flag,
   missing config) that was overlooked in favour of a circumstantial finding?

5. PERMANENCE TEST — Was the cited defect equally present while the system was
   working? A property that did not CHANGE at incident onset cannot explain a
   new incident, no matter how deficient it looks. Ask: what actually changed
   at onset? If the conclusion cannot point to a change (or to the first-ever
   exercise of a latent defect), reject it and demand the change be found.
   Corollary: a missing permission or setting matters only if the failing
   operation's actual execution path exercises it — verify the path, not just
   the absence.

6. UNTESTED CLAIM TEST — Examine every factual claim inside root_cause and evidence.
   A claim is only allowed if it traces to a directly quoted observation or a tested
   prediction from the branch data. Watch especially for "X is missing" claims:
   asserting something is missing requires evidence that it was ever REQUIRED —
   an absent setting that nothing reads is not a fault. If the primary conclusion
   is sound but padded with untested side-claims, issue verdict "revised" with the
   SAME root cause minus every untested claim.

If the conclusion passes all tests: respond with this JSON exactly:
{"verdict": "confirmed", "notes": "one sentence why it holds up"}

If a stronger conclusion exists in the branch data: respond with this JSON exactly:
{"verdict": "revised", "root_cause": "...", "evidence": ["...", "..."],
 "confidence": "LOW | MEDIUM | HIGH", "notes": "one sentence why this is stronger"}

If evidence is insufficient OR the conclusion fails the specificity/deployment-noise tests:
{"verdict": "needs_reinvestigation",
 "investigation_focus": "call [specific tool] on [specific resource] to find [what] — be precise",
 "notes": "one sentence: why the current conclusion does not explain the symptom"}

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
        system=_sys(_CRITIQUE_SYSTEM),
        messages=[{"role": "user", "content": [{"text": user_content}]}],
        inferenceConfig={"maxTokens": 600, "temperature": 0},
    )
    text = resp["output"]["message"]["content"][0]["text"].strip()
    critique = _extract_json(text, "verdict")

    if not isinstance(critique, dict) or critique.get("verdict") == "confirmed":
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


# NOTE: an _after_synthesize early exit ("skip critique when predictions are
# verified") was tried and removed: on 2026-07-02 it shipped a HIGH-confidence
# wrong diagnosis, because a CONFIRMED prediction can be true yet causally
# irrelevant (a permanent property of the system, unchanged at onset). The
# critique must always run — it is the layer that tests causal relevance.


def _build_graph():
    workflow = StateGraph(GraphState)
    workflow.add_node("observe",           observe_node)              # VERDICT 0
    workflow.add_node("triage",            triage_node)
    workflow.add_node("investigate",       investigate_node)
    workflow.add_node("log_intelligence",  log_intelligence_node)   # PRISM A
    workflow.add_node("discriminate",      discriminate_node)        # PRISM B
    workflow.add_node("clarify",           clarify_node)              # VERDICT HITL
    workflow.add_node("synthesize",        synthesize_node)
    workflow.add_node("critique",          critique_node)
    workflow.add_node("reinvestigate",     reinvestigate_node)

    # Observe measures the symptom first; triage hypothesizes from measurement.
    # After triage: fan out in parallel to investigate + log_intelligence.
    workflow.add_edge(START,     "observe")
    workflow.add_edge("observe", "triage")
    workflow.add_edge("triage",  "investigate")
    workflow.add_edge("triage",  "log_intelligence")

    # Both parallel branches merge at discriminate
    workflow.add_edge("investigate",      "discriminate")
    workflow.add_edge("log_intelligence", "discriminate")

    # Discriminate → clarify (HITL no-op unless interactive + dead end)
    # → synthesize → critique (ALWAYS — an early exit on "verified predictions"
    # shipped a confident-wrong diagnosis on 2026-07-02: a prediction can be
    # true-but-causally-irrelevant, and the critique is the layer that catches
    # exactly that) → (conditional) reinvestigate
    workflow.add_edge("discriminate", "clarify")
    workflow.add_edge("clarify", "synthesize")
    workflow.add_edge("synthesize", "critique")
    workflow.add_conditional_edges(
        "critique", _after_critique,
        {"reinvestigate": "reinvestigate", END: END},
    )
    workflow.add_edge("reinvestigate", "synthesize")
    return workflow.compile(checkpointer=_make_checkpointer())


def _make_checkpointer():
    """SQLite checkpointer so a crashed/interrupted investigation (credential
    expiry, process kill) can resume from its last completed node instead of
    restarting — set CLOUDCTL_RESUME_THREAD=<session_id> to resume.
    Returns None (no checkpointing) if the sqlite saver isn't installed."""
    import os
    try:
        import sqlite3
        from langgraph.checkpoint.sqlite import SqliteSaver
        ckpt_dir = os.path.join(os.path.expanduser("~"), ".cloudctl")
        os.makedirs(ckpt_dir, exist_ok=True)
        conn = sqlite3.connect(
            os.path.join(ckpt_dir, "graph_checkpoints.db"),
            check_same_thread=False,
        )
        return SqliteSaver(conn)
    except Exception:  # noqa: BLE001
        return None


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

    import os as _os
    # Make recordings self-describing: a _meta line with the symptom lets a
    # fixture be replayed (or batch-regressed) without external bookkeeping.
    if _os.environ.get("CLOUDCTL_RECORD"):
        from cloudctl.mcp.tools.recorder import _record
        _record("_meta", {"symptom": symptom, "region": region,
                          "minutes": minutes}, "")

    resume_thread = _os.environ.get("CLOUDCTL_RESUME_THREAD", "")
    thread_id = resume_thread or session_id
    invoke_config = {"configurable": {"thread_id": thread_id}}

    initial_state = None if resume_thread else {
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
        "log_insights": {},
        "discrimination": {},
        "observation": {},
    }
    final_state = _get_graph().invoke(initial_state, invoke_config)

    # Human-in-the-loop: clarify_node may interrupt when no hypothesis
    # survived. Prompt the operator on a real terminal and resume from the
    # checkpoint; otherwise resume with an empty answer (no-op).
    if final_state.get("__interrupt__"):
        from langgraph.types import Command
        answer = ""
        try:
            intr = final_state["__interrupt__"]
            payload = intr[0].value if isinstance(intr, (list, tuple)) else getattr(intr, "value", {})
            question = (payload or {}).get("question", "Additional context?")
            import sys as _sys
            if _sys.stdin.isatty():
                print(f"\n[agent] {question}")
                answer = input("> ").strip()
        except Exception:  # noqa: BLE001
            answer = ""
        final_state = _get_graph().invoke(Command(resume=answer), invoke_config)

    parsed = final_state["final_report"]
    all_fetched = final_state.get("all_fetched", {})

    # Diagnostics: record what the VERDICT/PRISM layers actually produced so a
    # silent no-op (empty observation / log_insights) is visible in results.
    parsed["_verdict_layers"] = {
        "observation":    final_state.get("observation") or {},
        "log_insights":   final_state.get("log_insights") or {},
        "discrimination": final_state.get("discrimination") or {},
    }
    # Resume a crashed run with CLOUDCTL_RESUME_THREAD=<this value>
    parsed["_thread_id"] = thread_id

    # Resolution plumbing: lift deployment_source/iac_file_hint from any
    # get_deployment_info result gathered during investigation — the
    # resolution agent refuses to write IaC fixes without a known source.
    if "deployment_source" not in parsed:
        for key, val in all_fetched.items():
            if key.startswith("get_deployment_info") and isinstance(val, dict):
                src = val.get("deployment_source")
                if src and src not in ("unknown", "manual"):
                    parsed["deployment_source"] = src
                    if val.get("iac_file_hint"):
                        parsed["iac_file_hint"] = val["iac_file_hint"]
                    break
    if "deployment_source" not in parsed:
        # No branch asked — probe directly on the first investigated resource
        # (CloudTrail user-agent detection works for any resource name).
        try:
            from cloudctl.mcp.tools.debug import get_deployment_info
            for res in (parsed.get("resources_investigated") or [])[:2]:
                info = json.loads(get_deployment_info(
                    resource_name=str(res).split(" ")[0],
                    service_type="unknown", profile=profile, region=region,
                ))
                src = info.get("deployment_source")
                if src and src not in ("unknown", "manual"):
                    parsed["deployment_source"] = src
                    if info.get("iac_file_hint"):
                        parsed["iac_file_hint"] = info["iac_file_hint"]
                    break
        except Exception:  # noqa: BLE001
            pass

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
