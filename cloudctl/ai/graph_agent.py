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
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TypedDict

from botocore.config import Config as _BotoConfig

log = logging.getLogger("cloudctl.graph_agent")
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
    # Feature 5 (VOI): True when the branch stopped its tool loop early because
    # its hypothesis was decisively resolved with the accuracy floor met — a
    # measurement hook, behavior-neutral (does not affect confidence/verdict).
    voi_early_stop: bool = False

    @field_validator("confidence")
    @classmethod
    def _valid_confidence(cls, v: str) -> str:
        return v if v in ("LOW", "MEDIUM", "HIGH") else "LOW"


class IncidentReport(BaseModel):
    # Preserve extra keys (confidence_calibration, _critique_notes, deployment_
    # source, …) through model_dump instead of silently dropping them — several
    # diagnostic/plumbing fields are attached to the report dict after synthesis.
    model_config = {"extra": "allow"}

    root_cause: str
    evidence: list[str]
    remediation_steps: list[str]
    severity: str
    confidence: str
    resources_investigated: list[str]
    alternatives_considered: list[dict] | None = None
    additional_causes: list[dict] | None = None   # independent confirmed faults
    # Provenance trail: each entry maps ONE reported claim (an evidence[] item
    # or a root_cause sentence) to the all_fetched keys (from _evidence_key —
    # the existing per-tool-call citation ids) whose stored value actually
    # contains the claim's facts, plus a short verbatim quote from that value.
    provenance: list[dict] | None = None
    # Claims that carry verifiable specifics (identifiers/values) yet traced to
    # ZERO fetched sources. Flag + confidence weight only — never a hard cap.
    unsourced_claims: list[str] | None = None

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
    failure_map: list      # LOCALIZE: components observed emitting failures now


# ── Shared Bedrock client factory ──────────────────────────────────────────────

# Model ids are configurable so a --model flag / config / env can override them
# without editing code; each falls back to a sane default.
_MODEL = os.environ.get("CLOUDCTL_MODEL", "us.anthropic.claude-sonnet-4-6")

# Lightweight model for the PRISM log-intelligence pass (cheap, high-volume).
# NOTE: the Bedrock inference-profile id REQUIRES the "-v1:0" suffix; without it
# converse() returns ValidationException("provided model identifier is invalid")
# and PRISM silently dies (verified against this account 2026-07-05).
_LOG_INTEL_MODEL = os.environ.get(
    "CLOUDCTL_LOG_MODEL", "us.anthropic.claude-haiku-4-5-20251001-v1:0"
)

# Decorrelated critic: the review pass can run on a DIFFERENT model than the
# investigator so it doesn't share the same blind spots. Defaults to the same
# model (safe out of the box); set CLOUDCTL_CRITIC_MODEL to a different model
# id (e.g. an Opus/Haiku inference profile) to actually decorrelate.
_CRITIC_MODEL = os.environ.get("CLOUDCTL_CRITIC_MODEL", _MODEL)

# Prompt caching. A cachePoint marks a prefix boundary Bedrock may reuse across
# calls; it does NOT change the tokens the model sees, so at temperature 0 the
# generated output is byte-identical with or without it. We cache only content
# that repeats verbatim across many calls: the tool schema (sent on every
# tool-use turn, identical everywhere) and static system prompts.
_CACHE_POINT = {"cachePoint": {"type": "default"}}


def _round_robin_merge(groups: list[list[str]]) -> list[str]:
    """Interleave lists one item at a time so a downstream truncation window is
    shared fairly across all groups, instead of the first group consuming it."""
    out: list[str] = []
    if not groups:
        return out
    for i in range(max(len(g) for g in groups)):
        for g in groups:
            if i < len(g):
                out.append(g[i])
    return out


def _evidence_key(tool_name: str, tool_input: dict) -> str:
    """Build a stable, human-readable evidence-store key that is UNIQUE per
    distinct tool call. The old key was f"{tool_name}:{resource_name}", but
    several tools (tail_logs→resource_hint, query_metrics→namespace/metric/dims,
    aws_read→service/operation, probe_permission→role/action, probe_http→url)
    carry no resource_name, so every one of their calls collapsed to the same
    key and overwrote the previous result — silently gutting the anti-fabrication
    corpus, the critique inventory, and the hallucination/grounding checks that
    all key off this store. This derives the discriminator generically from the
    call's identifying inputs (no per-tool/per-service literals), so distinct
    calls never collide.
    """
    parts: list[str] = []
    for k, v in (tool_input or {}).items():
        if k in ("region", "profile", "minutes", "reason"):
            continue
        if isinstance(v, (str, int, float)) and str(v).strip():
            parts.append(f"{k}={v}")
        elif isinstance(v, dict) and v:
            parts.append(f"{k}=" + ",".join(f"{kk}:{vv}" for kk, vv in v.items()))
        elif isinstance(v, (list, tuple)) and v:
            parts.append(f"{k}=" + ",".join(str(x) for x in v))
    disc = "|".join(parts)[:180]
    return f"{tool_name}:{disc}" if disc else tool_name


def _store_unique(store: dict, key: str, value) -> str:
    """Insert value under key, guaranteeing no in-store collision silently
    overwrites an earlier distinct result. An identical value already present is
    deduplicated (lossless); a different value under a taken key is renamed with
    a numeric suffix. Returns the key actually used."""
    if key not in store:
        store[key] = value
        return key
    if store[key] == value:
        return key
    n = 2
    while f"{key}#{n}" in store:
        if store[f"{key}#{n}"] == value:
            return f"{key}#{n}"
        n += 1
    store[f"{key}#{n}"] = value
    return f"{key}#{n}"


def _merge_fetched(dst: dict, src: dict) -> None:
    """Merge one branch's fetched corpus into the shared one WITHOUT lossy key
    collisions across branches. Two branches that each fetched a differently-keyed
    result under the same tool descriptor previously clobbered each other at
    .update(); here a colliding-but-different value is renamed instead of lost."""
    for k, v in (src or {}).items():
        _store_unique(dst, k, v)


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
    from cloudctl.mcp.tools.recorder import RecordingBedrock
    from cloudctl.ai.model_providers import make_model_client
    # Model-agnostic: bedrock (default) | anthropic | openai, via
    # CLOUDCTL_MODEL_PROVIDER. Each returns a client with converse(**kwargs) in
    # the Converse shape, so the graph and recorder are unchanged.
    client = make_model_client(profile, region)
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

# Reproduce-first addendum — appended to the observe prompt ONLY when active
# reproduction is enabled (--reproduce). Service-agnostic by design: it is
# keyed on the INTERACTION PATTERN (a user-facing operation with an
# HTTP-reachable entry point), names no service, and prescribes no expected
# response content. When probing is off, the observe prompt and toolset are
# byte-identical to before, so passive-only investigations are unaffected.
_OBSERVE_REPRODUCE_ADDENDUM = """\

REPRODUCE FIRST — the strongest possible measurement of a user-facing symptom
is the operation's own CONCRETE result, not telemetry about it. If the reported
symptom concerns an operation a user invokes:
  a. Identify the resource and its type (list_resources), and READ whatever a
     reproduction needs with read-only aws_read calls — the definition/ids the
     operation is built from. Use ONLY values you actually discovered; NEVER
     invent, guess, or mint a credential or a value.
  b. NATIVE-FIRST — PREFER native_reproduce: it exercises the operation
     SERVER-SIDE through the AWS control plane using cloudctl's own IAM role, so
     it needs no network path and no separate auth and can reproduce operations
     an HTTP request cannot reach (e.g. one behind an identity provider). It
     uses only side-effect-free evaluate/test APIs.
  c. FALL BACK in order: if native_reproduce returns
     native_reproduction=unavailable (no primitive for the type, access denied,
     or missing inputs), use probe_http to exercise an HTTP-reachable entry
     point the way the user would (a plain GET, or a read-only query `body`;
     never anything that could mutate). If that too is impossible (unreachable,
     no discoverable credential, declined), record that plainly and measure
     passively — this is the frontier-honest fallback.
  d. Record the CONCRETE result — evaluation output, or status/body/timing —
     verbatim in your measurements. What the operation actually produced
     outranks every other reading.
NEVER guess or invent what the result would have been — an unreproduced result
is unknown.
When you attempted reproduction, ALSO include in the concluding JSON:
  "reproduction": "concrete observed result, or 'not possible: <reason>'"
You may use up to 7 tool calls total when reproducing.
"""


def observe_node(state: GraphState) -> dict:
    from cloudctl.mcp.tools.debug import (
        _AGENT_TOOLS, _truncate_tool_output,
        list_resources, tail_logs, query_metrics, get_event_timeline,
        aws_read,
    )
    from cloudctl.mcp.tools.probe import _probes_enabled
    from cloudctl.ai.guardrails import validate_tool_call, audit_log_tool_call

    bedrock = _make_bedrock(state["profile"], state["region"])
    allowed = {"list_resources", "tail_logs", "query_metrics", "get_event_timeline"}
    # Reproduce-first (opt-in): when active reproduction is enabled, observe may
    # also DISCOVER the symptom's entry point (aws_read, read-only) and EXERCISE
    # it once (probe_http, consent-gated) so the concrete response — not a
    # narrative about it — is the primary measurement. When probing is off the
    # toolset and prompt are unchanged, so existing investigations are untouched.
    reproduce_enabled = _probes_enabled()
    if reproduce_enabled:
        allowed |= {"aws_read", "probe_http", "native_reproduce"}

    # Deterministic capture of every reproduction attempt: the concrete response
    # is carried into the observation verbatim (bounded), independent of how the
    # model chooses to summarize it — so synthesis sees what ACTUALLY happened.
    # Native (control-plane) and HTTP results are captured identically, so the
    # same grounding / consistency checks apply to both.
    reproductions: list = []

    def _capture_reproduction(tool_name: str, tool_input: dict, raw: str) -> None:
        try:
            resp = json.loads(raw)
        except Exception:  # noqa: BLE001
            resp = {"raw": str(raw)[:800]}
        for _field in ("body", "evaluation_result", "log", "logs"):
            if isinstance(resp, dict) and isinstance(resp.get(_field), str) \
                    and len(resp[_field]) > 1500:
                resp = {**resp, _field: resp[_field][:1500] + "…[truncated]"}
        if tool_name == "native_reproduce":
            reproductions.append({
                "via": "native",
                "service_type": str(tool_input.get("service_type", "")),
                "response": resp,
            })
        else:
            reproductions.append({
                "via": "http",
                "url": str(tool_input.get("url", "")),
                "method": str(tool_input.get("method") or "GET").upper(),
                "response": resp,
            })

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
                raw = list_resources(tool_input.get("service_type", ""),
                                     state["profile"], state["region"])
            elif tool_name == "tail_logs":
                raw = tail_logs(
                    resource_hint=tool_input["resource_hint"],
                    minutes=int(tool_input.get("minutes") or state["minutes"]),
                    profile=state["profile"], region=state["region"], max_events=50,
                    filter_pattern=tool_input.get("filter_pattern", ""),
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
            elif tool_name == "aws_read":
                raw = aws_read(
                    service=tool_input["service"],
                    operation=tool_input["operation"],
                    params=tool_input.get("params") or {},
                    profile=state["profile"], region=state["region"],
                )
            elif tool_name == "probe_http":
                from cloudctl.mcp.tools.probe import probe_http_gated
                raw = probe_http_gated(
                    url=tool_input["url"],
                    method=tool_input.get("method", "GET"),
                    headers=tool_input.get("headers") or {},
                    reason=tool_input.get("reason", ""),
                    body=tool_input.get("body") or None,
                )
                _capture_reproduction(tool_name, tool_input, raw)
            elif tool_name == "native_reproduce":
                from cloudctl.mcp.tools.probe import native_reproduce_gated
                raw = native_reproduce_gated(
                    service_type=tool_input["service_type"],
                    params=tool_input.get("params") or {},
                    profile=state["profile"], region=state["region"],
                    reason=tool_input.get("reason", ""),
                )
                _capture_reproduction(tool_name, tool_input, raw)
            else:
                return json.dumps({"error": f"tool not allowed here: {tool_name}"})
        except Exception as exc:
            return json.dumps({"error": str(exc)})
        return _truncate_tool_output(raw, tool_name)

    tools = [t for t in _AGENT_TOOLS if t["toolSpec"]["name"] in allowed]
    system_text = _OBSERVE_SYSTEM + (
        _OBSERVE_REPRODUCE_ADDENDUM if reproduce_enabled else ""
    )
    msgs = [{"role": "user", "content": [{"text": (
        f"Reported symptom: {state['symptom']}\n\n"
        f"Measure this symptom in real data now."
    )}]}]
    observation: dict = {}
    for _ in range(10 if reproduce_enabled else 8):
        try:
            resp = bedrock.converse(
                modelId=_MODEL,
                system=_sys(system_text),
                messages=_conv(msgs),
                toolConfig=_cached_tools(tools),
                inferenceConfig={"maxTokens": 900 if reproduce_enabled else 700,
                                 "temperature": 0},
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

    # First-class reproduction evidence: attach the CONCRETE responses verbatim
    # (deterministically captured above) so downstream nodes and the grounding
    # corpus see exactly what the exercised operation returned — never only the
    # model's paraphrase of it. No-op when no reproduction was attempted.
    if reproductions:
        if not isinstance(observation, dict):
            observation = {}
        observation["reproduction_observed"] = reproductions

    return {"observation": observation}


# ── Generic diagnostic methodology scaffold (Feature 3) ───────────────────────
#
# Domain-agnostic REASONING FRAMES the model applies to WHATEVER resources it
# discovers — deliberately NOT scenario answers. It names no service, resource
# type, or error code, and maps no symptom to any cause: it is methodology, not
# a lookup table. Kept as ONE static constant shared by the fully-static triage
# prompt and the branch-investigation prompt, so the text is invariant across
# every incident and sits inside a prompt-cacheable prefix (the triage system
# block is entirely static). Complements — does not duplicate — the existing
# DEPLOYMENT-AT-ONSET and CALL-GRAPH rules in the branch prompt.
_DIAGNOSTIC_SCAFFOLD = """\
DIAGNOSTIC FRAMES — apply these generic checks to WHATEVER resources you find;
they name no service and map no symptom to any cause:
  - USE (any resource): inspect its Utilization, Saturation, and Errors.
  - RED (any request path): inspect its Rate, Errors, and Duration.
  - DEPENDENCY-WALK: start at the failing symptom and walk INWARD along what it
    calls, what it reads/writes, and what authorizes it — test each hop before
    guessing an intrinsic cause.
  - CHANGE-FIRST: a fault with a clear onset usually follows a change; establish
    what changed at onset before theorizing an intrinsic defect.

"""


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
  2. Deployment MECHANICS (instance or container replacement, connection
     draining, image pulls) are almost NEVER the root cause — they are symptoms
     of routine change; do not use the churn itself as a primary hypothesis.
     BUT a wrong CHANGE shipped by a deployment (a regressed env var, a bad
     policy edit, a flipped flag) IS a valid primary hypothesis — target the
     specific changed setting, not the mechanical churn around it.
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

""" + _DIAGNOSTIC_SCAFFOLD + """\
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
            parsed_raw = None
            try:
                parsed_raw = json.loads(text)
            except Exception:
                # Salvage a JSON array/object embedded in prose instead of
                # discarding all three hypotheses on a stray character.
                parsed_raw = _extract_json(text, "service")
            if isinstance(parsed_raw, dict):
                parsed_raw = [parsed_raw]
            if isinstance(parsed_raw, list):
                # Parse each hypothesis INDEPENDENTLY: one malformed entry must
                # not abort the whole list (which previously collapsed triage to
                # the hard-coded IAM fallback).
                for h in parsed_raw[:3]:
                    try:
                        hypotheses.append(Hypothesis(**h).model_dump())
                    except Exception:
                        continue
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
        # Robust fallback: do NOT collapse to a single hard-coded guess. The old
        # default was a fixed IAM "permission denied" hypothesis, which biased
        # every unparseable triage toward one fault class regardless of symptom.
        # Derive neutral hypotheses from whatever resources were actually
        # discovered (hint-free — no fault category assumed).
        for svc, parsed in (discovered or {}).items():
            if svc.startswith("_"):
                continue
            names = parsed.get("resources") if isinstance(parsed, dict) else None
            first = names[0] if isinstance(names, list) and names else ""
            hypotheses.append({
                "service": svc,
                "reason": f"triage returned no parseable hypotheses; {svc} was discovered and may be implicated by the symptom",
                "focus": f"{first or svc} — inspect configuration and operational state",
                "predictions": [],
            })
            if len(hypotheses) >= 3:
                break
        if not hypotheses:
            hypotheses = [{
                "service": "unknown",
                "reason": "triage produced no parseable hypotheses and discovery found no resources",
                "focus": "enumerate the resources the symptom implicates, then inspect their config and logs",
                "predictions": [],
            }]

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
You are an AWS incident investigator. Phase 1 checked configuration state — now
investigate operational state to prove or disprove this hypothesis. Read the
Phase 1 finding below: if it already found a STRUCTURAL issue, that finding
STANDS — your job is to corroborate it with operational evidence and test the
predictions, NOT to assume the configuration is fine.

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

DISCOVERED-CAUSE rule — if your investigation surfaces a likely cause that was
NOT among the predictions above (you found the fault by following the evidence),
do NOT merely file it as evidence and stop. That is the most common reason a
correct branch fails to confirm: it gathers conclusive evidence but never frames
a testable claim, so it cannot be CONFIRMED. Instead: turn the discovery into a
NEW falsifiable prediction ("if THIS is the cause, then <specific discriminating
observation> must hold, and it would NOT hold under the alternative causes"),
TEST it with a tool call, and add it to predictions_tested with its verdict.
Only then may you set confirmed=true. A cause you found but never framed and
tested is asserted, not verified — verify it.

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

PARTIAL-FAILURE rule — if the impact is NON-uniform (affects only part of the
traffic, or some instances/paths and not their peers), the cause lives in
something ONLY the affected part uses; a systemic cause would affect everything.
  1. Read the DISTRIBUTION, not the aggregate: query_metrics percentiles and
     PER-TARGET / per-instance dimensions to see which instance/path carries the
     anomaly, rather than an average that hides it.
  2. If telemetry cannot localize it, REPRODUCE: fire several probe_http requests
     and correlate the anomalous responses to the specific serving component
     (via response headers, hostname, or trace ids), pinning the fault to one
     component instead of treating it as systemic.
  3. Then inspect that component's OWN configuration for what differs from peers.

CLEAN-TELEMETRY rule — if every reading you can take (metrics, logs, config,
events) looks healthy yet the symptom stands, do NOT conclude "no fault found" or
reach for the nearest incidental config weakness. A fault can live ENTIRELY in
what the system returns to a request — a success status carrying wrong output, a
single broken path — which no metric, log, or config will ever show. When passive
evidence is exhausted and unresolved: REPRODUCE (probe_http) to observe the actual
response, or, if reproduction is unavailable, state explicitly that the fault may
be runtime-only and is therefore unverified — never substitute a confident passive
guess for an observation you did not make.

DEPLOYMENT-AT-ONSET rule — if a deployment or rollout coincides with onset, that
is a LEAD to examine WHAT it changed (diff the new configuration against its
peers or prior intent), NOT a licence to attribute the incident to "deployment
churn". The churn is a symptom of the change; find the change.

DIFFERENTIAL rule — "wrong" is often invisible in the absolute (a config value
looks plausible on its own) but obvious as a DIFFERENCE. When a value on the
failing path is suspect and you cannot tell whether it is wrong by itself:
  - get_prior_config shows what it looked like BEFORE (retained versions +
    CloudTrail-reconstructed before→after). A field that CHANGED at/near the
    measured onset on the failing path is a prime suspect.
  - compare_peers shows how it differs from SIBLING resources of the same type
    (or diff nested siblings by passing their configs). A field where the
    failing resource diverges from otherwise-identical peers is a prime suspect.
Cite the old→new or peer-vs-peer values VERBATIM as evidence. A diff alone is
not proof — the changed/divergent field must still explain the observed failure.

ANCHOR-FIRST rule — when you differential-compare or reproduce, run it FIRST on
the resource where the failure was actually, specifically observed (the
component emitting the failure — or, when nothing downstream shows any
activity, the resource you tested/probed the symptom against), BEFORE widening
to resources further away in the dependency graph. A coincidental change found
on an unrelated resource you merely happened to be inspecting is the classic
wrong turn. The causal_search tool does this ordering for you: it identifies
the anchor, differential-checks it, then widens outward ring by ring,
returning the ranked trail as evidence.

CALL-GRAPH rule — for any latency, timeout, or error-that-propagates-across-
services symptom, get_traces is the richest single signal: it returns the
service-dependency graph with per-edge latency/error/fault/throttle rates and
localizes offending traces to the exact segment (service + operation) carrying
the fault, so you can pinpoint WHICH hop in the call path accumulates the time or
failures instead of guessing. If it reports available=false (tracing not enabled
/ no traces in window), simply fall back to metrics and logs — it is not a fault.

VALUE-OF-INFORMATION rule — do not gather breadth for its own sake. Before each
call, ask: which single check would most CHANGE which hypothesis is favored?
Prefer that maximally-discriminating check over one that only re-confirms what
you already believe. And the moment a prediction is decisively resolved — CONFIRMED
with observed data you can quote, or REFUTED — and the mandatory evidence is in
hand, STOP and conclude: further calls that cannot change the verdict have no value.

""" + _DIAGNOSTIC_SCAFFOLD + """\
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


# ── Feature 5: value-of-information adaptive early-stop ───────────────────────

def _voi_should_stop_branch(
    conclusion: dict | None,
    tools_called: set[str],
    symptom: str,
    corpus_lower: str,
) -> bool:
    """Deterministic VOI early-stop predicate. Returns True ONLY when the
    hypothesis is DECISIVELY resolved AND the accuracy FLOOR is satisfied — so a
    branch can end its tool loop instead of burning the remaining ceiling on
    checks whose information value is ~zero. Otherwise returns False (keep
    investigating). Pure and side-effect free.

    It can NEVER cut accuracy, by construction:
      FLOOR 1 — every mandatory tool for this symptom class must already have
                been called (reuses verify_tool_coverage; never skips required
                evidence such as logs/metrics).
      FLOOR 2 — at least one falsifiable prediction must have been TESTED, i.e.
                carry a decisive CONFIRMED or REFUTED verdict. A branch that has
                not tested its predictions is never stopped.
      TRACEABILITY — a CONFIRMED verdict counts only if its observed data traces
                to the fetched corpus (no stopping on a fabricated confirmation).
                A REFUTED prediction is itself decisive (the hypothesis is
                falsified), so it licenses a stop directly.

    Conservative default: anything short of the above (no conclusion yet,
    coverage unmet, predictions untested, untraceable confirmation) → False.
    """
    if not isinstance(conclusion, dict):
        return False   # no decisive verdict emitted yet → keep going

    # FLOOR 1: mandatory-tool coverage for this symptom class.
    from cloudctl.ai.guardrails import verify_tool_coverage
    if not verify_tool_coverage(symptom, set(tools_called)).satisfied:
        return False

    preds = [p for p in (conclusion.get("predictions_tested") or [])
             if isinstance(p, dict)]
    verdicts = [str(p.get("verdict", "")).upper() for p in preds]

    # FLOOR 2: at least one prediction decisively tested.
    if "REFUTED" in verdicts:
        return True   # hypothesis falsified — decisively resolved
    if "CONFIRMED" not in verdicts:
        return False  # nothing decisively tested → keep going

    # Confirmed path: the confirming observation must be corpus-traceable.
    for p in preds:
        if str(p.get("verdict", "")).upper() == "CONFIRMED":
            if _has_traceable_fact(str(p.get("observed", "")), corpus_lower):
                return True
    return False


def _run_branch(
    hypothesis: dict,
    symptom: str,
    profile: str | None,
    region: str,
    minutes: int,
    session_id: str,
    failure_map: list | None = None,
) -> BranchResult:
    from cloudctl.mcp.tools.debug import (
        _AGENT_TOOLS, _truncate_tool_output,
        list_resources, get_service_config, tail_logs,
        query_metrics, search_cloudtrail, get_event_timeline,
        get_deployment_info, probe_permission, get_dependency_graph, aws_read,
        get_traces, get_prior_config, compare_peers,
    )
    from cloudctl.ai.guardrails import (
        sanitise_fetched_data, validate_tool_call, audit_log_tool_call,
    )

    h = Hypothesis(**hypothesis)
    bedrock = _make_bedrock(profile, region)
    branch_fetched: dict = {}
    tools_called: list[str] = []
    _interned: dict = {}   # rung 4: sha1(output) -> reference id, within this branch

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
            raw = list_resources(tool_input.get("service_type", ""), profile, region)
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
                filter_pattern=tool_input.get("filter_pattern", ""),
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
        elif tool_name == "get_traces":
            raw = get_traces(
                profile=profile, region=region,
                minutes=int(tool_input.get("minutes") or minutes),
                resource_hint=tool_input.get("resource_hint") or None,
                filter_expression=tool_input.get("filter_expression") or None,
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
                resource_policy=tool_input.get("resource_policy", ""),
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
        elif tool_name == "probe_http":
            from cloudctl.mcp.tools.probe import probe_http_gated
            raw = probe_http_gated(
                url=tool_input["url"],
                method=tool_input.get("method", "GET"),
                headers=tool_input.get("headers") or {},
                reason=tool_input.get("reason", ""),
                body=tool_input.get("body") or None,
            )
        elif tool_name == "native_reproduce":
            from cloudctl.mcp.tools.probe import native_reproduce_gated
            raw = native_reproduce_gated(
                service_type=tool_input["service_type"],
                params=tool_input.get("params") or {},
                profile=profile, region=region,
                reason=tool_input.get("reason", ""),
            )
        elif tool_name == "get_prior_config":
            raw = get_prior_config(
                resource_name=tool_input["resource_name"],
                service_type=tool_input.get("service_type", ""),
                profile=profile, region=region,
                minutes=int(tool_input.get("minutes") or 10080),
            )
        elif tool_name == "compare_peers":
            raw = compare_peers(
                resource_name=tool_input["resource_name"],
                service_type=tool_input.get("service_type", ""),
                profile=profile, region=region,
                peer_names=tool_input.get("peer_names") or None,
                configs=tool_input.get("configs") or None,
            )
        elif tool_name == "causal_search":
            # Anchored ring search: anchor identification uses only generic
            # signals — the observed-emitting component (failure_map) or the
            # reproduction/probe target already recorded in THIS branch's
            # evidence store. Bounded and read-only; degrades to a structured
            # available=false result.
            from cloudctl.debug.causal_search_aws import causal_search_aws
            raw = json.dumps(causal_search_aws(
                profile=profile, region=region,
                failure_map=failure_map,
                evidence_store=branch_fetched,
                anchor_hint=tool_input.get("anchor_hint") or None,
                minutes=int(tool_input.get("minutes") or 10080),
                max_rings=int(tool_input.get("max_rings") or 3),
            ), default=str)
        else:
            return json.dumps({"error": f"unknown tool: {tool_name}"})

        try:
            parsed = json.loads(raw)
            sanitised = sanitise_fetched_data(parsed) if isinstance(parsed, dict) else parsed
            # Unique per distinct call (see _evidence_key) + collision-guarded, so
            # tail_logs/query_metrics/aws_read/probe_* results never overwrite one
            # another — the whole verification stack keys off this store.
            _store_unique(branch_fetched, _evidence_key(tool_name, tool_input), sanitised)
            raw = json.dumps(sanitised, default=str)
        except Exception:
            pass

        out = _truncate_tool_output(raw, tool_name)
        # Rung 4 — evidence interning: a byte-identical result already seen in
        # THIS branch is replaced by a short reference, never re-sent. Lossless
        # (the model already has the full block above) and never elides unseen
        # content. Small results are left alone (a reference wouldn't save).
        if len(out) > 400:
            import hashlib
            key = hashlib.sha1(out.encode("utf-8", "replace")).hexdigest()
            ref = _interned.get(key)
            if ref is not None:
                return json.dumps({"_identical_to": ref,
                                   "note": "identical to an earlier result this "
                                           "investigation already returned in full"})
            _interned[key] = f"{tool_name}:{resource_name or len(_interned)}"
        return out

    def _voi_stop_check(conclusion: dict | None) -> bool:
        """Feature 5: decisively-resolved-and-floor-met check, evaluated on the
        evidence gathered SO FAR (the pending call, if any, is what we may skip)."""
        corpus_lower = json.dumps(branch_fetched, default=str).lower()
        return _voi_should_stop_branch(
            conclusion, set(tools_called), symptom, corpus_lower
        )

    def _loop(system_text: str, init_messages: list, max_turns: int,
              stop_check=None) -> dict:
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
                # VOI early-stop: if the model has ALREADY narrated a decisive,
                # traceable conclusion (floor met) alongside this tool request,
                # the pending call has ~zero information value — end the branch
                # now instead of consuming more of the ceiling. Conservative: only
                # fires on a decisively-resolved verdict; otherwise dispatch as
                # usual. Never runs before the floor, never exceeds the ceiling.
                if stop_check is not None:
                    _txt = next(
                        (b["text"] for b in msg.get("content", []) if "text" in b), ""
                    ).strip()
                    _prelim = _extract_json(_txt, "conclusion") if _txt else None
                    if isinstance(_prelim, dict) and stop_check(_prelim):
                        _prelim["_voi_early_stop"] = True
                        return _prelim
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
        # Do NOT report the fetched-store KEYS as evidence: tool-key strings like
        # "get_service_config:resource_name=x" are not observations, yet ≥3 of
        # them wrongly qualified the branch as "well-evidenced" in calibration.
        return {"conclusion": "hit turn limit without a conclusion", "confidence": "LOW",
                "confirmed": False, "phase2_needed": True, "evidence": [],
                "_incomplete": "branch exhausted its turn budget before concluding"}

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

    # Phase 2: operational investigation (max 7 turns — was 10). Frame the kickoff
    # by what Phase 1 actually found: if Phase 1 confirmed a structural issue, do
    # NOT tell Phase 2 "config looked correct" (that contradicts the finding and
    # invites the branch to walk back a correct structural diagnosis).
    if p1.get("confirmed"):
        p2_kickoff = (
            f"Symptom: {symptom}\n\n"
            f"Phase 1 found a STRUCTURAL issue: {p1.get('conclusion', '')}\n"
            f"That finding stands. Now gather the mandatory operational evidence "
            f"(logs, metrics) to corroborate it and test the predictions for: {h.reason}"
        )
    else:
        p2_kickoff = (
            f"Symptom: {symptom}\n\n"
            f"Phase 1 found no structural config issue. Now investigate operational "
            f"state to prove or disprove: {h.reason}"
        )
    p2 = _loop(
        _PHASE2_SYSTEM.format(
            reason=h.reason, service=h.service,
            phase1_conclusion=p1.get("conclusion", "no config issues found"),
            predictions=predictions_text,
        ),
        [{"role": "user", "content": [{"text": p2_kickoff}]}],
        max_turns=7,
        stop_check=_voi_stop_check,   # Feature 5: VOI early-stop (floor-gated)
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
            stop_check=_voi_stop_check,   # Feature 5: stop once coverage+floor met
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

    # Calibration reliability: a branch often concludes confirmed=true WITH real
    # evidence but forgets to populate predictions_tested — so n_confirmed=0, the
    # confirmation is voided, and a correct answer ships LOW. When that happens,
    # derive one prediction entry from the branch's own evidence. This is NOT
    # fabrication: the anti-fabrication check below still verifies the observed
    # text against the fetched corpus, so a derived entry survives only if the
    # evidence is genuinely traceable.
    if p2.get("confirmed") and not any(
        isinstance(p, dict) and p.get("verdict") == "CONFIRMED" for p in preds
    ):
        ev = p2.get("evidence") or p1.get("evidence") or []
        joined = " ".join(str(e) for e in ev[:3])
        # Only manufacture a CONFIRMED prediction when the branch's own evidence
        # carries at least one distinctive, corpus-traceable FACT (identifier,
        # value, error code). A purely prose "confirmation" with no verifiable
        # specific is an assertion, not a test — it must NOT uphold confirmed=true
        # or feed a HIGH raise (the prose-confirmed loophole). Without a traceable
        # fact the confirmation stays voided below.
        if ev and _has_traceable_fact(joined, json.dumps(branch_fetched, default=str).lower()):
            preds.append({
                "prediction": getattr(h, "focus", "") or getattr(h, "reason", "") or "branch hypothesis",
                "verdict": "CONFIRMED",
                "observed": " ".join(str(e) for e in ev[:2]),
                "_derived": "confirmed with evidence but predictions_tested was empty",
            })

    # Anti-fabrication check: a CONFIRMED verdict must quote data that actually
    # exists in this branch's fetched corpus. A model can hallucinate the test
    # result just as confidently as a diagnosis — so the quote is verified
    # deterministically, and an untraceable "observation" downgrades to UNTESTED
    # (which the veto below then treats as no confirmation).
    corpus = json.dumps(branch_fetched, default=str).lower()
    for p in preds:
        if p.get("verdict") != "CONFIRMED":
            continue
        ok, reason = _observed_is_traceable(p.get("observed", ""), corpus)
        if not ok:
            p["verdict"] = "UNTESTED"
            p["_downgraded"] = reason
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
        voi_early_stop=bool(p2.get("_voi_early_stop", False)),
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
                state.get("failure_map"),
            ): h
            for h in state["hypotheses"]
        }
        for f in as_completed(futures):
            try:
                result = f.result()
            except Exception as exc:  # noqa: BLE001
                # Isolate one branch's failure (mid-flight IAM expiry, a Bedrock
                # exception, a bug in post-loop scoring) so the OTHER branches'
                # work is not discarded. Catch Exception only: BudgetExceededError
                # is a BaseException and still propagates — that abort is
                # deliberate (spend ceiling), and must stop the whole run.
                h = futures[f]
                log.error("investigation branch %r failed, continuing with the "
                          "others: %s", getattr(h, "service", h), exc)
                # Record a marker branch so synthesis KNOWS this hypothesis was
                # left uninvestigated — otherwise it silently vanishes and the
                # alternatives_considered step confabulates a ruling-out reason.
                hyp = h if isinstance(h, dict) else {"service": str(h), "reason": "", "focus": ""}
                branch_results.append({
                    "hypothesis": hyp,
                    "evidence": [],
                    "conclusion": f"investigation branch did not complete ({type(exc).__name__}); "
                                  "this hypothesis was NOT ruled out — it was never fully tested",
                    "confidence": "LOW",
                    "confirmed": False,
                    "tools_called": [],
                    "predictions_tested": [],
                    "_branch_error": f"{type(exc).__name__}: {exc}"[:200],
                })
                continue
            branch_results.append(result.model_dump())
            _merge_fetched(all_fetched_merged, result.all_fetched)

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
        per_group: list[list[str]] = []
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
                lines_here: list[str] = []
                for evt in events[:20]:
                    msg = evt.get("event", "").strip()
                    if msg:
                        ts = evt.get("time", "")
                        lines_here.append(f"[{ts}] [{short}] {msg[:300]}")
                if lines_here:
                    per_group.append(lines_here)
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"[:300]
        # Round-robin across groups so one noisy group can't starve the 80-line
        # window that feeds the model — every active service gets represented.
        events_out = _round_robin_merge(per_group)
        # Frequency view over everything fetched — the per-group line sample
        # can miss a flood entirely; template counts cannot.
        templates = [
            f"count={t['count']} :: {t['template'][:160]}"
            for t in _mine_log_templates(raw_events)
        ]
        # LOCALIZE pillar: from the SAME fetched events, determine which components
        # are actually EMITTING failures now (service-agnostic — reports what is
        # failing, never judges config). This anchors the diagnosis on the emitting
        # component instead of a quiet one that merely looks unusual.
        from cloudctl.debug.localize import localize_failures
        comp_logs: dict = {}
        for evt in raw_events:
            g = evt.get("_group", "")
            m = (evt.get("event", "") or "").strip()
            if g and m:
                comp_logs.setdefault(g, []).append(m)
        failure_map = localize_failures(comp_logs)
        return {"events": events_out, "groups": grps, "templates": templates,
                "error": err, "failure_map": failure_map}

    survey = recorded("log_survey", {"minutes": state["minutes"]}, _survey)
    if not isinstance(survey, dict):
        survey = {"events": [], "groups": [], "error": "unreplayable survey record"}
    all_events = survey.get("events", [])
    groups = survey.get("groups", [])
    survey_error = survey.get("error", "")
    failure_map = survey.get("failure_map", []) if isinstance(survey, dict) else []

    if not all_events:
        # Explain the empty result — an unexplained {} hid the survey bug for runs.
        return {"log_insights": {
            "_error": survey_error or (
                f"no log events in window; {len(groups)} recently-active "
                f"log groups found: {groups[:8]}"
            ),
        }, "failure_map": failure_map}

    log_text = "\n".join(all_events[:80])
    template_text = "\n".join(survey.get("templates", [])[:12])
    bedrock = _make_bedrock(state["profile"], state["region"])

    def _converse_logintel():
        return bedrock.converse(
            modelId=_LOG_INTEL_MODEL,
            system=_sys(_LOG_INTEL_SYSTEM),
            messages=[{"role": "user", "content": [{"text": (
                f"INCIDENT SYMPTOM: {state['symptom']}\n\n"
                f"LINE-SHAPE FREQUENCIES (count per structural template, all "
                f"fetched lines):\n{template_text or '(none)'}\n\n"
                f"LOG LINES ({len(all_events)} total):\n{log_text}"
            )}]}],
            inferenceConfig={"maxTokens": 800, "temperature": 0},
        )

    try:
        try:
            resp = _converse_logintel()
        except Exception as exc:  # noqa: BLE001
            # _make_bedrock already sets adaptive retries (max_attempts=10), so
            # most throttling is absorbed; this explicit last-resort retry means
            # a burst throttle can't silently drop the PRISM log signal and leave
            # the discriminate node blind.
            if "throttl" in (type(exc).__name__ + str(exc)).lower():
                import time as _t
                _t.sleep(2)
                resp = _converse_logintel()
            else:
                raise
        text = resp["output"]["message"]["content"][0]["text"].strip()
        insights = _extract_json(text, "behavioral_consistency") or {}
        if not isinstance(insights, dict):
            insights = {"_error": f"unparseable log-intel output: {text[:200]}"}
    except Exception as exc:
        insights = {"_error": f"{type(exc).__name__}: {exc}"[:300]}

    return {"log_insights": insights, "failure_map": failure_map}


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
  EXCEPTION — a directly observed STRUCTURAL absence (the resource does not
  exist, a feature is explicitly disabled, a required binding is entirely
  missing) is itself a confirmed observation and counts as strong support even
  if the branch did not frame it as a formal "prediction" entry — do not
  discount a directly observed structural fault merely because predictions_tested
  is empty.
  ATTRIBUTION vs EXISTENCE — a REFUTED prediction eliminates a hypothesis ONLY
  when it bears on the fault's EXISTENCE or MECHANISM (whether the misconfig /
  denial / breakage is really present, and whether it explains the symptom). A
  prediction about ATTRIBUTION — WHEN or HOW the fault was introduced, e.g. "a
  change-event for this appears in the audit trail (CloudTrail) at onset" —
  being refuted does NOT eliminate a hypothesis whose fault is DIRECTLY OBSERVED
  in current state (a live misconfiguration read now, or a permission the policy
  simulator returns as denied now). Audit trails have gaps (console actions,
  other principals, retention/lookback windows): a missing change-event revises
  WHEN/HOW the fault arose, never WHETHER it exists. Treat such a refutation as
  "weakens attribution", and still weigh the directly observed fault — which, if
  it explains the symptom, can be the root cause even without a traced change.
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
  A deployment is BOTH a source of transient noise AND the single most common
  real root cause — do not conflate the two:
    - TRANSIENT deployment artifacts: errors during the rollout window (instance
      or container replacement, image pulls, routing re-registration) that STOP
      once the rollout settles. These are noise; discount them.
    - REGRESSION introduced by the change: errors that BEGIN at/just after
      last_changed_at and PERSIST. A bad deploy is a leading root-cause
      candidate, not noise — if the symptom coincides with a change and persists,
      the change is a PRIME SUSPECT. Examine WHAT it changed (diff the new config
      against peers or prior intent); never dismiss a persistent post-deploy
      regression as "deployment churn".
  So: discard errors that ended when the rollout settled; but treat errors that
  started at the deploy and continue as valid incident evidence pointing at the
  change itself. Events strictly BEFORE the deployment predate this change.

Rule 1 — Behavioral consistency (evidence to weigh, not a verdict):
  behavioral_consistency reports the SHAPE of the anomaly across the fleet:
  "uniform" = every replica shows it, "partial" = only some replicas, and
  "single_request" = one request dominates the log volume. Treat this as one
  piece of evidence and infer the cause from what the evidence ACTUALLY shows —
  do not map a shape to a cause category by itself, and do not let a shape
  override a directly observed failing interaction with a specific resource.

Rule 2 — Evidence quality test:
  Prefer evidence from direct observation (log line content, metric value)
  over inferences. "The data shows X" is observation; "X COULD mean Y" is
  inference — an inference never outweighs a direct observation.
  A REPRODUCED response (the failing operation actually exercised, its concrete
  status/body/timing captured, e.g. under reproduction_observed) is the
  strongest direct observation of the symptom itself: weigh it above telemetry
  ABOUT the operation, and treat a proposed mechanism that would have produced
  a DIFFERENT concrete response as contradicted by the reproduction.

Rule 3 — Parsimony:
  The simplest explanation consistent with ALL observations is preferred.

Return ONLY this JSON. Emit the three decision fields FIRST so they survive
even if the response is truncated; the classifications array comes last:
{
  "cause_category": "application_code | infrastructure | configuration | dependency",
  "cause_category_confidence": "LOW | MEDIUM | HIGH",
  "investigation_constraint": "One binding sentence for synthesis, e.g.: The anomaly is uniform across all replicas with identical infrastructure — the root cause is application code behavior, not an AWS service failure.",
  "evidence_classifications": [
    {
      "evidence": "quote from branch result or log analysis",
      "category": "application_code | infrastructure | configuration | dependency",
      "rule_applied": "1 | 2 | 3",
      "reasoning": "one sentence"
    }
  ]
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
            inferenceConfig={"maxTokens": 1500, "temperature": 0},
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
  1. A hypothesis with a REFUTED prediction cannot be the root cause — UNLESS the
     only refuted prediction is about ATTRIBUTION (when/how the fault was
     introduced, e.g. a change-event expected in CloudTrail at onset) while the
     fault itself is DIRECTLY OBSERVED in current state (a live misconfiguration
     or a permission the policy simulator denies now). A missing change-event
     revises when/how the fault arose, never whether it exists; do not discard a
     directly observed, symptom-explaining fault for lack of an audit-trail entry.
  2. The root cause must have at least one CONFIRMED prediction backed by
     directly observed data. If no hypothesis meets this bar, say exactly that:
     root_cause = what was ruled out and what observation is still needed,
     confidence = LOW. An honest "not proven" beats a constructed narrative.
  3. symptom_observable_now=false means the symptom was not visible in the
     metrics/logs sampled — it does NOT mean the stack is healthy or the alert is
     a false alarm. Many real faults are SILENT: a config that rejects requests,
     a removed auth flow, a wrong identifier, a denied permission — these fail the
     user with ZERO error metric or log on the failing component. You may declare
     the reported symptom a false alarm / the stack healthy / "nothing wrong" ONLY
     if you POSITIVELY exercised the reported failing path and observed it SUCCEED
     (e.g. probe_http returned success on the user-facing path, or an operation
     you ran completed). Absence of errors is NOT evidence of health. If you can
     neither localize a fault NOR demonstrate the failing path succeeds, the
     correct verdict is: root_cause = "fault not localized; failing path not
     verified healthy — needs deeper investigation", confidence = LOW. NEVER a
     confident all-clear on a reported failure.
  4. A resource that does NOT currently exist cannot be the primary root cause of
     a currently-FAILING live stack. If your leading cause cites a resource that
     a live read returns as NotFound/absent, either it was recreated (re-read the
     CURRENT resource by name and diagnose that) or it is a stale audit-trail
     artifact from an earlier teardown — in both cases prefer a fault you can
     verify in the stack's CURRENT state, on the path the symptom describes. A
     directly-observed current-state fault on the failing path OUTRANKS a
     change-event narrative about a resource that is gone.
  5. Root-cause events must precede the measured onset. Events from our own
     deployment activity before onset are not causes.

MECHANISM & FRONTIER (the honesty test — apply to your chosen cause before shipping):
  Trace the causal chain from your root cause to the REPORTED symptom, link by
  link, and label each link OBSERVED (you have direct data for it) or ASSUMED
  (you inferred it). A confident verdict requires that every LOAD-BEARING link is
  OBSERVED — including the link that the cause actually produces the symptom's
  failure. A directly-observed misconfiguration whose mechanical effect you can
  show (a filter that cannot match, a flow that is absent, a permission the
  simulator denies) is OBSERVED even if it emitted no error — silent faults are
  real. But an ASSUMED link — "this component must use this value", "this is
  probably the failing path" — that you did not verify is NOT grounding.
  If a load-bearing link is ASSUMED, or you never observed the reported failure
  and cannot show the mechanism produces it, you are at the FRONTIER of what you
  can prove. Do NOT fabricate a cause to fill the gap. Emit the honest verdict:
    root_cause = "Localized to <the furthest point you verified>. Could not
    verify <the specific unobserved link>; the reported failure was not observed
    directly. To confirm: <reproduce the operation / instrument the path / read
    the component's code>.", confidence = LOW.
  An honest frontier verdict that tells the operator where you got to and what is
  needed is worth far more than a confident guess that sends them down a dead end
  — and it is the ONLY safe output on a system whose internals you cannot see.

REPRODUCED RESPONSE CONSISTENCY (binding whenever the operation was actually
exercised): if the investigation REPRODUCED the failing operation — an HTTP
probe with a concrete response (status, body, timing), OR a native control-plane
evaluation/test with a concrete produced result (evaluation output, or test
status/body/logs) — that concrete result is the primary ground truth for the
failure MECHANISM, and the specific cause you assert must be CONSISTENT with it.
Treat a native evaluation result the same as an HTTP response:
  - a result that SUCCEEDED but carried wrong, empty, or missing payload (e.g. a
    template evaluation that produced null/omitted fields, or a 200 with an
    empty body) points at whatever PRODUCES the payload (data, mapping,
    transformation, logic) — it RULES OUT latency, timeout, reachability, and
    availability mechanisms for that operation;
  - an authentication/authorization rejection points at the credential or the
    auth configuration handshake between caller and entry point (but if the
    probe carried NO credential — auth_sent=false — the rejection may only
    reflect the missing credential and is inconclusive);
  - a server-side error status points at the component behind the entry point;
  - only an actually observed timeout or connection failure supports a latency
    or reachability mechanism.
Never assert a specific mechanism that would have produced a DIFFERENT concrete
response than the one observed. If reproduction was attempted but not possible
(unreachable, no credential, declined, non-HTTP), the response-level mechanism
is at the FRONTIER: apply the rule above — do not invent what the response
"would have been".

DIFFERENTIAL EVIDENCE (when present): a configuration field that CHANGED at or
near the measured onset on the failing path, or a field where the failing
resource DIFFERS from otherwise-identical sibling resources, is a prime suspect
— cite the old→new (or peer-vs-peer) values verbatim in evidence. A diff alone
is NOT proof: the changed/divergent value must still explain the observed
failure under the MECHANISM and REPRODUCED-RESPONSE rules above. A diff that
cannot produce the observed symptom is context, not cause.

Select the hypothesis with the strongest direct evidence from real AWS data.
If multiple branches found real issues, list them all in evidence.
Treat unconfirmed or low-confidence branches as ruled-out alternatives.

MULTIPLE INDEPENDENT CAUSES: usually one root cause explains the whole symptom.
But if TWO OR MORE branches each CONFIRM a distinct fault (each with its own
CONFIRMED prediction) and neither explains the other — they are independent
faults, not competing hypotheses — do NOT force-pick one. Report the primary
root cause, and add an "additional_causes" list naming each other confirmed
fault with its evidence, so a real cascade or coincident-failure incident is
not silently reduced to a single cause. Only genuinely CONFIRMED, non-
overlapping faults qualify; a weakly-supported second branch stays a ruled-out
alternative.
  BAR FOR A SECONDARY / ADDITIONAL CAUSE (apply the SAME standard you apply to
  the primary): it must INDEPENDENTLY explain part of the REPORTED symptom and be
  tied to an OBSERVED failure of a path that is actually exercised. A mere
  configuration DIFFERENCE is not a fault: a permission a component never uses, a
  value that is absent but unread, a setting that differs from a sibling but
  breaks nothing — none of these are "confirmed faults", and appending them as
  additional/secondary causes is noise that misleads the operator. State ONE
  primary cause; add a secondary ONLY when the reported symptom would still occur
  because of it. Do not pad the diagnosis with incidental observations.

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


_TRACE_STRUCT = set(".:/_-")


def _distinctive_tokens(text: str) -> list[str]:
    """Extract the DISTINCTIVE fact tokens from text — those carrying a digit
    or a structural char (identifiers, ARNs, values, error codes). Purely
    shape-based: no service, resource, or scenario vocabulary. Shared by the
    anti-fabrication checks and the provenance builder so they agree on what
    counts as a verifiable specific."""
    tokens = re.findall(r"[a-z0-9][a-z0-9_.\-:/]{4,}", (text or "").lower())
    return [
        t for t in tokens
        if any(c.isdigit() for c in t) or any(c in _TRACE_STRUCT for c in t)
    ]


def _observed_is_traceable(observed: str, corpus: str) -> tuple[bool, str]:
    """Anti-fabrication: a CONFIRMED prediction must quote data that actually
    exists in the fetched corpus. Fabrication lives in specific FACTS —
    identifiers, ARNs, values, error codes — NOT in prose, which a real
    observation naturally phrases in the model's own words. So verify the
    DISTINCTIVE tokens (those carrying a digit or a structural char) trace to the
    corpus and ignore plain words; requiring half of ALL words to match (the old
    rule) wrongly downgraded legitimate observations whose facts were real but
    surrounded by prose. Returns (traceable, downgrade_reason)."""
    distinctive = _distinctive_tokens(observed)
    if not distinctive:
        # No specific fact was cited — nothing fabricatable to verify; do not
        # penalise a legitimately prose-phrased observation on this check.
        return True, ""
    matched = sum(1 for t in distinctive if t in corpus)
    if matched * 2 < len(distinctive):
        return False, ("observed facts not traceable to fetched data "
                       f"({matched}/{len(distinctive)} specific tokens found)")
    return True, ""


def _has_traceable_fact(text: str, corpus: str) -> bool:
    """True only when `text` carries at least one DISTINCTIVE fact (a token with
    a digit or structural char — an identifier, value, error code) that actually
    traces to the corpus. Unlike _observed_is_traceable (which passes pure prose
    to avoid downgrading legitimate prose observations), this REQUIRES a verified
    specific — used to gate manufacturing a CONFIRMED verdict out of prose."""
    return any(t in corpus for t in _distinctive_tokens(text))


# ── Provenance trail (deterministic claim → source grounding) ─────────────────

def _salient_tokens(text: str) -> list[str]:
    """Tokens a claim can be GROUNDED on: the distinctive fact tokens (see
    _distinctive_tokens), cleaned of trailing sentence punctuation so prose like
    "…exhausted." is not mistaken for an identifier, plus standalone multi-digit
    numbers (comma-normalized, so "12,000" matches a raw "12000"). Entirely
    shape-based — generic across any service or scenario."""
    norm = re.sub(r"(?<=\d),(?=\d)", "", (text or "").lower())
    out: list[str] = []
    for t in _distinctive_tokens(norm):
        t = t.rstrip("._-:/")
        # Re-check distinctiveness after stripping trailing punctuation — a
        # prose word that was "distinctive" only via its sentence period is not
        # a verifiable fact.
        if len(t) >= 5 and (any(c.isdigit() for c in t)
                            or any(c in _TRACE_STRUCT for c in t)):
            out.append(t)
    for n in re.findall(r"\d{2,}(?:\.\d+)?", norm):
        if not any(n in t for t in out):
            out.append(n)
    return list(dict.fromkeys(out))


def _split_claims(report: dict) -> list[str]:
    """The claims a report makes: each evidence[] item, plus each root_cause
    sentence (deterministic sentence split — no model call). Deduplicated,
    order-preserving."""
    claims: list[str] = []
    for e in report.get("evidence") or []:
        if isinstance(e, str) and e.strip():
            claims.append(e.strip())
    for s in re.split(r"(?<=[.!?])\s+", str(report.get("root_cause") or "")):
        s = s.strip()
        if s:
            claims.append(s)
    return list(dict.fromkeys(claims))


def _quote_from(entry_text: str, token: str, window: int = 45) -> str:
    """Short verbatim snippet from the stored evidence value around the first
    occurrence of the matched token."""
    i = entry_text.find(token)
    if i < 0:
        return ""
    start = max(0, i - window)
    end = min(len(entry_text), i + len(token) + window)
    snippet = re.sub(r"\s+", " ", entry_text[start:end]).strip()
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(entry_text) else ""
    return (prefix + snippet + suffix)[:140]


def _build_report_provenance(
    report: dict, all_fetched: dict
) -> tuple[list[dict], list[str]]:
    """Deterministic grounding pass: map each reported claim to the all_fetched
    entries (keyed by _evidence_key — the existing per-tool-call citation ids)
    whose stored value actually contains the claim's salient tokens.

    Generic by construction: matching is purely token-shape based (identifiers,
    values, error codes appearing verbatim in the stored data) — no service,
    tool, or scenario vocabulary. Claims with NO salient tokens are pure prose:
    nothing fabricatable to verify, so they are neither cited nor flagged
    (mirrors _observed_is_traceable). Claims WITH salient tokens that trace to
    zero entries are returned as unsourced — a flag/weight for the confidence
    path, never a hard cap. With an EMPTY corpus nothing can be distinguished
    from a missing fetch, so nothing is flagged.

    Returns (provenance_entries, unsourced_claims)."""
    entries: dict[str, str] = {}
    for k, v in (all_fetched or {}).items():
        try:
            entries[str(k)] = json.dumps(v, default=str).lower()
        except Exception:  # noqa: BLE001
            entries[str(k)] = str(v).lower()

    provenance: list[dict] = []
    unsourced: list[str] = []
    if not entries:
        return provenance, unsourced

    for claim in _split_claims(report):
        toks = _salient_tokens(claim)
        if not toks:
            continue  # pure prose — nothing verifiable either way
        scored: list[tuple[int, str, list[str]]] = []
        for key, text in entries.items():
            matched = [t for t in toks if t in text]
            if matched:
                scored.append((len(matched), key, matched))
        if not scored:
            unsourced.append(claim)
            continue
        # Most-covering sources first; key as deterministic tie-break.
        scored.sort(key=lambda s: (-s[0], s[1]))
        top = scored[:3]
        best_key, best_matched = top[0][1], top[0][2]
        provenance.append({
            "claim": claim,
            "evidence_keys": [k for _, k, _ in top],
            "quote": _quote_from(entries[best_key], best_matched[0]),
        })
    return provenance, unsourced


# ── Observability gap: make the ABSENCE of tracing productive ─────────────────

# Generic symptom-class detector. Latency / timeout / error-propagation is the
# incident class distributed tracing localizes best. These are METHODOLOGY
# keywords about the SHAPE of the symptom — not service or scenario knowledge —
# so classification stays hint-free.
_LATENCY_CLASS_RE = re.compile(
    r"\b(slow(?:ness|ing|er)?|latenc|timing\s*out|time[\s-]*out(?:s|ing)?|timed\s*out|"
    r"degrad|laggy?|hang(?:s|ing)?|stall(?:s|ing|ed)?|"
    r"unrespons|delay(?:s|ed|ing)?|"
    r"p9\d|p99|percentile|"
    r"propagat|cascad|downstream|upstream|call\s*(?:graph|chain|path)|"
    r"5\d\d\b|error\s*rate|errors?\s+(?:spread|propagat|cascad))",
    re.IGNORECASE,
)

_TRACING_RECOMMENDATION = (
    "No distributed tracing was available for this incident. Enabling AWS X-Ray "
    "(or OpenTelemetry) active tracing on the services in the call path would "
    "localize this class of failure to a single hop in future incidents."
)


def _is_latency_propagation_class(symptom: str) -> bool:
    """True when the symptom reads as a latency / timeout / error-propagation
    incident — the class distributed tracing localizes best. Purely keyword-shape
    based; carries no service or scenario knowledge."""
    return bool(_LATENCY_CLASS_RE.search(symptom or ""))


def _traces_were_unavailable(all_fetched: dict) -> bool:
    """True only when get_traces WAS called and EVERY call reported
    available=false. If tracing was never attempted, or any call returned data,
    this is False — so the recommendation never fires on traces-available runs
    and never claims tracing is absent when it was simply not queried."""
    saw_call = False
    for key, val in (all_fetched or {}).items():
        if not str(key).startswith("get_traces"):
            continue
        saw_call = True
        # A dict result with available truthy means tracing DID return data.
        if isinstance(val, dict) and val.get("available"):
            return False
    return saw_call


def _maybe_add_tracing_recommendation(report: dict, symptom: str,
                                      all_fetched: dict) -> dict:
    """Remediation-only addendum: when the incident is latency/propagation class
    AND tracing was queried but unavailable, append ONE generic observability
    recommendation. Never touches root_cause or confidence, never duplicates,
    and never fires when traces were available or the symptom is another class."""
    if not _is_latency_propagation_class(symptom):
        return report
    if not _traces_were_unavailable(all_fetched):
        return report
    steps = list(report.get("remediation_steps") or [])
    if any("distributed tracing was available" in str(s) for s in steps):
        return report   # already present — don't spam
    steps.append(_TRACING_RECOMMENDATION)
    report["remediation_steps"] = steps
    return report


def _calibrate_confidence(all_branch_results: list[dict],
                          agent_conf: str,
                          chosen_root_cause: str = "",
                          arbitrated: bool = False) -> tuple[str, str | None]:
    """VERDICT confidence calibration. Pure function so the policy is
    unit-testable without a live model.

    Confidence reflects what the ANALYSIS earned, not a cautious default. It is
    LOWERED only for concrete, analysis-grounded reasons — no real evidence, an
    unresolved contest between hypotheses, or a winner that refuted its own
    prediction — and RAISED when an under-rated answer carries objective
    verification (a confirmed prediction with no alternative verified). A single
    dominant, self-consistent branch keeps the level its reasoning earned,
    including HIGH; it is never capped merely to be safe.

    Returns (confidence_level, calibration_note_or_None).
    """
    _order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

    def _pred_stats(br: dict) -> tuple[int, int]:
        preds = [p for p in br.get("predictions_tested", []) if isinstance(p, dict)]
        return (
            sum(1 for p in preds if p.get("verdict") == "CONFIRMED"),
            sum(1 for p in preds if p.get("verdict") == "REFUTED"),
        )

    confirmed = [br for br in all_branch_results if br.get("confirmed")]
    evidenced = [
        br for br in all_branch_results
        if len(br.get("evidence") or []) >= 3 and br.get("conclusion")
    ]
    # A branch "stands" if it is verified (confirmed) or well-evidenced. Prefer a
    # verified branch as the winner; otherwise the well-evidenced one.
    standing = confirmed or evidenced

    # Nothing to be confident about — no branch confirmed a prediction or produced
    # substantial evidence.
    if not standing:
        return "LOW", "no branch confirmed a prediction or produced substantial evidence"

    def _pick_winner(cands: list[dict]) -> dict:
        # Calibrate the branch the FINAL report actually selected — matched by the
        # branch's service name and its distinctive evidence tokens appearing in
        # the chosen root cause — not an arbitrary as_completed() ordering. This
        # stops the HIGH-raise / LOW-cap from being computed off a branch other
        # than the one whose cause shipped.
        rc = (chosen_root_cause or "").lower()
        if rc:
            best, best_score = None, 0
            for br in cands:
                svc = str(br.get("hypothesis", {}).get("service", "")).lower()
                score = 2 if (svc and len(svc) >= 3 and svc in rc) else 0
                for e in (br.get("evidence") or [])[:5]:
                    toks = re.findall(r"[a-z0-9][a-z0-9_.\-:/]{4,}", str(e).lower())
                    if any((any(c.isdigit() for c in t) or any(c in _TRACE_STRUCT for c in t))
                           and t in rc for t in toks):
                        score += 1
                        break
                if score > best_score:
                    best, best_score = br, score
            if best is not None:
                return best
        return cands[0]

    # Genuinely unresolved — the analysis could not separate ≥2 competing causes
    # (two verified-but-contradicting, or two well-evidenced and neither verified).
    # This is the analysis's OWN uncertainty, not caution. EXCEPT when an
    # arbitration branch was run to resolve the contradiction: it produced a
    # ruling, so defer to the chosen winner rather than permanently capping every
    # resolved contest at MEDIUM.
    if not arbitrated and (len(confirmed) >= 2 or (not confirmed and len(evidenced) >= 2)):
        return ("MEDIUM" if _order.get(agent_conf, 0) > 1 else agent_conf,
                "two hypotheses retain substantial/verified support — unresolved")

    winner = _pick_winner(standing)

    # The winning hypothesis refuted its OWN prediction — its conclusion is unsafe.
    if _pred_stats(winner)[1] > 0:
        return "LOW", "winning hypothesis has a refuted prediction of its own"

    # Objective verification the model may have UNDER-rated: a confirmed prediction
    # with no alternative verified justifies raising a too-low confidence.
    n_conf, _ = _pred_stats(winner)
    alt_verified = any(_pred_stats(br)[0] > 0
                       for br in all_branch_results if br is not winner)
    if n_conf >= 1 and not alt_verified and _order.get(agent_conf, 0) < _order["HIGH"]:
        return "HIGH", ("raised: winning hypothesis has a confirmed prediction and "
                        "no alternative was verified")

    # Otherwise confidence follows the analysis — the dominant, self-consistent
    # branch keeps the level its reasoning earned, HIGH included.
    return agent_conf, None


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
                failure_map=state.get("failure_map"),
            )
            all_branch_results.append(arb_result.model_dump())
            _merge_fetched(all_fetched_merged, arb_result.all_fetched)
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
        # Gate how binding the constraint is on ITS OWN confidence. A LOW /
        # unclear category call is one weak signal, not a veto — treating it as
        # binding let a sparse-log category guess override a correct root cause.
        # And even a HIGH constraint must yield to a directly observed failing
        # interaction (a specific observation outweighs a category inference),
        # which also lets a reinvestigation's new evidence win over a stale call.
        _binding = str(category_conf).upper() in ("HIGH", "MEDIUM")
        if _binding:
            discrimination_block = (
                f"CAUSAL DISCRIMINATION RESULT (cause_category={category}, "
                f"confidence={category_conf}):\n"
                f"CONSTRAINT: {constraint}\n"
                f"Respect this constraint when selecting the root cause UNLESS a "
                f"branch presents directly observed evidence (a specific observed "
                f"failing interaction with a named resource) that contradicts it — "
                f"a direct observation outweighs a category inference. Absent such "
                f"evidence, do not attribute the cause to a different category."
            )
        else:
            discrimination_block = (
                f"CAUSAL DISCRIMINATION SIGNAL (cause_category={category}, "
                f"confidence={category_conf} — low/uncertain, ADVISORY ONLY):\n"
                f"{constraint}\n"
                f"This category call is low-confidence; treat it as one weak signal, "
                f"not a constraint. Let directly observed branch evidence decide."
            )
    else:
        discrimination_block = ""

    # LOCALIZE pillar: tell synthesis which components are ACTUALLY emitting
    # failures now, so it anchors the root cause on an emitting component instead
    # of building a story around a quiet one that merely looks unusual.
    _fmap = state.get("failure_map") or []
    if _fmap:
        _emitting = "; ".join(
            f"{e.get('component')} (errors={e.get('error_count')}): {str(e.get('sample',''))[:140]}"
            for e in _fmap[:5]
        )
        discrimination_block = (
            "OBSERVED FAILURE MAP — components actually EMITTING failures right now "
            "(the failure is localized HERE, not on a quiet component):\n"
            f"{_emitting}\n"
            "Anchor your root cause on one of these emitting components and diagnose "
            "from ITS own logs/config. If your leading cause is a component that is "
            "NOT in this list, you are mis-localized — inspect the emitting component "
            "first before concluding.\n\n"
        ) + discrimination_block

    # ABSENCE reasoning (no hardcoded field names — the model reads the config it
    # already fetched and reasons): a fault can be an ABSENCE — expected behaviour
    # that simply never happens, which emits no error to localize to. This rule
    # names no service and no field; it tells the model to consider the shape.
    discrimination_block = (
        "ABSENCE CHECK — before blaming a component that is merely logging, ask "
        "whether the reported failure is that something EXPECTED never HAPPENS (a "
        "process that never runs, a result that never appears, a step that is "
        "skipped). If so, the fault is usually that the mechanism which SHOULD "
        "produce it is turned off, not connected, or never invoked — verify from "
        "the fetched configuration that the expected mechanism is actually enabled "
        "and wired end-to-end. An absent/disabled mechanism explains a "
        "nothing-happens symptom better than a component's benign normal activity.\n\n"
    ) + discrimination_block

    system = _SYNTHESIZE_PROMPT.format(
        n=len(all_branch_results),
        discrimination_constraint=discrimination_block,
    )
    # Strip all_fetched + tools_called before synthesis — they can be 20-30K tokens
    # of raw tool responses that synthesize never uses. Only evidence + conclusion matter.
    # Rung 2 — reference-not-regenerate: parallel branches frequently cite the
    # SAME evidence string. Assign each unique item an id (E1, E2, ...) once and
    # replace repeats across branches with that id, so synthesize reads each
    # distinct fact a single time instead of N times. Lossless — the full text
    # lives in the catalog below. (compact separators = rung 1.)
    _ev_ids: dict = {}

    def _ref(ev_list):
        out = []
        for e in ev_list or []:
            s = str(e)
            if s not in _ev_ids:
                _ev_ids[s] = f"E{len(_ev_ids) + 1}"
                out.append({"id": _ev_ids[s], "text": s})
            else:
                out.append(_ev_ids[s])   # already stated — reference only
        return out

    branches_slim = [
        {
            "hypothesis": br.get("hypothesis", {}),
            "evidence":   _ref(br.get("evidence", [])),
            "predictions_tested": br.get("predictions_tested", []),
            "conclusion": br.get("conclusion", ""),
            "confidence": br.get("confidence", "LOW"),
            "confirmed":  br.get("confirmed", False),
        }
        for br in all_branch_results
    ]
    branches_text = json.dumps(branches_slim, separators=(",", ":"))
    obs = state.get("observation") or {}
    user_content = (
        f"Symptom: {state['symptom']}\n\n"
        f"Measured observation (real data, gathered before investigation):\n"
        f"{json.dumps(obs, indent=2) if obs else '(measurement unavailable)'}\n\n"
        f"Branch investigation results (evidence items appear as {{id,text}} on "
        f"first mention and as the bare id \"E#\" when another branch cites the "
        f"same fact — both refer to the identical evidence):\n{branches_text}"
        f"{arbitration_note}"
    )

    try:
        resp = bedrock.converse(
            modelId=_MODEL,
            system=_sys(system),
            messages=[{"role": "user", "content": [{"text": user_content}]}],
            inferenceConfig={"maxTokens": 2500, "temperature": 0},
        )
    except Exception as exc:  # noqa: BLE001
        # Do NOT crash a fully-completed investigation on a synthesis-call error
        # (exhausted-retry throttle, transient network). Assemble a best-effort
        # report from the strongest branch so the gathered evidence isn't lost.
        best = max(
            all_branch_results,
            key=lambda br: (bool(br.get("confirmed")), len(br.get("evidence") or [])),
            default={},
        )
        return {"final_report": {
            "root_cause": (best.get("conclusion")
                           or f"Synthesis step failed ({type(exc).__name__}); "
                              "reporting strongest branch finding."),
            "evidence": best.get("evidence", []),
            "remediation_steps": [],
            "severity": "UNKNOWN",
            "confidence": "LOW",
            "resources_investigated": [],
            "_synthesis_error": f"{type(exc).__name__}: {exc}"[:200],
        }, "all_fetched": all_fetched_merged, "branch_results": all_branch_results}
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
    # not branch agreement (see _calibrate_confidence for the policy).
    _conf, _cal_note = _calibrate_confidence(
        all_branch_results, result.get("confidence", "LOW"),
        chosen_root_cause=result.get("root_cause", ""),
        arbitrated=bool(arbitration_note),
    )
    result["confidence"] = _conf
    if _cal_note:
        result["confidence_calibration"] = _cal_note

    # Provenance trail: deterministically map every reported claim to the
    # fetched-corpus entries that actually contain its facts. (Rebuilt once more
    # in debug_incident_graph against the FINAL report/corpus, since critique
    # may revise claims and the observation is folded into the corpus there.)
    _prov, _unsourced = _build_report_provenance(result, all_fetched_merged)
    result["provenance"] = _prov
    result["unsourced_claims"] = _unsourced

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

CORE TEST — VERIFY, DON'T ASSUME. This is the root of every check below. Any
claim that something is ABSENT, not the cause, fine, healthy, permitted, or that
a fault CANNOT be confirmed, is valid ONLY if it traces to an actual observation
that CHECKED that thing — never to an assumption, a default belief, or a
DERIVED/predicted proxy (a simulator result, a metric, a "usually", "should
be"). Negative and "all clear" claims are exactly where unverified assumptions
hide, because — unlike a positive finding — they require no discovery to state.
Whenever the conclusion rests on an unverified absence or negative, reject it
with "needs_reinvestigation" naming the specific check that would actually
confirm it. The tests below are named instances of this one principle:

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

2. DEPLOYMENT NOISE TEST — Is the conclusion anchored to the MECHANICS of our OWN
   infrastructure management (instance or container replacement, image pulls,
   routing re-registration) rather than a real fault? That churn appears after
   EVERY deployment and is rarely the cause.
   KEY RULE: Compare evidence timestamps against get_deployment_info's last_changed_at.
   Transient errors that occur DURING the rollout and STOP once it settles are
   artifacts. BUT do not over-apply this: a bad deployment is the most common real
   root cause. If the symptom BEGAN at the deployment and PERSISTS, the change
   itself is the prime suspect — the correct verdict is to find WHAT changed
   (diff config against peers/prior intent), NOT to dismiss it as deployment
   noise. Only dismiss errors that demonstrably ended when the rollout finished.

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

7. FABRICATION TEST (you are armed with the FETCHED INVENTORY below — the actual
   resources, services, and data the investigation looked at). Every resource,
   component, system, or mechanism the root cause hinges on must correspond to
   something in that inventory. If the conclusion invokes a component or causal
   mechanism that appears NOWHERE in the fetched inventory — a process, system,
   or component nobody actually observed — it is FABRICATED, no matter how
   plausible it sounds. Real negative facts (something absent, something not
   found) assembled into an invented mechanism are still a fabrication. Reject a
   fabricated mechanism with verdict "needs_reinvestigation"
   (investigate what the symptom's real dependencies actually show) — never let an
   invented mechanism ship.

8. RECONCILIATION TEST — when a directly OBSERVED signal and a DERIVED/predicted
   signal about the same thing disagree, the diagnosis must EXPLAIN the
   discrepancy rather than silently side with one. A directly observed signal is
   strong evidence of what actually happened; a derived result that contradicts
   it is a LEAD to investigate further, not a reason to dismiss the observation
   (and the observation itself must be checked for recency and relevance). If the
   conclusion trusted one signal over a conflicting one without reconciling them,
   issue "needs_reinvestigation" naming the specific conflict to resolve.

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

    # Arm the critic with the inventory of what was ACTUALLY fetched, so it can
    # ground the diagnosis's claims against real evidence and catch fabricated
    # mechanisms (the FABRICATION TEST). Keys of all_fetched are the tool calls /
    # resources the investigation touched — a compact, cache-friendly index.
    fetched = state.get("all_fetched") or {}
    inventory = sorted({str(k)[:160] for k in fetched.keys()})
    inventory_text = "\n".join(f"  - {k}" for k in inventory) or "  (nothing fetched)"

    user_content = (
        f"Symptom: {state['symptom']}\n\n"
        f"Chosen conclusion:\n{json.dumps(report, indent=2)}\n\n"
        f"What each branch found:\n{branches_summary}\n\n"
        f"FETCHED INVENTORY (every resource/data the investigation actually "
        f"looked at — anything the conclusion names that is NOT here is "
        f"fabricated):\n{inventory_text}"
    )
    try:
        resp = bedrock.converse(
            modelId=_CRITIC_MODEL,
            system=_sys(_CRITIQUE_SYSTEM),
            messages=[{"role": "user", "content": [{"text": user_content}]}],
            inferenceConfig={"maxTokens": 600, "temperature": 0},
        )
    except Exception:  # noqa: BLE001
        # A critique-call failure must not crash a completed run — ship the
        # synthesized report unchanged (critique is a refinement layer).
        return {"final_report": report, "critique_feedback": ""}
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


# ── Node 4b: falsify (Feature 4 — adversarial falsification gate) ─────────────
#
# Before the verdict ships, actively try to DISPROVE the leading root cause using
# the SAME evidence. This is deliberately conservative — a genuine adversarial
# pass that can pass OR fail, but never blindly flips the answer:
#   survived            → verdict untouched (the common, correct outcome).
#   not survived + budget→ ONE targeted reinvestigation on the specific
#                          contradiction (shares critique's round bound — the
#                          alternative only wins if that reinvestigation returns
#                          CONFIRMED evidence and synthesize then picks it).
#   not survived + none  → weaken confidence ONE step (never a hard cap) and
#                          record the surviving doubt in alternatives_considered;
#                          the original root cause STANDS.
# Runs on the decorrelated _CRITIC_MODEL so it does not share the investigator's
# blind spots, and fails open (any model error ⇒ treated as survived).

_FALSIFICATION_SYSTEM = """\
You are an adversarial reviewer performing a FALSIFICATION pass on an incident
diagnosis before it ships. You did not run the investigation. Your job is NOT to
confirm the conclusion — it is to genuinely try to DISPROVE it using ONLY the
evidence already gathered.

Ask two questions, answered strictly from the fetched evidence provided:
  1. CONTRADICTION — Is there anything in the evidence INCONSISTENT with the
     stated root cause: a measurement, log line, status, or timestamp the root
     cause cannot explain, or something that should be present if the root cause
     were true but is absent where it was actually checked?
  2. BETTER FIT — Does the SAME evidence support a DIFFERENT explanation at
     least as well as, or better than, the stated one?

Rules that keep this honest:
  - Argue only from evidence that is actually present. Do NOT invent data, and
    do NOT speculate about signals nobody observed.
  - "No contradicting evidence found" is a legitimate and COMMON result. If the
    evidence is consistent with the root cause and no alternative fits better,
    the diagnosis SURVIVES — say so plainly. Do NOT manufacture a doubt to seem
    rigorous.
  - A weaker or equally-weak alternative does NOT count. Surface an alternative
    only if the evidence supports it AS WELL OR BETTER than the stated cause.
  - Judge reasoning and fit, not vocabulary. Name no fix and no remediation.

Respond ONLY with this JSON (no markdown, no extra text):
{"survived": true | false,
 "contradicting_evidence": ["a specific fact from the evidence the root cause cannot explain", ...],
 "stronger_alternative": {"hypothesis": "the alternative the same evidence supports as well or better", "why": "one sentence grounded in the evidence"} | null,
 "reasoning": "one or two sentences: why it survived, or exactly what it failed to withstand"}

survived MUST be false if and only if you listed real contradicting_evidence OR a
genuine stronger_alternative. If both are empty, survived MUST be true.
"""


def _run_falsification(state: GraphState, report: dict) -> dict:
    """Decorrelated adversarial model call. Fails open: any error or unparseable
    response is treated as 'survived' (inconclusive) so the gate never derails a
    completed investigation."""
    try:
        bedrock = _make_bedrock(state["profile"], state["region"])
        corpus = json.dumps(state.get("all_fetched") or {}, default=str)[:12000]
        user_content = (
            f"Symptom: {state.get('symptom', '')}\n\n"
            f"Diagnosis under test:\n"
            f"  root_cause: {report.get('root_cause', '')}\n"
            f"  evidence: {json.dumps(report.get('evidence', []), default=str)}\n\n"
            f"FETCHED EVIDENCE (the ONLY data you may argue from):\n{corpus}"
        )
        resp = bedrock.converse(
            modelId=_CRITIC_MODEL,
            system=_sys(_FALSIFICATION_SYSTEM),
            messages=[{"role": "user", "content": [{"text": user_content}]}],
            inferenceConfig={"maxTokens": 700, "temperature": 0},
        )
        text = resp["output"]["message"]["content"][0]["text"].strip()
        parsed = _extract_json(text, "survived")
        if isinstance(parsed, dict) and "survived" in parsed:
            return parsed
        # No parseable verdict — do NOT invent a failure; treat as survived.
        return {"survived": True, "contradicting_evidence": [],
                "stronger_alternative": None,
                "reasoning": "falsification returned no parseable verdict; treated as survived",
                "_inconclusive": True}
    except Exception as exc:  # noqa: BLE001
        return {"survived": True, "contradicting_evidence": [],
                "stronger_alternative": None,
                "reasoning": f"falsification unavailable ({type(exc).__name__}); treated as survived",
                "_error": True}


def _weaken_confidence_one_step(report: dict, contradiction: list,
                                alt: dict | None, reasoning: str) -> dict:
    """Weaken confidence by exactly ONE step (HIGH→MEDIUM→LOW, never below LOW)
    and record the surviving doubt in alternatives_considered. Matches the
    weaken-not-cap philosophy of enforce_confidence — never a hard cap, never a
    forced floor, and the root cause is left STANDING."""
    _order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    _inv = {0: "LOW", 1: "MEDIUM", 2: "HIGH"}
    out = dict(report)
    cur = out.get("confidence", "LOW")
    new = _inv[max(0, _order.get(cur, 0) - 1)]
    if new != cur:
        out["confidence"] = new
        out["confidence_override_reason"] = (
            f"Confidence weakened from {cur} to {new}: an adversarial "
            f"falsification pass surfaced a doubt the reinvestigation budget "
            f"could not resolve. The root cause STANDS; the doubt is recorded."
        )
    alts = list(out.get("alternatives_considered") or [])
    if isinstance(alt, dict) and alt.get("hypothesis"):
        alts.append({
            "hypothesis": str(alt.get("hypothesis")),
            "reason": str(alt.get("why") or reasoning or
                          "surfaced by falsification; not confirmed"),
            "verdict": "unresolved_falsification_doubt",
        })
    elif contradiction:
        alts.append({
            "hypothesis": "evidence inconsistent with the root cause remains unresolved",
            "reason": "; ".join(str(c) for c in contradiction[:3]) or reasoning,
            "verdict": "unresolved_falsification_doubt",
        })
    out["alternatives_considered"] = alts
    out["_falsification"] = {
        "survived": False,
        "resolved": False,
        "reasoning": str(reasoning)[:400],
    }
    return out


def _falsification_focus(contradiction: list, alt: dict | None,
                         reasoning: str) -> str:
    """Build the targeted reinvestigation focus from what the falsification
    surfaced. Echoes evidence-grounded text only — it introduces no service or
    scenario knowledge of its own."""
    parts: list[str] = []
    if isinstance(alt, dict) and alt.get("hypothesis"):
        why = str(alt.get("why") or "").strip()
        parts.append(
            f"The evidence may support a different cause: {alt.get('hypothesis')}."
            + (f" {why}" if why else "")
        )
    if contradiction:
        parts.append(
            "Evidence the current root cause does not explain: "
            + "; ".join(str(c) for c in contradiction[:3])
        )
    if not parts and reasoning:
        parts.append(str(reasoning))
    if not parts:
        return ""
    return (
        "Resolve this contradiction to the current diagnosis. "
        + " ".join(parts)
        + " Gather the specific data that would CONFIRM or REFUTE it, and "
          "determine which cause the evidence actually supports."
    )


def _falsification_outcome(report: dict, falsification: dict,
                           critique_round: int, budget_bound: int = 1) -> dict:
    """Pure, conservative wiring of a falsification verdict → GraphState updates.
    Never flips root_cause; never hard-caps confidence. Testable without a model.

    - survived (or inconclusive, or no substantive finding) → untouched.
    - not survived + budget remains → ONE targeted reinvestigation (via the
      SHARED critique_feedback channel and round bound — not a new loop).
    - not survived + no budget → weaken one step + record doubt; root cause stands.
    """
    survived = falsification.get("survived", True)
    if survived is None:
        survived = True
    contradiction = falsification.get("contradicting_evidence") or []
    alt = falsification.get("stronger_alternative") or None
    reasoning = falsification.get("reasoning", "")

    # Conservative guard: a non-survival with NOTHING concrete behind it is
    # treated as inconclusive-survive, so a vague or rubber-stamp "failure" can
    # never over-correct a right answer.
    substantive = bool(contradiction) or bool(
        isinstance(alt, dict) and alt.get("hypothesis")
    )
    if survived or not substantive:
        out = dict(report)
        out["_falsification"] = {
            "survived": True,
            "reasoning": str(reasoning)[:400],
        }
        return {"final_report": out, "critique_feedback": ""}

    # Not survived, with substance. Prefer to RESOLVE it if budget remains.
    if critique_round < budget_bound:
        focus = _falsification_focus(contradiction, alt, reasoning)
        if focus:
            out = dict(report)
            out["_falsification"] = {
                "survived": False,
                "resolved": "pending_reinvestigation",
                "reasoning": str(reasoning)[:400],
            }
            return {"final_report": out, "critique_feedback": focus}

    # No budget (or nothing actionable to reinvestigate) → weaken + record.
    weakened = _weaken_confidence_one_step(report, contradiction, alt, reasoning)
    return {"final_report": weakened, "critique_feedback": ""}


def falsify_node(state: GraphState) -> dict:
    report = state.get("final_report") or {}

    # Compose, don't fight: if critique already claimed the (single) round for a
    # reinvestigation, defer entirely — its decision owns the budget this pass.
    if state.get("critique_feedback"):
        return {}

    # Nothing to falsify: a degenerate/failed report or one with no evidence to
    # argue from. Skip the call rather than manufacture a verdict.
    if not (report.get("root_cause") or "").strip() or not report.get("evidence"):
        return {}

    falsification = _run_falsification(state, report)
    return _falsification_outcome(
        report, falsification, state.get("critique_round", 0)
    )


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
            failure_map=state.get("failure_map"),
        )
        new_branches = list(state["branch_results"]) + [result.model_dump()]
        new_fetched = dict(state.get("all_fetched", {}))
        _merge_fetched(new_fetched, result.all_fetched)
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

def _after_falsify(state: GraphState) -> str:
    """Route after the critique→falsify gate. Reinvestigate at most once, whether
    the trigger came from critique OR the falsification gate — they SHARE the
    single-round budget (critique_round), so this bound cannot be doubled."""
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
    workflow.add_node("falsify",           falsify_node)             # Feature 4
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
    # Feature 4: critique → falsify (adversarial gate) → conditional reinvestigate.
    # Falsify defers to critique when critique already asked to reinvestigate, so
    # the two gates share ONE reinvestigation round (critique_round) rather than
    # each opening a loop of their own.
    workflow.add_edge("critique", "falsify")
    workflow.add_conditional_edges(
        "falsify", _after_falsify,
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
            timeout=30,   # wait for a busy lock instead of failing instantly
        )
        # WAL lets concurrent readers/writers coexist and avoids the "database is
        # locked" crash when two cloudctl runs (or an IDE subagent + a CLI run)
        # touch the checkpoint DB at once — strict file locking on Windows hits
        # this readily under the default rollback journal.
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
        except Exception:  # noqa: BLE001
            pass
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
    minutes: int = 60,   # was 10 — a 10-min window made any incident older than
                         # ~10 minutes invisible to logs/the survey (0 events →
                         # "cannot reproduce" on a live, ongoing incident).
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
        check_evidence_grounding, cap_speculative_dismissal,
        enforce_failure_grounding,
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
    # recursion_limit bounds the number of graph steps; combined with the
    # per-call boto/Bedrock timeouts this bounds total wall-clock. The ceiling
    # below is the hard backstop that emits a partial report instead of hanging.
    invoke_config = {"configurable": {"thread_id": thread_id}, "recursion_limit": 60}
    _ceiling_s = int(_os.environ.get("CLOUDCTL_INVESTIGATION_CEILING_S", "1200"))

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
    from cloudctl.mcp.tools.recorder import reset_usage_stats, usage_report
    reset_usage_stats()
    from cloudctl.mcp.tools.probe import reset_probe_budget
    reset_probe_budget()

    graph = _get_graph()

    from cloudctl.mcp.tools.recorder import BudgetExceededError
    _stop_reason = {"why": ""}

    def _invoke_bounded(arg):
        """Run one graph invocation under the wall-clock ceiling AND the spend
        budget. On breach, return None so the caller emits a best-effort partial
        report from the last checkpoint rather than blocking or overspending.
        Per-call timeouts mean the abandoned worker thread finishes shortly."""
        import concurrent.futures
        # Manually managed executor: a `with` block calls shutdown(wait=True) on
        # exit, which JOINS the still-running graph worker and defeats the whole
        # ceiling (the process blocks until the graph finishes anyway). Detach the
        # worker on breach instead — per-call boto/Bedrock timeouts bound its life.
        _ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
        fut = _ex.submit(graph.invoke, arg, invoke_config)
        try:
            return fut.result(timeout=_ceiling_s)
        except concurrent.futures.TimeoutError:
            _stop_reason["why"] = f"exceeded the {_ceiling_s}s time ceiling"
            return None
        except BudgetExceededError as exc:
            _stop_reason["why"] = str(exc)
            return None
        finally:
            _ex.shutdown(wait=False, cancel_futures=True)

    final_state = _invoke_bounded(initial_state)
    if final_state is None:
        # Ceiling or budget breached — assemble whatever the checkpoint holds.
        try:
            snap = graph.get_state(invoke_config)
            checkpointed = dict(snap.values) if snap and snap.values else {}
        except Exception:  # noqa: BLE001
            checkpointed = {}
        partial = checkpointed.get("final_report") or {}
        report = {
            "root_cause": partial.get("root_cause")
                or (f"Investigation stopped early ({_stop_reason['why']}) before "
                    "reaching a conclusion. Partial findings below; resume with "
                    f"CLOUDCTL_RESUME_THREAD={thread_id}."),
            "evidence": partial.get("evidence", []),
            "remediation_steps": partial.get("remediation_steps", []),
            "severity": partial.get("severity", "UNKNOWN"),
            "confidence": "LOW",
            "resources_investigated": partial.get("resources_investigated", []),
            "_timed_out": True,
            "_thread_id": thread_id,
            "_usage": usage_report(),
        }
        return json.dumps(report), checkpointed.get("all_fetched", {}) or {}

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
        resumed = _invoke_bounded(Command(resume=answer))
        if resumed is not None:
            final_state = resumed

    parsed = final_state["final_report"]
    all_fetched = final_state.get("all_fetched", {})

    # Fold the observe node's MEASUREMENTS into the grounding corpus. The observe
    # node reads real metrics/logs but stored nothing in all_fetched, so a
    # conclusion citing an onset/measurement seen only during observation failed
    # the grounding/hallucination checks and was wrongly downgraded. Including it
    # makes those facts traceable. (Kept under a clearly-marked key.)
    _obs = final_state.get("observation") or {}
    if _obs and isinstance(all_fetched, dict) and "_observation" not in all_fetched:
        all_fetched = {**all_fetched, "_observation": _obs}

    # Diagnostics: record what the VERDICT/PRISM layers actually produced so a
    # silent no-op (empty observation / log_insights) is visible in results.
    parsed["_verdict_layers"] = {
        "observation":    final_state.get("observation") or {},
        "log_insights":   final_state.get("log_insights") or {},
        "discrimination": final_state.get("discrimination") or {},
    }
    # Resume a crashed run with CLOUDCTL_RESUME_THREAD=<this value>
    parsed["_thread_id"] = thread_id
    # Cost/latency of this investigation (behavior-neutral instrumentation).
    parsed["_usage"] = usage_report()

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

    # Rebuild the provenance trail against the FINAL report and corpus: the
    # critique node may have revised root_cause/evidence after synthesis, and
    # the observation measurements were only folded into the corpus above.
    # Deterministic and cheap, so recomputing beats shipping a stale trail.
    _prov, _unsourced = _build_report_provenance(parsed, all_fetched)
    parsed["provenance"] = _prov
    parsed["unsourced_claims"] = _unsourced

    hal_report = detect_hallucinations(parsed, all_fetched)
    parsed = enforce_confidence(parsed, all_fetched, hal_report)
    # Safety net: never let a "this alert is a false positive / not a real fault"
    # verdict ship at high confidence (see cap_speculative_dismissal). Fires only
    # on dismissal language; exempts a grounded misconfigured-alarm diagnosis
    # (needs all_fetched to verify the alarm is real, not invented).
    parsed = cap_speculative_dismissal(parsed, all_fetched)

    # Frontier-honest core (ENFORCED): surface whether a failure was actually
    # OBSERVED; and when the verdict CLAIMS a runtime failure (denial/throttle/
    # timeout/5xx) that was never observed, cap it to an honest frontier verdict —
    # the prompt-level discipline alone did not hold. Silent-fault diagnoses assert
    # no such signal and are untouched.
    parsed = enforce_failure_grounding(parsed, all_fetched)

    # LOCALIZE pillar: if components were observed emitting failures but the verdict
    # blames one that was NOT, it is mis-localized — cap it and surface where the
    # failures actually are. No-op when the failure map is empty (silent fault).
    from cloudctl.debug.localize import enforce_localization_anchor
    parsed = enforce_localization_anchor(parsed, final_state.get("failure_map") or [])

    # ANCHORED CAUSAL SEARCH pillar: when ring-ordered anchor evidence exists but
    # the verdict names a cause at ring distance > 0 while the anchor itself was
    # never differential-checked, soft-cap confidence ONE step with a structured
    # note (same shape/discipline as the frontier and localization enforcers —
    # never a hard block). No-op when no causal_search evidence was gathered.
    from cloudctl.debug.causal_search_aws import enforce_causal_anchor
    parsed = enforce_causal_anchor(parsed, all_fetched)

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

    # Observability gap (Feature 2 addendum): make the ABSENCE of tracing
    # productive. When this is a latency/timeout/error-propagation-class symptom
    # AND get_traces was queried but returned no data, append ONE generic
    # observability recommendation to remediation. Remediation-only: it does not
    # touch root_cause or confidence, and it never fires when traces were
    # available or the symptom is a different class.
    parsed = _maybe_add_tracing_recommendation(parsed, symptom, all_fetched)

    parsed = redact_output(parsed)

    reinvestigated = final_state.get("critique_round", 0) > 0

    # Per-branch confirmation trace — makes the correct-but-LOW question (why did
    # a branch that found the right cause fail to CONFIRM a prediction?) directly
    # observable in the result, instead of inferred. For each branch: whether it
    # confirmed, how many predictions it framed and their verdicts, evidence
    # count, and any anti-fabrication downgrade reasons.
    def _branch_trace(br: dict) -> dict:
        preds = [p for p in (br.get("predictions_tested") or []) if isinstance(p, dict)]
        return {
            "service":     br.get("hypothesis", {}).get("service", "?"),
            "confirmed":   br.get("confirmed", False),
            "n_predictions": len(preds),
            "n_confirmed": sum(1 for p in preds if p.get("verdict") == "CONFIRMED"),
            "n_refuted":   sum(1 for p in preds if p.get("verdict") == "REFUTED"),
            "n_evidence":  len(br.get("evidence") or []),
            "downgrades":  [p.get("_downgraded") for p in preds if p.get("_downgraded")],
        }

    parsed["_guardrails"] = {
        "agent_version": "graph_v2",
        "hypotheses_explored": len(final_state.get("hypotheses", [])),
        "branches_completed": len(final_state.get("branch_results", [])),
        "branches_confirmed": sum(1 for br in final_state.get("branch_results", []) if br.get("confirmed")),
        "branch_verdicts": [_branch_trace(br) for br in final_state.get("branch_results", [])],
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
