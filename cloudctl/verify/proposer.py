"""The proposer call: one prompt and one schema for every model.

The model's only job here is to propose candidate causes as predictions in
the nine primitives. It never decides the verdict.

Fairness rules from the design, enforced here:
  * One schema subset for all providers: objects, arrays, strings and enums
    only (no oneOf, no type unions). Primitive arguments vary by primitive, so
    they travel as a JSON string (``args_json``) that code validates.
  * Node ids and primitive names are enums built per run from the graph (the
    node enum is dropped above ``max_enum`` nodes, and code still validates).
  * One system prompt for all models. Per-model differences live only in the
    profile (structured mode, temperature, reasoning, token cap).
"""
from __future__ import annotations

import json
import re
import time
from collections.abc import Callable

from cloudctl.verify import primitives as P
from cloudctl.verify.profiles import ModelProfile

TOOL_NAME = "submit_hypotheses"

SYSTEM_PROMPT = """You propose candidate root causes for a cloud incident. You do not decide which one is right: code runs your predictions against recorded evidence and decides.

You are given the discovered system graph (node ids are exact; use them verbatim), the anchor node (the one emitting the failure), the incident timing, and results of earlier rounds.

For each candidate cause, give:
- node: the node id you claim is the cause.
- property: a short label for what is wrong on that node (for example a config path, a policy action, a signal name).
- claim: one or two sentences. This text is never scored.
- predictions: falsifiable checks, each a primitive, its arguments as a JSON object encoded in the string args_json, and expect (PASS or FAIL). At least one prediction must be about the node itself. Prefer predictions that would come out differently if a rival cause were true.

Primitives and their arguments:
- signal: {"node", "query": {"metric": "<name>"} or {"log": "<terms>"}, optional "stat": max|min|avg|sum, "predicate": {"op": above|below|rising|present|absent, "value"?: number, "factor"?: number}, "window"?: incident|lookback|pre_onset}
- config: {"node", "path": "dotted.path[0]", "predicate": {"op": equals|not_equals|contains|not_contains|exists|missing|gt|lt|matches, "value"?}, "window"?}
- drift: {"node", "path": "<path in IaC>", "live_path"?: "<path in live config>", "window"?} PASS when live differs from IaC
- changed: {"node", "window"?: lookback (default)|incident|pre_onset, "match"?: "<substring>"} PASS when something changed on the node
- before: {"a": {"event": change|signal_onset|symptom_onset, "node"?, "query"?, "predicate"?}, "b": {...}, "max_gap"?: seconds} PASS when a happened before b
- permit: {"principal": "<node>", "action": "service:Action", "resource"?: "<node>", "resource_policy"?: "<json>", "window"?} PASS when allowed
- reach: {"src": "<node>", "dst": "<node>", "port": int, "protocol"?: tcp|udp, "window"?} PASS when traffic can flow
- path_health: {"anchor": "<node>", "depth"?: int, "first_failing"?: "<node>", "window"?}
- peer: {"node", "query": {"config_path": "<path>"} or {"metric"|"log": ..., "predicate": {...}}, "window"?} PASS when the node differs from its healthy peers

Rules that code applies (so write predictions that can satisfy them): every prediction must hold; the same predictions must not all hold in the pre_onset window or on healthy peers; something on the node must change or start before onset; every rival on the failing path must be refuted by at least one prediction. A missing signal comes back UNAVAILABLE and does not count as support.

Output only the JSON object {"hypotheses": [...]}. At most {max_hypotheses} hypotheses per round."""


def build_schema(node_ids: list[str], max_enum: int = 500) -> dict:
    node = {"type": "string"}
    if 0 < len(node_ids) <= max_enum:
        node = {"type": "string", "enum": sorted(node_ids)}
    prediction = {
        "type": "object",
        "properties": {
            "primitive": {"type": "string", "enum": sorted(P.SCHEMAS)},
            "args_json": {"type": "string"},
            "expect": {"type": "string", "enum": ["PASS", "FAIL"]},
        },
        "required": ["primitive", "args_json", "expect"],
        "additionalProperties": False,
    }
    hypothesis = {
        "type": "object",
        "properties": {
            "node": node,
            "property": {"type": "string"},
            "claim": {"type": "string"},
            "predictions": {"type": "array", "items": prediction},
        },
        "required": ["node", "property", "claim", "predictions"],
        "additionalProperties": False,
    }
    return {
        "title": "hypotheses",
        "type": "object",
        "properties": {"hypotheses": {"type": "array", "items": hypothesis}},
        "required": ["hypotheses"],
        "additionalProperties": False,
    }


def _compact_previous(previous: list[dict], limit: int = 12) -> list[dict]:
    rows = []
    for o in previous[:limit]:
        h = o.get("hypothesis", {})
        rows.append({
            "id": h.get("id"), "node": h.get("node"), "property": h.get("property"),
            "rules": {k: v.get("ok") for k, v in (o.get("rules") or {}).items()},
            "why": {k: v.get("why") for k, v in (o.get("rules") or {}).items() if not v.get("ok")},
            "results": [{"primitive": r.get("primitive"), "expect": r.get("expect"),
                         "status": r.get("status"), "reason": (r.get("reason") or "")[:160]}
                        for r in o.get("results") or []],
            "missing": o.get("missing", []),
        })
    return rows


def build_user_message(request: dict, symptom: str, context: dict | None = None) -> str:
    parts = [
        f"Symptom: {symptom}",
        f"Anchor (emitting the failure): {request['anchor']}",
        f"Incident timing (epoch seconds): {json.dumps(request['incident'])}",
        "Discovered graph (edge from -> to means from depends on to):",
        json.dumps(request["graph"], separators=(",", ":"), default=str),
    ]
    if context:
        parts.append("Observations so far (from the investigation, may be partial):")
        parts.append(json.dumps(context, separators=(",", ":"), default=str)[:6000])
    if request.get("previous"):
        parts.append(f"Round {request['round']}. Results of earlier hypotheses:")
        parts.append(json.dumps(_compact_previous(request["previous"]), separators=(",", ":")))
    if request.get("repair"):
        parts.append("Your last output had these problems; return a corrected, complete output:")
        parts.extend(f"- {e}" for e in request["repair"][:20])
    return "\n".join(parts)


def extract_json(text: str):
    """First balanced JSON object in text (handles ```json fences and prose)."""
    if not text:
        return None
    t = re.sub(r"```(?:json)?", "", text)
    start = t.find("{")
    while start != -1:
        depth, in_str, esc = 0, False, False
        for i in range(start, len(t)):
            c = t[i]
            if in_str:
                if esc:
                    esc = False
                elif c == "\\":
                    esc = True
                elif c == '"':
                    in_str = False
                continue
            if c == '"':
                in_str = True
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(t[start:i + 1])
                    except json.JSONDecodeError:
                        break
        start = t.find("{", start + 1)
    return None


def _call_with_backoff(fn: Callable[[], dict], profile: ModelProfile,
                       sleep: Callable[[float], None]) -> dict:
    retries = int((profile.rate_limit or {}).get("max_retries", 6))
    delay = float((profile.rate_limit or {}).get("base_delay_s", 2.0))
    for attempt in range(retries + 1):
        try:
            return fn()
        except Exception as exc:
            name = type(exc).__name__
            throttled = "Throttl" in name or "RateLimit" in name or "ResourceExhausted" in name \
                or "ThrottlingException" in str(exc)[:200]
            if not throttled or attempt == retries:
                raise
            sleep(delay * (2 ** attempt))
    raise RuntimeError("unreachable")


class Proposer:
    """Callable used by verifier.verify_loop. Records usage per call so cost
    and rounds can be reported per scenario."""

    def __init__(self, client, profile: ModelProfile, symptom: str,
                 context: dict | None = None, max_hypotheses: int = 5,
                 sleep: Callable[[float], None] = time.sleep):
        self.client = client
        self.profile = profile
        self.symptom = symptom
        self.context = context
        self.max_hypotheses = max_hypotheses
        self.sleep = sleep
        self.usage = {"calls": 0, "input_tokens": 0, "output_tokens": 0}

    def _request_kwargs(self, request: dict) -> dict:
        node_ids = [n["id"] for n in request["graph"]["nodes"]]
        schema = build_schema(node_ids)
        system = SYSTEM_PROMPT.replace("{max_hypotheses}", str(self.max_hypotheses))
        kw = {
            "modelId": self.profile.model_id,
            "system": [{"text": system}],
            "messages": [{"role": "user", "content": [{"text": build_user_message(
                request, self.symptom, self.context)}]}],
            "inferenceConfig": self.profile.inference_config(),
        }
        mode = self.profile.structured_mode
        if mode == "tool_use":
            kw["toolConfig"] = {
                "tools": [{"toolSpec": {"name": TOOL_NAME,
                                        "description": "Submit candidate causes as predictions.",
                                        "inputSchema": {"json": schema}}}],
            }
            if self.profile.force_tool:
                kw["toolConfig"]["toolChoice"] = {"tool": {"name": TOOL_NAME}}
        elif mode == "native_schema":
            kw["responseSchema"] = schema
        if self.profile.provider == "bedrock":
            if self.profile.additional_request_fields:
                kw["additionalModelRequestFields"] = self.profile.additional_request_fields
        elif self.profile.reasoning and "level" not in self.profile.reasoning:
            kw["reasoning"] = self.profile.reasoning
        return kw

    def __call__(self, request: dict):
        kw = self._request_kwargs(request)
        resp = _call_with_backoff(lambda: self.client.converse(**kw), self.profile, self.sleep)
        self.usage["calls"] += 1
        u = resp.get("usage") or {}
        self.usage["input_tokens"] += int(u.get("inputTokens", 0) or 0)
        self.usage["output_tokens"] += int(u.get("outputTokens", 0) or 0)
        content = ((resp.get("output") or {}).get("message") or {}).get("content") or []
        for block in content:
            tu = block.get("toolUse") if isinstance(block, dict) else None
            if tu and tu.get("name") == TOOL_NAME:
                return tu.get("input") or {}
        text = " ".join(b.get("text", "") for b in content if isinstance(b, dict) and "text" in b)
        parsed = extract_json(text)
        # An unparseable reply goes back to verify_loop as text; parse_hypotheses
        # reports it as a schema error, which triggers the one repair retry.
        return parsed if parsed is not None else text

    def cost(self) -> float | None:
        return self.profile.cost(self.usage["input_tokens"], self.usage["output_tokens"])
