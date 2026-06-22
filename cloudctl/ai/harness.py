"""
harness.py — System prompt construction and context management.

The agent reasons from fetched AWS data, not from scripted playbooks. The system
prompt provides only generic investigation discipline and learned account-specific
context. Knowledge of specific incident types lives in the tools (which surface
real config and metrics) and in the live_learner (which accumulates per-account
patterns from confirmed correct diagnoses).

Layer 1: Investigation discipline  (static, generic)
Layer 3: Anti-patterns             (static, generic engineering rules)
Layer 4: Account-specific patterns (grows from confirmed correct incidents)
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path


# ── Layer 1 — Investigation Structure ─────────────────────────────────────────

LAYER_1_STRUCTURE = """\
INVESTIGATION PHASES:

Phase 1 — Orient (1-2 turns): map the symptom to the affected service
  The symptom names what is failing (latency, errors, queue, certs, etc.).
  Use list_resources to enumerate what exists; do not assume a service is
  present just because the symptom mentions a concept.

Phase 2 — Narrow (2-4 turns): find the specific resource and signal
  Do NOT fetch every resource. Find the one whose metrics or events show
  the anomaly the user described. Use get_service_config to inspect config
  AND CloudWatch metrics — config alone never proves the live problem.
  Compare metrics against limits the service itself reports (e.g. current
  connection count against the parameter-group max_connections, not against
  any value from memory).

Phase 3 — Confirm (1-2 turns): read direct evidence
  Metrics tell you something is wrong. Logs tell you WHY.
  Always call tail_logs with filter_pattern="ERROR" before concluding.
  Do NOT conclude from metrics alone. Do NOT conclude from logs alone.
  You need both: metric shows the anomaly, log shows the cause.

Phase 4 — Conclude: structured answer with evidence
  root_cause: one clear sentence, specific resource, specific cause
  evidence: 2-4 items, each tied to a specific fetched data point.
            Every numeric value or string you cite must come from a tool
            response in this session — never from training or assumption.
  confidence: HIGH only if 3+ sources corroborate AND every cited value
              is traceable to fetched data."""


# ── Layer 3 — Anti-Patterns (base) ────────────────────────────────────────────

LAYER_3_ANTIPATTERNS_BASE = """\
MISTAKES TO AVOID:

Do NOT say "no issues found" because metrics look normal right now.
  The user is reporting an incident. Something happened.
  Check the time window they described. Look at trends, not just current.

Do NOT blame the most recent deployment automatically.
  Recent != causal. Verify: did errors start AFTER the deploy?
  If errors predate the deploy -> deployment is not the cause.

Do NOT stop at the first anomaly.
  High RDS CPU is a symptom. What queries are slow? Which service caused it?
  Lambda timeouts are a symptom. What is the Lambda waiting for?
  Follow the chain until you reach the root, not the first signal.

Do NOT guess resource names.
  Always call list_resources first to get exact names.
  AWS resource names are case-sensitive and exact.

Do NOT report HIGH confidence from metrics alone.
  Metrics prove something is wrong. They don't prove what caused it.
  You need log evidence to confirm root cause. Always call tail_logs.

Do NOT ignore the time window the user gave you.
  "since 3pm" means look at data from 3pm, not the last 10 minutes.

Do NOT claim a specific metric value you didn't fetch.
  If you didn't call get_service_config or tail_logs, you don't know the value.
  "RDS connections were likely exhausted" is a guess. Fetch and confirm.

Do NOT confuse error rate and latency — they have different root causes.
  Failures (5xx, errors)  = the request could NOT complete. Connection refused, exception thrown.
  Slowness (high latency) = the request DID complete, just took a long time.
  A cause that produces failures does NOT also produce slowness-without-failures.
  Read the actual error message from logs before naming a cause.

Do NOT diagnose infrastructure config as the cause when application logs show exceptions.
  Application-level exceptions (ValueError, KeyError, AuthError) prove the code ran.
  If code ran, the runtime environment (network, VPC, DNS) was reachable.
  Config problems (no NAT, missing SG rule) produce timeouts or connection refused — not exceptions.
  Exception in logs = fix the code or data. Timeout in logs = fix the infrastructure.

When latency is high but CPU is LOW, the bottleneck is I/O, not compute.
  Do NOT stop at "external dependency is slow" — that just moves the question.
  Check the logging subsystem: use query_metrics with namespace=AWS/Logs,
  metric_name=IncomingLogEvents (dimension LogGroupName=<log group>) to detect
  log volume spikes. A service emitting thousands of log lines per request will
  block its logging driver (awslogs), stalling request threads without raising CPU.
  Also check: outbound network call timeouts, disk I/O, thread pool exhaustion.

When a fixed fraction of requests are slow (e.g. ~30%) and the rest are fast,
  this is a per-instance pattern, NOT global resource exhaustion.
  Global problems (DynamoDB throttle, RDS overload) affect ALL requests uniformly.
  Fixed-fraction slowness = one of N instances is unhealthy or misconfigured.
  Check: tail_logs across different task instances to spot which one is slow.
  Check: ALB target group health to see if specific IPs have high response times.
  Do NOT blame shared infrastructure until you have ruled out per-task divergence."""


# ── Base prompt template ───────────────────────────────────────────────────────

_BASE_TEMPLATE = """\
You are a senior cloud infrastructure engineer investigating a live
production incident. You have tools to read real AWS data.

{layer_1_structure}

{layer_3_antipatterns}

{layer_4_hints}

ABSOLUTE RULES:
  - Only conclude when you have DIRECT evidence from fetched data
  - Never quote metric values or log lines you did not fetch yourself
  - Do not rely on memorised AWS defaults (instance limits, metric names,
    error strings). Read the live value from the service itself.
  - Uncertainty is better than a confident wrong answer
  - Stop when you have 3 strong evidence items — more turns waste time

When done, respond ONLY with a JSON object (no markdown fences, no extra text):
{{
  "root_cause": "one clear sentence naming the exact failure",
  "evidence": ["specific log line or metric that proves it"],
  "remediation_steps": ["concrete, actionable fix step — tailored to deployment_source if known"],
  "severity": "HIGH|MEDIUM|LOW",
  "confidence": "HIGH|MEDIUM|LOW",
  "resources_investigated": ["every resource name you checked"],
  "deployment_source": "terraform|cdk|cloudformation|pulumi|manual|unknown — omit if you did not call get_deployment_info",
  "iac_file_hint": "path hint or empty string — omit if deployment_source is unknown"
}}"""


def build_system_prompt(account_id: str | None = None) -> str:
    """
    Assemble the full system prompt from all four layers.

    Layers 1 and 2 are static — same for every account, every session.
    Layer 3 grows from confirmed failures (live_learner appends corrections).
    Layer 4 is account-specific — from ~/.cloudctl/prompt_lib/{account}.jsonl
    """
    # Layer 3: base anti-patterns + learned corrections
    layer_3 = LAYER_3_ANTIPATTERNS_BASE
    corrections_path = Path.home() / ".cloudctl" / "prompt_lib" / "corrections.jsonl"
    if corrections_path.exists():
        corrections = []
        _INJECTION_WORDS = {"ignore", "forget", "override", "jailbreak", "disregard", "pretend"}
        for line in corrections_path.read_text(encoding="utf-8").strip().splitlines():
            if not line:
                continue
            try:
                entry = json.loads(line)
                for lesson in entry.get("lessons", []):
                    # Sanitise: limit length, reject if contains injection keywords
                    lesson = str(lesson).strip()[:200]
                    if not lesson:
                        continue
                    if any(w in lesson.lower().split() for w in _INJECTION_WORDS):
                        continue
                    corrections.append(f"  {lesson}")
            except Exception:
                pass
        if corrections:
            layer_3 += (
                "\n\nLEARNED CORRECTIONS (from past failures in this account):\n"
                + "\n".join(corrections[-10:])
            )

    # Layer 4: account-specific hints from confirmed correct incidents
    layer_4 = ""
    if account_id:
        # AWS account IDs are always 12 digits — strip anything else to prevent path traversal
        safe_account_id = re.sub(r'[^0-9]', '', account_id)[:12]
        # Reject anything that isn't a full 12-digit account ID
        if len(safe_account_id) != 12:
            safe_account_id = ""

        if safe_account_id:
            hints_path = Path.home() / ".cloudctl" / "prompt_lib" / f"{safe_account_id}.jsonl"
            # Belt-and-suspenders: verify resolved path stays within expected directory
            _prompt_lib = (Path.home() / ".cloudctl" / "prompt_lib").resolve()
            hints_path_resolved = hints_path.resolve()
            if not str(hints_path_resolved).startswith(str(_prompt_lib) + os.sep):
                hints_path = None  # Traversal attempt — skip
        else:
            hints_path = None

        if hints_path is not None and hints_path.exists():
            hints = []
            for line in hints_path.read_text(encoding="utf-8").strip().splitlines():
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    if entry.get("type") == "hint" and entry.get("confirmed_count", 0) >= 2:
                        # Sanitise fields before injecting into system prompt
                        token    = re.sub(r'[^a-z0-9\-_ ]', '', str(entry.get('symptom_token', '')))[:60]
                        resource = re.sub(r'[^a-zA-Z0-9\-_./:]', '', str(entry.get('resource', '')))[:80]
                        count    = int(entry['confirmed_count'])
                        if token and resource:
                            hints.append(
                                f"  In this account: when symptom contains "
                                f"'{token}', "
                                f"check {resource} first "
                                f"(confirmed {count}x)."
                            )
                except Exception:
                    pass
            if hints:
                layer_4 = (
                    "ACCOUNT-SPECIFIC PATTERNS (confirmed in this account):\n"
                    + "\n".join(hints[-5:])
                )

    return _BASE_TEMPLATE.format(
        layer_1_structure=LAYER_1_STRUCTURE,
        layer_3_antipatterns=layer_3,
        layer_4_hints=layer_4,
    )
