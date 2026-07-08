"""probe.py — safe, bounded, READ-ONLY active reproduction.

The rest of the agent is passive: it reads telemetry, logs, and config. Silent
faults (HTTP 200 with wrong data, one broken auth path) leave no passive signal,
so the agent must sometimes EXERCISE the system once and observe the real
response — the diagnostic equivalent of a single `curl` to reproduce a bug.

This is the ONLY place the agent touches running infrastructure, so safety is
enforced here in CODE, never left to the model's judgement:

  * READ-ONLY requests only (GET / HEAD / OPTIONS; POST is admitted ONLY when
    its payload is PROVABLY a non-mutating query document — anything that
    cannot be proven read-only is rejected in code, so a mutating probe is
    impossible).
  * SSRF-guarded — cloud metadata (169.254.169.254 / link-local), loopback, and
    non-http(s) schemes are rejected; the agent can only reach real service
    endpoints it discovered from config.
  * HARD BOUNDS — connect/read timeout, response-size cap, no redirect
    following, and a per-investigation probe BUDGET (a few probes, never load).
  * OPT-IN — disabled unless CLOUDCTL_ENABLE_PROBES=1, so a passive-only
    deployment stays passive.

AWS-native sandbox test primitives (apigateway test-invoke-method, Lambda
DryRun) are added on top of this same budget/guard machinery — they are safe by
construction (AWS runs them without touching the live stage) and generic (AWS
capabilities, not per-incident knowledge).
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

# ── Hard limits (not model-adjustable) ────────────────────────────────────────
_CONNECT_TIMEOUT = 6
_READ_TIMEOUT = 8
_MAX_BODY_BYTES = 64 * 1024
_MAX_REQUEST_BODY_BYTES = 8 * 1024
_MAX_PROBES_PER_INVESTIGATION = 5
_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
_SAFE_SCHEMES = {"http", "https"}

# Per-process probe budget. reset at investigation start (like usage stats).
_PROBE_STATS = {"used": 0}


def reset_probe_budget() -> None:
    _PROBE_STATS["used"] = 0


def probes_used() -> int:
    return _PROBE_STATS["used"]


def _probes_enabled() -> bool:
    return os.environ.get("CLOUDCTL_ENABLE_PROBES", "") in ("1", "true", "yes")


# ── Read-only request-body proof ──────────────────────────────────────────────
# Some user-facing entry points take their READ operation as a POSTed query
# document (the cross-vendor query-over-HTTP convention: a JSON object with a
# "query" string and optional "operationName"/"variables"). Reproducing such an
# operation requires a POST, so POST is admitted ONLY when the payload is
# PROVABLY a non-mutating query. This is keyed on the INTERACTION PATTERN of
# the request itself — it knows no service, no schema, and no field names; it
# only proves the document contains no write operation. Anything that cannot
# be proven read-only is rejected: the safe default is not to send it.

def _strip_query_noise(doc: str) -> str:
    """Remove string literals and line comments from a query document so
    keyword detection can be neither fooled nor false-triggered by literal
    text (e.g. a search argument that happens to contain the word)."""
    doc = re.sub(r'"""[\s\S]*?"""', " ", doc)          # block strings first
    doc = re.sub(r'"(?:\\.|[^"\\])*"', " ", doc)       # quoted strings
    doc = re.sub(r"#[^\n\r]*", " ", doc)               # line comments
    return doc


def _body_is_read_only_query(body) -> tuple[bool, str]:
    """Return (True, "") only when `body` is PROVABLY a non-mutating query
    payload. Conservative by construction: unknown shape → rejected."""
    if not body or not isinstance(body, str):
        return False, "no request body given"
    if len(body.encode("utf-8", "replace")) > _MAX_REQUEST_BODY_BYTES:
        return False, f"request body exceeds the {_MAX_REQUEST_BODY_BYTES}B cap"
    try:
        payload = json.loads(body)
    except Exception:  # noqa: BLE001
        return False, "request body is not valid JSON"
    if not isinstance(payload, dict):
        return False, "request body is not a JSON object"
    extra = set(payload) - {"query", "operationName", "variables"}
    if extra:
        return False, (f"payload carries keys {sorted(extra)} beyond the "
                       "query/operationName/variables convention — cannot "
                       "prove it is read-only")
    doc = payload.get("query")
    if not isinstance(doc, str) or not doc.strip():
        return False, "payload has no query document under 'query'"
    stripped = _strip_query_noise(doc)
    if re.search(r"\b(mutation|subscription)\b", stripped, re.I):
        return False, ("query document contains a mutation/subscription "
                       "operation — only read-only queries may be sent")
    head = stripped.lstrip()
    if not (head.startswith("query") or head.startswith("{")
            or head.startswith("fragment")):
        return False, ("query document does not start with a read operation "
                       "(query / anonymous selection / fragment)")
    return True, ""


# ── Consent gate ──────────────────────────────────────────────────────────────
# Active reproduction is opt-in AND consent-gated: even when enabled, no probe
# runs until a human sees exactly what it will do and approves. The gate is
# transparent (shows target + reason + safety bounds), serialized (parallel
# investigation branches can't prompt over each other), and offers a paste-back
# path so a target the console can't reach (a private ALB) is still reproducible
# by the operator running the same request from where they can and pasting the
# response. If no handler is registered we DECLINE — we never fall back to a
# silent probe.
_CONSENT_LOCK = threading.Lock()
_consent_handler = None   # callable(plan: dict) -> {"decision": .., "pasted": ..}


def set_consent_handler(fn) -> None:
    """Register the interactive consent handler (owned by the CLI layer, which
    has the console). Passing None restores decline-by-default."""
    global _consent_handler
    _consent_handler = fn


def _resolve_decision(plan: dict) -> dict:
    if _consent_handler is not None:
        return _consent_handler(plan) or {"decision": "skip"}
    # No interactive handler wired. Allow a deterministic auto-mode for
    # CI/replay only; otherwise decline — never probe without consent.
    auto = os.environ.get("CLOUDCTL_PROBE_AUTO", "").lower()
    if auto in ("approve", "yes", "y"):
        return {"decision": "approve"}
    return {"decision": "skip", "reason": "no interactive consent available"}


def probe_http_gated(url: str, method: str = "GET",
                     headers: dict | None = None, reason: str = "",
                     body: str | None = None) -> str:
    """Consent-gated wrapper around probe_http. Presents the plan to a human and
    only acts on their decision: approve (cloudctl runs it), paste (operator ran
    it, provides the response), or skip (continue passively)."""
    if not _probes_enabled():
        return _err("reproduction disabled — enable with --reproduce "
                    "(or CLOUDCTL_ENABLE_PROBES=1) to allow consent-gated, "
                    "read-only reproduction probes")

    # Preflight the body BEFORE prompting a human: a payload that cannot be
    # proven read-only will never run, so never ask consent for it.
    if body is not None:
        ok, why = _body_is_read_only_query(body)
        if not ok:
            return _err(f"request body rejected before consent: {why}")

    plan = {
        "action": "reproduce",
        "method": (method or "GET").upper(),
        "url": url,
        "reason": reason or "(no reason given)",
        "safety": ("read-only (GET/HEAD/OPTIONS, or a provably non-mutating "
                   "query POST), 8s timeout, 64KB cap, no redirects, "
                   "SSRF-guarded"),
    }
    if body is not None:
        plan["body"] = body   # full transparency: the operator sees exactly what runs

    # Serialize: only one consent prompt at a time across parallel branches.
    with _CONSENT_LOCK:
        decision = _resolve_decision(plan)
        choice = (decision.get("decision") or "skip").lower()

        if choice in ("approve", "a", "yes", "y"):
            kwargs: dict = {"method": method, "headers": headers}
            if body is not None:
                kwargs["body"] = body
            result = probe_http(url, **kwargs)
            try:
                obj = json.loads(result)
                if isinstance(obj, dict):
                    obj["_reproduction"] = "cloudctl-executed (operator approved)"
                    return json.dumps(obj, default=str)
            except Exception:
                pass
            return result

        if choice in ("paste", "p", "operator"):
            pasted = (decision.get("pasted") or "").strip()
            _PROBE_STATS["used"] += 1   # the operator spent a reproduction on our behalf
            return json.dumps({
                "_reproduction": "operator-executed (response pasted by operator)",
                "observed_response": pasted[:_MAX_BODY_BYTES],
                "probes_used": _PROBE_STATS["used"],
            })

        # skip / decline / anything unrecognized → never probe.
        return json.dumps({
            "probe_declined": True,
            "note": ("operator declined this reproduction. Do NOT claim the "
                     "endpoint's response was verified or observed; reason only "
                     "from passive evidence, and say so explicitly if the fault "
                     "may be runtime-only and thus unverified."),
            "reason": decision.get("reason", "operator skipped"),
        })


def _err(reason: str, **extra) -> str:
    return json.dumps({"probe_error": reason, **extra})


def _host_is_blocked(host: str) -> tuple[bool, str]:
    """Reject loopback, link-local (incl. the cloud metadata endpoint), and
    unspecified addresses — the SSRF danger surface. Private ranges are allowed:
    they are the user's own internal service endpoints, which are legitimate
    diagnostic targets."""
    if not host:
        return True, "empty host"
    # Resolve to catch DNS names that point at blocked addresses.
    candidates = set()
    try:
        candidates.add(ipaddress.ip_address(host))
    except ValueError:
        try:
            for res in socket.getaddrinfo(host, None):
                try:
                    candidates.add(ipaddress.ip_address(res[4][0]))
                except ValueError:
                    pass
        except socket.gaierror:
            return True, f"host does not resolve: {host}"
    if not candidates:
        return True, f"host does not resolve: {host}"
    for ip in candidates:
        if ip.is_loopback or ip.is_link_local or ip.is_unspecified or ip.is_multicast:
            return True, f"blocked address ({ip}) — loopback/link-local/metadata"
    return False, ""


def probe_http(url: str, method: str = "GET", headers: dict | None = None,
               body: str | None = None) -> str:
    """Make ONE bounded, read-only HTTP request and return the observed response
    (status, selected headers, truncated body, timing). All safety limits are
    enforced here; the model cannot widen them."""
    if not _probes_enabled():
        return _err("probes disabled — set CLOUDCTL_ENABLE_PROBES=1 to allow "
                    "bounded read-only reproduction probes")
    if _PROBE_STATS["used"] >= _MAX_PROBES_PER_INVESTIGATION:
        return _err(f"probe budget exhausted ({_MAX_PROBES_PER_INVESTIGATION} "
                    "per investigation)")

    method = (method or "GET").upper()
    body_bytes: bytes | None = None
    if method in _SAFE_METHODS:
        if body:
            return _err(f"a request body is not allowed on {method} — send a "
                        "plain read-only request, or use a query POST")
    elif method == "POST":
        # POST is read-only ONLY when its payload is provably a non-mutating
        # query document; anything else is rejected before any bytes are sent.
        ok, why = _body_is_read_only_query(body)
        if not ok:
            return _err(f"POST is not read-only unless its payload is a "
                        f"provably non-mutating query — {why}")
        body_bytes = body.encode("utf-8")
    else:
        return _err(f"method {method!r} is not read-only; allowed: "
                    f"{sorted(_SAFE_METHODS)} (or a query POST whose payload "
                    "is provably non-mutating)")

    parsed = urlparse(url)
    if parsed.scheme not in _SAFE_SCHEMES:
        return _err(f"scheme {parsed.scheme!r} not allowed; only http/https")
    blocked, why = _host_is_blocked(parsed.hostname or "")
    if blocked:
        return _err(f"target blocked: {why}")

    # Count the probe the moment it is admitted, so a failure still consumes budget.
    _PROBE_STATS["used"] += 1

    safe_headers = {}
    for k, v in (headers or {}).items():
        if k.lower() in ("authorization", "x-api-key", "cookie", "content-type"):
            safe_headers[k] = v   # allow the caller's discovered auth header
    # Honest auth: record whether ANY credential was sent, so a rejection can be
    # read for what it is (a credential the system refused vs. no credential at
    # all). Credentials are only ever caller-supplied — never fabricated here.
    auth_sent = any(k.lower() in ("authorization", "x-api-key", "cookie")
                    for k in safe_headers)
    if body_bytes is not None and not any(
            k.lower() == "content-type" for k in safe_headers):
        safe_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body_bytes, method=method,
                                 headers=safe_headers)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):  # noqa: D401
            return None   # never follow redirects (SSRF pivot guard)

    opener = urllib.request.build_opener(_NoRedirect)
    started = time.monotonic()

    def _elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    try:
        with opener.open(req, timeout=_READ_TIMEOUT) as resp:
            payload = resp.read(_MAX_BODY_BYTES + 1)
            elapsed = _elapsed_ms()
            truncated = len(payload) > _MAX_BODY_BYTES
            return json.dumps({
                "status": resp.status,
                "final_url": resp.url,
                "content_type": resp.headers.get("Content-Type", ""),
                "body": payload[:_MAX_BODY_BYTES].decode("utf-8", "replace"),
                "body_truncated": truncated,
                "elapsed_ms": elapsed,
                "auth_sent": auth_sent,
                "probes_used": _PROBE_STATS["used"],
            })
    except urllib.error.HTTPError as e:
        payload = e.read(_MAX_BODY_BYTES)
        out = {
            "status": e.code,
            "content_type": e.headers.get("Content-Type", "") if e.headers else "",
            "body": payload.decode("utf-8", "replace"),
            "elapsed_ms": _elapsed_ms(),
            "auth_sent": auth_sent,
            "probes_used": _PROBE_STATS["used"],
        }
        if not auth_sent and e.code in (401, 403):
            out["note"] = (
                "this probe carried NO credential — an auth rejection here may "
                "only reflect the missing credential, not the incident's fault. "
                "Reproduce with a discoverable probing credential, or treat the "
                "auth behaviour as unverified.")
        return json.dumps(out)
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as e:
        # Graceful degradation: an unreachable endpoint / timeout is a CLEAR
        # structured signal, never an exception. An actual timeout is itself an
        # observation (the operation did not answer within the bound).
        timed_out = (isinstance(e, (socket.timeout, TimeoutError))
                     or isinstance(getattr(e, "reason", None),
                                   (socket.timeout, TimeoutError)))
        return _err(f"could not reproduce: {type(e).__name__}: {e}",
                    elapsed_ms=_elapsed_ms(),
                    timed_out=timed_out,
                    probes_used=_PROBE_STATS["used"])
