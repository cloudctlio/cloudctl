"""probe.py — safe, bounded, READ-ONLY active reproduction.

The rest of the agent is passive: it reads telemetry, logs, and config. Silent
faults (HTTP 200 with wrong data, one broken auth path) leave no passive signal,
so the agent must sometimes EXERCISE the system once and observe the real
response — the diagnostic equivalent of a single `curl` to reproduce a bug.

This is the ONLY place the agent touches running infrastructure, so safety is
enforced here in CODE, never left to the model's judgement:

  * READ-ONLY verbs only (GET / HEAD / OPTIONS) — a mutating probe is impossible.
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
import socket
import threading
import urllib.error
import urllib.request
from urllib.parse import urlparse

# ── Hard limits (not model-adjustable) ────────────────────────────────────────
_CONNECT_TIMEOUT = 6
_READ_TIMEOUT = 8
_MAX_BODY_BYTES = 64 * 1024
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
                     headers: dict | None = None, reason: str = "") -> str:
    """Consent-gated wrapper around probe_http. Presents the plan to a human and
    only acts on their decision: approve (cloudctl runs it), paste (operator ran
    it, provides the response), or skip (continue passively)."""
    if not _probes_enabled():
        return _err("reproduction disabled — enable with --reproduce "
                    "(or CLOUDCTL_ENABLE_PROBES=1) to allow consent-gated, "
                    "read-only reproduction probes")

    plan = {
        "action": "reproduce",
        "method": (method or "GET").upper(),
        "url": url,
        "reason": reason or "(no reason given)",
        "safety": ("read-only (GET/HEAD/OPTIONS), 8s timeout, 64KB cap, "
                   "no redirects, SSRF-guarded"),
    }

    # Serialize: only one consent prompt at a time across parallel branches.
    with _CONSENT_LOCK:
        decision = _resolve_decision(plan)
        choice = (decision.get("decision") or "skip").lower()

        if choice in ("approve", "a", "yes", "y"):
            result = probe_http(url, method=method, headers=headers)
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


def probe_http(url: str, method: str = "GET", headers: dict | None = None) -> str:
    """Make ONE bounded, read-only HTTP request and return the observed response
    (status, selected headers, truncated body). All safety limits are enforced
    here; the model cannot widen them."""
    if not _probes_enabled():
        return _err("probes disabled — set CLOUDCTL_ENABLE_PROBES=1 to allow "
                    "bounded read-only reproduction probes")
    if _PROBE_STATS["used"] >= _MAX_PROBES_PER_INVESTIGATION:
        return _err(f"probe budget exhausted ({_MAX_PROBES_PER_INVESTIGATION} "
                    "per investigation)")

    method = (method or "GET").upper()
    if method not in _SAFE_METHODS:
        return _err(f"method {method!r} is not read-only; allowed: "
                    f"{sorted(_SAFE_METHODS)}")

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
    req = urllib.request.Request(url, method=method, headers=safe_headers)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):  # noqa: D401
            return None   # never follow redirects (SSRF pivot guard)

    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=_READ_TIMEOUT) as resp:
            body = resp.read(_MAX_BODY_BYTES + 1)
            truncated = len(body) > _MAX_BODY_BYTES
            return json.dumps({
                "status": resp.status,
                "final_url": resp.url,
                "content_type": resp.headers.get("Content-Type", ""),
                "body": body[:_MAX_BODY_BYTES].decode("utf-8", "replace"),
                "body_truncated": truncated,
                "probes_used": _PROBE_STATS["used"],
            })
    except urllib.error.HTTPError as e:
        body = e.read(_MAX_BODY_BYTES)
        return json.dumps({
            "status": e.code,
            "content_type": e.headers.get("Content-Type", "") if e.headers else "",
            "body": body.decode("utf-8", "replace"),
            "probes_used": _PROBE_STATS["used"],
        })
    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        return _err(f"probe failed: {type(e).__name__}: {e}",
                    probes_used=_PROBE_STATS["used"])
