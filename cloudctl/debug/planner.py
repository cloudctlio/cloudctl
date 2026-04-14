"""Debug planner — extracts resource hints from symptoms for targeted log discovery."""
from __future__ import annotations

# Cloud-agnostic data sources — every cloud platform has these:
#   service_logs       — application/service logs
#   audit_logs         — API call history (CloudTrail / Azure Activity Log / GCP Audit Logs)
#   network_context    — network topology (VPC/VNet, security groups, routing, load balancers)
#   deployment_method  — IaC tool detection (CDK/Terraform/Pulumi/etc.)
#   acm_expiry_check   — SSL/TLS certificate expiry (always-fetch: expired certs cause silent outages)
ALL_SOURCES = ["service_logs", "audit_logs", "network_context", "deployment_method", "acm_expiry_check"]


def plan_sources(symptom: str) -> list[str]:  # noqa: ARG001
    """Return all generic data sources to fetch. Always the same set."""
    return list(ALL_SOURCES)


def extract_service_hints(symptom: str) -> list[str]:
    """
    Extract likely service/resource names from the symptom for targeted log discovery.
    For example: "payments service returning 502s" → ["payments"]
    Used to narrow which log groups to search instead of scanning all groups.
    """
    import re  # noqa: PLC0415

    _STOP_WORDS = {
        "the", "is", "are", "was", "were", "been", "returning", "getting",
        "seeing", "since", "from", "after", "before", "when", "with", "high",
        "low", "slow", "fast", "error", "errors", "service", "services",
        "system", "our", "my", "this", "that", "all", "some", "any",
        "502s", "503s", "504s", "5xx", "4xx", "why", "what", "how",
    }

    # Quoted strings are likely service names
    quoted = re.findall(r'"([^"]+)"|\'([^\']+)\'', symptom)
    hints = [q[0] or q[1] for q in quoted]

    # Hyphenated words (e.g. payments-api, auth-service)
    hyphenated = re.findall(r'\b([a-z]+-[a-z]+(?:-[a-z]+)*)\b', symptom.lower())
    for h in hyphenated:
        if h not in hints:
            hints.append(h)

    # Words longer than 4 chars not in stop list
    words = re.findall(r'\b([a-z]{5,})\b', symptom.lower())
    for w in words:
        if w not in _STOP_WORDS and w not in hints:
            hints.append(w)

    return hints[:5]  # Cap at 5 hints
