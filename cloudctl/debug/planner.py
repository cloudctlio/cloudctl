"""Debug planner — maps symptoms to data sources and discovers affected resources."""
from __future__ import annotations

from typing import Optional

# Maps symptom keywords to the data sources (fetcher methods) to call
SYMPTOM_SOURCES: dict[str, list[str]] = {
    # HTTP / API errors — include network context since LB/target health is often root cause
    "502":             ["service_logs", "ecs_events", "cloudwatch_metrics", "cloudtrail", "network_context"],
    "503":             ["service_logs", "ecs_events", "cloudwatch_metrics", "network_context"],
    "504":             ["service_logs", "ecs_events", "cloudwatch_metrics", "rds_events", "network_context"],
    "timeout":         ["cloudwatch_metrics", "ecs_events", "rds_events", "service_logs", "network_context"],
    "latency":         ["cloudwatch_metrics", "rds_events", "service_logs", "network_context"],
    "slow":            ["cloudwatch_metrics", "rds_events", "cloudwatch_logs", "network_context"],
    "error rate":      ["service_logs", "cloudwatch_metrics", "cloudwatch_logs"],
    "5xx":             ["service_logs", "ecs_events", "cloudwatch_metrics", "network_context"],
    "4xx":             ["service_logs", "cloudwatch_logs"],

    # Compute
    "crash":           ["ecs_events", "cloudwatch_logs", "cloudtrail"],
    "unhealthy":       ["ecs_events", "service_logs", "cloudwatch_metrics", "network_context"],
    "oom":             ["cloudwatch_logs", "ecs_events", "cloudwatch_metrics"],
    "out of memory":   ["cloudwatch_logs", "ecs_events", "cloudwatch_metrics"],
    "cpu":             ["cloudwatch_metrics", "ecs_events"],
    "memory":          ["cloudwatch_metrics", "ecs_events", "cloudwatch_logs"],
    "container":       ["ecs_events", "cloudwatch_logs"],
    "task":            ["ecs_events", "cloudwatch_logs"],
    "lambda":          ["service_logs", "cloudwatch_metrics"],
    "function":        ["service_logs", "cloudwatch_metrics"],

    # Database
    "connection":      ["rds_events", "cloudwatch_metrics", "cloudwatch_logs", "network_context"],
    "database":        ["rds_events", "cloudwatch_metrics"],
    "rds":             ["rds_events", "cloudwatch_metrics"],
    "pool":            ["rds_events", "cloudwatch_metrics", "cloudwatch_logs"],
    "query":           ["rds_events", "cloudwatch_metrics", "cloudwatch_logs"],
    "deadlock":        ["rds_events", "cloudwatch_logs"],

    # Deployment
    "deploy":          ["cloudtrail", "codepipeline", "ecs_events"],
    "rollout":         ["cloudtrail", "codepipeline", "ecs_events"],
    "pipeline":        ["codepipeline", "cloudtrail"],
    "release":         ["codepipeline", "cloudtrail"],
    "regression":      ["cloudtrail", "codepipeline", "cloudwatch_metrics"],

    # IAM / permissions
    "permission":      ["cloudtrail", "iam_simulation"],
    "access denied":   ["cloudtrail", "iam_simulation"],
    "unauthorized":    ["cloudtrail", "iam_simulation"],
    "forbidden":       ["cloudtrail", "iam_simulation"],
    "iam":             ["cloudtrail", "iam_simulation"],
    "role":            ["cloudtrail", "iam_simulation"],

    # Network — dedicated symptoms
    "network":         ["network_context", "cloudwatch_metrics", "cloudtrail"],
    "connectivity":    ["network_context", "cloudtrail"],
    "unreachable":     ["network_context", "cloudtrail"],
    "dns":             ["cloudwatch_logs", "network_context"],
    "nat":             ["network_context"],
    "vpc":             ["network_context"],
    "subnet":          ["network_context"],
    "security group":  ["network_context", "cloudtrail"],
    "firewall":        ["network_context", "cloudtrail"],
    "routing":         ["network_context"],
    "load balancer":   ["network_context", "service_logs", "cloudwatch_metrics"],
    "target group":    ["network_context", "service_logs"],
    "vpn":             ["network_context", "cloudtrail"],
    "direct connect":  ["network_context"],
    "peering":         ["network_context"],
    "endpoint":        ["network_context", "cloudtrail"],

    # Processing / application failures
    "failing":         ["service_logs", "cloudwatch_metrics", "cloudtrail"],
    "failed":          ["service_logs", "cloudwatch_metrics", "cloudtrail"],
    "exception":       ["service_logs", "cloudwatch_logs"],
    "processing":      ["service_logs", "cloudwatch_metrics", "cloudwatch_logs"],
    "retry":           ["service_logs", "cloudwatch_metrics"],
    "dead":            ["service_logs", "cloudwatch_metrics"],
    "throttl":         ["service_logs", "cloudwatch_metrics", "cloudtrail"],
    "concurren":       ["service_logs", "cloudwatch_metrics"],

    # Cost
    "cost":            ["cloudwatch_metrics"],
    "billing":         ["cloudwatch_metrics"],
    "expensive":       ["cloudwatch_metrics"],

    # Storage
    "s3":              ["cloudtrail", "cloudwatch_metrics"],
    "bucket":          ["cloudtrail", "cloudwatch_metrics"],
    "disk":            ["cloudwatch_metrics"],
}

# Default sources to always fetch
_DEFAULT_SOURCES = ["cloudwatch_metrics", "cloudtrail"]


def plan_sources(symptom: str) -> list[str]:
    """
    Return ordered list of data source names to fetch for the given symptom.
    Deduplicated, defaults appended last.
    """
    symptom_lower = symptom.lower()
    sources: list[str] = []

    for keyword, src_list in SYMPTOM_SOURCES.items():
        if keyword in symptom_lower:
            for s in src_list:
                if s not in sources:
                    sources.append(s)

    # Always include defaults if not already present
    for s in _DEFAULT_SOURCES:
        if s not in sources:
            sources.append(s)

    return sources


def extract_service_hints(symptom: str) -> list[str]:
    """
    Extract likely service names from the symptom for resource discovery.
    Returns list of strings like 'payments', 'api', 'auth-service'.
    """
    import re  # noqa: PLC0415

    # Words that are likely service names (not generic words)
    _STOP_WORDS = {
        "the", "is", "are", "was", "were", "been", "returning", "getting",
        "seeing", "since", "from", "after", "before", "when", "with", "high",
        "low", "slow", "fast", "error", "errors", "service", "services",
        "system", "our", "my", "this", "that", "all", "some", "any",
        "502s", "503s", "504s", "5xx", "4xx", "why", "what", "how",
    }

    # Quoted strings or hyphenated words are likely service names
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


def prioritize_sources(sources: list[str], available: set[str]) -> list[str]:
    """Filter sources to only those available in the current environment."""
    return [s for s in sources if s in available]
