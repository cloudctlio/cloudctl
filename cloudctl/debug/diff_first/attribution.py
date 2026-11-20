"""Who made a change, and how: by hand, by the IaC, or by other automation.

Every cloud keeps an audit trail of write calls (AWS CloudTrail, Azure Activity
Log, GCP Cloud Audit Logs). This module turns each one's records into the same
row shape and labels each change with its *route*:

* ``iac``         - deployed by an IaC tool (Terraform/OpenTofu, CloudFormation
                    or CDK, Pulumi, ARM/Bicep, Config Connector).
* ``manual``      - made by a person: the web console, CloudShell, a CLI, or a
                    direct SDK/script call outside any IaC.
* ``automation``  - made by the cloud itself (a service acting on its own) or
                    by a pipeline running a script outside the IaC.
* ``outside_iac`` - the live config differs from what the IaC declares on the
                    fields this call set, but the trail doesn't say who did it.
* ``unknown``     - not enough evidence either way.

Evidence, strongest first:

1. The caller's own signature: the user agent an IaC tool or CLI sets, the
   console-session flag, the service that invoked the call (CloudFormation),
   an ARM deployment that the call belongs to.
2. Whether the change matches the IaC: live equal to the declared state on the
   fields the call set means the IaC holds the change (Terraform state is
   updated by ``apply``, never by a console edit); live different means it went
   around the IaC. This decides when the trail is ambiguous (Azure's Activity
   Log records no user agent, so Terraform run with Azure CLI credentials and a
   hand ``az`` command look alike there).
3. The principal: a configured deploy principal (``CLOUDCTL_IAC_PRINCIPALS``),
   a principal named like a pipeline, or a human identity (SSO user, IAM user,
   Azure user, Google account). People run Terraform from laptops too, so a
   human principal only breaks ties.

The signatures below are a naming table of tools and client ids, the same kind
as the type-name table in ``normalize``: they say who called, never what a
failure looks like. Nothing here calls a cloud API or a model.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from cloudctl.debug.diff_first.model import iso, to_dt

# ── Signatures ───────────────────────────────────────────────────────────────

# (tool, pattern on the lower-cased user agent). Order matters: Pulumi's AWS
# provider is bridged from Terraform's and carries both names; Terraform's own
# AWS user agent also names the Go SDK, so IaC tools are matched before SDKs.
_IAC_UA: list[tuple[str, re.Pattern]] = [
    ("pulumi", re.compile(r"pulumi")),
    ("opentofu", re.compile(r"opentofu")),
    ("terraform", re.compile(r"terraform/|terraform-provider-|hashicorp/")),
    ("cdk", re.compile(r"aws-cdk")),
    ("crossplane", re.compile(r"crossplane")),
    ("config_connector", re.compile(r"\bkcc/|cnrm")),
    ("cloudformation", re.compile(r"^cloudformation\.amazonaws\.com$")),
]

_CONSOLE_UA = re.compile(
    r"^console\.|\.console\.|^signin\.amazonaws\.com|^aws internal|^mozilla/|"
    r"awsconsole|portal\.azure|azureportal|console\.cloud\.google")
_CLOUDSHELL_UA = re.compile(r"cloudshell")
_CLI_UA = re.compile(
    r"aws-cli/|azure-cli|azurecli|azure-powershell|azurepowershell|az\.accounts|"
    r"aws-tools-for-powershell|awspowershell|google-cloud-sdk|gcloud/")
_SDK_UA = re.compile(
    r"boto3/|botocore/|aws-sdk|azsdk-|azure-sdk|azure-mgmt|msrest|google-api-|"
    r"gl-python/|gl-go/|gl-java/|gccl|gapic|grpc-")

# Microsoft's own client applications, as they appear in the ``appid`` claim of
# an Azure Activity Log record. Fixed, published first-party ids.
_AZURE_APPS = {
    "c44b4083-3bb0-49c1-b47d-974e53cbdf3c": ("console", "Azure portal"),
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46": ("cli", "Azure CLI"),
    "1950a258-227b-4e31-a9cf-717495945fc2": ("cli", "Azure PowerShell"),
}

# Principals named like a deploy pipeline. Weak evidence: names are free text.
_PIPELINE_PRINCIPAL = re.compile(
    r"terraform|opentofu|\btfc\b|tfc-|atlantis|spacelift|env0|scalr|pulumi|"
    r"cdk-[a-z0-9]+-(cfn-exec|deploy)-role|cloudformation|github-?actions|"
    r"token\.actions\.githubusercontent|gitlab|codebuild|codepipeline|jenkins|"
    r"circleci|buildkite|azure-?devops|azdo|vstoken|harness|argocd|flux|deploy")

TOOL_NAMES = {
    "terraform": "Terraform", "opentofu": "OpenTofu", "pulumi": "Pulumi",
    "cdk": "AWS CDK", "cloudformation": "CloudFormation", "arm": "an ARM/Bicep deployment",
    "crossplane": "Crossplane", "config_connector": "Config Connector",
}
_HOW_NAMES = {
    "console": "in the {cloud} console", "cloudshell": "in {cloud} CloudShell",
    "cli": "with the {client}", "sdk": "by a direct SDK or script call ({client})",
}
_CLOUD_NAMES = {"aws": "AWS", "azure": "Azure", "gcp": "Google Cloud"}

# Which IaC tools write which expected-state kind (for "made by a different tool").
_TOOL_FAMILY = {"terraform": "terraform", "opentofu": "terraform", "pulumi": "pulumi",
                "cdk": "cloudformation", "cloudformation": "cloudformation",
                "arm": "arm", "crossplane": "crossplane", "config_connector": "config_connector"}
_KIND_FAMILY = {"terraform": "terraform", "cloudformation": "cloudformation", "cdk": "cloudformation",
                "pulumi": "pulumi"}


def configured_iac_principals() -> list[re.Pattern]:
    """``CLOUDCTL_IAC_PRINCIPALS``: comma-separated regexes for the principals
    your pipelines deploy with (role names, service-principal ids, service
    account emails). A match is strong evidence a change came through the IaC."""
    out: list[re.Pattern] = []
    for part in (os.environ.get("CLOUDCTL_IAC_PRINCIPALS") or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            out.append(re.compile(part, re.I))
        except re.error:
            out.append(re.compile(re.escape(part), re.I))
    return out


# ── Audit rows: one shape for every cloud ────────────────────────────────────
# Row keys: time, event_name, event_source, actor, resources, params, error_code
# (what the checks always used) plus cloud, principal, principal_type,
# user_agent, source_ip, invoked_by, console, client_app, correlation_id.

def normalize_cloudtrail(e: dict) -> dict:
    """One CloudTrail LookupEvents record (or a raw CloudTrail event) -> row."""
    detail = e.get("CloudTrailEvent")
    if isinstance(detail, str):
        try:
            detail = json.loads(detail)
        except ValueError:
            detail = {}
    elif not isinstance(detail, dict):
        detail = e if "eventName" in e else {}
    uid = detail.get("userIdentity") or {}
    issuer = ((uid.get("sessionContext") or {}).get("sessionIssuer") or {})
    actor = (uid.get("userName") or issuer.get("userName", "")
             or str(uid.get("arn", "")).split("/")[-1])
    console = str(detail.get("sessionCredentialFromConsole", "")).lower() == "true"
    resources = [r.get("ResourceName", "") for r in e.get("Resources", []) or []]
    resources += [r.get("ARN", "") for r in detail.get("resources", []) or [] if isinstance(r, dict)]
    return {
        "cloud": "aws",
        "time": iso(to_dt(e.get("EventTime") or detail.get("eventTime"))),
        "event_name": e.get("EventName") or detail.get("eventName", ""),
        "event_source": e.get("EventSource") or detail.get("eventSource", ""),
        "actor": actor,
        "principal": str(uid.get("arn") or issuer.get("arn") or actor),
        "principal_type": str(uid.get("type") or ""),
        "user_agent": str(detail.get("userAgent") or ""),
        "source_ip": str(detail.get("sourceIPAddress") or ""),
        "invoked_by": str(uid.get("invokedBy") or ""),
        "console": console,
        "resources": [r for r in resources if r],
        "params": detail.get("requestParameters") or {},
        "error_code": detail.get("errorCode", "") or "",
    }


def _get(obj: Any, *path: str) -> Any:
    for p in path:
        if obj is None:
            return None
        obj = obj.get(p) if isinstance(obj, dict) else getattr(obj, p, None)
    return obj


def _value(v: Any) -> str:
    """Azure wraps names as {"value": ..., "localizedValue": ...}."""
    if isinstance(v, dict):
        return str(v.get("value") or v.get("localizedValue") or "")
    return str(getattr(v, "value", v) or "")


def arm_parent(rid: str) -> str:
    """The top-level resource of an ARM id: a write to
    ``.../Microsoft.Web/sites/app/config/appsettings`` changes the site."""
    parts = rid.strip("/").split("/")
    low = [x.lower() for x in parts]
    if "providers" not in low:
        return rid
    i = len(low) - 1 - low[::-1].index("providers")
    top = parts[:i + 4]          # providers / namespace / type / name
    return "/" + "/".join(top) if len(top) == i + 4 else rid


def normalize_azure_activity(e: Any) -> dict:
    """One Azure Activity Log record (REST JSON, or the SDK model's
    ``as_dict()``, camel or snake case) -> row."""
    if not isinstance(e, dict) and hasattr(e, "as_dict"):
        e = e.as_dict()
    g = lambda *names: next((e.get(n) for n in names if e.get(n) not in (None, "")), None)  # noqa: E731
    claims = g("claims") or {}
    http = g("httpRequest", "http_request") or {}
    props = g("properties") or {}
    status = _value(g("status"))
    sub_status = _value(g("subStatus", "sub_status"))
    op = _value(g("operationName", "operation_name"))
    rid = str(g("resourceId", "resource_id") or "")
    appid = str(claims.get("appid") or claims.get("azp") or "").lower()
    idtyp = str(claims.get("idtyp") or "").lower()
    caller = str(g("caller") or "")
    error = ""
    if status.lower() == "failed":
        error = sub_status or "Failed"
    ua = str(props.get("userAgent") or props.get("clientUserAgent") or http.get("userAgent") or "")
    return {
        "cloud": "azure",
        "time": iso(to_dt(g("eventTimestamp", "event_timestamp", "submissionTimestamp"))),
        "event_name": op,
        "event_source": op.split("/")[0] if "/" in op else op,
        "actor": caller,
        "principal": caller,
        "principal_type": "user" if idtyp == "user" or "@" in caller else ("app" if idtyp == "app" or appid else ""),
        "user_agent": ua,
        "source_ip": str(http.get("clientIpAddress") or http.get("client_ip_address") or ""),
        "invoked_by": "",
        "console": False,
        "client_app": appid,
        "correlation_id": str(g("correlationId", "correlation_id") or ""),
        "status": status,
        "resources": list(dict.fromkeys(x for x in (rid, arm_parent(rid)) if x)),
        "params": props.get("requestbody") if isinstance(props.get("requestbody"), dict) else _json_or_empty(
            props.get("requestbody")),
        "error_code": error,
    }


def _json_or_empty(v: Any) -> dict:
    if isinstance(v, str):
        try:
            out = json.loads(v)
            return out if isinstance(out, dict) else {}
        except ValueError:
            return {}
    return v if isinstance(v, dict) else {}


def normalize_gcp_audit(e: dict) -> dict:
    """One Cloud Audit Logs entry (LogEntry JSON with ``protoPayload``) -> row."""
    p = e.get("protoPayload") or e.get("proto_payload") or e.get("payload") or {}
    auth = p.get("authenticationInfo") or {}
    meta = p.get("requestMetadata") or {}
    status = p.get("status") or {}
    email = str(auth.get("principalEmail") or "")
    code = status.get("code") or 0
    rname = str(p.get("resourceName") or "")
    return {
        "cloud": "gcp",
        "time": iso(to_dt(e.get("timestamp") or e.get("receiveTimestamp"))),
        "event_name": str(p.get("methodName") or ""),
        "event_source": str(p.get("serviceName") or ""),
        "actor": email,
        "principal": email,
        "principal_type": ("service_account" if email.endswith("gserviceaccount.com")
                           else ("user" if "@" in email else "")),
        "user_agent": str(meta.get("callerSuppliedUserAgent") or ""),
        "source_ip": str(meta.get("callerIp") or ""),
        "invoked_by": "",
        "console": False,
        "resources": [rname] if rname else [],
        "params": p.get("request") if isinstance(p.get("request"), dict) else {},
        "error_code": (str(status.get("message") or f"code {code}") if code else ""),
    }


def normalize_audit(record: Any, cloud: str) -> dict:
    return {"aws": normalize_cloudtrail, "azure": normalize_azure_activity,
            "gcp": normalize_gcp_audit}[cloud](record)


def is_write(row: dict) -> bool:
    """Write calls only: reads never change config. CloudTrail is already
    filtered to ReadOnly=false; Azure and GCP name the verb in the operation."""
    cloud = row.get("cloud") or "aws"
    name = str(row.get("event_name") or "").lower()
    if cloud == "azure":
        if row.get("status", "").lower() in ("started", "accepted") and not row.get("error_code"):
            return False          # the Succeeded/Failed record of the same call follows
        return name.endswith(("/write", "/delete", "/action")) and not name.endswith(
            ("/listkeys/action", "/read"))
    if cloud == "gcp":
        last = name.rsplit(".", 1)[-1]
        return not last.startswith(("get", "list", "search", "test", "query", "batchget", "lookup"))
    return True


# ── Signals ──────────────────────────────────────────────────────────────────

@dataclass
class Signal:
    kind: str = "unknown"     # iac | console | cloudshell | cli | sdk | cloud_service | unknown
    tool: str = ""            # terraform, cdk, ... for iac; client name otherwise
    strong: bool = False
    evidence: list[str] = field(default_factory=list)


def _ua_short(ua: str) -> str:
    return ua.split(" ")[0][:60] if ua else ""


def caller_signal(row: dict, deployments: set[str] | None = None) -> Signal:
    """What the caller's own fingerprint says, without looking at the IaC."""
    cloud = row.get("cloud") or "aws"
    ua = str(row.get("user_agent") or "")
    low = ua.lower().strip()
    invoked = str(row.get("invoked_by") or "").lower()
    src_ip = str(row.get("source_ip") or "").lower()

    if cloud == "aws":
        if invoked == "cloudformation.amazonaws.com" or src_ip == "cloudformation.amazonaws.com":
            return Signal("iac", "cloudformation", True,
                          ["CloudTrail: the call was made by the CloudFormation service"])
    if cloud == "azure" and row.get("correlation_id") and deployments and \
            row["correlation_id"] in deployments:
        return Signal("iac", "arm", True,
                      ["Activity Log: the call belongs to an ARM deployment (same correlation id)"])
    for tool, rx in _IAC_UA:
        if low and rx.search(low):
            return Signal("iac", tool, True, [f"user agent names {TOOL_NAMES[tool]}: {ua[:140]}"])
    if row.get("console"):
        return Signal("console", "console", True, ["CloudTrail: session credentials came from the console"])
    if cloud == "aws" and (str(row.get("principal_type")) == "AWSService" or
                           (invoked.endswith(".amazonaws.com") and invoked != "cloudformation.amazonaws.com")):
        who = invoked or "an AWS service"
        return Signal("cloud_service", who, True, [f"CloudTrail: invoked by {who}"])
    if low and _CLOUDSHELL_UA.search(low):
        return Signal("cloudshell", "CloudShell", True, [f"user agent is CloudShell: {ua[:140]}"])
    if low and _CONSOLE_UA.search(low):
        return Signal("console", "console", True, [f"user agent is the web console: {ua[:140]}"])
    if cloud == "gcp":
        email = str(row.get("principal") or "").lower()
        if re.search(r"cnrm-system@|cnrm-controller-manager", email):
            return Signal("iac", "config_connector", True, [f"principal is Config Connector's: {email}"])
        if email.endswith("@cloudservices.gserviceaccount.com") or "@gcp-sa-" in email or \
                re.search(r"^service-\d+@", email):
            return Signal("cloud_service", email, True, [f"principal is a Google-managed service agent: {email}"])
    if cloud == "azure":
        app = _AZURE_APPS.get(str(row.get("client_app") or "").lower())
        if app and app[0] == "console":
            return Signal("console", app[1], True, [f"Activity Log: client application is the {app[1]}"])
        if app:
            # Terraform's azurerm provider can sign in with Azure CLI credentials
            # and the Activity Log keeps no user agent, so this is not decisive.
            return Signal("cli", app[1], False, [f"Activity Log: client application is {app[1]} "
                                                  "(Terraform signed in with CLI credentials looks the same)"])
    if low and _CLI_UA.search(low):
        return Signal("cli", _ua_short(ua), True, [f"user agent is a CLI: {ua[:140]}"])
    if low and _SDK_UA.search(low):
        return Signal("sdk", _ua_short(ua), True, [f"user agent is an SDK: {ua[:140]}"])
    ev = [f"user agent not recognised: {ua[:140]}"] if ua else ["the audit record has no user agent"]
    return Signal("unknown", "", False, ev)


def principal_hint(row: dict) -> tuple[str, str]:
    """('pipeline_configured' | 'pipeline_named' | 'human' | '', evidence)."""
    p = " ".join(str(row.get(k) or "") for k in ("principal", "actor")).strip()
    low = p.lower()
    for rx in configured_iac_principals():
        if rx.search(p):
            return "pipeline_configured", f"principal {p.split()[0]} matches CLOUDCTL_IAC_PRINCIPALS"
    if low and _PIPELINE_PRINCIPAL.search(low):
        return "pipeline_named", f"principal {p.split()[0]} is named like a deploy pipeline"
    ptype = str(row.get("principal_type") or "")
    if ptype in ("IAMUser", "Root", "user") or "assumed-role/awsreservedsso_" in low or (
            row.get("cloud") in ("gcp", "azure") and "@" in low and "gserviceaccount.com" not in low):
        return "human", f"principal {p.split()[0] if p else '?'} is a person's identity"
    return "", ""


# ── Route ────────────────────────────────────────────────────────────────────

@dataclass
class Attribution:
    route: str = "unknown"
    how: str = ""                 # tool or client: terraform, console, cli, sdk, cloud_service ...
    confidence: str = "low"       # high | medium | low
    matches_iac: bool | None = None
    label: str = ""
    fix_direction: str = ""       # reapply_iac | edit_iac | reconcile | ""
    evidence: list[str] = field(default_factory=list)

    def to_fields(self) -> dict:
        return {"route": self.route, "route_how": self.how, "route_confidence": self.confidence,
                "matches_iac": self.matches_iac, "route_label": self.label,
                "fix_direction": self.fix_direction, "route_evidence": list(self.evidence)}


FIX_TEXT = {
    "reapply_iac": "re-apply the IaC to restore the declared value; do not edit the code to match "
                   "unless the change is meant to stay",
    "edit_iac": "the IaC itself holds this change: fix it in the code and deploy again",
    "reconcile": "an IaC run made this change but the declared state here does not hold it: find "
                 "which workspace, branch or stack applied it before changing either side",
}


def _match_text(m: bool | None) -> str:
    return {True: "live matches the declared IaC on the fields this call set",
            False: "live differs from the declared IaC on the fields this call set",
            None: "whether it matches the declared IaC could not be checked"}[m]


def attribute(row: dict, matches_iac: bool | None, expected_kind: str = "",
              deployments: set[str] | None = None) -> Attribution:
    """Label one change. ``matches_iac``: True = live equals the declared state
    on the fields the call set, False = it differs, None = can't tell."""
    cloud = _CLOUD_NAMES.get(row.get("cloud") or "aws", "the cloud")
    sig = caller_signal(row, deployments)
    hint, hint_ev = principal_hint(row)
    ev = list(sig.evidence) + ([hint_ev] if hint_ev else []) + [_match_text(matches_iac)]
    a = Attribution(matches_iac=matches_iac, evidence=ev)
    family = _KIND_FAMILY.get(expected_kind, "")

    if sig.kind == "iac":
        name = TOOL_NAMES.get(sig.tool, sig.tool)
        a.how = sig.tool
        other_tool = family and _TOOL_FAMILY.get(sig.tool) and _TOOL_FAMILY[sig.tool] != family
        if matches_iac is False or other_tool:
            a.route, a.confidence, a.fix_direction = "iac", "high", "reconcile"
            why = (f"this app's IaC is {expected_kind}" if other_tool
                   else "the declared state here does not hold it")
            a.label = (f"made by {name}, but {why} (another workspace, branch, stack, or a run "
                       "that was never committed)")
        else:
            a.route, a.confidence, a.fix_direction = "iac", "high", "edit_iac"
            a.label = f"deployed by {name}"
        return a

    if sig.kind in ("console", "cloudshell"):
        a.route, a.how, a.confidence, a.fix_direction = "manual", sig.kind, "high", "reapply_iac"
        a.label = "made by hand " + _HOW_NAMES[sig.kind].format(cloud=cloud, client=sig.tool) + ", outside the IaC"
        return a

    if sig.kind == "cloud_service":
        a.route, a.how, a.confidence = "automation", "cloud_service", "high"
        a.fix_direction = "reapply_iac" if matches_iac is False else ""
        a.label = f"made by the cloud itself ({sig.tool}), not by a person or the IaC"
        return a

    if sig.kind in ("cli", "sdk"):
        how = _HOW_NAMES[sig.kind].format(cloud=cloud, client=sig.tool or sig.kind.upper())
        if not sig.strong:
            # Azure CLI / PowerShell client id: Terraform with CLI credentials looks the same.
            if matches_iac is True:
                a.route, a.how, a.confidence, a.fix_direction = "iac", expected_kind or "iac", "medium", "edit_iac"
                a.label = (f"consistent with an IaC run: the call came {how}, which Terraform also "
                           "uses, and live matches the declared state")
            elif matches_iac is False:
                a.route, a.how, a.confidence, a.fix_direction = "manual", sig.kind, "medium", "reapply_iac"
                a.label = f"made by hand {how}, outside the IaC (live differs from the declared state)"
            else:
                a.route, a.how, a.confidence = "unknown", sig.kind, "low"
                a.label = f"made {how}; whether that was a person or Terraform can't be told from the audit log"
            return a
        if hint.startswith("pipeline"):
            a.route, a.how, a.confidence = "automation", sig.kind, "medium"
            a.fix_direction = "reapply_iac" if matches_iac is not True else ""
            a.label = f"made by a pipeline principal {how}, outside the IaC tool"
            return a
        a.route, a.how = "manual", sig.kind
        a.confidence = "high" if matches_iac is not True else "medium"
        a.fix_direction = "reapply_iac"
        a.label = f"made by hand {how}, outside the IaC"
        return a

    # No usable fingerprint: fall back to the IaC match and the principal.
    if hint == "pipeline_configured" and matches_iac is not False:
        a.route, a.how, a.confidence, a.fix_direction = "iac", expected_kind or "iac", "medium", "edit_iac"
        a.label = "deployed by the configured IaC principal"
        return a
    if matches_iac is False:
        if hint == "human":
            a.route, a.how, a.confidence = "manual", "unknown", "medium"
            a.label = "made by a person outside the IaC (live differs from the declared state)"
        else:
            a.route, a.how, a.confidence = "outside_iac", "unknown", "medium"
            a.label = "made outside the IaC (live differs from the declared state; the caller is unknown)"
        a.fix_direction = "reapply_iac"
        return a
    if matches_iac is True:
        a.route, a.how, a.fix_direction = "iac", expected_kind or "iac", "edit_iac"
        a.confidence = "medium" if hint.startswith("pipeline") else "low"
        a.label = ("consistent with an IaC deploy: live matches the declared state"
                   + (" and the principal is named like a pipeline" if hint.startswith("pipeline") else ""))
        return a
    a.route, a.how, a.confidence = "unknown", "", "low"
    a.label = "who made this change could not be told"
    return a


def deployment_correlations(rows: list[dict]) -> set[str]:
    """Azure: correlation ids of ARM deployments in the trail. A resource write
    that shares one was made by that deployment (ARM template or Bicep)."""
    return {r["correlation_id"] for r in rows
            if r.get("cloud") == "azure" and r.get("correlation_id")
            and str(r.get("event_name", "")).lower().startswith("microsoft.resources/deployments/")}


def drift_attribution(observer: bool = False) -> Attribution:
    """Drift with no audit record that explains it: by definition it went
    around the declared IaC; who did it is unknown."""
    return Attribution(
        route="outside_iac", how="unknown", confidence="medium", matches_iac=False,
        fix_direction="reapply_iac",
        label="changed outside the IaC (no audit record of who changed it was found in the window)",
        evidence=["live differs from the declared IaC",
                  "no matching write call in the audit trail for this resource"])


# ── Applying it to the checks' changes and drift ─────────────────────────────

def _leaves(keys) -> set[str]:
    return {str(k).split(".")[-1] for k in keys}


def _set_keys(params: Any) -> dict[str, Any]:
    """Fields a write call set. Top-level names, ARNs and ids only say which
    resource it targets; nested ones (an env var called QUEUE_URL) are values."""
    from cloudctl.debug.diff_first.changes import _ID_SUFFIXES
    from cloudctl.debug.diff_first.normalize import flatten
    flat = flatten(params or {}) if isinstance(params, (dict, list)) else {}
    return {k: v for k, v in flat.items() if "." in k or not k.endswith(_ID_SUFFIXES)}


def iac_match(change: Any, drift_by_key: dict[str, list], compared: set[str],
              latest: bool = False) -> bool | None:
    """Does live still equal the declared IaC on the fields this call set?
    False when a drift item on the same resource covers one of those fields
    (or the resource is gone after a Delete); True when the resource was
    compared and showed no drift; None when it wasn't compared.

    Some audit logs keep no request body (Azure's Activity Log, many Google
    audit entries). Then a call that is the last write to a resource that
    drifted is taken to have left it off the IaC: nothing after it changed
    the resource, so live is what it wrote."""
    keys = [k for k in (change.resource_key or "").split(",") if k]
    want = _leaves(_set_keys(change.params))
    verdict: bool | None = None
    for k in keys:
        items = drift_by_key.get(k) or []
        for d in items:
            if d.kind == "deleted" and str(change.event_name).lower().startswith("delete"):
                return False
            if want & _leaves(f["field"] for f in d.fields):
                return False
        if items and latest and not want and change.params in (None, {}, [], ""):
            return False
        if items:
            continue            # drift here, but not on what this call set: can't tell
        if k in compared:
            verdict = True
    return verdict


def apply_attribution(changes: list, drift: list, compared_keys: set[str] | list[str],
                      expected_kind: str = "", rows: list[dict] | None = None) -> None:
    """Label every matched change and every drift item with its route (in place)."""
    from dataclasses import asdict
    compared = set(compared_keys or [])
    drift_by_key: dict[str, list] = {}
    for d in drift:
        drift_by_key.setdefault(d.resource_key, []).append(d)
    deployments = deployment_correlations(rows or [])
    last: dict[str, Any] = {}
    for c in sorted((c for c in changes if c.resource_key and not c.error_code), key=lambda c: c.time or ""):
        for k in c.resource_key.split(","):
            last[k] = c
    for c in changes:
        if not c.resource_key or c.error_code:
            continue
        is_last = any(last.get(k) is c for k in c.resource_key.split(","))
        a = attribute(asdict(c), iac_match(c, drift_by_key, compared, is_last), expected_kind, deployments)
        for k, v in a.to_fields().items():
            setattr(c, k, v)
    by_key: dict[str, list] = {}
    for c in changes:
        if c.resource_key and not c.error_code:
            for k in c.resource_key.split(","):
                by_key.setdefault(k, []).append(c)
    for d in drift:
        fields = _leaves(f["field"] for f in d.fields)
        mine = by_key.get(d.resource_key, [])
        hits = [c for c in mine
                if (fields & _leaves(_set_keys(c.params))) or
                (d.kind == "deleted" and str(c.event_name).lower().startswith("delete"))]
        # A call can change a field it doesn't name (DisableAlarmActions turns
        # ActionsEnabled off): failing a field match, the latest write to the
        # drifted resource is the best evidence of who drifted it.
        hits = hits or [c for c in mine if c.route != "iac" or c.matches_iac is not True]
        if hits:
            c = sorted(hits, key=lambda x: x.time or "")[-1]
            d.route, d.route_label, d.route_confidence = c.route, c.route_label, c.route_confidence
            d.fix_direction = c.fix_direction
            d.route_evidence = [f"{c.event_name} at {c.time} by {c.actor or 'unknown'}"] + list(c.route_evidence)
            d.changed_at, d.changed_by = d.changed_at or c.time, d.changed_by or c.actor
        else:
            a = drift_attribution()
            d.route, d.route_label, d.route_confidence = a.route, a.label, a.confidence
            d.fix_direction, d.route_evidence = a.fix_direction, a.evidence
