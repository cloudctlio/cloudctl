"""Read-only live sources for Azure and Google Cloud, and one source that
serves an app spread over several clouds.

They implement the same ``LiveSource`` calls as ``AwsLive``, so drift (monitors
included) and who-made-each-change run the same way on every cloud:

* ``read``          - Azure: Resource Manager ``GET`` by resource id (any type;
                      the API version is looked up from the resource provider).
                      Google Cloud: the resource's own REST ``GET`` (self link,
                      or the service's API path for ``projects/...`` names).
* ``write_events``  - Azure Activity Log; Google Cloud Audit Logs (Admin
                      Activity). Records are normalised by ``attribution``.

What they don't do yet: ``metrics`` returns nothing (the incident window and
flow checks are AWS-only), and ``discover`` finds nothing (Azure and Google
Cloud need IaC or a baseline file for the expected state).

Every call here is a read. Credentials come from the standard chains:
``DefaultAzureCredential`` and ``google.auth.default``. Missing SDKs or
credentials are reported in ``notes`` and never raise.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from cloudctl.debug.diff_first.live import NOT_FOUND
from cloudctl.debug.diff_first.model import Resource, iso
from cloudctl.debug.diff_first.normalize import cloud_of_type

_MAX_AUDIT_ROWS = 5000


def _arm_id(r: Resource) -> str:
    for v in (r.physical_id, (r.config or {}).get("id"), r.arn):
        if isinstance(v, str) and v.lower().startswith("/subscriptions/"):
            return v
    return ""


def _arm_shape(body: dict) -> dict:
    """A Resource Manager object in the shape the IaC declares it: ``properties``
    lifted to the top (Terraform's azurerm attributes sit there), and a single
    ``criteria.allOf`` entry merged into ``criteria`` (azurerm writes one
    ``criteria`` block per condition)."""
    if not isinstance(body, dict):
        return body
    props = body.get("properties") if isinstance(body.get("properties"), dict) else {}
    out = {k: v for k, v in body.items() if k != "properties"}
    out.update(props)
    crit = out.get("criteria")
    if isinstance(crit, dict) and isinstance(crit.get("allOf"), list) and len(crit["allOf"]) == 1:
        merged = {k: v for k, v in crit.items() if k != "allOf"}
        merged.update(crit["allOf"][0] if isinstance(crit["allOf"][0], dict) else {})
        out["criteria"] = merged
    return out


class AzureLive:
    """Read-only Azure access through Resource Manager and the Activity Log."""

    def __init__(self, credential: Any = None, subscription_id: str = ""):
        self.credential = credential
        self.subscriptions: set[str] = {subscription_id} if subscription_id else set()
        self.notes: list[str] = []
        self._api: dict[str, str] = {}
        self._rm: dict[str, Any] = {}

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _cred(self):
        if self.credential is None:
            from azure.identity import DefaultAzureCredential  # noqa: PLC0415
            self.credential = DefaultAzureCredential(exclude_interactive_browser_credential=True)
        return self.credential

    def _client(self, sub: str):
        if sub not in self._rm:
            from azure.mgmt.resource import ResourceManagementClient  # noqa: PLC0415
            self._rm[sub] = ResourceManagementClient(self._cred(), sub)
        return self._rm[sub]

    def _api_version(self, sub: str, rid: str) -> str:
        m = re.search(r"/providers/([^/]+)/(.+)$", rid, re.I)
        if not m:
            return ""
        namespace = m.group(1)
        segs = m.group(2).split("/")
        rtype = "/".join(segs[0::2])          # metricAlerts, namespaces/queues, ...
        key = f"{namespace}/{rtype}".lower()
        if key not in self._api:
            prov = self._client(sub).providers.get(namespace)
            versions: list[str] = []
            for rt in getattr(prov, "resource_types", None) or []:
                if str(getattr(rt, "resource_type", "")).lower() == rtype.lower():
                    versions = list(getattr(rt, "api_versions", None) or [])
            stable = [v for v in versions if "preview" not in v.lower()]
            self._api[key] = sorted(stable or versions)[-1] if (stable or versions) else ""
        return self._api[key]

    def read(self, resource: Resource) -> dict | None:
        rid = _arm_id(resource)
        if not rid:
            return None
        sub = rid.split("/")[2]
        self.subscriptions.add(sub)
        try:
            api = self._api_version(sub, rid)
            if not api:
                return None
            got = self._client(sub).resources.get_by_id(rid, api)
            body = got.as_dict() if hasattr(got, "as_dict") else dict(got)
            return _arm_shape(body)
        except ImportError:
            self._note("Azure SDK not installed (pip install 'cctl[azure]'): Azure resources were not read")
            return None
        except Exception as exc:  # noqa: BLE001
            if getattr(exc, "status_code", None) == 404 or type(exc).__name__ == "ResourceNotFoundError":
                return NOT_FOUND
            self._note(f"Azure read failed for some resources: {type(exc).__name__}")
            return None

    def write_events(self, start: datetime, end: datetime) -> list[dict]:
        from cloudctl.debug.diff_first.attribution import is_write, normalize_azure_activity
        rows: list[dict] = []
        if not self.subscriptions:
            return rows
        try:
            from azure.mgmt.monitor import MonitorManagementClient  # noqa: PLC0415
        except ImportError:
            self._note("azure-mgmt-monitor not installed: the Azure Activity Log was not read")
            return rows
        fmt = "%Y-%m-%dT%H:%M:%SZ"
        filt = (f"eventTimestamp ge '{start.astimezone(timezone.utc).strftime(fmt)}' and "
                f"eventTimestamp le '{end.astimezone(timezone.utc).strftime(fmt)}'")
        for sub in sorted(self.subscriptions):
            try:
                client = MonitorManagementClient(self._cred(), sub)
                for ev in client.activity_logs.list(filter=filt):
                    row = normalize_azure_activity(ev)
                    if is_write(row):
                        rows.append(row)
                    if len(rows) >= _MAX_AUDIT_ROWS:
                        self._note("Azure Activity Log: stopped at the row limit; older writes not read")
                        break
            except Exception as exc:  # noqa: BLE001
                self._note(f"Azure Activity Log unavailable for a subscription: {type(exc).__name__}")
        return rows

    def metrics(self, queries, start, end, period) -> dict:
        return {}

    def discover(self) -> list[Resource]:
        return []

    def stack_resources(self, stack: str) -> list[dict]:
        return []

    def stack_drifts(self, stack: str, detect: bool = False) -> list[dict]:
        return []

    def config_history(self, resource: Resource, at: str | None) -> dict | None:
        return None

    def _note(self, msg: str) -> None:
        if msg not in self.notes:
            self.notes.append(msg)


# ── Google Cloud ─────────────────────────────────────────────────────────────

# Where each service's resources are served: a naming table of API roots.
_GCP_API = {
    "monitoring.googleapis.com": "https://monitoring.googleapis.com/v3/",
    "logging.googleapis.com": "https://logging.googleapis.com/v2/",
    "pubsub.googleapis.com": "https://pubsub.googleapis.com/v1/",
    "run.googleapis.com": "https://run.googleapis.com/v2/",
    "iam.googleapis.com": "https://iam.googleapis.com/v1/",
    "container.googleapis.com": "https://container.googleapis.com/v1/",
}
_GCP_TYPE_API = {
    "cloudfunctions.googleapis.com/Function": "https://cloudfunctions.googleapis.com/v2/",
    "cloudfunctions.googleapis.com/CloudFunction": "https://cloudfunctions.googleapis.com/v1/",
}


def gcp_url(r: Resource) -> str:
    cfg = r.config or {}
    self_link = cfg.get("self_link") or cfg.get("selfLink")
    if isinstance(self_link, str) and self_link.startswith("https://"):
        return self_link
    if r.type == "storage.googleapis.com/Bucket":
        name = cfg.get("name") or r.name or r.physical_id
        return f"https://storage.googleapis.com/storage/v1/b/{name}" if name else ""
    if r.type == "sqladmin.googleapis.com/Instance":
        name, project = cfg.get("name") or r.name, cfg.get("project")
        return f"https://sqladmin.googleapis.com/v1/projects/{project}/instances/{name}" if name and project else ""
    path = next((v for v in (r.physical_id, cfg.get("id"), cfg.get("name"), r.name)
                 if isinstance(v, str) and v.startswith("projects/")), "")
    if not path:
        return ""
    base = _GCP_TYPE_API.get(r.type) or _GCP_API.get(r.type.split("/")[0], "")
    return base + path if base else ""


def _project_of(r: Resource) -> str:
    cfg = r.config or {}
    if isinstance(cfg.get("project"), str) and cfg["project"]:
        return cfg["project"]
    for v in (r.physical_id, cfg.get("id"), cfg.get("name"), cfg.get("self_link")):
        m = re.search(r"projects/([^/]+)", str(v or ""))
        if m:
            return m.group(1)
    return ""


class GcpLive:
    """Read-only Google Cloud access over REST (google-auth only)."""

    def __init__(self, project: str = "", session: Any = None):
        self.projects: set[str] = {project} if project else set()
        self.session = session
        self.notes: list[str] = []

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _s(self):
        if self.session is None:
            import google.auth  # noqa: PLC0415
            from google.auth.transport.requests import AuthorizedSession  # noqa: PLC0415
            creds, default_project = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"])
            if default_project and not self.projects:
                self.projects.add(default_project)
            self.session = AuthorizedSession(creds)
        return self.session

    def read(self, resource: Resource) -> dict | None:
        url = gcp_url(resource)
        if not url:
            return None
        p = _project_of(resource)
        if p:
            self.projects.add(p)
        try:
            resp = self._s().get(url, timeout=20)
        except ImportError:
            self._note("google-auth not installed (pip install 'cctl[gcp]'): Google Cloud resources were not read")
            return None
        except Exception as exc:  # noqa: BLE001
            self._note(f"Google Cloud read failed for some resources: {type(exc).__name__}")
            return None
        if resp.status_code == 404:
            return NOT_FOUND
        if resp.status_code != 200:
            self._note(f"Google Cloud read returned HTTP {resp.status_code} for some resources")
            return None
        try:
            return resp.json()
        except ValueError:
            return None

    def write_events(self, start: datetime, end: datetime, max_pages: int = 10) -> list[dict]:
        from cloudctl.debug.diff_first.attribution import is_write, normalize_gcp_audit
        rows: list[dict] = []
        for project in sorted(self.projects):
            body = {
                "resourceNames": [f"projects/{project}"],
                "filter": (f'logName="projects/{project}/logs/cloudaudit.googleapis.com%2Factivity" '
                           f'AND timestamp>="{iso(start)}" AND timestamp<="{iso(end)}"'),
                "orderBy": "timestamp asc", "pageSize": 1000,
            }
            try:
                for _ in range(max_pages):
                    resp = self._s().post("https://logging.googleapis.com/v2/entries:list",
                                          json=body, timeout=30)
                    if resp.status_code != 200:
                        self._note(f"Google Cloud Audit Logs returned HTTP {resp.status_code} for a project")
                        break
                    data = resp.json()
                    for e in data.get("entries", []) or []:
                        row = normalize_gcp_audit(e)
                        if is_write(row):
                            rows.append(row)
                    token = data.get("nextPageToken")
                    if not token or len(rows) >= _MAX_AUDIT_ROWS:
                        break
                    body["pageToken"] = token
            except ImportError:
                self._note("google-auth not installed: Google Cloud Audit Logs were not read")
                break
            except Exception as exc:  # noqa: BLE001
                self._note(f"Google Cloud Audit Logs unavailable for a project: {type(exc).__name__}")
        return rows

    def metrics(self, queries, start, end, period) -> dict:
        return {}

    def discover(self) -> list[Resource]:
        return []

    def stack_resources(self, stack: str) -> list[dict]:
        return []

    def stack_drifts(self, stack: str, detect: bool = False) -> list[dict]:
        return []

    def config_history(self, resource: Resource, at: str | None) -> dict | None:
        return None

    def _note(self, msg: str) -> None:
        if msg not in self.notes:
            self.notes.append(msg)


# ── Several clouds behind one source ─────────────────────────────────────────

class MultiCloudLive:
    """Send each resource to its own cloud; merge the audit trails of every
    cloud the app uses. Metrics, discovery, stacks and AWS Config stay with the
    primary (AWS) source. One cloud failing never hides another's rows."""

    def __init__(self, aws: Any, azure: Any = None, gcp: Any = None):
        self.aws = aws
        self._factories = {"azure": azure, "gcp": gcp}
        self._live: dict[str, Any] = {"aws": aws}
        self.used: set[str] = set()
        self._notes: list[str] = []

    def _for(self, cloud: str):
        if cloud not in self._live:
            f = self._factories.get(cloud)
            self._live[cloud] = f() if callable(f) else f
        return self._live.get(cloud)

    @property
    def notes(self) -> list[str]:
        out = list(self._notes)
        for c, src in self._live.items():
            if c != "aws" and src is not None:
                out += [n for n in getattr(src, "notes", []) or [] if n not in out]
        return out

    def now(self) -> datetime:
        return self.aws.now() if hasattr(self.aws, "now") else datetime.now(timezone.utc)

    def read(self, resource: Resource):
        cloud = cloud_of_type(resource.type, resource.source_type)
        self.used.add(cloud)
        src = self._for(cloud)
        if src is None:
            return None
        return src.read(resource)

    def write_events(self, start: datetime, end: datetime) -> list[dict]:
        rows: list[dict] = []
        for cloud in ["aws"] + sorted(self.used - {"aws"}):
            src = self._for(cloud)
            if src is None:
                continue
            try:
                rows += src.write_events(start, end)
            except Exception as exc:  # noqa: BLE001
                if cloud == "aws" and self.used <= {"aws"}:
                    raise
                self._notes.append(f"{cloud} audit trail unavailable: {type(exc).__name__}: {exc}")
        return rows

    def metrics(self, queries, start, end, period):
        return self.aws.metrics(queries, start, end, period)

    def discover(self):
        return self.aws.discover()

    def stack_resources(self, stack):
        return self.aws.stack_resources(stack)

    def stack_drifts(self, stack, detect=False):
        return self.aws.stack_drifts(stack, detect=detect)

    def config_history(self, resource, at):
        return self.aws.config_history(resource, at)
