"""Kubernetes planner (EKS, AKS, GKE): ``kubectl diff`` against the live cluster.

The cluster credential is derived from the environment's scoped cloud
credentials, never from the operator's ``~/.kube/config``:

* **EKS** — a presigned ``sts:GetCallerIdentity`` token (the same token
  ``aws eks get-token`` produces), from the scoped AWS session.
* **AKS** — an Entra ID token for the AKS server application, from the scoped
  Azure credential (requires an Entra-ID-integrated cluster).
* **GKE** — the scoped, impersonated Google access token.

The token is written to a 0600 kubeconfig inside the private plan workdir and
deleted with it.
"""
from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any, Optional

import yaml

from cloudctl.gate.models import Action, Plan, PlanError, ResourceChange
from cloudctl.gate.plan.base import find_binary, run_tool, tool_version_matches

AKS_SERVER_APP = "6dae42f8-4368-4678-94ff-3960e28e3630/.default"

_DIFF_HEADER = re.compile(r"^diff -u -N (\S*/LIVE-[^/\s]+/(\S+)) (\S*/MERGED-[^/\s]+/\S+)$")
_OBJ_NAME = re.compile(
    r"^(?:(?P<group>.+)\.)?(?P<version>v\d+(?:(?:alpha|beta)\d+)?)\.(?P<kind>[A-Z][A-Za-z0-9]*)"
    r"\.(?P<ns>[a-z0-9-]*)\.(?P<name>.+)$")
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_kubectl_diff(text: str, *, environment: str, cluster: str) -> list[ResourceChange]:
    """Parse ``kubectl diff`` unified output into resource changes."""
    changes: list[ResourceChange] = []
    current: Optional[dict] = None

    def flush() -> None:
        if current is None:
            return
        old_len, new_len = current["old_len"], current["new_len"]
        if old_len == 0 and new_len > 0:
            action = Action.CREATE
        elif new_len == 0 and old_len > 0:
            action = Action.DELETE
        else:
            action = Action.UPDATE
        m = current["m"]
        group = m.group("group") or "core"
        ns = m.group("ns")
        kind = m.group("kind")
        changes.append(ResourceChange(
            address=f"{cluster}/{ns or '_cluster'}/{kind}/{m.group('name')}",
            type=f"{group}/{m.group('version')}/{kind}", action=action, cloud="kubernetes",
            name=m.group("name"), location=ns,
            after={"namespace": ns, "kind": kind, "diff_lines": current["lines"][:400]},
        ))

    for line in text.splitlines():
        h = _DIFF_HEADER.match(line)
        if h:
            flush()
            m = _OBJ_NAME.match(h.group(2))
            if not m:
                raise PlanError(f"cannot parse kubectl diff object name {h.group(2)!r}")
            current = {"m": m, "old_len": None, "new_len": None, "lines": []}
            continue
        if current is None:
            continue
        hk = _HUNK.match(line)
        if hk and current["old_len"] is None:
            current["old_len"] = 0 if hk.group(1) == "0" and (hk.group(2) or "1") == "0" else 1
            current["new_len"] = 0 if hk.group(3) == "0" and (hk.group(4) or "1") == "0" else 1
        elif line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
            current["lines"].append(line[:500])
    if current is not None:
        if current["old_len"] is None:
            current["old_len"] = current["new_len"] = 1
        flush()
    return changes


def _write_kubeconfig(path: Path, *, server: str, ca_b64: str, token: str, name: str) -> None:
    doc = {
        "apiVersion": "v1", "kind": "Config", "current-context": name,
        "clusters": [{"name": name, "cluster": {"server": server, "certificate-authority-data": ca_b64}}],
        "users": [{"name": "cctl-gate", "user": {"token": token}}],
        "contexts": [{"name": name, "context": {"cluster": name, "user": "cctl-gate"}}],
    }
    path.touch(mode=0o600, exist_ok=True)
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass


def eks_token(session: Any, cluster: str, region: str) -> str:
    from botocore.signers import RequestSigner  # noqa: PLC0415

    sts = session.client("sts", region_name=region)
    signer = RequestSigner(sts.meta.service_model.service_id, region, "sts", "v4",
                           session.get_credentials(), session.events)
    url = signer.generate_presigned_url(
        {"method": "GET", "url": f"https://sts.{region}.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15",
         "body": {}, "headers": {"x-k8s-aws-id": cluster}, "context": {}},
        region_name=region, expires_in=60, operation_name="")
    return "k8s-aws-v1." + base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def cluster_access(env: Any, creds: Any, *, factories: Optional[dict] = None) -> tuple[str, str, str]:
    """Return (server, ca_b64, bearer token) for the environment's cluster."""
    k = env.kubernetes
    if k is None:
        raise PlanError(f"environment {env.name} has no `kubernetes` block")
    f = factories or {}
    if k.provider == "eks":
        session = creds.client("session")
        eks = session.client("eks", region_name=env.scope["region"])
        c = eks.describe_cluster(name=k.cluster)["cluster"]
        return c["endpoint"], c["certificateAuthority"]["data"], eks_token(session, k.cluster, env.scope["region"])
    if k.provider == "aks":
        cred = creds.client("credential")
        if "aks" in f:
            client = f["aks"](cred, env.scope["subscription_id"])
        else:
            try:
                from azure.mgmt.containerservice import ContainerServiceClient  # noqa: PLC0415
            except ImportError as e:
                raise PlanError("AKS needs azure-mgmt-containerservice (pip install 'cctl[azure]')") from e
            client = ContainerServiceClient(cred, env.scope["subscription_id"])
        rg = k.location or env.scope["resource_group"]
        res = client.managed_clusters.list_cluster_user_credentials(rg, k.cluster)
        kc = yaml.safe_load(res.kubeconfigs[0].value)
        cl = kc["clusters"][0]["cluster"]
        token = cred.get_token(AKS_SERVER_APP).token
        return cl["server"], cl["certificate-authority-data"], token
    if k.provider == "gke":
        gcreds = creds.client("credentials")
        if "gke" in f:
            svc = f["gke"](gcreds)
        else:
            try:
                from googleapiclient import discovery  # noqa: PLC0415
            except ImportError as e:
                raise PlanError("GKE needs google-api-python-client (pip install 'cctl[gcp]')") from e
            svc = discovery.build("container", "v1", credentials=gcreds, cache_discovery=False)
        name = f"projects/{env.scope['project_id']}/locations/{k.location}/clusters/{k.cluster}"
        c = svc.projects().locations().clusters().get(name=name).execute()
        return f"https://{c['endpoint']}", c["masterAuth"]["clusterCaCertificate"], gcreds.token
    raise PlanError(f"unknown kubernetes provider {k.provider!r}")


class KubernetesPlanner:
    platform = "kubernetes"

    def __init__(self, manifests: Path | str, *, binary_path: Optional[str] = None,
                 pinned_version: Optional[str] = None, prune_selector: Optional[str] = None,
                 server_side: bool = True, factories: Optional[dict] = None, timeout: int = 300) -> None:
        self.manifests = Path(manifests).expanduser().resolve()
        self.binary_path = binary_path
        self.pinned_version = pinned_version
        self.prune_selector = prune_selector
        self.server_side = server_side
        self.factories = factories
        self.timeout = timeout

    def plan(self, *, env: Any, creds: Any, workdir: Path) -> Plan:
        if not self.manifests.exists():
            raise PlanError(f"manifests path {self.manifests} does not exist")
        exe = find_binary("kubectl", self.binary_path)
        server, ca, token = cluster_access(env, creds, factories=self.factories)
        kubeconfig = workdir / "kubeconfig"
        _write_kubeconfig(kubeconfig, server=server, ca_b64=ca, token=token, name=env.kubernetes.cluster)
        senv = creds.subprocess_env()
        senv["KUBECONFIG"] = str(kubeconfig)
        ver = run_tool([exe, "version", "--client"], cwd=workdir, env=senv, timeout=60, what="kubectl version")
        if not tool_version_matches(ver.stdout, self.pinned_version):
            raise PlanError(f"kubectl version mismatch: pinned {self.pinned_version}")
        argv = [exe, "diff", "-f", str(self.manifests), "-R"]
        if self.server_side:
            argv.append("--server-side")
        if env.kubernetes.namespace:
            argv += ["-n", env.kubernetes.namespace]
        if self.prune_selector:
            argv += ["--prune", "-l", self.prune_selector]
        # kubectl diff: 0 = no differences, 1 = differences, >1 = error
        res = run_tool(argv, cwd=workdir, env=senv, timeout=self.timeout, ok_codes=(0, 1), what="kubectl diff")
        changes = parse_kubectl_diff(res.stdout, environment=env.name, cluster=env.kubernetes.cluster)
        return Plan(platform="kubernetes", environment=env.name, changes=tuple(changes),
                    source=str(self.manifests),
                    artifacts={"k8s_manifests": str(self.manifests), "iac_root": str(self.manifests)},
                    metadata={"cluster": env.kubernetes.cluster, "provider": env.kubernetes.provider})
