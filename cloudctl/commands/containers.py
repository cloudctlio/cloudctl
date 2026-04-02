"""cloudctl containers — clusters, functions, and registries across AWS, Azure, and GCP."""
from __future__ import annotations

from typing import Optional

import typer

from cloudctl.commands._helpers import (
    console,
    get_aws_provider,
    get_azure_provider,
    get_gcp_provider,
    require_init,
    run_parallel,
)
from cloudctl.output.formatter import cloud_label, print_table, warn

app = typer.Typer(help="Inspect container services (ECS/EKS/AKS/GKE, Lambda/Functions, ECR/ACR).")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region / location to query")


# ── AWS helpers ────────────────────────────────────────────────────────────────

def _aws_cluster_rows(cfg, account, region) -> list[dict]:
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]

    def _fetch(profile_name: str) -> list[dict]:
        rows: list[dict] = []
        try:
            prov = get_aws_provider(profile_name, region)
            for c in prov.list_ecs_clusters(account=profile_name, region=region):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": c["account"],
                    "Type": "ECS", "Name": c["name"],
                    "Status": c.get("status", "—"), "Region": c["region"],
                })
            for c in prov.list_eks_clusters(account=profile_name, region=region):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": c["account"],
                    "Type": "EKS", "Name": c["name"],
                    "Status": c.get("status", "—"), "Region": c["region"],
                })
            for s in prov.list_app_runner_services(account=profile_name, region=region):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": s["account"],
                    "Type": "App Runner", "Name": s["name"],
                    "Status": s.get("status", "—"), "Region": s["region"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
        return rows

    return run_parallel(_fetch, targets)


def _aws_function_rows(cfg, account, region) -> list[dict]:
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]

    def _fetch(profile_name: str) -> list[dict]:
        rows: list[dict] = []
        try:
            for fn in get_aws_provider(profile_name, region).list_lambda_functions(
                account=profile_name, region=region
            ):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": fn["account"],
                    "Name": fn["name"], "Runtime": fn.get("runtime", "—"),
                    "Memory": fn.get("memory_mb", "—"), "Region": fn["region"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
        return rows

    return run_parallel(_fetch, targets)


def _aws_registry_rows(cfg, account, region) -> list[dict]:
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]

    def _fetch(profile_name: str) -> list[dict]:
        rows: list[dict] = []
        try:
            for r in get_aws_provider(profile_name, region).list_ecr_repositories(
                account=profile_name, region=region
            ):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": r["account"],
                    "Type": "ECR", "Name": r["name"],
                    "URI": r.get("uri", "—"), "Region": r["region"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
        return rows

    return run_parallel(_fetch, targets)


# ── Azure helpers ──────────────────────────────────────────────────────────────

def _azure_cluster_rows(account, region) -> list[dict]:
    rows: list[dict] = []
    try:
        prov = get_azure_provider(subscription_id=account)
        for c in prov.list_aks_clusters(account=account or "azure", region=region):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": c["account"],
                "Type": "AKS", "Name": c["name"],
                "Status": c.get("state", "—"), "Region": c["region"],
            })
        for i in prov.list_container_instances(account=account or "azure", region=region):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": i["account"],
                "Type": "ACI", "Name": i["name"],
                "Status": i.get("state", "—"), "Region": i["region"],
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _azure_registry_rows(account, region) -> list[dict]:
    rows: list[dict] = []
    try:
        for r in get_azure_provider(subscription_id=account).list_container_registries(
            account=account or "azure", region=region
        ):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": r["account"],
                "Type": "ACR", "Name": r["name"],
                "URI": r.get("login_server", "—"), "Region": r["region"],
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


# ── GCP helpers ────────────────────────────────────────────────────────────────

def _gcp_cluster_rows(account, region) -> list[dict]:
    rows: list[dict] = []
    try:
        prov = get_gcp_provider(project_id=account)
        for c in prov.list_gke_clusters(account=account or "gcp", region=region):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": c["account"],
                "Type": "GKE", "Name": c["name"],
                "Status": c.get("status", "—"), "Region": c.get("region", "—"),
            })
        for s in prov.list_cloud_run(account=account or "gcp", region=region):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": s["account"],
                "Type": "Cloud Run", "Name": s["name"],
                "Status": s.get("status", "—"), "Region": s.get("region", "—"),
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


def _gcp_function_rows(account, region) -> list[dict]:
    rows: list[dict] = []
    try:
        for fn in get_gcp_provider(project_id=account).list_cloud_functions(
            account=account or "gcp", region=region
        ):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": fn["account"],
                "Name": fn["name"], "Runtime": fn.get("runtime", "—"),
                "Memory": fn.get("memory_mb", "—"), "Region": fn.get("region", "—"),
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


# ── Commands ──────────────────────────────────────────────────────────────────

@app.command("clusters")
def containers_clusters(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """List container clusters (ECS, EKS, AKS, ACI, GKE, Cloud Run)."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_cluster_rows(cfg, account, region)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_cluster_rows(account, region)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_cluster_rows(account, region)

    if not rows:
        console.print("[dim]No clusters found.[/dim]")
        return
    print_table(rows, title=f"Container Clusters ({len(rows)})")


@app.command("functions")
def containers_functions(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """List serverless functions (Lambda, Cloud Functions)."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_function_rows(cfg, account, region)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_function_rows(account, region)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        warn("[Azure] Azure Functions are listed under: cloudctl pipeline functions --cloud azure")

    if not rows:
        console.print("[dim]No functions found.[/dim]")
        return
    print_table(rows, title=f"Serverless Functions ({len(rows)})")


@app.command("registries")
def containers_registries(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """List container registries (ECR, ACR)."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_registry_rows(cfg, account, region)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_registry_rows(account, region)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        warn("[GCP] Use Artifact Registry: cloudctl pipeline artifacts --cloud gcp")

    if not rows:
        console.print("[dim]No registries found.[/dim]")
        return
    print_table(rows, title=f"Container Registries ({len(rows)})")
