"""cloudctl analytics — data warehouses, jobs, and AI/ML across AWS, Azure, and GCP."""
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

app = typer.Typer(help="Inspect analytics and AI/ML services (Redshift, Synapse, BigQuery, SageMaker, Vertex).")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region / location to query")


# ── AWS helpers ────────────────────────────────────────────────────────────────

def _aws_warehouse_rows(cfg, account, region) -> list[dict]:
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]

    def _fetch(profile_name: str) -> list[dict]:
        rows: list[dict] = []
        try:
            prov = get_aws_provider(profile_name, region)
            for c in prov.list_redshift_clusters(account=profile_name, region=region):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": c["account"],
                    "Type": "Redshift", "Name": c["name"],
                    "Status": c.get("status", "—"), "Nodes": c.get("nodes", "—"),
                    "Region": c["region"],
                })
            for d in prov.list_opensearch_domains(account=profile_name, region=region):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": d["account"],
                    "Type": "OpenSearch", "Name": d["name"],
                    "Status": d.get("status", "—"), "Nodes": d.get("instance_count", "—"),
                    "Region": d["region"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
        return rows

    return run_parallel(_fetch, targets)


def _aws_job_rows(cfg, account, region) -> list[dict]:
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]

    def _fetch(profile_name: str) -> list[dict]:
        rows: list[dict] = []
        try:
            prov = get_aws_provider(profile_name, region)
            for wg in prov.list_athena_workgroups(account=profile_name, region=region):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": wg["account"],
                    "Type": "Athena", "Name": wg["name"],
                    "Status": wg.get("state", "—"), "Region": wg["region"],
                })
            for j in prov.list_glue_jobs(account=profile_name, region=region):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": j["account"],
                    "Type": "Glue", "Name": j["name"],
                    "Status": j.get("last_run_status", "—"), "Region": j["region"],
                })
            for c in prov.list_emr_clusters(account=profile_name, region=region):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": c["account"],
                    "Type": "EMR", "Name": c["name"],
                    "Status": c.get("status", "—"), "Region": c["region"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
        return rows

    return run_parallel(_fetch, targets)


def _aws_ai_rows(cfg, account, region) -> list[dict]:
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]

    def _fetch(profile_name: str) -> list[dict]:
        rows: list[dict] = []
        try:
            prov = get_aws_provider(profile_name, region)
            for ep in prov.list_sagemaker_endpoints(account=profile_name, region=region):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": ep["account"],
                    "Type": "SageMaker", "Name": ep["name"],
                    "Status": ep.get("status", "—"), "Region": ep["region"],
                })
            for m in prov.list_bedrock_models(account=profile_name, region=region):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": m["account"],
                    "Type": "Bedrock", "Name": m["name"],
                    "Status": m.get("status", "—"), "Region": m["region"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
        return rows

    return run_parallel(_fetch, targets)


# ── Azure helpers ──────────────────────────────────────────────────────────────

def _azure_warehouse_rows(account, region) -> list[dict]:
    rows: list[dict] = []
    try:
        for ws in get_azure_provider(subscription_id=account).list_synapse_workspaces(
            account=account or "azure", region=region
        ):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": ws["account"],
                "Type": "Synapse", "Name": ws["name"],
                "Status": ws.get("state", "—"), "Nodes": "—",
                "Region": ws["region"],
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _azure_ai_rows(account, region) -> list[dict]:
    rows: list[dict] = []
    try:
        for svc in get_azure_provider(subscription_id=account).list_cognitive_services(
            account=account or "azure", region=region
        ):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": svc["account"],
                "Type": f"Cognitive ({svc.get('kind', '?')})", "Name": svc["name"],
                "Status": svc.get("state", "—"), "Region": svc["region"],
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


# ── GCP helpers ────────────────────────────────────────────────────────────────

def _gcp_warehouse_rows(account) -> list[dict]:
    rows: list[dict] = []
    try:
        for ds in get_gcp_provider(project_id=account).list_bigquery_datasets(
            account=account or "gcp"
        ):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": ds["account"],
                "Type": "BigQuery", "Name": ds["name"],
                "Status": "active", "Nodes": "—",
                "Region": ds.get("location", "—"),
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


def _gcp_job_rows(account, region) -> list[dict]:
    rows: list[dict] = []
    try:
        prov = get_gcp_provider(project_id=account)
        for j in prov.list_dataflow_jobs(account=account or "gcp", region=region):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": j["account"],
                "Type": "Dataflow", "Name": j["name"],
                "Status": j.get("state", "—"), "Region": j.get("region", "—"),
            })
        for c in prov.list_dataproc_clusters(account=account or "gcp", region=region):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": c["account"],
                "Type": "Dataproc", "Name": c["name"],
                "Status": c.get("status", "—"), "Region": c.get("region", "—"),
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


def _gcp_ai_rows(account, region) -> list[dict]:
    rows: list[dict] = []
    try:
        prov = get_gcp_provider(project_id=account)
        for ep in prov.list_vertex_endpoints(account=account or "gcp", region=region):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": ep["account"],
                "Type": "Vertex Endpoint", "Name": ep["name"],
                "Status": ep.get("state", "—"), "Region": ep.get("region", "—"),
            })
        for m in prov.list_vertex_models(account=account or "gcp", region=region):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": m["account"],
                "Type": "Vertex Model", "Name": m["name"],
                "Status": m.get("state", "—"), "Region": m.get("region", "—"),
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


# ── Commands ──────────────────────────────────────────────────────────────────

@app.command("warehouses")
def analytics_warehouses(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """List data warehouses (Redshift, OpenSearch, Synapse, BigQuery)."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_warehouse_rows(cfg, account, region)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_warehouse_rows(account, region)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_warehouse_rows(account)

    if not rows:
        console.print("[dim]No data warehouses found.[/dim]")
        return
    print_table(rows, title=f"Data Warehouses ({len(rows)})")


@app.command("jobs")
def analytics_jobs(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """List analytics jobs (Athena, Glue, EMR, Dataflow, Dataproc)."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_job_rows(cfg, account, region)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_job_rows(account, region)

    if not rows:
        console.print("[dim]No analytics jobs found.[/dim]")
        return
    print_table(rows, title=f"Analytics Jobs ({len(rows)})")


@app.command("ai")
def analytics_ai(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """List AI/ML resources (SageMaker, Bedrock, Cognitive Services, Vertex AI)."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_ai_rows(cfg, account, region)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_ai_rows(account, region)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_ai_rows(account, region)

    if not rows:
        console.print("[dim]No AI/ML resources found.[/dim]")
        return
    print_table(rows, title=f"AI/ML Resources ({len(rows)})")
