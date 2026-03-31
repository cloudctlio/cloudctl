"""cloudctl security — audit, public-resources across AWS, Azure, and GCP."""
from __future__ import annotations

from typing import Optional

import typer

from cloudctl.commands._helpers import (
    console,
    get_aws_provider,
    get_azure_provider,
    get_gcp_provider,
    require_init,
)
from cloudctl.output.formatter import cloud_label, print_table, warn

app = typer.Typer(help="Security posture checks across cloud accounts.")

_SEVERITY_COLOR = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "dim"}

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")


def _format_finding_row(cloud_name: str, f: dict) -> dict:
    color = _SEVERITY_COLOR.get(f["severity"], "")
    return {
        "Cloud": cloud_label(cloud_name), "Account": f["account"],
        "Severity": f"[{color}]{f['severity']}[/{color}]",
        "Resource": f["resource"], "Issue": f["issue"],
    }


def _aws_audit_rows(cfg, account) -> list[dict]:
    rows: list[dict] = []
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]
    for profile_name in targets:
        try:
            for f in get_aws_provider(profile_name).security_audit(account=profile_name):
                rows.append(_format_finding_row("aws", f))
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
    return rows


def _azure_audit_rows(account) -> list[dict]:
    rows: list[dict] = []
    try:
        for f in get_azure_provider(subscription_id=account).security_audit(account=account or "azure"):
            rows.append(_format_finding_row("azure", f))
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _gcp_audit_rows(account) -> list[dict]:
    rows: list[dict] = []
    try:
        for f in get_gcp_provider(project_id=account).security_audit(account=account or "gcp"):
            rows.append(_format_finding_row("gcp", f))
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


def _aws_public_resource_rows(cfg, account) -> list[dict]:
    rows: list[dict] = []
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]
    for profile_name in targets:
        try:
            for r in get_aws_provider(profile_name).list_public_resources(account=profile_name):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": r["account"],
                    "Type": r["type"], "ID": r["id"], "Region": r["region"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
    return rows


def _azure_public_resource_rows(account) -> list[dict]:
    rows: list[dict] = []
    try:
        for r in get_azure_provider(subscription_id=account).list_public_resources(account=account or "azure"):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": r["account"],
                "Type": r["type"], "ID": r["id"], "Region": r["region"],
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _gcp_public_resource_rows(account) -> list[dict]:
    rows: list[dict] = []
    try:
        for r in get_gcp_provider(project_id=account).list_public_resources(account=account or "gcp"):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": r["account"],
                "Type": r["type"], "ID": r["id"], "Region": r["region"],
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


@app.command("audit")
def security_audit(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
) -> None:
    """Run security checks: public buckets, open security groups, IAM users without MFA."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_audit_rows(cfg, account)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_audit_rows(account)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_audit_rows(account)

    if not rows:
        console.print("[bold green]No security issues found.[/bold green]")
        return
    print_table(rows, title=f"Security Audit Findings ({len(rows)})")


@app.command("public-resources")
def security_public_resources(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
) -> None:
    """List all publicly accessible resources."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_public_resource_rows(cfg, account)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_public_resource_rows(account)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_public_resource_rows(account)

    if not rows:
        console.print("[bold green]No public resources found.[/bold green]")
        return
    print_table(rows, title=f"Publicly Accessible Resources ({len(rows)})")
