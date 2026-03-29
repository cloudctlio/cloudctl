"""cloudctl security — audit, public-resources across AWS, Azure, and GCP."""
from __future__ import annotations

from typing import Optional

import typer

from cloudctl.commands._helpers import console, get_aws_provider, get_azure_provider, require_init
from cloudctl.output.formatter import cloud_label, print_table, warn

app = typer.Typer(help="Security posture checks across cloud accounts.")

_SEVERITY_COLOR = {"HIGH": "bold red", "MEDIUM": "bold yellow", "LOW": "dim"}

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")


@app.command("audit")
def security_audit(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
) -> None:
    """Run security checks: public buckets, open security groups, IAM users without MFA."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                for f in get_aws_provider(profile_name).security_audit(account=profile_name):
                    color = _SEVERITY_COLOR.get(f["severity"], "")
                    rows.append({
                        "Cloud": cloud_label("aws"), "Account": f["account"],
                        "Severity": f"[{color}]{f['severity']}[/{color}]",
                        "Resource": f["resource"], "Issue": f["issue"],
                    })
            except Exception as e:
                warn(f"[AWS/{profile_name}] {e}")

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        try:
            for f in get_azure_provider(account).security_audit(account=account or "azure"):
                color = _SEVERITY_COLOR.get(f["severity"], "")
                rows.append({
                    "Cloud": cloud_label("azure"), "Account": f["account"],
                    "Severity": f"[{color}]{f['severity']}[/{color}]",
                    "Resource": f["resource"], "Issue": f["issue"],
                })
        except Exception as e:
            warn(f"[Azure] {e}")

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        warn("[GCP] Security Command Center audit coming in Day 9.")

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

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        try:
            for r in get_azure_provider(account).list_public_resources(account=account or "azure"):
                rows.append({
                    "Cloud": cloud_label("azure"), "Account": r["account"],
                    "Type": r["type"], "ID": r["id"], "Region": r["region"],
                })
        except Exception as e:
            warn(f"[Azure] {e}")

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        warn("[GCP] Public resource check coming in Day 9.")

    if not rows:
        console.print("[bold green]No public resources found.[/bold green]")
        return
    print_table(rows, title=f"Publicly Accessible Resources ({len(rows)})")
