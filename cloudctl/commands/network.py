"""cloudctl network — VPCs, security groups across AWS, Azure, and GCP."""
from __future__ import annotations

from typing import Optional

import typer

from cloudctl.commands._helpers import console, get_aws_provider, require_init
from cloudctl.output.formatter import cloud_label, print_table, warn

app = typer.Typer(help="Inspect cloud networking (VPCs, security groups).")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region / location to query")


@app.command("vpcs")
def network_vpcs(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """List VPCs / virtual networks."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                for v in get_aws_provider(profile_name, region).list_vpcs(account=profile_name, region=region):
                    rows.append({
                        "Cloud": cloud_label("aws"), "Account": v["account"],
                        "VPC ID": v["id"], "Name": v["name"],
                        "CIDR": v["cidr"], "State": v["state"],
                        "Default": "yes" if v["default"] else "no",
                        "Region": v["region"],
                    })
            except Exception as e:
                warn(f"[AWS/{profile_name}] {e}")

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        warn("[Azure] VNet listing coming in Day 7 — azure network commands not yet implemented.")

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        warn("[GCP] VPC listing coming in Day 9 — gcp network commands not yet implemented.")

    if not rows:
        console.print("[dim]No VPCs found.[/dim]")
        return
    print_table(rows, title=f"VPCs ({len(rows)})")


@app.command("security-groups")
def network_security_groups(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
    vpc_id:  Optional[str] = typer.Option(None, "--vpc", help="Filter by VPC ID. AWS only."),
) -> None:
    """List security groups / NSGs / firewall rules."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                for sg in get_aws_provider(profile_name, region).list_security_groups(
                    account=profile_name, region=region, vpc_id=vpc_id
                ):
                    rows.append({
                        "Cloud": cloud_label("aws"), "Account": sg["account"],
                        "ID": sg["id"], "Name": sg["name"],
                        "VPC": sg["vpc_id"],
                        "Inbound": sg["inbound_rules"],
                        "Outbound": sg["outbound_rules"],
                        "Region": sg["region"],
                    })
            except Exception as e:
                warn(f"[AWS/{profile_name}] {e}")

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        warn("[Azure] NSG listing coming in Day 7 — azure network commands not yet implemented.")

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        warn("[GCP] Firewall listing coming in Day 9 — gcp network commands not yet implemented.")

    if not rows:
        console.print("[dim]No security groups found.[/dim]")
        return
    print_table(rows, title=f"Security Groups ({len(rows)})")
