"""cloudctl network — VPCs, security groups across AWS, Azure, and GCP."""
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

app = typer.Typer(help="Inspect cloud networking (VPCs, security groups).")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region / location to query")

_VPC_ID = "VPC ID"


def _aws_vpc_rows(cfg, account, region) -> list[dict]:
    rows: list[dict] = []
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]
    for profile_name in targets:
        try:
            for v in get_aws_provider(profile_name, region).list_vpcs(account=profile_name, region=region):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": v["account"],
                    _VPC_ID: v["id"], "Name": v["name"],
                    "CIDR": v["cidr"], "State": v["state"],
                    "Default": "yes" if v["default"] else "no",
                    "Region": v["region"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
    return rows


def _azure_vpc_rows(account) -> list[dict]:
    rows: list[dict] = []
    try:
        for v in get_azure_provider(subscription_id=account).list_vnets(account=account or "azure"):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": v["account"],
                _VPC_ID: v["id"], "Name": v["name"],
                "CIDR": v["cidr"], "State": v["state"],
                "Default": "no", "Region": v["region"],
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _gcp_vpc_rows(account) -> list[dict]:
    rows: list[dict] = []
    try:
        for v in get_gcp_provider(project_id=account).list_vpcs(account=account or "gcp"):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": v["account"],
                _VPC_ID: v["id"], "Name": v["name"],
                "CIDR": v["cidr"], "State": v["state"],
                "Default": "yes" if v["default"] else "no",
                "Region": v["region"],
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


def _aws_sg_rows(cfg, account, region, vpc_id) -> list[dict]:
    rows: list[dict] = []
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
    return rows


def _azure_sg_rows(account) -> list[dict]:
    rows: list[dict] = []
    try:
        for nsg in get_azure_provider(subscription_id=account).list_nsgs(account=account or "azure"):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": nsg["account"],
                "ID": nsg["id"], "Name": nsg["name"],
                "VPC": nsg.get("vpc_id", "—"),
                "Inbound": nsg["inbound_rules"],
                "Outbound": nsg["outbound_rules"],
                "Region": nsg["region"],
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _gcp_sg_rows(account, vpc_id) -> list[dict]:
    rows: list[dict] = []
    try:
        for fw in get_gcp_provider(project_id=account).list_security_groups(
            account=account or "gcp", vpc_id=vpc_id
        ):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": fw["account"],
                "ID": fw["id"], "Name": fw["name"],
                "VPC": fw["vpc_id"],
                "Inbound": fw["inbound_rules"],
                "Outbound": fw["outbound_rules"],
                "Region": fw["region"],
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


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
        rows += _aws_vpc_rows(cfg, account, region)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_vpc_rows(account)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_vpc_rows(account)

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
        rows += _aws_sg_rows(cfg, account, region, vpc_id)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_sg_rows(account)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_sg_rows(account, vpc_id)

    if not rows:
        console.print("[dim]No security groups found.[/dim]")
        return
    print_table(rows, title=f"Security Groups ({len(rows)})")
