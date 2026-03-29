"""cloudctl messaging — queues, topics, streams across AWS, Azure, and GCP."""
from __future__ import annotations

from typing import Optional

import typer

from cloudctl.commands._helpers import console, get_aws_provider, get_azure_provider, require_init
from cloudctl.output.formatter import cloud_label, print_table, warn

app = typer.Typer(help="Inspect messaging services (SQS/SNS/Kinesis, Service Bus, Pub/Sub).")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_REGION  = typer.Option(None,   "--region",  "-r", help="Region / location to query")


@app.command("queues")
def messaging_queues(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """List queues (SQS, Service Bus namespaces)."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                for q in get_aws_provider(profile_name, region).list_sqs_queues(
                    account=profile_name, region=region
                ):
                    rows.append({
                        "Cloud": cloud_label("aws"), "Account": q["account"],
                        "Type": "SQS", "Name": q["name"],
                        "Messages": q.get("messages", "—"), "Region": q["region"],
                    })
            except Exception as e:
                warn(f"[AWS/{profile_name}] {e}")

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        try:
            for ns in get_azure_provider(account).list_service_bus_namespaces(
                account=account or "azure", region=region
            ):
                rows.append({
                    "Cloud": cloud_label("azure"), "Account": ns["account"],
                    "Type": f"Service Bus ({ns['sku']})", "Name": ns["name"],
                    "Messages": "—", "Region": ns["region"],
                })
        except Exception as e:
            warn(f"[Azure] {e}")

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        warn("[GCP] Pub/Sub topics coming in Day 10.")

    if not rows:
        console.print("[dim]No queues found.[/dim]")
        return
    print_table(rows, title=f"Queues ({len(rows)})")


@app.command("topics")
def messaging_topics(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """List topics (SNS, EventBridge buses)."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                for t in get_aws_provider(profile_name, region).list_sns_topics(
                    account=profile_name, region=region
                ):
                    rows.append({
                        "Cloud": cloud_label("aws"), "Account": t["account"],
                        "Type": "SNS", "Name": t["name"], "Region": t["region"],
                    })
                for b in get_aws_provider(profile_name, region).list_eventbridge_buses(
                    account=profile_name, region=region
                ):
                    rows.append({
                        "Cloud": cloud_label("aws"), "Account": b["account"],
                        "Type": "EventBridge", "Name": b["name"], "Region": b["region"],
                    })
            except Exception as e:
                warn(f"[AWS/{profile_name}] {e}")

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        warn("[Azure] Service Bus topics are nested under namespaces — use: cloudctl messaging queues --cloud azure")

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        warn("[GCP] Pub/Sub topics coming in Day 10.")

    if not rows:
        console.print("[dim]No topics found.[/dim]")
        return
    print_table(rows, title=f"Topics ({len(rows)})")


@app.command("streams")
def messaging_streams(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    region:  Optional[str] = _REGION,
) -> None:
    """List data streams (Kinesis, Event Hubs, MSK)."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                for s in get_aws_provider(profile_name, region).list_kinesis_streams(
                    account=profile_name, region=region
                ):
                    rows.append({
                        "Cloud": cloud_label("aws"), "Account": s["account"],
                        "Type": "Kinesis", "Name": s["name"],
                        "State": s["state"], "Region": s["region"],
                    })
                for m in get_aws_provider(profile_name, region).list_msk_clusters(
                    account=profile_name, region=region
                ):
                    rows.append({
                        "Cloud": cloud_label("aws"), "Account": m["account"],
                        "Type": "MSK", "Name": m["name"],
                        "State": m["state"], "Region": m["region"],
                    })
            except Exception as e:
                warn(f"[AWS/{profile_name}] {e}")

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        try:
            for ns in get_azure_provider(account).list_event_hub_namespaces(
                account=account or "azure", region=region
            ):
                rows.append({
                    "Cloud": cloud_label("azure"), "Account": ns["account"],
                    "Type": f"Event Hubs ({ns['sku']})", "Name": ns["name"],
                    "State": ns["state"], "Region": ns["region"],
                })
        except Exception as e:
            warn(f"[Azure] {e}")

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        warn("[GCP] Dataflow/Pub/Sub streams coming in Day 10.")

    if not rows:
        console.print("[dim]No streams found.[/dim]")
        return
    print_table(rows, title=f"Streams ({len(rows)})")
