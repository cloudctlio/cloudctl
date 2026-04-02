"""cloudctl cost — summary, by-service across AWS, Azure, and GCP."""
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

app = typer.Typer(help="View cloud costs (AWS Cost Explorer, Azure Cost, GCP Billing).")

_CLOUD   = typer.Option("aws",  "--cloud",   "-c", help="Cloud provider: aws | azure | gcp | all")
_ACCOUNT = typer.Option(None,   "--account", "-a", help="AWS profile | Azure subscription ID | GCP project ID")
_DAYS    = typer.Option(30,     "--days",    "-d", help="Number of days to look back.")

_TOTAL_COST = "Total Cost"


def _budget_status_color(status: str) -> str:
    if status == "ALARM":
        return "bold red"
    if status == "WARNING":
        return "bold yellow"
    return "green"


def _aws_cost_summary_rows(cfg, account, days) -> list[dict]:
    rows: list[dict] = []
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]
    for profile_name in targets:
        try:
            for entry in get_aws_provider(profile_name).cost_summary(account=profile_name, days=days):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": entry["account"],
                    "Period": entry["period"], _TOTAL_COST: entry["cost"],
                    "Currency": entry["currency"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
    return rows


def _azure_cost_summary_rows(account, days) -> list[dict]:
    rows: list[dict] = []
    try:
        for entry in get_azure_provider(subscription_id=account).cost_summary(account=account or "azure", days=days):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": entry["account"],
                "Period": entry["period"], _TOTAL_COST: entry["cost"],
                "Currency": entry.get("currency", "USD"),
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _gcp_cost_summary_rows(account, days) -> list[dict]:
    rows: list[dict] = []
    try:
        for entry in get_gcp_provider(project_id=account).cost_summary(account=account or "gcp", days=days):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": entry["account"],
                "Period": entry["period"], _TOTAL_COST: entry["cost"],
                "Currency": entry.get("currency", "USD"),
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


def _aws_cost_by_service_rows(cfg, account, days) -> list[dict]:
    rows: list[dict] = []
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]
    for profile_name in targets:
        try:
            for entry in get_aws_provider(profile_name).cost_by_service(account=profile_name, days=days):
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": entry["account"],
                    "Service": entry["service"], "Period": entry["period"],
                    "Cost": entry["cost"],
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
    return rows


def _azure_cost_by_service_rows(account, days) -> list[dict]:
    rows: list[dict] = []
    try:
        for entry in get_azure_provider(subscription_id=account).cost_by_service(account=account or "azure", days=days):
            rows.append({
                "Cloud": cloud_label("azure"), "Account": entry["account"],
                "Service": entry["service"], "Period": entry["period"],
                "Cost": entry["cost"],
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


def _gcp_cost_by_service_rows(account, days) -> list[dict]:
    rows: list[dict] = []
    try:
        for entry in get_gcp_provider(project_id=account).cost_by_service(account=account or "gcp", days=days):
            rows.append({
                "Cloud": cloud_label("gcp"), "Account": entry["account"],
                "Service": entry["service"], "Period": entry["period"],
                "Cost": entry["cost"],
            })
    except Exception as e:
        warn(f"[GCP] {e}")
    return rows


@app.command("summary")
def cost_summary(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    days:    int           = _DAYS,
) -> None:
    """Show total cost summary by month."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_cost_summary_rows(cfg, account, days)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_cost_summary_rows(account, days)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_cost_summary_rows(account, days)

    if not rows:
        console.print("[dim]No cost data found. Ensure Cost Explorer / Cost Management is enabled.[/dim]")
        return
    print_table(rows, title=f"Cost Summary (last {days} days)")


@app.command("by-service")
def cost_by_service(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
    days:    int           = _DAYS,
    fix:     bool          = typer.Option(False, "--fix", help="Propose AI-generated cost optimizations (requires AI configured)."),
) -> None:
    """Show cost breakdown by service."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_cost_by_service_rows(cfg, account, days)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_cost_by_service_rows(account, days)

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        rows += _gcp_cost_by_service_rows(account, days)

    if not rows:
        console.print("[dim]No cost data found.[/dim]")
        return
    print_table(rows, title=f"Cost by Service (last {days} days)")

    if fix and rows:
        _apply_cost_fixes(cfg, rows)


def _apply_cost_fixes(cfg, rows: list[dict]) -> None:
    """Propose AI cost optimizations for the top spending services."""
    try:
        from cloudctl.ai.fixer import AIFixer  # noqa: PLC0415
    except ImportError:
        warn("AI module not installed. Run: pip install 'cctl[ai]'")
        return

    issues = [
        {
            "issue":   f"High spend on {row.get('Service', '?')}: {row.get('Cost', '?')}",
            "resource": f"service/{row.get('Service', '?')}",
            "account":  row.get("Account", ""),
            "severity": "MEDIUM",
        }
        for row in rows
    ]
    fixer     = AIFixer(cfg)
    proposals = fixer.propose(issues)
    proposals = fixer.present_and_confirm(proposals)
    fixer.apply(proposals)


def _aws_budget_rows(cfg, account) -> list[dict]:
    rows: list[dict] = []
    profiles = cfg.accounts.get("aws", [])
    targets = [p["name"] for p in profiles if not account or p["name"] == account]
    for profile_name in targets:
        try:
            for b in get_aws_provider(profile_name).list_budgets(account=profile_name):
                pct = b.get("pct_used")
                pct_str = f"{pct:.1f}%" if pct is not None else "—"
                status = b.get("status", "OK")
                color = _budget_status_color(status)
                rows.append({
                    "Cloud": cloud_label("aws"), "Account": b["account"],
                    "Budget": b["name"],
                    "Limit": b["limit"],
                    "Actual": b["actual"],
                    "Forecast": b.get("forecast", "—"),
                    "Used %": pct_str,
                    "Status": f"[{color}]{status}[/{color}]",
                })
        except Exception as e:
            warn(f"[AWS/{profile_name}] {e}")
    return rows


def _azure_budget_rows(account) -> list[dict]:
    rows: list[dict] = []
    try:
        for b in get_azure_provider(subscription_id=account).list_budgets(account=account or "azure"):
            pct = b.get("pct_used")
            pct_str = f"{pct:.1f}%" if pct is not None else "—"
            status = b.get("status", "OK")
            color = _budget_status_color(status)
            rows.append({
                "Cloud": cloud_label("azure"), "Account": b["account"],
                "Budget": b["name"],
                "Limit": b["limit"],
                "Actual": b["actual"],
                "Forecast": b.get("forecast", "—"),
                "Used %": pct_str,
                "Status": f"[{color}]{status}[/{color}]",
            })
    except Exception as e:
        warn(f"[Azure] {e}")
    return rows


@app.command("budgets")
def cost_budgets(
    cloud:   str           = _CLOUD,
    account: Optional[str] = _ACCOUNT,
) -> None:
    """List cost budgets and their current usage / alert status."""
    cfg = require_init()
    rows: list[dict] = []

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        rows += _aws_budget_rows(cfg, account)

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        rows += _azure_budget_rows(account)

    if cloud == "gcp":
        warn("[GCP] Budget alerts require the Cloud Billing API with BigQuery export — not available via REST.")

    if not rows:
        console.print("[dim]No budgets found. Create one in AWS Cost Explorer or Azure Cost Management.[/dim]")
        return
    print_table(rows, title=f"Cost Budgets ({len(rows)})")
