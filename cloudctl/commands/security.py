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
    fix:     bool          = typer.Option(False, "--fix", help="Propose and apply AI-generated fixes (requires AI configured)."),
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

    if fix and rows:
        _apply_fixes(cfg, rows)


def _apply_fixes(cfg, raw_findings: list[dict]) -> None:
    """Propose and apply AI fixes for security findings (requires AI configured)."""
    try:
        from cloudctl.ai.fixer import AIFixer  # noqa: PLC0415
    except ImportError:
        warn("AI module not installed. Run: pip install 'cctl[ai]'")
        return

    # Convert display rows back to finding dicts by stripping Rich markup
    import re  # noqa: PLC0415
    issues = []
    for row in raw_findings:
        issues.append({
            "severity": re.sub(r"\[[^\]]*\]", "", row.get("Severity", "")),
            "resource":  row.get("Resource", ""),
            "issue":     row.get("Issue", ""),
            "account":   row.get("Account", ""),
        })

    fixer     = AIFixer(cfg)
    proposals = fixer.propose(issues)
    proposals = fixer.present_and_confirm(proposals)
    fixer.apply(proposals)


@app.command("certs")
def security_certs(
    cloud:    str           = _CLOUD,
    account:  Optional[str] = _ACCOUNT,
    expiring: int           = typer.Option(
        60, "--expiring", help="Warn on certs expiring within N days (default 60)"
    ),
) -> None:
    """List SSL/TLS certificates and flag expiry risks across cloud accounts.

    Highlights:
      - EXPIRED certs — active outage cause
      - Certs expiring within --expiring days
      - Imported/self-managed certs that will NOT auto-renew

    Examples:
      cloudctl security certs --cloud aws
      cloudctl security certs --cloud all --expiring 90
    """
    cfg  = require_init()
    rows: list[dict] = []

    _STATUS_ICON = {
        "EXPIRED":               "[bold red]EXPIRED[/bold red]",
        "EXPIRING_SOON":         "[yellow]EXPIRING SOON[/yellow]",
        "IMPORTED_NO_AUTO_RENEW": "[dim]IMPORTED[/dim]",
        "OK":                    "[green]OK[/green]",
    }

    def _cert_rows(certs: list[dict]) -> list[dict]:
        result = []
        for c in certs:
            days = c.get("days_to_expiry")
            # Apply user-supplied --expiring threshold
            if c["status"] == "OK" and days is not None and days < expiring:
                display_status = "[yellow]EXPIRING SOON[/yellow]"
            else:
                display_status = _STATUS_ICON.get(c["status"], c["status"])
            result.append({
                "Cloud":          cloud_label(c.get("cloud", "aws")),
                "Account":        c.get("account", "—"),
                "Domain":         c.get("domain", "—"),
                "Status":         display_status,
                "Expires in":     f"{days}d" if days is not None else "—",
                "Auto-Renew":     "YES" if c.get("auto_renew") else "[yellow]NO[/yellow]",
                "Source":         c.get("source", "—"),
                "In Use By":      str(len(c.get("in_use_by", []))),
            })
        return result

    if cloud in ("aws", "all") and "aws" in cfg.clouds:
        profiles = cfg.accounts.get("aws", [])
        targets  = [p["name"] for p in profiles if not account or p["name"] == account]
        for profile_name in targets:
            try:
                certs = get_aws_provider(profile_name).list_ssl_certificates(account=profile_name)
                rows += _cert_rows(certs)
            except Exception as e:
                warn(f"[AWS/{profile_name}] {e}")

    if cloud in ("azure", "all") and (cloud == "azure" or "azure" in cfg.clouds):
        try:
            certs = get_azure_provider(subscription_id=account).list_ssl_certificates(
                account=account or "azure"
            )
            rows += _cert_rows(certs)
        except Exception as e:
            warn(f"[Azure] {e}")

    if cloud in ("gcp", "all") and (cloud == "gcp" or "gcp" in cfg.clouds):
        try:
            certs = get_gcp_provider(project_id=account).list_ssl_certificates(
                account=account or "gcp"
            )
            rows += _cert_rows(certs)
        except Exception as e:
            warn(f"[GCP] {e}")

    if not rows:
        console.print("[bold green]No SSL/TLS certificates found.[/bold green]")
        return

    print_table(rows, title=f"SSL/TLS Certificates ({len(rows)})")


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
