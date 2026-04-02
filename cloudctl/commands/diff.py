"""cloudctl diff — compare resource state between accounts or regions."""
from __future__ import annotations

from typing import Optional

import typer

from cloudctl.commands._helpers import (
    console,
    get_aws_provider,
    require_init,
)
from cloudctl.output.formatter import error, print_table, warn

app = typer.Typer(help="Compare resource state between two accounts or regions.")

_RESOURCE_TYPES = ("compute", "storage", "database")


def _get_compute_names(prov, profile, region) -> set[str]:
    try:
        return {inst.name or inst.id for inst in prov.list_compute(account=profile, region=region)}
    except Exception as e:
        warn(f"[{profile}] compute: {e}")
        return set()


def _get_storage_names(prov, profile, region) -> set[str]:
    try:
        return {b.name for b in prov.list_storage(account=profile, region=region)}
    except Exception as e:
        warn(f"[{profile}] storage: {e}")
        return set()


def _get_database_names(prov, profile, region) -> set[str]:
    try:
        return {db.id for db in prov.list_databases(account=profile, region=region)}
    except Exception as e:
        warn(f"[{profile}] database: {e}")
        return set()


_FETCHERS = {
    "compute":  _get_compute_names,
    "storage":  _get_storage_names,
    "database": _get_database_names,
}


def _diff_sets(left_names: set, right_names: set, left_label: str, right_label: str, rtype: str) -> list[dict]:
    rows: list[dict] = []
    for name in sorted(left_names | right_names):
        in_left  = name in left_names
        in_right = name in right_names
        if in_left and in_right:
            status = "[green]both[/green]"
        elif in_left:
            status = f"[yellow]only in {left_label}[/yellow]"
        else:
            status = f"[cyan]only in {right_label}[/cyan]"
        rows.append({
            "Type": rtype,
            "Name": name,
            "Status": status,
            left_label: "yes" if in_left  else "—",
            right_label: "yes" if in_right else "—",
        })
    return rows


@app.command("accounts")
def diff_accounts(
    left:    str           = typer.Argument(..., help="First AWS profile / account name."),
    right:   str           = typer.Argument(..., help="Second AWS profile / account name."),
    region:  Optional[str] = typer.Option(None, "--region", "-r", help="Region to compare."),
    type_:   Optional[str] = typer.Option(
        None, "--type", "-t",
        help=f"Resource type to diff: {' | '.join(_RESOURCE_TYPES)}. Default: all."
    ),
) -> None:
    """Diff resource inventory between two AWS accounts/profiles."""
    cfg = require_init()

    if "aws" not in cfg.clouds:
        error("AWS is not configured. Run: cloudctl init")
        raise typer.Exit(1)

    types = [type_] if type_ else list(_RESOURCE_TYPES)
    unknown = [t for t in types if t not in _RESOURCE_TYPES]
    if unknown:
        error(f"Unknown resource type(s): {', '.join(unknown)}. Choose from: {', '.join(_RESOURCE_TYPES)}")
        raise typer.Exit(1)

    prov_left  = get_aws_provider(left,  region)
    prov_right = get_aws_provider(right, region)

    rows: list[dict] = []
    for rtype in types:
        fetch = _FETCHERS[rtype]
        left_names  = fetch(prov_left,  left,  region)
        right_names = fetch(prov_right, right, region)
        rows += _diff_sets(left_names, right_names, left, right, rtype)

    if not rows:
        console.print("[dim]No resources found to compare.[/dim]")
        return

    only_left  = sum(1 for r in rows if r[left]  == "yes" and r[right] == "—")
    only_right = sum(1 for r in rows if r[right] == "yes" and r[left]  == "—")
    both       = sum(1 for r in rows if r[left]  == "yes" and r[right] == "yes")
    print_table(rows, title=f"Diff: {left} vs {right} — {both} shared, {only_left} only-left, {only_right} only-right")


@app.command("regions")
def diff_regions(
    left_region:  str           = typer.Argument(..., help="First region (e.g. us-east-1)."),
    right_region: str           = typer.Argument(..., help="Second region (e.g. eu-west-1)."),
    account:      Optional[str] = typer.Option(None, "--account", "-a", help="AWS profile to use."),
    type_:        Optional[str] = typer.Option(
        None, "--type", "-t",
        help=f"Resource type to diff: {' | '.join(_RESOURCE_TYPES)}. Default: all."
    ),
) -> None:
    """Diff resource inventory between two regions for the same AWS account."""
    cfg = require_init()

    if "aws" not in cfg.clouds:
        error("AWS is not configured. Run: cloudctl init")
        raise typer.Exit(1)

    profile = account or next(
        (p["name"] for p in cfg.accounts.get("aws", [])), None
    )
    if not profile:
        error("No AWS profile configured.")
        raise typer.Exit(1)

    types = [type_] if type_ else list(_RESOURCE_TYPES)
    unknown = [t for t in types if t not in _RESOURCE_TYPES]
    if unknown:
        error(f"Unknown resource type(s): {', '.join(unknown)}. Choose from: {', '.join(_RESOURCE_TYPES)}")
        raise typer.Exit(1)

    prov_left  = get_aws_provider(profile, left_region)
    prov_right = get_aws_provider(profile, right_region)

    rows: list[dict] = []
    for rtype in types:
        fetch = _FETCHERS[rtype]
        left_names  = fetch(prov_left,  profile, left_region)
        right_names = fetch(prov_right, profile, right_region)
        rows += _diff_sets(left_names, right_names, left_region, right_region, rtype)

    if not rows:
        console.print("[dim]No resources found to compare.[/dim]")
        return

    only_left  = sum(1 for r in rows if r[left_region]  == "yes" and r[right_region] == "—")
    only_right = sum(1 for r in rows if r[right_region] == "yes" and r[left_region]  == "—")
    both       = sum(1 for r in rows if r[left_region]  == "yes" and r[right_region] == "yes")
    print_table(
        rows,
        title=f"Diff: {left_region} vs {right_region} — {both} shared, {only_left} only-left, {only_right} only-right"
    )
