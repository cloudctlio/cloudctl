"""Resolves --cloud / --account flags into a typed list of accounts to query."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cloudctl.config.manager import ConfigManager


@dataclass
class ResolvedAccount:
    cloud: str          # aws | azure | gcp
    account_id: str     # profile name (AWS), subscription id (Azure), project id (GCP)
    account_name: str   # human-readable label
    region: Optional[str] = None


def resolve(
    cfg: ConfigManager,
    cloud: str = "aws",
    account: Optional[str] = None,
    region: Optional[str] = None,
) -> list[ResolvedAccount]:
    """Return the accounts to query based on --cloud / --account flags."""
    clouds_to_query = cfg.clouds if cloud == "all" else [cloud]
    targets: list[ResolvedAccount] = []

    for c in clouds_to_query:
        if c not in cfg.clouds:
            continue
        for p in cfg.accounts.get(c, []):
            name = p.get("name") or p.get("id", "")
            if account and name != account:
                continue
            targets.append(ResolvedAccount(
                cloud=c,
                account_id=name,
                account_name=name,
                region=region,
            ))

    return targets
