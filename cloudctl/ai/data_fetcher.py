"""AI data fetcher — fetches real cloud data before any AI call."""
from __future__ import annotations

from typing import Optional

from cloudctl.commands._helpers import get_aws_provider, get_azure_provider, get_gcp_provider
from cloudctl.config.manager import ConfigManager


class DataFetcher:
    """Fetches real cloud data for AI context. Never calls AI without fetching first."""

    def __init__(self, cfg: ConfigManager):
        self._cfg = cfg

    # ── Public entry point ─────────────────────────────────────────────────────

    def fetch_summary(
        self,
        cloud: str = "all",
        account: Optional[str] = None,
        region: Optional[str] = None,
        include: Optional[list[str]] = None,
    ) -> dict:
        """Fetch a summary of cloud resources for AI context."""
        include = include or ["compute", "storage", "database", "cost", "security"]
        ctx: dict = {}

        if cloud in ("aws", "all") and "aws" in self._cfg.clouds:
            ctx["aws"] = self._fetch_aws(account, region, include)

        if cloud in ("azure", "all") and "azure" in self._cfg.clouds:
            ctx["azure"] = self._fetch_azure(account, region, include)

        if cloud in ("gcp", "all") and "gcp" in self._cfg.clouds:
            ctx["gcp"] = self._fetch_gcp(account, region, include)

        return ctx

    # ── AWS ────────────────────────────────────────────────────────────────────

    def _fetch_aws(self, account: Optional[str], region: Optional[str], include: list[str]) -> dict:
        profiles = self._cfg.accounts.get("aws", [])
        targets  = [p["name"] for p in profiles if not account or p["name"] == account]
        result: dict = {}
        for profile in targets:
            result[profile] = self._fetch_aws_profile(profile, region, include)
        return result

    def _fetch_aws_profile(self, profile: str, region: Optional[str], include: list[str]) -> dict:
        data: dict = {}
        try:
            prov = get_aws_provider(profile, region)
        except Exception:
            return data

        if "compute" in include:
            try:
                data["compute"] = [
                    {"id": i.id, "name": i.name, "type": i.type, "state": i.state, "region": i.region}
                    for i in prov.list_compute(account=profile, region=region)
                ]
            except Exception:
                pass

        if "storage" in include:
            try:
                data["storage"] = [
                    {"name": b.name, "region": b.region or "global", "public": b.public}
                    for b in prov.list_storage(account=profile, region=region)
                ]
            except Exception:
                pass

        if "database" in include:
            try:
                data["database"] = [
                    {"id": db.id, "engine": db.engine, "state": db.state, "region": db.region}
                    for db in prov.list_databases(account=profile, region=region)
                ]
            except Exception:
                pass

        if "cost" in include:
            try:
                data["cost"] = prov.get_cost_summary(account=profile)
            except Exception:
                pass

        if "security" in include:
            try:
                data["security_findings"] = prov.get_security_findings(account=profile)
            except Exception:
                pass

        return data

    # ── Azure ──────────────────────────────────────────────────────────────────

    def _fetch_azure(self, account: Optional[str], region: Optional[str], include: list[str]) -> dict:
        data: dict = {}
        try:
            prov = get_azure_provider(subscription_id=account)
            acct = account or "azure"
        except Exception:
            return data

        if "compute" in include:
            try:
                data["compute"] = [
                    {"id": i.id, "name": i.name, "type": i.type, "state": i.state, "region": i.region}
                    for i in prov.list_compute(account=acct, region=region)
                ]
            except Exception:
                pass

        if "storage" in include:
            try:
                data["storage"] = [
                    {"name": b.name, "region": b.region or "—", "public": b.public}
                    for b in prov.list_storage(account=acct, region=region)
                ]
            except Exception:
                pass

        if "cost" in include:
            try:
                data["cost"] = prov.get_cost_summary(account=acct)
            except Exception:
                pass

        return data

    # ── GCP ────────────────────────────────────────────────────────────────────

    def _fetch_gcp(self, account: Optional[str], region: Optional[str], include: list[str]) -> dict:
        data: dict = {}
        try:
            prov = get_gcp_provider(project_id=account)
            acct = account or "gcp"
        except Exception:
            return data

        if "compute" in include:
            try:
                data["compute"] = [
                    {"id": i.id, "name": i.name, "type": i.type, "state": i.state, "region": i.region}
                    for i in prov.list_compute(account=acct, region=region)
                ]
            except Exception:
                pass

        if "storage" in include:
            try:
                data["storage"] = [
                    {"name": b.name, "region": b.region or "global", "public": b.public}
                    for b in prov.list_storage(account=acct, region=region)
                ]
            except Exception:
                pass

        if "cost" in include:
            try:
                data["cost"] = prov.get_cost_summary(account=acct)
            except Exception:
                pass

        return data

    # ── Specific fetchers (used by debug engine) ───────────────────────────────

    def fetch_compute_metrics(self, accounts: list[str], days: int = 14) -> dict:
        """Fetch CloudWatch/Monitor metrics for compute instances."""
        result: dict = {}
        for profile in accounts:
            try:
                prov = get_aws_provider(profile)
                result[profile] = prov.list_compute(account=profile)
            except Exception:
                pass
        return result

    def fetch_cost_data(self, accounts: list[str], days: int = 30) -> dict:
        """Fetch cost data from Cost Explorer / Cost Management / Billing."""
        result: dict = {}
        for profile in accounts:
            try:
                prov = get_aws_provider(profile)
                result[profile] = prov.get_cost_summary(account=profile)
            except Exception:
                pass
        return result

    def fetch_security_data(self, accounts: list[str]) -> dict:
        """Fetch security findings from SecurityHub / Defender / SCC."""
        result: dict = {}
        for profile in accounts:
            try:
                prov = get_aws_provider(profile)
                result[profile] = prov.get_security_findings(account=profile)
            except Exception:
                pass
        return result
