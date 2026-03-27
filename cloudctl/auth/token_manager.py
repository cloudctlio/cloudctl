"""Loads existing cloud credentials — never creates new auth."""
from __future__ import annotations

import configparser
import os
from pathlib import Path


class TokenManager:
    # ── AWS ──────────────────────────────────────────────────────────────────

    def has_aws_credentials(self) -> bool:
        aws_config = Path.home() / ".aws" / "config"
        aws_creds = Path.home() / ".aws" / "credentials"
        return aws_config.exists() or aws_creds.exists()

    def list_aws_profiles(self) -> list[dict]:
        """Return profiles from ~/.aws/config + ~/.aws/credentials."""
        profiles: dict[str, dict] = {}

        aws_config = Path.home() / ".aws" / "config"
        if aws_config.exists():
            cfg = configparser.ConfigParser()
            cfg.read(aws_config)
            for section in cfg.sections():
                # sections are "profile foo" or "default"
                name = section.removeprefix("profile ").strip()
                profiles[name] = {
                    "name": name,
                    "region": cfg.get(section, "region", fallback="—"),
                    "source": "config",
                    "sso": cfg.has_option(section, "sso_start_url"),
                }

        aws_creds = Path.home() / ".aws" / "credentials"
        if aws_creds.exists():
            creds = configparser.ConfigParser()
            creds.read(aws_creds)
            for section in creds.sections():
                if section not in profiles:
                    profiles[section] = {
                        "name": section,
                        "region": "—",
                        "source": "credentials",
                        "sso": False,
                    }

        return list(profiles.values())

    def get_aws_profile(self, name: str) -> dict | None:
        for p in self.list_aws_profiles():
            if p["name"] == name:
                return p
        return None

    # ── Azure ─────────────────────────────────────────────────────────────────

    def has_azure_credentials(self) -> bool:
        # Require an actual access token or service principal file — not just the directory
        azure_dir = Path.home() / ".azure"
        token_file = azure_dir / "msal_token_cache.json"
        sp_file = azure_dir / "accessTokens.json"
        return token_file.exists() or sp_file.exists()

    # ── GCP ───────────────────────────────────────────────────────────────────

    def has_gcp_credentials(self) -> bool:
        adc = Path.home() / ".config" / "gcloud" / "application_default_credentials.json"
        gcloud_cfg = Path.home() / ".config" / "gcloud" / "configurations"
        return adc.exists() or gcloud_cfg.exists()
