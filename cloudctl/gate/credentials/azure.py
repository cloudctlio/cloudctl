"""Azure: workload identity federation or managed identity, one subscription
and resource group per environment.

Azure AD access tokens cannot be issued for less than ~60 minutes, and their
reach is decided by the identity's RBAC role assignments, not by the token.
So scoping works in two layers:

* the environment names one identity whose role assignment an admin grants at
  the resource-group scope (``cloudctl gate validate --live`` checks it), and
* the gate itself refuses to use the credentials after 900 s, and the policy
  stage rejects any planned change whose resource ID is outside the
  environment's subscription and resource group (rule CCTL-SCOPE-001).
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cloudctl.gate.credentials.base import ScopedCredentials, capped_expiry
from cloudctl.gate.models import CredentialError, utcnow

ARM_SCOPE = "https://management.azure.com/.default"


class AzureBroker:
    cloud = "azure"

    def __init__(self, identity_module: Any = None) -> None:
        self._mod = identity_module

    def _identity(self) -> Any:
        if self._mod is not None:
            return self._mod
        try:
            import azure.identity as mod  # noqa: PLC0415
        except ImportError as e:
            raise CredentialError("Azure credentials need azure-identity (pip install 'cctl[azure]')") from e
        return mod

    def acquire(self, env: Any, *, request_id: str, requester: str) -> ScopedCredentials:
        ident = self._identity()
        mode = env.credentials.mode
        p = env.credentials.params
        tenant = env.scope["tenant_id"]
        sub = env.scope["subscription_id"]
        rg = env.scope["resource_group"]
        env_extra: dict[str, str] = {"ARM_TENANT_ID": tenant, "ARM_SUBSCRIPTION_ID": sub,
                                     "AZURE_TENANT_ID": tenant}
        if mode == "workload_identity":
            token_file = Path(p["token_file"]).expanduser()
            if not token_file.is_file():
                raise CredentialError(f"federated token file {token_file} does not exist")
            cred = ident.WorkloadIdentityCredential(tenant_id=tenant, client_id=p["client_id"],
                                                    token_file_path=str(token_file))
            identity = f"wif:{p['client_id']}"
            env_extra.update({"ARM_CLIENT_ID": p["client_id"], "ARM_USE_OIDC": "true",
                              "ARM_OIDC_TOKEN_FILE_PATH": str(token_file),
                              "AZURE_CLIENT_ID": p["client_id"],
                              "AZURE_FEDERATED_TOKEN_FILE": str(token_file)})
        elif mode == "managed_identity":
            kwargs = {"client_id": p["client_id"]} if p.get("client_id") else {}
            cred = ident.ManagedIdentityCredential(**kwargs)
            identity = f"msi:{p.get('client_id', 'system-assigned')}"
            env_extra["ARM_USE_MSI"] = "true"
            if p.get("client_id"):
                env_extra["ARM_CLIENT_ID"] = p["client_id"]
        elif mode == "cli":
            cred = ident.AzureCliCredential(tenant_id=tenant)
            identity = "azure-cli"
            env_extra["ARM_USE_CLI"] = "true"
        else:
            raise CredentialError(f"unsupported Azure credentials mode {mode!r}")

        acquired = utcnow()
        try:
            token = cred.get_token(ARM_SCOPE, tenant_id=tenant) if mode != "managed_identity" \
                else cred.get_token(ARM_SCOPE)
        except Exception as e:  # noqa: BLE001
            raise CredentialError(f"Azure token for {identity} failed: {e}") from e
        expiry = datetime.fromtimestamp(int(token.expires_on), tz=timezone.utc)
        secret = {"credential": cred, "token": token.token}

        def credential() -> Any:
            return _CappedCredential(secret, creds_ref)

        def env_vars() -> dict[str, str]:
            return dict(env_extra)

        creds = ScopedCredentials(
            cloud="azure", identity=identity,
            scope={"tenant_id": tenant, "subscription_id": sub, "resource_group": rg},
            expires_at=capped_expiry(acquired, expiry), acquired_at=acquired,
            _secret=secret, _builders={"credential": credential, "env": env_vars},
        )
        creds_ref = creds
        return creds


class _CappedCredential:
    """TokenCredential wrapper that stops working when the gate's 900-second
    window closes, even if the underlying identity could still mint tokens."""

    def __init__(self, secret: dict, creds: ScopedCredentials) -> None:
        self._secret = secret
        self._creds = creds

    def get_token(self, *scopes: str, **kwargs: Any) -> Any:
        self._creds.ensure_valid(min_remaining=1.0)
        cred = self._secret.get("credential")
        if cred is None:
            raise CredentialError("credentials were destroyed")
        return cred.get_token(*scopes, **kwargs)

    def close(self) -> None:  # azure SDK clients call this
        pass


def resource_in_scope(resource_id: str, subscription_id: str, resource_group: str) -> bool:
    """True when an ARM resource ID lies in the given subscription and resource group."""
    rid = (resource_id or "").lower()
    prefix = f"/subscriptions/{subscription_id.lower()}/resourcegroups/{resource_group.lower()}"
    return rid == prefix or rid.startswith(prefix + "/")
