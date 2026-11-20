"""AWS: STS AssumeRole, 900-second session, per operation."""
from __future__ import annotations

import re
from typing import Any, Callable, Optional

from cloudctl.gate.credentials.base import MAX_LIFETIME_SECONDS, ScopedCredentials, capped_expiry
from cloudctl.gate.models import CredentialError, utcnow


def _session_name(request_id: str) -> str:
    # RoleSessionName: [\w+=,.@-]{2,64}
    return ("cctl-" + re.sub(r"[^\w+=,.@-]", "", request_id))[:64]


def _source_identity(requester: str) -> str:
    # SourceIdentity: [\w+=,.@-]{2,64}; it is sticky across role chaining and
    # appears in CloudTrail, so the human behind every change is recorded.
    s = re.sub(r"[^\w+=,.@-]", "-", requester)[:64]
    return s if len(s) >= 2 else "cctl-operator"


class AwsAssumeRoleBroker:
    cloud = "aws"

    def __init__(self, session_factory: Optional[Callable[..., Any]] = None) -> None:
        if session_factory is None:
            import boto3  # noqa: PLC0415
            session_factory = boto3.Session
        self._session_factory = session_factory

    def acquire(self, env: Any, *, request_id: str, requester: str) -> ScopedCredentials:
        mode = env.credentials.mode
        region = env.scope["region"]
        account = env.scope["account_id"]
        if mode == "profile":
            return self._profile(env, region, account)
        if mode != "assume_role":
            raise CredentialError(f"unsupported AWS credentials mode {mode!r}")
        p = env.credentials.params
        base = self._session_factory(profile_name=p.get("source_profile"), region_name=region)
        sts = base.client("sts", region_name=region)
        kwargs: dict[str, Any] = {
            "RoleArn": p["role_arn"],
            "RoleSessionName": _session_name(request_id),
            "DurationSeconds": MAX_LIFETIME_SECONDS,
            "SourceIdentity": _source_identity(requester),
            "Tags": [{"Key": "cctl-request", "Value": request_id[:256]}],
        }
        if p.get("external_id"):
            kwargs["ExternalId"] = p["external_id"]
        if p.get("session_policy_arns"):
            kwargs["PolicyArns"] = [{"arn": a} for a in p["session_policy_arns"]]
        acquired = utcnow()
        try:
            resp = sts.assume_role(**kwargs)
        except Exception as e:  # noqa: BLE001
            raise CredentialError(f"sts:AssumeRole on {p['role_arn']} failed: {e}") from e
        c = resp["Credentials"]
        secret = {"access_key": c["AccessKeyId"], "secret_key": c["SecretAccessKey"],
                  "token": c["SessionToken"]}
        creds = self._wrap(identity=resp.get("AssumedRoleUser", {}).get("Arn", p["role_arn"]),
                           account=account, region=region, secret=secret,
                           acquired=acquired, cloud_expiry=c.get("Expiration"))
        self._verify_account(creds, account)
        return creds

    def _profile(self, env: Any, region: str, account: str) -> ScopedCredentials:
        """Non-prod only (enforced by config validation): resolve the named
        profile once into static session credentials, so the subprocess and
        SDK clients still get an explicit, capped credential set."""
        sess = self._session_factory(profile_name=env.credentials.params["profile"], region_name=region)
        acquired = utcnow()
        raw = sess.get_credentials()
        if raw is None:
            raise CredentialError(f"AWS profile {env.credentials.params['profile']!r} has no credentials")
        frozen = raw.get_frozen_credentials()
        secret = {"access_key": frozen.access_key, "secret_key": frozen.secret_key, "token": frozen.token}
        creds = self._wrap(identity=f"profile:{env.credentials.params['profile']}", account=account,
                           region=region, secret=secret, acquired=acquired, cloud_expiry=None)
        self._verify_account(creds, account)
        return creds

    def _wrap(self, *, identity: str, account: str, region: str, secret: dict, acquired, cloud_expiry):
        factory = self._session_factory

        def session(**kw: Any) -> Any:
            return factory(aws_access_key_id=secret["access_key"],
                           aws_secret_access_key=secret["secret_key"],
                           aws_session_token=secret["token"],
                           region_name=kw.get("region_name", region))

        def env_vars() -> dict[str, str]:
            out = {"AWS_ACCESS_KEY_ID": secret["access_key"], "AWS_SECRET_ACCESS_KEY": secret["secret_key"],
                   "AWS_REGION": region, "AWS_DEFAULT_REGION": region,
                   # make sure no shared config/profile can override the scoped creds
                   "AWS_SDK_LOAD_CONFIG": "0", "AWS_EC2_METADATA_DISABLED": "true"}
            if secret.get("token"):
                out["AWS_SESSION_TOKEN"] = secret["token"]
            return out

        return ScopedCredentials(
            cloud="aws", identity=identity, scope={"account_id": account, "region": region},
            expires_at=capped_expiry(acquired, cloud_expiry), acquired_at=acquired,
            _secret=secret, _builders={"session": session, "env": env_vars},
        )

    @staticmethod
    def _verify_account(creds: ScopedCredentials, account: str) -> None:
        """Defence in depth: the credentials must belong to the environment's account."""
        try:
            ident = creds.client("session").client("sts").get_caller_identity()
        except Exception as e:  # noqa: BLE001
            creds.destroy()
            raise CredentialError(f"sts:GetCallerIdentity with the scoped credentials failed: {e}") from e
        if str(ident.get("Account")) != account:
            creds.destroy()
            raise CredentialError(f"scoped credentials are for account {ident.get('Account')}, "
                                  f"but the environment is account {account}")
