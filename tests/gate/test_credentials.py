"""Scoped credentials for AWS, Azure and GCP: 900 s cap, memory only,
account check, ambient variables stripped from subprocesses."""
import pickle
import types
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from cloudctl.gate.config import parse_config
from cloudctl.gate.credentials.aws import AwsAssumeRoleBroker
from cloudctl.gate.credentials.azure import AzureBroker, resource_in_scope
from cloudctl.gate.credentials.base import MAX_LIFETIME_SECONDS
from cloudctl.gate.credentials.gcp import GcpImpersonationBroker
from cloudctl.gate.models import CredentialError, utcnow
from tests.gate.conftest import AWS_ACCT, AWS_ROLE, SUB, aws_env, azure_env, config_doc, gcp_env

PUB = "MCowBQYDK2VwAyEAplaceholderplaceholderplaceholderxx="


def _env(envd, name="e"):
    tier = envd["tier"]
    doc = config_doc({name: envd}, approvers={"alice": {"public_key": PUB}},
                     sink={"type": "s3", "bucket": "b", "region": "us-east-1", "retain_days": 1},
                     policy={"engines": {"checkov": {"enabled": True, "version": "3.4.6"}}})
    if tier == "prod":
        envd.setdefault("approval", {"approvers": ["alice"]})
    return parse_config(doc).environment(name)


class FakeSession:
    """boto3.Session stand-in recording how it was built."""
    built = []

    def __init__(self, **kw):
        self.kw = kw
        FakeSession.built.append(kw)
        self.sts = MagicMock()
        self.sts.assume_role.return_value = {
            "Credentials": {"AccessKeyId": "ASIAEXAMPLEEXAMPLE12", "SecretAccessKey": "s", "SessionToken": "t",
                            "Expiration": utcnow() + timedelta(hours=1)},
            "AssumedRoleUser": {"Arn": f"arn:aws:sts::{AWS_ACCT}:assumed-role/cctl-apply/x"}}
        self.sts.get_caller_identity.return_value = {"Account": FakeSession.account}

    account = AWS_ACCT

    def client(self, name, **kw):
        assert name == "sts"
        return self.sts

    def get_credentials(self):
        frozen = types.SimpleNamespace(access_key="AKIA", secret_key="s", token=None)
        return types.SimpleNamespace(get_frozen_credentials=lambda: frozen)


def test_aws_assume_role_is_900s_tagged_and_account_checked():
    FakeSession.built.clear()
    FakeSession.account = AWS_ACCT
    b = AwsAssumeRoleBroker(session_factory=FakeSession)
    env = _env(aws_env("prod"))
    c = b.acquire(env, request_id="req-1", requester="alice@example.com")
    assert c.remaining_seconds <= MAX_LIFETIME_SECONDS
    assert c.scope == {"account_id": AWS_ACCT, "region": "us-east-1"}
    env_vars = c.subprocess_env({"AWS_PROFILE": "admin", "PATH": "/bin"})
    assert "AWS_PROFILE" not in env_vars and env_vars["AWS_SESSION_TOKEN"] == "t"
    assert env_vars["PATH"] == "/bin"
    # the session built from scoped creds used the explicit keys
    assert any(k.get("aws_access_key_id") == "ASIAEXAMPLEEXAMPLE12" for k in FakeSession.built)


def test_aws_assume_role_call_arguments():
    sessions = []

    def factory(**kw):
        s = FakeSession(**kw)
        sessions.append(s)
        return s
    AwsAssumeRoleBroker(session_factory=factory).acquire(_env(aws_env("prod")), request_id="r 1!",
                                                         requester="bob smith")
    kw = sessions[0].sts.assume_role.call_args.kwargs
    assert kw["RoleArn"] == AWS_ROLE and kw["DurationSeconds"] == 900
    assert kw["RoleSessionName"] == "cctl-r1" and kw["SourceIdentity"] == "bob-smith"


def test_aws_wrong_account_is_refused_and_destroyed():
    FakeSession.account = "999999999999"
    try:
        with pytest.raises(CredentialError, match="account 999999999999"):
            AwsAssumeRoleBroker(session_factory=FakeSession).acquire(_env(aws_env("prod")), request_id="r",
                                                                     requester="a")
    finally:
        FakeSession.account = AWS_ACCT


def test_aws_assume_role_failure_is_a_credential_error():
    class Bad(FakeSession):
        def __init__(self, **kw):
            super().__init__(**kw)
            self.sts.assume_role.side_effect = RuntimeError("AccessDenied")
    with pytest.raises(CredentialError, match="AccessDenied"):
        AwsAssumeRoleBroker(session_factory=Bad).acquire(_env(aws_env("prod")), request_id="r", requester="a")


def test_aws_profile_mode_for_dev():
    c = AwsAssumeRoleBroker(session_factory=FakeSession).acquire(_env(aws_env("dev")), request_id="r",
                                                                 requester="a")
    assert c.identity == "profile:dev" and "AWS_SESSION_TOKEN" not in c.subprocess_env({})


def test_credentials_cannot_be_pickled_copied_or_reused():
    import copy
    c = AwsAssumeRoleBroker(session_factory=FakeSession).acquire(_env(aws_env("prod")), request_id="r",
                                                                 requester="a")
    assert "secret" not in repr(c).lower() or "ASIA" not in repr(c)
    with pytest.raises(TypeError):
        pickle.dumps(c)
    with pytest.raises(TypeError):
        copy.deepcopy(c)
    c.destroy()
    with pytest.raises(CredentialError):
        c.client("session")


def test_expired_credentials_are_refused():
    c = AwsAssumeRoleBroker(session_factory=FakeSession).acquire(_env(aws_env("prod")), request_id="r",
                                                                 requester="a")
    c.expires_at = utcnow() + timedelta(seconds=10)
    with pytest.raises(CredentialError, match="expire"):
        c.ensure_valid()


def _azure_identity(expires_in=3600):
    tok = types.SimpleNamespace(token="aad", expires_on=int((utcnow() + timedelta(seconds=expires_in)).timestamp()))
    cred = MagicMock()
    cred.get_token.return_value = tok
    mod = types.SimpleNamespace(WorkloadIdentityCredential=MagicMock(return_value=cred),
                                ManagedIdentityCredential=MagicMock(return_value=cred),
                                AzureCliCredential=MagicMock(return_value=cred))
    return mod, cred


def test_azure_workload_identity_caps_a_60_minute_token_at_900s(tmp_path):
    tok_file = tmp_path / "tok"
    tok_file.write_text("jwt")
    envd = azure_env("prod")
    envd["credentials"]["token_file"] = str(tok_file)
    mod, cred = _azure_identity()
    c = AzureBroker(identity_module=mod).acquire(_env(envd), request_id="r", requester="a")
    assert c.remaining_seconds <= MAX_LIFETIME_SECONDS
    assert c.scope["subscription_id"] == SUB and c.scope["resource_group"] == "rg-app"
    env_vars = c.subprocess_env({"AZURE_CLIENT_SECRET": "x"})
    assert "AZURE_CLIENT_SECRET" not in env_vars and env_vars["ARM_USE_OIDC"] == "true"
    capped = c.client("credential")
    capped.get_token("scope")
    c.expires_at = utcnow()
    with pytest.raises(CredentialError):
        capped.get_token("scope")


def test_azure_missing_token_file_is_refused(tmp_path):
    envd = azure_env("prod")
    envd["credentials"]["token_file"] = str(tmp_path / "missing")
    mod, _ = _azure_identity()
    with pytest.raises(CredentialError, match="does not exist"):
        AzureBroker(identity_module=mod).acquire(_env(envd), request_id="r", requester="a")


def test_azure_resource_scope_check():
    rg = f"/subscriptions/{SUB}/resourceGroups/rg-app"
    assert resource_in_scope(rg + "/providers/Microsoft.Storage/storageAccounts/x", SUB, "rg-app")
    assert not resource_in_scope(f"/subscriptions/{SUB}/resourceGroups/rg-app2/x", SUB, "rg-app")


def test_gcp_impersonation_is_900s():
    source = object()
    imp = MagicMock()
    inst = imp.return_value
    inst.expiry = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)
    inst.token = "ya29.token"
    b = GcpImpersonationBroker(default_fn=lambda scopes: (source, "proj"), impersonated_cls=imp,
                               request_cls=MagicMock)
    c = b.acquire(_env(gcp_env("prod")), request_id="r", requester="a")
    assert imp.call_args.kwargs["lifetime"] == 900
    assert imp.call_args.kwargs["target_principal"].startswith("cctl@")
    assert c.remaining_seconds <= MAX_LIFETIME_SECONDS
    env_vars = c.subprocess_env({"GOOGLE_APPLICATION_CREDENTIALS": "/key.json"})
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in env_vars
    assert env_vars["CLOUDSDK_CORE_PROJECT"] == "proj-app"


def test_gcp_without_adc_is_a_credential_error():
    def no_adc(scopes):
        raise RuntimeError("no ADC")
    b = GcpImpersonationBroker(default_fn=no_adc, impersonated_cls=MagicMock(), request_cls=MagicMock)
    with pytest.raises(CredentialError, match="application-default"):
        b.acquire(_env(gcp_env("prod")), request_id="r", requester="a")
