"""Control-plane config: strict validation, and the production rules."""
import pytest

from cloudctl.gate.config import engine_enabled, load_config, parse_config
from cloudctl.gate.models import ConfigError, Severity
from tests.gate.conftest import AWS_ACCT, aws_env, azure_env, config_doc, gcp_env

PUB = "MCowBQYDK2VwAyEAplaceholderplaceholderplaceholderxx="
S3 = {"type": "s3", "bucket": "audit", "region": "us-east-1", "retain_days": 400}
PROD_POLICY = {"engines": {"checkov": {"enabled": True, "version": "3.4.6"}}}


def prod(envf, **kw):
    return envf("prod", approval={"approvers": ["alice"]}, **kw)


def prod_doc(env, **kw):
    kw.setdefault("sink", S3)
    kw.setdefault("policy", PROD_POLICY)
    return config_doc({"prod": env}, approvers={"alice": {"public_key": PUB}}, **kw)


@pytest.mark.parametrize("envf", [aws_env, azure_env, gcp_env])
def test_dev_environment_for_each_cloud_parses(envf):
    cfg = parse_config(config_doc({"dev": envf()}))
    env = cfg.environment("dev")
    assert env.tier == "dev" and not env.is_prod
    assert engine_enabled(cfg.policy, "rego") and engine_enabled(cfg.policy, f"{env.cloud}_native")


@pytest.mark.parametrize("envf", [aws_env, azure_env, gcp_env])
def test_prod_environment_for_each_cloud_parses(envf):
    cfg = parse_config(prod_doc(prod(envf)))
    env = cfg.environment("prod")
    assert env.is_prod and env.approval.threshold == 1 and env.approval.approvers == ("alice",)


def test_unknown_keys_are_errors():
    with pytest.raises(ConfigError, match="unknown key"):
        parse_config(config_doc({"dev": aws_env(colour="blue")}))


@pytest.mark.parametrize("envf,mode", [(aws_env, {"mode": "profile", "profile": "p"}),
                                       (azure_env, {"mode": "cli"}), (gcp_env, {"mode": "adc"})])
def test_prod_refuses_long_lived_credentials(envf, mode):
    env = prod(envf)
    env["credentials"] = mode
    with pytest.raises(ConfigError, match="not allowed in a prod"):
        parse_config(prod_doc(env))


def test_prod_needs_immutable_audit_sink():
    with pytest.raises(ConfigError, match="immutable"):
        parse_config(prod_doc(prod(aws_env), sink=None))


def test_prod_needs_a_named_approver():
    env = aws_env("prod")
    with pytest.raises(ConfigError, match="named approver"):
        parse_config(prod_doc(env))


def test_approver_needs_a_public_key():
    doc = prod_doc(prod(aws_env))
    doc["approvers"] = {}
    with pytest.raises(ConfigError, match="no public key"):
        parse_config(doc)


def test_prod_needs_a_pinned_baseline_scanner():
    with pytest.raises(ConfigError, match="baseline scanner"):
        parse_config(prod_doc(prod(aws_env), policy={}))
    with pytest.raises(ConfigError, match="pin"):
        parse_config(prod_doc(prod(aws_env), policy={"engines": {"checkov": {"enabled": True}}}))


def test_prod_cannot_turn_off_rego_or_native_checks():
    for off in ("rego", "aws_native"):
        pol = {"engines": {**PROD_POLICY["engines"], off: {"enabled": False}}}
        with pytest.raises(ConfigError):
            parse_config(prod_doc(prod(aws_env), policy=pol))


def test_prod_cannot_lower_a_builtin_rule():
    pol = {**PROD_POLICY, "severity_overrides": {"CCTL-NET-001": "LOW"}}
    with pytest.raises(ConfigError, match="lower"):
        parse_config(prod_doc(prod(aws_env), policy=pol))


def test_prod_cannot_disable_rules():
    with pytest.raises(ConfigError, match="cannot be disabled"):
        parse_config(prod_doc(prod(aws_env, disabled_rules=["CCTL-NET-001"])))


def test_role_must_be_in_the_environment_account():
    env = prod(aws_env)
    env["credentials"]["role_arn"] = "arn:aws:iam::999999999999:role/x"
    with pytest.raises(ConfigError, match="another account"):
        parse_config(prod_doc(env))


def test_cloud_blocks_must_match_the_cloud():
    env = aws_env()
    env["gcp"] = {"project_id": "x"}
    with pytest.raises(ConfigError, match="cloud is 'aws'"):
        parse_config(config_doc({"dev": env}))


def test_resolve_environment_never_guesses(tmp_path):
    cfg = parse_config(config_doc({
        "a": aws_env(match={"profiles": ["dev"], "iac_roots": [str(tmp_path)]}),
        "b": aws_env(match={"profiles": ["dev"]}),
        "z": azure_env(match={"accounts": ["sub-z"]}),
    }))
    with pytest.raises(ConfigError, match="several"):
        cfg.resolve_environment(profile="dev")
    with pytest.raises(ConfigError, match="no environment"):
        cfg.resolve_environment(profile="nope")
    assert cfg.resolve_environment(iac_root=str(tmp_path)).name == "a"
    assert cfg.resolve_environment(account="sub-z").name == "z"
    with pytest.raises(ConfigError, match="is aws, not azure"):
        cfg.resolve_environment(name="a", cloud="azure")


def test_missing_config_file_is_a_clear_error(tmp_path):
    with pytest.raises(ConfigError, match="cloudctl gate init"):
        load_config(tmp_path / "nope.yaml")


def test_severity_parse_is_strict():
    assert Severity.parse("high") is Severity.HIGH
    assert Severity.parse("SEVERE") is Severity.CRITICAL     # scanner alias
    with pytest.raises(ValueError):
        Severity.parse("UNKNOWN")
    with pytest.raises(ValueError):
        Severity.parse(3)
    assert AWS_ACCT.isdigit()
