"""Control-plane configuration (``~/.cloudctl/controlplane.yaml``).

The file is validated strictly: unknown keys, wrong types and unsafe
combinations are errors, and an error means the gate rejects every change.
Production-tier environments must use short-lived federated credentials,
an immutable remote audit sink and a named approver.

Example::

    version: 1
    audit:
      chain: cctl-acme
      sink: {type: s3, bucket: acme-cctl-audit, region: us-east-1, retain_days: 400}
    approvers:
      alice: {public_key: "MCowBQYDK2VwAyEA..."}       # from `cloudctl gate keygen`
    environments:
      prod-aws:
        tier: prod
        cloud: aws
        aws: {account_id: "111122223333", region: us-east-1}
        match: {profiles: [prod], accounts: ["111122223333"]}
        credentials:
          mode: assume_role
          role_arn: arn:aws:iam::111122223333:role/cctl-apply
        approval: {threshold: 3, approvers: [alice]}
        cost: {max_monthly_increase_usd: 500}
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

from cloudctl.gate.models import ConfigError, Severity

DEFAULT_CONFIG_PATH = Path.home() / ".cloudctl" / "controlplane.yaml"
CONFIG_ENV_VAR = "CLOUDCTL_GATE_CONFIG"

TIERS = ("dev", "test", "staging", "prod")
CLOUDS = ("aws", "azure", "gcp")

#: Credential modes per cloud, and whether each is allowed in production.
CREDENTIAL_MODES: dict[str, dict[str, bool]] = {
    "aws":   {"assume_role": True, "profile": False},
    "azure": {"workload_identity": True, "managed_identity": True, "cli": False},
    "gcp":   {"impersonation": True, "adc": False},
}

AUDIT_SINKS = ("s3", "azure_blob", "gcs")


def _check_keys(where: str, data: Mapping[str, Any], allowed: set[str], required: set[str] = frozenset()) -> None:
    if not isinstance(data, Mapping):
        raise ConfigError(f"{where}: expected a mapping, got {type(data).__name__}")
    unknown = set(data) - allowed
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {sorted(unknown)}; allowed: {sorted(allowed)}")
    missing = required - set(data)
    if missing:
        raise ConfigError(f"{where}: missing required key(s) {sorted(missing)}")


def _str(where: str, v: Any, *, pattern: Optional[str] = None, allow_empty: bool = False) -> str:
    if not isinstance(v, str) or (not v and not allow_empty):
        raise ConfigError(f"{where}: expected a non-empty string")
    if pattern and not re.fullmatch(pattern, v):
        raise ConfigError(f"{where}: {v!r} does not match {pattern}")
    return v


def _int(where: str, v: Any, *, minimum: int = 0, maximum: Optional[int] = None) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise ConfigError(f"{where}: expected an integer")
    if v < minimum or (maximum is not None and v > maximum):
        raise ConfigError(f"{where}: {v} is outside [{minimum}, {maximum if maximum is not None else '∞'}]")
    return v


def _num(where: str, v: Any, *, minimum: float = 0.0) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ConfigError(f"{where}: expected a number")
    if v < minimum:
        raise ConfigError(f"{where}: must be >= {minimum}")
    return float(v)


def _bool(where: str, v: Any) -> bool:
    if not isinstance(v, bool):
        raise ConfigError(f"{where}: expected true or false")
    return v


def _strlist(where: str, v: Any) -> tuple[str, ...]:
    if not isinstance(v, list) or not all(isinstance(x, str) and x for x in v):
        raise ConfigError(f"{where}: expected a list of strings")
    return tuple(v)


def _path(v: str) -> Path:
    return Path(os.path.expandvars(v)).expanduser()


@dataclass(frozen=True)
class CredentialsConfig:
    mode: str
    params: Mapping[str, str]


@dataclass(frozen=True)
class ApprovalConfig:
    #: Plans changing more than this many resources need a signed approval.
    threshold: int = 0
    #: Require approval for every mutating plan regardless of size.
    always: bool = False
    approvers: tuple[str, ...] = ()
    #: How long an approval request stays valid.
    ttl_seconds: int = 3600


@dataclass(frozen=True)
class CostConfig:
    max_monthly_increase_usd: Optional[float] = None
    max_model_cost_usd: Optional[float] = None
    #: If a cost limit is set but cost cannot be estimated, reject (default).
    allow_unestimated: bool = False


@dataclass(frozen=True)
class KubernetesConfig:
    provider: str              # eks | aks | gke
    cluster: str
    location: str = ""         # GKE location / AKS resource group override
    namespace: str = ""


@dataclass(frozen=True)
class EnvironmentConfig:
    name: str
    tier: str
    cloud: str
    scope: Mapping[str, str]        # aws: account_id, region | azure: tenant_id, subscription_id,
                                    # resource_group | gcp: project_id, region
    credentials: CredentialsConfig
    approval: ApprovalConfig = ApprovalConfig()
    cost: CostConfig = CostConfig()
    match_profiles: tuple[str, ...] = ()
    match_accounts: tuple[str, ...] = ()
    match_iac_roots: tuple[str, ...] = ()
    kubernetes: Optional[KubernetesConfig] = None
    #: Rule IDs disabled for this environment (never allowed in prod for
    #: HIGH/CRITICAL built-ins; see validation).
    disabled_rules: tuple[str, ...] = ()

    @property
    def is_prod(self) -> bool:
        return self.tier == "prod"

    def to_policy_input(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "tier": self.tier,
            "cloud": self.cloud,
            "scope": dict(self.scope),
            "approval_threshold": self.approval.threshold,
            "cost": {
                "max_monthly_increase_usd": self.cost.max_monthly_increase_usd,
                "max_model_cost_usd": self.cost.max_model_cost_usd,
                "allow_unestimated": self.cost.allow_unestimated,
            },
        }


@dataclass(frozen=True)
class EngineConfig:
    name: str
    enabled: bool
    params: Mapping[str, Any]


@dataclass(frozen=True)
class PolicyConfig:
    builtin_rules: bool = True
    rule_paths: tuple[Path, ...] = ()
    rego_paths: tuple[Path, ...] = ()
    engines: Mapping[str, EngineConfig] = field(default_factory=dict)
    severity_overrides: Mapping[str, Severity] = field(default_factory=dict)


@dataclass(frozen=True)
class AuditConfig:
    chain: str
    local_path: Path
    sink: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class GateConfig:
    environments: Mapping[str, EnvironmentConfig]
    approvers: Mapping[str, str]                 # name -> base64 Ed25519 public key
    policy: PolicyConfig
    audit: AuditConfig
    approvals_dir: Path
    source: str = ""

    def environment(self, name: str) -> EnvironmentConfig:
        try:
            return self.environments[name]
        except KeyError:
            raise ConfigError(f"unknown environment {name!r}; configured: "
                              f"{sorted(self.environments) or 'none'}") from None

    def resolve_environment(self, *, name: Optional[str] = None, cloud: Optional[str] = None,
                            profile: Optional[str] = None, account: Optional[str] = None,
                            iac_root: Optional[str] = None) -> EnvironmentConfig:
        """Pick exactly one environment. Ambiguity is an error, never a guess."""
        if name:
            env = self.environment(name)
            if cloud and env.cloud != cloud:
                raise ConfigError(f"environment {name!r} is {env.cloud}, not {cloud}")
            return env
        hits = []
        for env in self.environments.values():
            if cloud and env.cloud != cloud:
                continue
            if profile and profile in env.match_profiles:
                hits.append(env)
            elif account and account in env.match_accounts:
                hits.append(env)
            elif iac_root and any(_same_path(iac_root, r) for r in env.match_iac_roots):
                hits.append(env)
        hits = list({e.name: e for e in hits}.values())
        if len(hits) == 1:
            return hits[0]
        key = profile or account or iac_root or "(nothing)"
        if not hits:
            raise ConfigError(f"no environment matches {key!r}; pass --env or add it to an "
                              "environment's `match` block")
        raise ConfigError(f"{key!r} matches several environments ({sorted(e.name for e in hits)}); pass --env")


def _same_path(a: str, b: str) -> bool:
    try:
        return Path(a).expanduser().resolve() == _path(b).resolve()
    except OSError:
        return False


# ── parsing ───────────────────────────────────────────────────────────────────

_NAME = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,62}"

_SCOPE_KEYS = {
    "aws":   ({"account_id", "region"}, {"account_id", "region"}),
    "azure": ({"tenant_id", "subscription_id", "resource_group", "location"},
              {"tenant_id", "subscription_id", "resource_group"}),
    "gcp":   ({"project_id", "region"}, {"project_id"}),
}

_CRED_KEYS = {
    ("aws", "assume_role"): ({"mode", "role_arn", "external_id", "source_profile", "session_policy_arns"},
                             {"role_arn"}),
    ("aws", "profile"): ({"mode", "profile"}, {"profile"}),
    ("azure", "workload_identity"): ({"mode", "client_id", "token_file"}, {"client_id", "token_file"}),
    ("azure", "managed_identity"): ({"mode", "client_id"}, set()),
    ("azure", "cli"): ({"mode"}, set()),
    ("gcp", "impersonation"): ({"mode", "service_account", "delegates"}, {"service_account"}),
    ("gcp", "adc"): ({"mode"}, set()),
}

ENGINE_NAMES = ("rego", "trivy", "checkov", "cfn_guard", "kyverno", "infracost",
                "aws_native", "azure_native", "gcp_native")


def _parse_env(name: str, d: Mapping[str, Any]) -> EnvironmentConfig:
    w = f"environments.{name}"
    _str(w, name, pattern=_NAME)
    _check_keys(w, d, {"tier", "cloud", "aws", "azure", "gcp", "credentials", "approval", "cost",
                       "match", "kubernetes", "disabled_rules"},
                {"tier", "cloud", "credentials"})
    tier = _str(f"{w}.tier", d["tier"])
    if tier not in TIERS:
        raise ConfigError(f"{w}.tier: {tier!r} is not one of {TIERS}")
    cloud = _str(f"{w}.cloud", d["cloud"])
    if cloud not in CLOUDS:
        raise ConfigError(f"{w}.cloud: {cloud!r} is not one of {CLOUDS}")
    for other in set(CLOUDS) - {cloud}:
        if other in d:
            raise ConfigError(f"{w}: has a {other!r} block but cloud is {cloud!r}")
    allowed, required = _SCOPE_KEYS[cloud]
    scope_raw = d.get(cloud) or {}
    _check_keys(f"{w}.{cloud}", scope_raw, allowed, required)
    scope = {k: _str(f"{w}.{cloud}.{k}", v) for k, v in scope_raw.items()}
    if cloud == "aws":
        _str(f"{w}.aws.account_id", scope["account_id"], pattern=r"\d{12}")

    c = d["credentials"]
    if not isinstance(c, Mapping) or "mode" not in c:
        raise ConfigError(f"{w}.credentials: needs a `mode`")
    mode = _str(f"{w}.credentials.mode", c["mode"])
    if mode not in CREDENTIAL_MODES[cloud]:
        raise ConfigError(f"{w}.credentials.mode: {mode!r} is not valid for {cloud}; "
                          f"use one of {sorted(CREDENTIAL_MODES[cloud])}")
    if tier == "prod" and not CREDENTIAL_MODES[cloud][mode]:
        raise ConfigError(f"{w}: credentials mode {mode!r} is not allowed in a prod environment; "
                          "use short-lived federated credentials")
    ck, cr = _CRED_KEYS[(cloud, mode)]
    _check_keys(f"{w}.credentials", c, ck, cr)
    params: dict[str, Any] = {}
    for k, v in c.items():
        if k == "mode":
            continue
        params[k] = _strlist(f"{w}.credentials.{k}", v) if k in ("session_policy_arns", "delegates") \
            else _str(f"{w}.credentials.{k}", v)
    if cloud == "aws" and mode == "assume_role":
        _str(f"{w}.credentials.role_arn", params["role_arn"],
             pattern=r"arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]+")
        if params["role_arn"].split(":")[4] != scope["account_id"]:
            raise ConfigError(f"{w}.credentials.role_arn is in another account than aws.account_id")

    a = d.get("approval") or {}
    _check_keys(f"{w}.approval", a, {"threshold", "always", "approvers", "ttl_seconds"})
    approval = ApprovalConfig(
        threshold=_int(f"{w}.approval.threshold", a.get("threshold", 0 if tier != "prod" else 1)),
        always=_bool(f"{w}.approval.always", a.get("always", False)),
        approvers=_strlist(f"{w}.approval.approvers", a.get("approvers", [])),
        ttl_seconds=_int(f"{w}.approval.ttl_seconds", a.get("ttl_seconds", 3600), minimum=60, maximum=7 * 86400),
    )
    if tier == "prod" and not approval.approvers:
        raise ConfigError(f"{w}.approval.approvers: a prod environment needs at least one named approver")

    co = d.get("cost") or {}
    _check_keys(f"{w}.cost", co, {"max_monthly_increase_usd", "max_model_cost_usd", "allow_unestimated"})
    cost = CostConfig(
        max_monthly_increase_usd=_num(f"{w}.cost.max_monthly_increase_usd", co["max_monthly_increase_usd"])
        if co.get("max_monthly_increase_usd") is not None else None,
        max_model_cost_usd=_num(f"{w}.cost.max_model_cost_usd", co["max_model_cost_usd"])
        if co.get("max_model_cost_usd") is not None else None,
        allow_unestimated=_bool(f"{w}.cost.allow_unestimated", co.get("allow_unestimated", False)),
    )

    m = d.get("match") or {}
    _check_keys(f"{w}.match", m, {"profiles", "accounts", "iac_roots"})

    k8s = None
    if d.get("kubernetes") is not None:
        kd = d["kubernetes"]
        _check_keys(f"{w}.kubernetes", kd, {"provider", "cluster", "location", "namespace"},
                    {"provider", "cluster"})
        prov = _str(f"{w}.kubernetes.provider", kd["provider"])
        expected = {"aws": "eks", "azure": "aks", "gcp": "gke"}[cloud]
        if prov != expected:
            raise ConfigError(f"{w}.kubernetes.provider: a {cloud} environment uses {expected}, not {prov}")
        if cloud == "gcp" and not kd.get("location"):
            raise ConfigError(f"{w}.kubernetes.location is required for GKE")
        k8s = KubernetesConfig(provider=prov, cluster=_str(f"{w}.kubernetes.cluster", kd["cluster"]),
                               location=kd.get("location", ""), namespace=kd.get("namespace", ""))

    return EnvironmentConfig(
        name=name, tier=tier, cloud=cloud, scope=scope,
        credentials=CredentialsConfig(mode=mode, params=params),
        approval=approval, cost=cost,
        match_profiles=_strlist(f"{w}.match.profiles", m.get("profiles", [])),
        match_accounts=_strlist(f"{w}.match.accounts", m.get("accounts", [])),
        match_iac_roots=_strlist(f"{w}.match.iac_roots", m.get("iac_roots", [])),
        kubernetes=k8s,
        disabled_rules=_strlist(f"{w}.disabled_rules", d.get("disabled_rules", [])),
    )


def _parse_audit(d: Mapping[str, Any]) -> AuditConfig:
    _check_keys("audit", d, {"chain", "local_path", "sink"})
    chain = _str("audit.chain", d.get("chain", "cctl"), pattern=r"[A-Za-z0-9._-]{1,128}")
    local = _path(d.get("local_path", "~/.cloudctl/audit/chain.jsonl"))
    sink = d.get("sink")
    if sink is not None:
        if not isinstance(sink, Mapping) or sink.get("type") not in AUDIT_SINKS:
            raise ConfigError(f"audit.sink.type must be one of {AUDIT_SINKS}")
        t = sink["type"]
        keys = {
            "s3": ({"type", "bucket", "prefix", "region", "profile", "mode", "retain_days", "kms_key_id"},
                   {"bucket", "retain_days"}),
            "azure_blob": ({"type", "account_url", "container", "prefix", "retain_days"},
                           {"account_url", "container", "retain_days"}),
            "gcs": ({"type", "bucket", "prefix", "project", "retain_days"}, {"bucket", "retain_days"}),
        }[t]
        _check_keys("audit.sink", sink, *keys)
        _int("audit.sink.retain_days", sink["retain_days"], minimum=1, maximum=36500)
        if t == "s3" and sink.get("mode", "COMPLIANCE") not in ("COMPLIANCE", "GOVERNANCE"):
            raise ConfigError("audit.sink.mode must be COMPLIANCE or GOVERNANCE")
        if t == "azure_blob":
            _str("audit.sink.account_url", sink["account_url"], pattern=r"https://[a-z0-9]{3,24}\.blob\.core\.[a-z.]+/?")
    return AuditConfig(chain=chain, local_path=local, sink=dict(sink) if sink else None)


def _parse_policy(d: Mapping[str, Any]) -> PolicyConfig:
    _check_keys("policy", d, {"builtin_rules", "rule_paths", "rego_paths", "engines", "severity_overrides"})
    engines: dict[str, EngineConfig] = {}
    raw = d.get("engines") or {}
    if not isinstance(raw, Mapping):
        raise ConfigError("policy.engines: expected a mapping")
    for name, e in raw.items():
        if name not in ENGINE_NAMES:
            raise ConfigError(f"policy.engines: unknown engine {name!r}; known: {ENGINE_NAMES}")
        if not isinstance(e, Mapping):
            raise ConfigError(f"policy.engines.{name}: expected a mapping")
        params = {k: v for k, v in e.items() if k != "enabled"}
        engines[name] = EngineConfig(name=name, enabled=_bool(f"policy.engines.{name}.enabled",
                                                                e.get("enabled", True)), params=params)
    overrides: dict[str, Severity] = {}
    for rid, sev in (d.get("severity_overrides") or {}).items():
        try:
            overrides[str(rid)] = Severity.parse(sev)
        except ValueError as e:
            raise ConfigError(f"policy.severity_overrides.{rid}: {e}") from None
    return PolicyConfig(
        builtin_rules=_bool("policy.builtin_rules", d.get("builtin_rules", True)),
        rule_paths=tuple(_path(p) for p in _strlist("policy.rule_paths", d.get("rule_paths", []))),
        rego_paths=tuple(_path(p) for p in _strlist("policy.rego_paths", d.get("rego_paths", []))),
        engines=engines,
        severity_overrides=overrides,
    )


#: Engines that are on unless the config turns them off.
DEFAULT_ON_ENGINES = ("rego", "aws_native", "azure_native", "gcp_native")
BASELINE_SCANNERS = ("trivy", "checkov")


def engine_enabled(policy: PolicyConfig, name: str) -> bool:
    e = policy.engines.get(name)
    if e is None:
        return name in DEFAULT_ON_ENGINES
    return e.enabled


def _check_prod_policy(env: EnvironmentConfig, policy: PolicyConfig) -> None:
    w = f"environments.{env.name}"
    if not engine_enabled(policy, "rego"):
        raise ConfigError(f"{w}: the rego engine (built-in gate rules) cannot be disabled when a prod "
                          "environment exists")
    if not policy.builtin_rules:
        raise ConfigError(f"{w}: policy.builtin_rules cannot be false when a prod environment exists")
    native = f"{env.cloud}_native"
    if not engine_enabled(policy, native):
        raise ConfigError(f"{w}: prod on {env.cloud} requires the {native} engine (native guardrails)")
    baseline = [n for n in BASELINE_SCANNERS if engine_enabled(policy, n)]
    if not baseline:
        raise ConfigError(f"{w}: prod requires a baseline scanner; enable policy.engines.trivy or "
                          "policy.engines.checkov")
    for n in baseline + [x for x in ("cfn_guard", "kyverno", "infracost") if engine_enabled(policy, x)]:
        if not policy.engines[n].params.get("version"):
            raise ConfigError(f"policy.engines.{n}: pin `version:` when a prod environment exists")
    builtin = _builtin_severities()
    for rid, sev in policy.severity_overrides.items():
        if rid in builtin and sev < builtin[rid]:
            raise ConfigError(f"policy.severity_overrides.{rid}: built-in gate rules cannot be lowered "
                              f"(below {builtin[rid].name}) when a prod environment exists")


def _builtin_severities() -> dict[str, Severity]:
    from cloudctl.gate.policy.rego import BUILTIN_DIR, load_rule_files  # noqa: PLC0415

    return {r.id: r.severity for r in load_rule_files([BUILTIN_DIR])}


def parse_config(data: Any, *, source: str = "<memory>") -> GateConfig:
    if not isinstance(data, Mapping):
        raise ConfigError(f"{source}: top level must be a mapping")
    _check_keys("config", data, {"version", "environments", "approvers", "policy", "audit", "approvals_dir"},
                {"version", "environments"})
    if data["version"] != 1:
        raise ConfigError(f"config.version: unsupported version {data['version']!r}; expected 1")
    envs_raw = data["environments"]
    if not isinstance(envs_raw, Mapping) or not envs_raw:
        raise ConfigError("environments: define at least one environment")
    envs = {str(n): _parse_env(str(n), e) for n, e in envs_raw.items()}

    approvers: dict[str, str] = {}
    for n, a in (data.get("approvers") or {}).items():
        _str(f"approvers.{n}", n, pattern=_NAME)
        _check_keys(f"approvers.{n}", a, {"public_key"}, {"public_key"})
        approvers[n] = _str(f"approvers.{n}.public_key", a["public_key"])
    for env in envs.values():
        for ap in env.approval.approvers:
            if ap not in approvers:
                raise ConfigError(f"environments.{env.name}.approval.approvers: {ap!r} has no public key "
                                  "under `approvers`")

    audit = _parse_audit(data.get("audit") or {})
    policy = _parse_policy(data.get("policy") or {})

    for env in envs.values():
        if env.is_prod and audit.sink is None:
            raise ConfigError(f"environments.{env.name}: a prod environment requires an immutable "
                              "remote audit sink (audit.sink: s3 | azure_blob | gcs)")
        if env.is_prod and env.disabled_rules:
            raise ConfigError(f"environments.{env.name}.disabled_rules: rules cannot be disabled in prod")
        if env.is_prod:
            _check_prod_policy(env, policy)

    return GateConfig(
        environments=envs, approvers=approvers, policy=policy, audit=audit,
        approvals_dir=_path(data.get("approvals_dir", "~/.cloudctl/approvals")),
        source=source,
    )


def config_path() -> Path:
    return _path(os.environ.get(CONFIG_ENV_VAR, str(DEFAULT_CONFIG_PATH)))


def load_config(path: Optional[Path | str] = None) -> GateConfig:
    """Load and validate the gate configuration. Raises ConfigError."""
    import yaml  # noqa: PLC0415

    p = _path(str(path)) if path else config_path()
    if not p.exists():
        raise ConfigError(
            f"no control-plane config at {p}. cctl will not change any cloud resource without one. "
            "Create it with `cloudctl gate init`, then `cloudctl gate validate`.")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise ConfigError(f"cannot read {p}: {e}") from e
    return parse_config(data, source=str(p))
