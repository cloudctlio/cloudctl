"""Service settings (``CLOUDCTL_SERVICE_CONFIG``, YAML) and wiring.

.. code-block:: yaml

    gate_config: /etc/cctl/controlplane.yaml   # the policy gate's own config
    state:                                     # shared state for every replica
      backend: dynamodb                        # dynamodb | cosmos | firestore | memory
      table: cctl-control-plane
      region: us-east-1
    auth:
      issuer: https://token.example.com/
      audience: cctl-control-plane
      role_map:
        operator: [platform-team]
        approver: [platform-leads]
        auditor: [security]
    model: {adapter: converse, region: us-east-1, tokens_per_hour: 2000000}
    drift: {interval_seconds: 900, repair: true}   # 0 turns the scheduled loop off
    workers: 4
    max_body_bytes: 1048576

``memory`` state is refused unless ``allow_memory_state: true`` (one replica,
for trying it out): the gate's single-use approvals and run locks need shared
state once there is more than one replica.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping, Optional

from cloudctl.gate.models import ConfigError

_TOP = {"gate_config", "state", "auth", "model", "drift", "workers", "max_body_bytes", "allow_memory_state"}


def load_settings(path: Optional[str] = None) -> dict[str, Any]:
    import yaml  # noqa: PLC0415
    p = Path(path or os.environ.get("CLOUDCTL_SERVICE_CONFIG") or "/etc/cctl/service.yaml")
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise ConfigError(f"cannot read service settings {p}: {e}") from e
    return validate_settings(doc, source=str(p))


def validate_settings(doc: Any, *, source: str = "settings") -> dict[str, Any]:
    if not isinstance(doc, Mapping):
        raise ConfigError(f"{source}: expected a mapping")
    extra = set(doc) - _TOP
    if extra:
        raise ConfigError(f"{source}: unknown key(s) {sorted(extra)}")
    for k in ("gate_config", "state", "auth"):
        if k not in doc:
            raise ConfigError(f"{source}: {k} is required")
    state = doc["state"]
    if not isinstance(state, Mapping) or state.get("backend") not in ("dynamodb", "cosmos", "firestore", "memory"):
        raise ConfigError(f"{source}: state.backend must be dynamodb, cosmos, firestore or memory")
    need = {"dynamodb": ("table",), "cosmos": ("endpoint", "database", "container"), "firestore": ("project",),
            "memory": ()}[state["backend"]]
    missing = [k for k in need if not state.get(k)]
    if missing:
        raise ConfigError(f"{source}: state.{state['backend']} needs {missing}")
    if state["backend"] == "memory" and not doc.get("allow_memory_state"):
        raise ConfigError(f"{source}: memory state loses approvals and locks across replicas; "
                          "set allow_memory_state: true only for a single local replica")
    workers = doc.get("workers", 4)
    if not isinstance(workers, int) or not 1 <= workers <= 64:
        raise ConfigError(f"{source}: workers must be 1 to 64")
    drift = doc.get("drift") or {}
    iv = drift.get("interval_seconds", 0)
    if not isinstance(iv, int) or (iv and iv < 60):
        raise ConfigError(f"{source}: drift.interval_seconds must be 0 (off) or at least 60")
    return dict(doc)


def build_context(settings: Mapping[str, Any]) -> Any:
    from cloudctl.controlplane.kv import kv_from_settings  # noqa: PLC0415
    from cloudctl.controlplane.model import GuardedAdapter, load_adapter  # noqa: PLC0415
    from cloudctl.controlplane.shared import KvApprovalStore, KvDriftStore, KvRollbackQueue, KvRunStore  # noqa: PLC0415
    from cloudctl.gate.config import load_config  # noqa: PLC0415
    from cloudctl.gate.gate import PolicyGate, build_audit_log  # noqa: PLC0415
    from cloudctl.service.app import ServiceContext  # noqa: PLC0415
    from cloudctl.service.auth import AuthSettings, OIDCVerifier  # noqa: PLC0415

    config = load_config(settings["gate_config"])
    kv = kv_from_settings(settings["state"])
    audit = build_audit_log(config, actor="cctl-control-plane")
    if any(e.is_prod for e in config.environments.values()) and not audit.immutable:
        raise ConfigError("a prod environment needs the immutable audit sink in the service too")
    gate = PolicyGate(config, audit=audit, approvals=KvApprovalStore(kv))
    a = dict(settings["auth"])
    auth = AuthSettings(issuer=a["issuer"], audience=a["audience"], jwks_url=a.get("jwks_url", ""),
                        algorithms=tuple(a.get("algorithms", ("RS256", "ES256"))),
                        subject_claim=a.get("subject_claim", "email"), roles_claim=a.get("roles_claim", "groups"),
                        approver_claim=a.get("approver_claim", "preferred_username"),
                        role_map=a.get("role_map", {}))
    m = dict(settings.get("model") or {})
    adapter_name = m.pop("adapter", "converse")
    limits = {k: m.pop(k) for k in ("tokens_per_hour", "max_prompt_chars", "retries") if k in m}

    def model_factory() -> Any:
        return GuardedAdapter(load_adapter(adapter_name, **m), audit=gate.record, **limits)

    drift = settings.get("drift") or {}
    return ServiceContext(gate=gate, kv=kv, verifier=OIDCVerifier(auth), runs=KvRunStore(kv),
                          drift_store=KvDriftStore(kv), rollbacks=KvRollbackQueue(kv), model_factory=model_factory,
                          workers=int(settings.get("workers", 4)),
                          max_body_bytes=int(settings.get("max_body_bytes", 1_048_576)),
                          drift_interval=int(drift.get("interval_seconds", 0)),
                          drift_repair=bool(drift.get("repair", True)))
