"""The autonomy table: how far the drift loop may go on its own.

The decision is made in a fixed order, and each step can only make it more
cautious:

1. **Class.** Drift that looks like a security incident (identity, audit
   logging or key changes, or live exposure to the internet) is always
   ``report``: it is never repaired automatically, at any tier, whatever the
   config says. Repairing it could destroy evidence or hide an intruder.
2. **Environment tier and severity.** The table maps (tier, severity) to
   ``auto``, ``approve`` or ``report``.
3. **Platform cap.** Some IaC tools cannot repair drift by re-applying
   (CloudFormation); those are ``report``.
4. **Confidence θ.** Only inside an ``auto`` cell: if the repair's confidence
   is below the tier's θ, the decision drops to ``approve``.

Config (all optional; the defaults below apply):

.. code-block:: yaml

    drift:
      autonomy:
        dev:     {LOW: auto, MEDIUM: auto,    HIGH: approve, CRITICAL: report}
        staging: {LOW: auto, MEDIUM: approve, HIGH: approve, CRITICAL: report}
        prod:    {LOW: auto, MEDIUM: approve, HIGH: approve, CRITICAL: report}
      theta: {dev: 0.6, test: 0.6, staging: 0.8, prod: 0.9}

Validation refuses ``auto`` for CRITICAL anywhere and for HIGH in prod, and
θ below 0.5 in prod.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

AUTO, APPROVE, REPORT = "auto", "approve", "report"
MODES = (AUTO, APPROVE, REPORT)
_RANK = {AUTO: 0, APPROVE: 1, REPORT: 2}
SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
TIERS = ("dev", "test", "staging", "prod")

SECURITY_INCIDENT = "security_incident"
CONFIG_DRIFT = "config_drift"
FAILED_CHANGE = "failed_change"
DRIFT_CLASSES = (SECURITY_INCIDENT, CONFIG_DRIFT, FAILED_CHANGE)

#: Platforms that cannot fix drift by re-applying their declared state.
REPORT_ONLY_PLATFORMS = {
    "cloudformation": "CloudFormation does not revert drift when the same template is deployed again; "
                      "fix the resource by hand or change the template",
    "cdk": "CloudFormation (under CDK) does not revert drift when the same template is deployed again; "
           "fix the resource by hand or change the app",
}

DEFAULT_TABLE: dict[str, dict[str, str]] = {
    "dev": {"LOW": AUTO, "MEDIUM": AUTO, "HIGH": APPROVE, "CRITICAL": REPORT},
    "test": {"LOW": AUTO, "MEDIUM": AUTO, "HIGH": APPROVE, "CRITICAL": REPORT},
    "staging": {"LOW": AUTO, "MEDIUM": APPROVE, "HIGH": APPROVE, "CRITICAL": REPORT},
    "prod": {"LOW": AUTO, "MEDIUM": APPROVE, "HIGH": APPROVE, "CRITICAL": REPORT},
}
DEFAULT_THETA: dict[str, float] = {"dev": 0.6, "test": 0.6, "staging": 0.8, "prod": 0.9}


class AutonomyConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Decision:
    mode: str
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"mode": self.mode, "reasons": list(self.reasons)}


@dataclass(frozen=True)
class AutonomyTable:
    table: Mapping[str, Mapping[str, str]] = field(default_factory=lambda: DEFAULT_TABLE)
    theta: Mapping[str, float] = field(default_factory=lambda: DEFAULT_THETA)

    def decide(self, *, tier: str, severity: str, drift_class: str, confidence: float,
               platform: str = "") -> Decision:
        if tier not in TIERS:
            raise AutonomyConfigError(f"unknown tier {tier!r}")
        if severity not in SEVERITIES:
            raise AutonomyConfigError(f"unknown severity {severity!r}")
        if drift_class not in DRIFT_CLASSES:
            raise AutonomyConfigError(f"unknown drift class {drift_class!r}")
        # 1. class
        if drift_class == SECURITY_INCIDENT:
            return Decision(REPORT, ("looks like a security incident: never repaired automatically",))
        reasons: list[str] = []
        # 2. tier × severity
        mode = self.table[tier][severity]
        reasons.append(f"{tier} × {severity} is {mode}")
        if drift_class == FAILED_CHANGE and mode == AUTO:
            mode = APPROVE
            reasons.append("a failed change is repaired only with a person's go-ahead")
        # 3. platform cap
        if platform in REPORT_ONLY_PLATFORMS:
            mode = REPORT
            reasons.append(REPORT_ONLY_PLATFORMS[platform])
        # 4. confidence, only inside an auto cell
        if mode == AUTO:
            th = self.theta[tier]
            if confidence < th:
                mode = APPROVE
                reasons.append(f"confidence {confidence:.2f} is below θ {th:.2f} for {tier}")
            else:
                reasons.append(f"confidence {confidence:.2f} meets θ {th:.2f}")
        return Decision(mode, tuple(reasons))

    def to_dict(self) -> dict[str, Any]:
        return {"autonomy": {t: dict(r) for t, r in self.table.items()}, "theta": dict(self.theta)}


def parse_autonomy(doc: Any) -> AutonomyTable:
    """Parse the ``drift:`` config section. Missing cells take the defaults;
    unsafe cells are refused."""
    if doc is None:
        doc = {}
    if not isinstance(doc, Mapping):
        raise AutonomyConfigError("drift: expected a mapping")
    extra = set(doc) - {"autonomy", "theta"}
    if extra:
        raise AutonomyConfigError(f"drift: unknown key(s) {sorted(extra)}")
    table = {t: dict(r) for t, r in DEFAULT_TABLE.items()}
    raw = doc.get("autonomy") or {}
    if not isinstance(raw, Mapping):
        raise AutonomyConfigError("drift.autonomy: expected a mapping of tier to severities")
    for tier, row in raw.items():
        if tier not in TIERS:
            raise AutonomyConfigError(f"drift.autonomy.{tier}: unknown tier; one of {TIERS}")
        if not isinstance(row, Mapping):
            raise AutonomyConfigError(f"drift.autonomy.{tier}: expected severity: mode")
        for sev, mode in row.items():
            sev_u = str(sev).upper()
            if sev_u not in SEVERITIES:
                raise AutonomyConfigError(f"drift.autonomy.{tier}.{sev}: unknown severity")
            if mode not in MODES:
                raise AutonomyConfigError(f"drift.autonomy.{tier}.{sev}: {mode!r} is not one of {MODES}")
            table[tier][sev_u] = mode
    for tier, row in table.items():
        if row["CRITICAL"] == AUTO:
            raise AutonomyConfigError(f"drift.autonomy.{tier}.CRITICAL: CRITICAL drift is never auto-repaired")
        if tier == "prod" and row["HIGH"] == AUTO:
            raise AutonomyConfigError("drift.autonomy.prod.HIGH: HIGH drift in prod is never auto-repaired")
        prev = -1
        for sev in SEVERITIES:     # a more severe cell may not be more autonomous than a milder one
            if _RANK[row[sev]] < prev:
                raise AutonomyConfigError(f"drift.autonomy.{tier}.{sev}: more autonomous than a lower severity")
            prev = _RANK[row[sev]]
    theta = dict(DEFAULT_THETA)
    raw_t = doc.get("theta") or {}
    if not isinstance(raw_t, Mapping):
        raise AutonomyConfigError("drift.theta: expected a mapping of tier to a number")
    for tier, v in raw_t.items():
        if tier not in TIERS:
            raise AutonomyConfigError(f"drift.theta.{tier}: unknown tier")
        if isinstance(v, bool) or not isinstance(v, (int, float)) or not 0.0 <= float(v) <= 1.0:
            raise AutonomyConfigError(f"drift.theta.{tier}: expected a number from 0 to 1")
        theta[tier] = float(v)
    if theta["prod"] < 0.5:
        raise AutonomyConfigError("drift.theta.prod: must be at least 0.5")
    return AutonomyTable(table=table, theta=theta)
