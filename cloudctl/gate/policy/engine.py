"""Policy stage: run every enabled engine over the structured plan.

Two kinds of plug-ins:

* **Enrichers** add facts to the policy input before rules run (Infracost's
  monthly cost delta, the request's model spend).
* **Engines** return findings in the gate's single contract (rule ID,
  severity, message, fix hint, resource).

Fail closed: an enabled engine that is missing, mis-versioned, times out or
returns output the adapter cannot read raises :class:`EngineError`, and the
gate rejects the change. "Could not evaluate" is never "passed".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional, Protocol, Sequence

from cloudctl.gate.models import ChangeRequest, EngineError, Finding, Plan, Severity


@dataclass
class PolicyContext:
    """Everything an engine may read. ``input`` is the JSON document Rego and
    the other engines see; ``plan``/``env``/``creds`` are for adapters that
    need to call tools or cloud APIs."""

    plan: Plan
    env: Any
    request: ChangeRequest
    creds: Any = None
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def input(self) -> dict[str, Any]:
        doc = {
            "plan": self.plan.to_dict(),
            "environment": self.env.to_policy_input(),
            "request": self.request.to_dict(),
            "cost": self.facts.get("cost", {"estimated": False, "monthly_delta_usd": None,
                                            "currency": "USD", "source": ""}),
            "model": self.facts.get("model", {"cost_usd": _num(self.request.context.get("model_cost_usd"))}),
        }
        return doc


def _num(v: Any) -> Optional[float]:
    try:
        return None if v is None else float(v)
    except (TypeError, ValueError):
        return None


class Enricher(Protocol):
    name: str

    def enrich(self, ctx: PolicyContext) -> None: ...


class Engine(Protocol):
    name: str

    def applies_to(self, ctx: PolicyContext) -> bool: ...

    def evaluate(self, ctx: PolicyContext) -> list[Finding]: ...


@dataclass(frozen=True)
class EngineRun:
    engine: str
    ran: bool
    findings: int
    detail: str = ""


@dataclass(frozen=True)
class PolicyResult:
    findings: tuple[Finding, ...]
    runs: tuple[EngineRun, ...]

    @property
    def blocking(self) -> tuple[Finding, ...]:
        return tuple(f for f in self.findings if f.severity.blocking)


def evaluate_policy(ctx: PolicyContext, *, enrichers: Sequence[Any], engines: Sequence[Any],
                    severity_overrides: Mapping[str, Severity] = {},
                    disabled_rules: Iterable[str] = ()) -> PolicyResult:
    """Run enrichers then engines. Any engine failure raises EngineError."""
    runs: list[EngineRun] = []
    for e in enrichers:
        try:
            e.enrich(ctx)
        except EngineError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise EngineError(f"{e.name}: {exc}") from exc
        applies = getattr(e, "applies_to", None)
        ran = applies(ctx) if callable(applies) else True
        runs.append(EngineRun(engine=e.name, ran=ran, findings=0,
                              detail="enricher" if ran else "not applicable"))

    disabled = set(disabled_rules)
    findings: list[Finding] = []
    for eng in engines:
        if not eng.applies_to(ctx):
            runs.append(EngineRun(engine=eng.name, ran=False, findings=0, detail="not applicable"))
            continue
        try:
            got = eng.evaluate(ctx)
        except EngineError:
            raise
        except Exception as exc:  # noqa: BLE001
            raise EngineError(f"{eng.name}: {exc}") from exc
        if not isinstance(got, list) or not all(isinstance(f, Finding) for f in got):
            raise EngineError(f"{eng.name}: returned something other than a list of findings")
        kept = []
        for f in got:
            if f.rule_id in disabled:
                continue
            if f.rule_id in severity_overrides:
                f = Finding(rule_id=f.rule_id, severity=severity_overrides[f.rule_id], message=f.message,
                            engine=f.engine, fix_hint=f.fix_hint, resource=f.resource,
                            references=f.references)
            kept.append(f)
        findings += kept
        runs.append(EngineRun(engine=eng.name, ran=True, findings=len(kept),
                              detail=str(getattr(eng, "last_detail", "") or "")))
    # de-duplicate identical findings from overlapping engines
    seen: set[tuple] = set()
    uniq = []
    for f in sorted(findings, key=lambda x: (-x.severity, x.rule_id, x.resource)):
        key = (f.rule_id, f.resource, f.message)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return PolicyResult(findings=tuple(uniq), runs=tuple(runs))
