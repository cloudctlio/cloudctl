"""OPA / Rego engine — the gate's core rule engine.

Rules are written as YAML in the gate's contract (ID, severity LOW..CRITICAL,
condition, fix hint); each rule's ``condition`` is a Rego body. The YAML is
compiled to Rego modules and evaluated by an OPA implementation:

* ``regopy`` (default) — Microsoft's rego-cpp, in process, MIT licence; no
  binary to install, works on Linux, macOS and Windows.
* ``opa`` — the reference OPA binary (Apache-2.0) via ``opa eval``, with a
  capabilities file that removes network and runtime built-ins. Pin its
  version in config; the service image ships it.

Plain Rego packs are accepted too (Conftest style): any module whose package
starts with ``cloudctl.packs.`` and defines ``deny`` / ``warn`` sets. Elements
may be objects ``{"id", "severity", "msg", "fix_hint", "resource"}`` or bare
strings (a bare ``deny`` string is HIGH, a bare ``warn`` string LOW).

Rules never reach the network: modules that reference ``http.send``,
``net.lookup_ip_addr`` or ``opa.runtime`` are refused at load time.
"""
from __future__ import annotations

import hashlib
import json
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

import yaml

from cloudctl.gate.models import EngineError, Finding, PlanError, Severity
from cloudctl.gate.plan.base import find_binary, run_tool, tool_version_matches
from cloudctl.gate.policy.engine import PolicyContext

BUILTIN_DIR = Path(__file__).parent / "builtin"
_FORBIDDEN = re.compile(r"\b(http\.send|net\.lookup_ip_addr|opa\.runtime|rego\.parse_module)\b")
_RULE_KEYS = {"id", "title", "severity", "scope", "clouds", "tiers", "platforms", "condition",
              "message", "fix_hint", "references"}
_ID = re.compile(r"[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){1,4}")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: Severity
    scope: str
    condition: str
    message: str
    fix_hint: str
    clouds: tuple[str, ...] = ()
    tiers: tuple[str, ...] = ()
    platforms: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    origin: str = ""

    @property
    def package(self) -> str:
        return "r_" + re.sub(r"[^a-z0-9]", "_", self.id.lower())

    def to_rego(self) -> str:
        body = "\n".join("  " + ln for ln in self.condition.strip().splitlines() if ln.strip())
        head = f"package cloudctl.rules.{self.package}\n\nimport rego.v1\n\n"
        if self.scope == "plan":
            return head + f"hits contains \"plan\" if {{\n{body}\n}}\n"
        clouds = ""
        if self.clouds:
            clouds = "  change.cloud in {" + ", ".join(json.dumps(c) for c in self.clouds) + "}\n"
        return (head + "hits contains change.address if {\n  some change in input.plan.changes\n"
                + clouds + body + "\n}\n")


def _check_source(name: str, src: str) -> None:
    m = _FORBIDDEN.search(src)
    if m:
        raise EngineError(f"{name}: uses forbidden built-in {m.group(1)!r} (rules must not reach the network)")


def parse_rules(doc: Any, *, origin: str) -> list[Rule]:
    if not isinstance(doc, Mapping) or not isinstance(doc.get("rules"), list):
        raise EngineError(f"{origin}: a rule file must have a top-level `rules:` list")
    out = []
    for i, r in enumerate(doc["rules"]):
        where = f"{origin} rule #{i + 1}"
        if not isinstance(r, Mapping):
            raise EngineError(f"{where}: expected a mapping")
        unknown = set(r) - _RULE_KEYS
        if unknown:
            raise EngineError(f"{where}: unknown keys {sorted(unknown)}")
        for k in ("id", "severity", "condition", "fix_hint"):
            if not r.get(k):
                raise EngineError(f"{where}: `{k}` is required")
        rid = str(r["id"])
        if not _ID.fullmatch(rid):
            raise EngineError(f"{where}: id {rid!r} must look like ABC-DEF-001")
        try:
            sev = Severity.parse(r["severity"])
        except ValueError as e:
            raise EngineError(f"{where} ({rid}): {e}") from None
        scope = r.get("scope", "change")
        if scope not in ("change", "plan"):
            raise EngineError(f"{where} ({rid}): scope must be change or plan")
        cond = str(r["condition"])
        _check_source(f"{where} ({rid})", cond)
        out.append(Rule(
            id=rid, title=str(r.get("title", rid)), severity=sev, scope=scope, condition=cond,
            message=str(r.get("message") or r.get("title") or rid), fix_hint=str(r["fix_hint"]),
            clouds=tuple(r.get("clouds") or ()), tiers=tuple(r.get("tiers") or ()),
            platforms=tuple(r.get("platforms") or ()), references=tuple(r.get("references") or ()),
            origin=origin,
        ))
    return out


def load_rule_files(paths: Iterable[Path]) -> list[Rule]:
    rules: list[Rule] = []
    for p in paths:
        files = sorted(p.glob("*.y*ml")) if p.is_dir() else [p]
        if p.is_dir() is False and not p.exists():
            raise EngineError(f"rule path {p} does not exist")
        for f in files:
            try:
                doc = yaml.safe_load(f.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError) as e:
                raise EngineError(f"cannot read rule file {f}: {e}") from e
            rules += parse_rules(doc, origin=str(f))
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise EngineError(f"duplicate rule ids: {sorted(dupes)}")
    return rules


def load_rego_files(paths: Iterable[Path]) -> dict[str, str]:
    mods: dict[str, str] = {}
    for p in paths:
        files = sorted(p.rglob("*.rego")) if p.is_dir() else [p]
        if not p.exists():
            raise EngineError(f"rego path {p} does not exist")
        for f in files:
            if f.name.endswith("_test.rego"):
                continue
            src = f.read_text(encoding="utf-8")
            _check_source(str(f), src)
            pkg = re.search(r"^\s*package\s+([\w.]+)", src, re.MULTILINE)
            if not pkg or not (pkg.group(1).startswith("cloudctl.packs.") or pkg.group(1).startswith("cloudctl.lib")):
                raise EngineError(f"{f}: package must start with cloudctl.packs. (got "
                                  f"{pkg.group(1) if pkg else 'none'})")
            mods[f"user:{f}"] = src
    return mods


# ── backends ─────────────────────────────────────────────────────────────────

class RegopyBackend:
    name = "regopy"

    def __init__(self, pinned_version: Optional[str] = None) -> None:
        try:
            import regopy  # noqa: PLC0415
        except ImportError as e:
            raise EngineError("the Rego engine needs regopy (pip install 'cctl[gate]'), "
                              "or set policy.engines.rego.backend: opa") from e
        if pinned_version and regopy.__version__ != pinned_version:
            raise EngineError(f"regopy version mismatch: pinned {pinned_version}, found {regopy.__version__}")
        self._regopy = regopy
        self.version = regopy.__version__

    def evaluate(self, modules: Mapping[str, str], input_doc: Mapping[str, Any], query: str) -> Any:
        rego = self._regopy.Interpreter()
        try:
            for name, src in modules.items():
                rego.add_module(name, src)
            rego.set_input(json.loads(json.dumps(input_doc)))
            out = rego.query(query)
        except self._regopy.RegoError as e:
            raise EngineError(f"Rego evaluation failed: {str(e)[:2000]}") from e
        if not out.ok():
            raise EngineError(f"Rego evaluation failed: {str(out)[:2000]}")
        text = str(out)
        if text.strip() == "undefined":
            return {}
        # regopy's Node.json() is unreliable in 1.5.x; the Output's string form
        # is the canonical JSON result document.
        try:
            doc = json.loads(text)
        except ValueError as e:
            raise EngineError(f"Rego returned unreadable output: {text[:500]}") from e
        if isinstance(doc, Mapping) and "expressions" in doc:
            exprs = doc["expressions"]
        elif isinstance(doc, list) and doc and isinstance(doc[0], Mapping):
            exprs = doc[0].get("expressions") or []
        else:
            raise EngineError(f"Rego returned an unexpected result shape: {text[:500]}")
        return exprs[0] if exprs else {}


class OpaBinaryBackend:
    name = "opa"
    _DENY_BUILTINS = {"http.send", "net.lookup_ip_addr", "opa.runtime", "rego.parse_module", "time.now_ns"}

    def __init__(self, binary_path: Optional[str] = None, pinned_version: Optional[str] = None,
                 timeout: int = 60) -> None:
        try:
            self._setup(binary_path, pinned_version, timeout)
        except PlanError as e:        # tool failures are engine failures here
            raise EngineError(str(e)) from e

    def _setup(self, binary_path: Optional[str], pinned_version: Optional[str], timeout: int) -> None:
        self.exe = find_binary("opa", binary_path)
        self.timeout = timeout
        ver = run_tool([self.exe, "version"], cwd=".", env={"PATH": ""}, timeout=30, what="opa version")
        if not tool_version_matches(ver.stdout, pinned_version):
            raise EngineError(f"opa version mismatch: pinned {pinned_version}, found {ver.stdout.splitlines()[:1]}")
        self.version = (ver.stdout.splitlines() or ["?"])[0]
        caps = run_tool([self.exe, "capabilities", "--current"], cwd=".", env={"PATH": ""}, timeout=30,
                        what="opa capabilities")
        doc = json.loads(caps.stdout)
        doc["builtins"] = [b for b in doc.get("builtins", []) if b.get("name") not in self._DENY_BUILTINS]
        doc.pop("allow_net", None)
        doc["allow_net"] = []
        self._caps = json.dumps(doc)

    def evaluate(self, modules: Mapping[str, str], input_doc: Mapping[str, Any], query: str) -> Any:
        with tempfile.TemporaryDirectory(prefix="cctl-opa-") as d:
            dd = Path(d)
            (dd / "caps.json").write_text(self._caps, encoding="utf-8")
            (dd / "input.json").write_text(json.dumps(input_doc), encoding="utf-8")
            mod_dir = dd / "policy"
            mod_dir.mkdir()
            for i, (name, src) in enumerate(modules.items()):
                safe = hashlib.sha256(name.encode()).hexdigest()[:16]
                (mod_dir / f"{i:04d}_{safe}.rego").write_text(src, encoding="utf-8")
            try:
                res = run_tool([self.exe, "eval", "--format", "json", "--capabilities", str(dd / "caps.json"),
                                "--strict-builtin-errors", "-d", str(mod_dir), "-i", str(dd / "input.json"),
                                query], cwd=dd, env={"PATH": ""}, timeout=self.timeout, what="opa eval")
            except PlanError as e:
                raise EngineError(str(e)) from e
        try:
            doc = json.loads(res.stdout)
        except ValueError as e:
            raise EngineError(f"opa eval returned invalid JSON: {e}") from e
        if doc.get("errors"):
            raise EngineError(f"opa eval errors: {json.dumps(doc['errors'])[:2000]}")
        results = doc.get("result") or []
        if not results:
            return {}
        return results[0]["expressions"][0]["value"]


def make_backend(params: Mapping[str, Any]) -> Any:
    backend = params.get("backend", "regopy")
    if backend == "regopy":
        return RegopyBackend(pinned_version=params.get("version"))
    if backend == "opa":
        return OpaBinaryBackend(binary_path=params.get("binary"), pinned_version=params.get("version"))
    raise EngineError(f"unknown rego backend {backend!r}; use regopy or opa")


# ── the engine ───────────────────────────────────────────────────────────────

@dataclass
class RegoEngine:
    rules: list[Rule] = field(repr=False)
    user_modules: dict[str, str] = field(default_factory=dict, repr=False)
    backend: Any = None
    name: str = "rego"

    @classmethod
    def from_config(cls, *, builtin: bool, rule_paths: Iterable[Path], rego_paths: Iterable[Path],
                    params: Mapping[str, Any], backend: Any = None) -> "RegoEngine":
        paths = ([BUILTIN_DIR] if builtin else []) + list(rule_paths)
        rules = load_rule_files(paths)
        mods = load_rego_files(rego_paths)
        lib = (BUILTIN_DIR / "lib.rego").read_text(encoding="utf-8")
        mods = {"builtin:lib.rego": lib, **mods}
        return cls(rules=rules, user_modules=mods, backend=backend or make_backend(params))

    def applies_to(self, ctx: PolicyContext) -> bool:
        return True

    def _active_rules(self, ctx: PolicyContext) -> list[Rule]:
        out = []
        for r in self.rules:
            if r.tiers and ctx.env.tier not in r.tiers:
                continue
            if r.platforms and ctx.plan.platform not in r.platforms:
                continue
            out.append(r)
        return out

    def evaluate(self, ctx: PolicyContext) -> list[Finding]:
        rules = self._active_rules(ctx)
        modules = dict(self.user_modules)
        for r in rules:
            modules[f"rule:{r.id}"] = r.to_rego()
        value = self.backend.evaluate(modules, ctx.input, "data.cloudctl")
        if not isinstance(value, Mapping):
            raise EngineError("Rego returned a non-object for data.cloudctl")
        findings: list[Finding] = []
        rule_out = value.get("rules") or {}
        for r in rules:
            hits = (rule_out.get(r.package) or {}).get("hits") or []
            if not isinstance(hits, list):
                raise EngineError(f"rule {r.id}: hits is not a set")
            for h in sorted(str(x) for x in hits):
                resource = "" if h == "plan" else h
                findings.append(Finding(
                    rule_id=r.id, severity=r.severity, engine=f"rego/{self.backend.name}",
                    message=r.message.replace("{resource}", resource or "the plan"),
                    fix_hint=r.fix_hint, resource=resource, references=r.references,
                ))
        findings += self._pack_findings(value.get("packs") or {})
        return findings

    def _pack_findings(self, packs: Mapping[str, Any], prefix: str = "cloudctl.packs") -> list[Finding]:
        out: list[Finding] = []
        for pkg, val in packs.items():
            if not isinstance(val, Mapping):
                continue
            name = f"{prefix}.{pkg}"
            if "deny" in val or "warn" in val:
                for kind, default in (("deny", Severity.HIGH), ("warn", Severity.LOW)):
                    for item in val.get(kind) or []:
                        out.append(_pack_item(name, item, default, self.backend.name))
            else:
                out += self._pack_findings(val, name)
        return out


def _pack_item(pkg: str, item: Any, default: Severity, backend: str) -> Finding:
    if isinstance(item, str):
        return Finding(rule_id=pkg, severity=default, message=item, engine=f"rego/{backend}")
    if not isinstance(item, Mapping):
        raise EngineError(f"{pkg}: deny/warn elements must be strings or objects")
    try:
        sev = Severity.parse(item.get("severity", default.name))
    except ValueError as e:
        raise EngineError(f"{pkg}: {e}") from None
    return Finding(rule_id=str(item.get("id") or pkg), severity=sev,
                   message=str(item.get("msg") or item.get("message") or pkg),
                   engine=f"rego/{backend}", fix_hint=str(item.get("fix_hint", "")),
                   resource=str(item.get("resource", "")))
