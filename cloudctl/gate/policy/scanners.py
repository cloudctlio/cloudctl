"""Baseline IaC scanners as gate engines.

Each adapter runs an industry-standard scanner as a subprocess (no shell,
minimal environment, no cloud credentials: these are static scans) and maps
its findings into the gate's contract.

==========  ===============  ========================================================
Engine      Licence          Covers
==========  ===============  ========================================================
trivy       Apache-2.0       Terraform/OpenTofu, CloudFormation/CDK templates,
                             ARM JSON, Kubernetes manifests — AWS, Azure, GCP checks
checkov     Apache-2.0       Terraform/OpenTofu plan JSON, CloudFormation/CDK,
                             ARM, Bicep, Kubernetes — AWS, Azure, GCP checks
cfn_guard   Apache-2.0       CloudFormation / CDK templates (AWS only)
kyverno     Apache-2.0       Kubernetes manifests (EKS, AKS, GKE)
==========  ===============  ========================================================

Fail closed: if an enabled scanner is missing, the wrong version, times out,
exits with an error code, or prints output the adapter cannot read, the
adapter raises :class:`EngineError` and the gate rejects the change.

Pin each scanner in the config (``version:``). Production configs should pin;
an unpinned scanner is accepted only outside production (see gate config
validation).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess  # noqa: S404 — fixed argv, never a shell
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence

import yaml

from cloudctl.gate.models import EngineError, Finding, Severity
from cloudctl.gate.plan.base import tool_version_matches
from cloudctl.gate.policy.engine import PolicyContext

DEFAULT_TIMEOUT = 600
_SAFE_ENV_KEYS = ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                  "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy")
# Windows programs (Python-based scanners above all) fail to start without these.
# None of them carries a credential.
_WINDOWS_ENV_KEYS = ("SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "TEMP", "TMP",
                     "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA")


def scanner_env(extra: Optional[Mapping[str, str]] = None) -> dict[str, str]:
    """A minimal environment: no cloud credentials, nothing inherited beyond
    what a static scanner needs to find itself, its cache and a proxy."""
    keys = _SAFE_ENV_KEYS + (_WINDOWS_ENV_KEYS if os.name == "nt" else ())
    env = {k: os.environ[k] for k in keys if k in os.environ}
    if os.name == "nt":
        env["PYTHONUTF8"] = "1"     # scanner output is read as UTF-8, not the ANSI code page
    env.update(extra or {})
    return env


def run_scanner(argv: Sequence[str], *, what: str, timeout: int, ok_codes: Iterable[int] = (0,),
                env: Optional[Mapping[str, str]] = None, cwd: Optional[Path] = None
                ) -> subprocess.CompletedProcess:
    try:
        p = subprocess.run(  # noqa: S603 — argv list, no shell
            list(argv), cwd=str(cwd) if cwd else None, env=dict(env if env is not None else scanner_env()),
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, check=False,
        )
    except FileNotFoundError as e:
        raise EngineError(f"{what}: binary not found ({e})") from e
    except subprocess.TimeoutExpired as e:
        raise EngineError(f"{what} timed out after {timeout}s") from e
    if p.returncode not in set(ok_codes):
        tail = (p.stderr or p.stdout or "").strip()[-1500:]
        raise EngineError(f"{what} exited {p.returncode}: {tail}")
    return p


@dataclass
class CliScanner:
    """Shared plumbing: locate the binary, check its pinned version once."""

    binary: str = ""
    version: Optional[str] = None
    timeout: int = DEFAULT_TIMEOUT
    extra_args: tuple[str, ...] = ()
    _checked: bool = field(default=False, init=False, repr=False)

    name = "scanner"
    default_binary = ""
    version_args: tuple[str, ...] = ("--version",)

    def _bin(self) -> str:
        path = shutil.which(self.binary or self.default_binary)
        if not path:
            raise EngineError(f"{self.name}: `{self.binary or self.default_binary}` is not installed or "
                              "not on PATH (the engine is enabled, so the gate fails closed)")
        return path

    def _check_version(self, path: str) -> None:
        if self._checked:
            return
        if self.version:
            p = run_scanner([path, *self.version_args], what=f"{self.name} --version", timeout=60)
            found = (p.stdout + p.stderr).strip()
            if not tool_version_matches(found, self.version):
                raise EngineError(f"{self.name}: version mismatch — pinned {self.version}, found {found[:200]!r}")
        self._checked = True

    def binary_path(self) -> str:
        path = self._bin()
        self._check_version(path)
        return path


def _common(params: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if params.get("binary"):
        out["binary"] = str(params["binary"])
    if params.get("version"):
        out["version"] = str(params["version"])
    if params.get("timeout"):
        out["timeout"] = int(params["timeout"])
    extra = params.get("extra_args") or []
    if not isinstance(extra, list) or not all(isinstance(a, str) for a in extra):
        raise EngineError("extra_args must be a list of strings")
    out["extra_args"] = tuple(extra)
    return out


def _sev(value: Any, default: Severity) -> Severity:
    if value in (None, "", "UNKNOWN", "unknown"):
        return default
    try:
        return Severity.parse(str(value))
    except ValueError:
        return default


def _load_json(text: str, what: str) -> Any:
    text = (text or "").strip()
    if not text:
        raise EngineError(f"{what} printed no output")
    try:
        return json.loads(text)
    except ValueError:
        # some scanners print a banner line before the JSON document
        start = min([i for i in (text.find("{"), text.find("[")) if i >= 0], default=-1)
        if start > 0:
            try:
                return json.loads(text[start:])
            except ValueError:
                pass
        raise EngineError(f"{what} printed output that is not JSON: {text[:300]!r}") from None


def _art(ctx: PolicyContext, key: str) -> Optional[Path]:
    v = ctx.plan.artifacts.get(key)
    return Path(v) if v else None


def _templates(ctx: PolicyContext) -> list[Path]:
    return [Path(v) for k, v in sorted(ctx.plan.artifacts.items()) if k.startswith("template:")]


# ── Trivy ────────────────────────────────────────────────────────────────────

@dataclass
class TrivyEngine(CliScanner):
    """``trivy config`` over the IaC source. Trivy no longer reads Terraform
    plan JSON, so Terraform/OpenTofu are scanned from the root module."""

    skip_check_update: bool = False
    checks_bundle_repository: Optional[str] = None

    name = "trivy"
    default_binary = "trivy"
    PLATFORMS = {"terraform", "opentofu", "cloudformation", "cdk", "arm", "bicep", "kubernetes"}

    @classmethod
    def from_params(cls, params: Mapping[str, Any]) -> "TrivyEngine":
        return cls(**_common(params), skip_check_update=bool(params.get("skip_check_update", False)),
                   checks_bundle_repository=params.get("checks_bundle_repository"))

    def targets(self, ctx: PolicyContext) -> list[Path]:
        p = ctx.plan.platform
        if p in ("terraform", "opentofu", "kubernetes"):
            root = _art(ctx, "iac_root") or _art(ctx, "k8s_manifests")
            return [root] if root else []
        if p in ("cloudformation", "cdk"):
            return _templates(ctx)
        if p in ("arm", "bicep"):
            t = _art(ctx, "arm_template_json")
            return [t] if t else []
        return []

    def applies_to(self, ctx: PolicyContext) -> bool:
        return ctx.plan.platform in self.PLATFORMS and bool(self.targets(ctx))

    def evaluate(self, ctx: PolicyContext) -> list[Finding]:
        exe = self.binary_path()
        out: list[Finding] = []
        for target in self.targets(ctx):
            argv = [exe, "config", "--format", "json", "--quiet", "--exit-code", "0"]
            if self.skip_check_update:
                argv.append("--skip-check-update")
            if self.checks_bundle_repository:
                argv += ["--checks-bundle-repository", self.checks_bundle_repository]
            argv += [*self.extra_args, str(target)]
            p = run_scanner(argv, what="trivy config", timeout=self.timeout)
            out += parse_trivy(_load_json(p.stdout, "trivy"))
        return out


def parse_trivy(doc: Any) -> list[Finding]:
    if not isinstance(doc, Mapping):
        raise EngineError("trivy: report is not an object")
    findings = []
    for result in doc.get("Results") or []:
        for m in result.get("Misconfigurations") or []:
            if str(m.get("Status", "FAIL")).upper() != "FAIL":
                continue
            cause = m.get("CauseMetadata") or {}
            resource = cause.get("Resource") or result.get("Target") or ""
            refs = tuple(str(r) for r in (m.get("References") or [])[:5])
            if m.get("PrimaryURL") and m["PrimaryURL"] not in refs:
                refs = (str(m["PrimaryURL"]),) + refs
            findings.append(Finding(
                rule_id=str(m.get("AVDID") or m.get("ID") or "TRIVY"),
                severity=_sev(m.get("Severity"), Severity.MEDIUM),
                message=str(m.get("Message") or m.get("Title") or m.get("Description") or ""),
                engine="trivy", fix_hint=str(m.get("Resolution") or ""), resource=str(resource),
                references=refs,
            ))
    return findings


# ── Checkov ──────────────────────────────────────────────────────────────────

@dataclass
class CheckovEngine(CliScanner):
    """Checkov over the Terraform/OpenTofu plan JSON (so it sees resolved
    values), CloudFormation/CDK templates, ARM JSON, Bicep and Kubernetes.

    Checkov's open-source checks carry no severity, so ``default_severity``
    (MEDIUM unless configured) applies, and ``severity_map`` sets per-check
    severities (e.g. ``CKV_AWS_24: HIGH``)."""

    default_severity: Severity = Severity.MEDIUM
    severity_map: Mapping[str, Severity] = field(default_factory=dict)
    offline: bool = True

    name = "checkov"
    default_binary = "checkov"
    PLATFORMS = {"terraform", "opentofu", "cloudformation", "cdk", "arm", "bicep", "kubernetes"}

    @classmethod
    def from_params(cls, params: Mapping[str, Any]) -> "CheckovEngine":
        raw = params.get("severity_map") or {}
        if not isinstance(raw, Mapping):
            raise EngineError("checkov.severity_map must be a mapping of check id to severity")
        try:
            smap = {str(k): Severity.parse(str(v)) for k, v in raw.items()}
            dflt = Severity.parse(str(params.get("default_severity", "MEDIUM")))
        except ValueError as e:
            raise EngineError(f"checkov: {e}") from None
        return cls(**_common(params), default_severity=dflt, severity_map=smap,
                   offline=bool(params.get("offline", True)))

    def jobs(self, ctx: PolicyContext) -> list[tuple[str, str, Path]]:
        """(framework, -f|-d, path) to scan."""
        p = ctx.plan.platform
        if p in ("terraform", "opentofu"):
            j = _art(ctx, "terraform_plan_json")
            return [("terraform_plan", "-f", j)] if j else []
        if p in ("cloudformation", "cdk"):
            return [("cloudformation", "-f", t) for t in _templates(ctx)]
        if p == "arm":
            j = _art(ctx, "arm_template_json")
            return [("arm", "-f", j)] if j else []
        if p == "bicep":
            src = Path(ctx.plan.source) if ctx.plan.source.endswith(".bicep") else None
            if src and src.is_file():
                return [("bicep", "-f", src)]
            j = _art(ctx, "arm_template_json")
            return [("arm", "-f", j)] if j else []
        if p == "kubernetes":
            d = _art(ctx, "k8s_manifests")
            return [("kubernetes", "-d", d)] if d else []
        return []

    def applies_to(self, ctx: PolicyContext) -> bool:
        return ctx.plan.platform in self.PLATFORMS and bool(self.jobs(ctx))

    def evaluate(self, ctx: PolicyContext) -> list[Finding]:
        exe = self.binary_path()
        out: list[Finding] = []
        for framework, flag, path in self.jobs(ctx):
            argv = [exe, flag, str(path), "--framework", framework, "-o", "json", "--quiet",
                    "--compact", "--soft-fail"]
            if self.offline:
                argv.append("--skip-download")
            argv += list(self.extra_args)
            p = run_scanner(argv, what=f"checkov ({framework})", timeout=self.timeout,
                            env=scanner_env({"BC_SKIP_MAPPING": "TRUE"} if self.offline else None))
            out += parse_checkov(_load_json(p.stdout, "checkov"), default=self.default_severity,
                                 severity_map=self.severity_map)
        return out


def parse_checkov(doc: Any, *, default: Severity = Severity.MEDIUM,
                  severity_map: Mapping[str, Severity] = {}) -> list[Finding]:
    reports = doc if isinstance(doc, list) else [doc]
    findings = []
    for rep in reports:
        if not isinstance(rep, Mapping):
            raise EngineError("checkov: report is not an object")
        results = rep.get("results")
        if results is None:
            # summary-only output means nothing was scanned or nothing failed
            if "summary" in rep or {"passed", "failed"} <= set(rep):
                continue
            raise EngineError("checkov: report has no results section")
        for c in results.get("failed_checks") or []:
            cid = str(c.get("check_id") or "CHECKOV")
            sev = severity_map.get(cid) or _sev(c.get("severity"), default)
            refs = (str(c["guideline"]),) if c.get("guideline") else ()
            findings.append(Finding(
                rule_id=cid, severity=sev, message=str(c.get("check_name") or cid), engine="checkov",
                fix_hint=str(c.get("guideline") or ""), resource=str(c.get("resource") or ""),
                references=refs,
            ))
    return findings


# ── cfn-guard (AWS only) ─────────────────────────────────────────────────────

@dataclass
class CfnGuardEngine(CliScanner):
    """AWS CloudFormation Guard over CloudFormation / CDK templates. Rules
    are a directory of ``.guard`` files (for example the AWS Guard Rules
    Registry). Guard rules carry no severity; ``severity_map`` and
    ``default_severity`` set it. AWS only, by design: it is one plug-in among
    the multi-cloud engines, not the baseline."""

    rules: Optional[Path] = None
    default_severity: Severity = Severity.MEDIUM
    severity_map: Mapping[str, Severity] = field(default_factory=dict)

    name = "cfn_guard"
    default_binary = "cfn-guard"

    @classmethod
    def from_params(cls, params: Mapping[str, Any]) -> "CfnGuardEngine":
        if not params.get("rules"):
            raise EngineError("cfn_guard needs `rules:` (a .guard file or directory)")
        rules = Path(str(params["rules"])).expanduser()
        try:
            smap = {str(k): Severity.parse(str(v)) for k, v in (params.get("severity_map") or {}).items()}
            dflt = Severity.parse(str(params.get("default_severity", "MEDIUM")))
        except ValueError as e:
            raise EngineError(f"cfn_guard: {e}") from None
        return cls(**_common(params), rules=rules, default_severity=dflt, severity_map=smap)

    def applies_to(self, ctx: PolicyContext) -> bool:
        return ctx.plan.platform in ("cloudformation", "cdk") and bool(_templates(ctx))

    def evaluate(self, ctx: PolicyContext) -> list[Finding]:
        exe = self.binary_path()
        assert self.rules is not None  # noqa: S101 — set by from_params
        if not self.rules.exists():
            raise EngineError(f"cfn_guard: rules path {self.rules} does not exist")
        out: list[Finding] = []
        for t in _templates(ctx):
            argv = [exe, "validate", "--data", str(t), "--rules", str(self.rules),
                    "--output-format", "json", "--show-summary", "none", *self.extra_args]
            # 0 = compliant, 19 = non-compliant; anything else is an error
            p = run_scanner(argv, what="cfn-guard validate", timeout=self.timeout, ok_codes=(0, 19))
            if p.returncode == 0 and not p.stdout.strip():
                continue
            out += parse_cfn_guard(p.stdout, default=self.default_severity, severity_map=self.severity_map)
        return out


def _guard_messages(node: Any, msgs: list[str], paths: list[str]) -> None:
    if isinstance(node, Mapping):
        for k, v in node.items():
            if k in ("custom_message", "error_message") and isinstance(v, str) and v.strip():
                msgs.append(v.strip())
            elif k == "path" and isinstance(v, str) and v.startswith("/Resources/"):
                paths.append(v)
            else:
                _guard_messages(v, msgs, paths)
    elif isinstance(node, list):
        for v in node:
            _guard_messages(v, msgs, paths)


def parse_cfn_guard(text: str, *, default: Severity = Severity.MEDIUM,
                    severity_map: Mapping[str, Severity] = {}) -> list[Finding]:
    docs: list[Any] = []
    text = (text or "").strip()
    if not text:
        raise EngineError("cfn-guard reported non-compliance but printed no report")
    try:
        loaded = json.loads(text)
        docs = loaded if isinstance(loaded, list) else [loaded]
    except ValueError:
        # one JSON document per data file, concatenated
        dec = json.JSONDecoder()
        i = 0
        while i < len(text):
            while i < len(text) and text[i].isspace():
                i += 1
            if i >= len(text):
                break
            try:
                obj, i = dec.raw_decode(text, i)
            except ValueError as e:
                raise EngineError(f"cfn-guard output is not JSON: {text[:300]!r}") from e
            docs.append(obj)
    findings = []
    for d in docs:
        if not isinstance(d, Mapping):
            raise EngineError("cfn-guard: report is not an object")
        for nc in d.get("not_compliant") or []:
            rule = nc.get("Rule") if isinstance(nc, Mapping) else None
            rule = rule or nc
            name = str(rule.get("name") or "GUARD") if isinstance(rule, Mapping) else "GUARD"
            msgs: list[str] = []
            paths: list[str] = []
            _guard_messages(rule, msgs, paths)
            resources = sorted({p.split("/")[2] for p in paths if len(p.split("/")) > 2}) or [""]
            for res in resources:
                findings.append(Finding(
                    rule_id=name, severity=severity_map.get(name, default),
                    message=(msgs[0] if msgs else f"Guard rule {name} failed"), engine="cfn_guard",
                    resource=res,
                ))
    return findings


# ── Kyverno (Kubernetes) ─────────────────────────────────────────────────────

@dataclass
class KyvernoEngine(CliScanner):
    """``kyverno apply`` of Kyverno policies against the manifests the
    Kubernetes plan would apply, read back as a PolicyReport. Same checks on
    EKS, AKS and GKE."""

    policies: Optional[Path] = None
    default_severity: Severity = Severity.MEDIUM

    name = "kyverno"
    default_binary = "kyverno"
    version_args = ("version",)

    @classmethod
    def from_params(cls, params: Mapping[str, Any]) -> "KyvernoEngine":
        if not params.get("policies"):
            raise EngineError("kyverno needs `policies:` (a policy file or directory)")
        try:
            dflt = Severity.parse(str(params.get("default_severity", "MEDIUM")))
        except ValueError as e:
            raise EngineError(f"kyverno: {e}") from None
        return cls(**_common(params), policies=Path(str(params["policies"])).expanduser(),
                   default_severity=dflt)

    def applies_to(self, ctx: PolicyContext) -> bool:
        return ctx.plan.platform == "kubernetes" and _art(ctx, "k8s_manifests") is not None

    def evaluate(self, ctx: PolicyContext) -> list[Finding]:
        exe = self.binary_path()
        assert self.policies is not None  # noqa: S101 — set by from_params
        if not self.policies.exists():
            raise EngineError(f"kyverno: policies path {self.policies} does not exist")
        manifests = _art(ctx, "k8s_manifests")
        argv = [exe, "apply", str(self.policies), "--resource", str(manifests), "--policy-report",
                "--output-format", "json", *self.extra_args]
        # kyverno exits non-zero when policies fail; the report decides, and
        # unreadable output still fails closed in parse_kyverno.
        p = run_scanner(argv, what="kyverno apply", timeout=self.timeout, ok_codes=(0, 1))
        return parse_kyverno(p.stdout, default=self.default_severity)


def parse_kyverno(text: str, *, default: Severity = Severity.MEDIUM) -> list[Finding]:
    text = (text or "").strip()
    if not text:
        raise EngineError("kyverno printed no policy report")
    start = min([i for i in (text.find("{"), text.find("apiVersion")) if i >= 0], default=0)
    try:
        docs = [d for d in yaml.safe_load_all(text[start:]) if d is not None]
    except yaml.YAMLError as e:
        raise EngineError(f"kyverno output is not a policy report: {text[:300]!r}") from e
    reports = []
    for d in docs:
        if isinstance(d, Mapping) and d.get("kind") in ("List",) and isinstance(d.get("items"), list):
            reports += d["items"]
        else:
            reports.append(d)
    if not reports or not all(isinstance(r, Mapping) and "results" in r for r in reports):
        raise EngineError("kyverno: no PolicyReport results in the output")
    findings = []
    for rep in reports:
        for r in rep.get("results") or []:
            if str(r.get("result", "")).lower() not in ("fail", "error"):
                continue
            res = r.get("resources") or [{}]
            for obj in res:
                ident = "/".join(x for x in (obj.get("kind"), obj.get("namespace"), obj.get("name")) if x)
                sev = Severity.HIGH if str(r.get("result")).lower() == "error" else _sev(r.get("severity"), default)
                findings.append(Finding(
                    rule_id=f"{r.get('policy', 'kyverno')}/{r.get('rule', '')}".rstrip("/"),
                    severity=sev, message=str(r.get("message") or ""), engine="kyverno", resource=ident,
                ))
    return findings
