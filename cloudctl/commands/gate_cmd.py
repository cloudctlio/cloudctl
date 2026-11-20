"""cctl gate — the policy gate every cloud change goes through.

    cloudctl gate init        write a starter control-plane config
    cloudctl gate validate    check the config (prod rules included)
    cloudctl gate engines     which policy engines are on, pinned and installed
    cloudctl gate policy eval run the policy engines on a Terraform plan JSON (CI)
    cloudctl gate keygen      make an approver's Ed25519 signing key
    cloudctl gate approvals   list approval requests waiting for a signature
    cloudctl gate approve     sign one approval request
    cloudctl gate audit verify  check the audit hash chain end to end
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
from pathlib import Path
from typing import Any, Optional

import typer
from rich.console import Console
from rich.table import Table

app = typer.Typer(help="Policy gate: config, policy engines, signed approvals and the audit chain.",
                  no_args_is_help=True)
approvals_app = typer.Typer(help="Approval requests.", no_args_is_help=True)
audit_app = typer.Typer(help="The hash-chained audit log.", no_args_is_help=True)
policy_app = typer.Typer(help="Run the policy engines without changing anything.", no_args_is_help=True)
app.add_typer(approvals_app, name="approvals")
app.add_typer(audit_app, name="audit")
app.add_typer(policy_app, name="policy")

console = Console()

_CONFIG_OPT = typer.Option(None, "--config", help="Config path (default: $CLOUDCTL_GATE_CONFIG or "
                                                   "~/.cloudctl/controlplane.yaml).")


def _load(path: Optional[str]) -> Any:
    from cloudctl.gate.config import load_config  # noqa: PLC0415
    from cloudctl.gate.models import ConfigError  # noqa: PLC0415
    try:
        return load_config(path)
    except ConfigError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from None


# ── init / validate ──────────────────────────────────────────────────────────

def _starter(cloud: str, scope: dict[str, str], creds: dict[str, str], name: str, iac_root: Optional[str],
             profile: Optional[str]) -> dict[str, Any]:
    match: dict[str, Any] = {}
    if profile:
        match["profiles"] = [profile]
    if iac_root:
        match["iac_roots"] = [str(Path(iac_root).expanduser().resolve())]
    env: dict[str, Any] = {"tier": "dev", "cloud": cloud, cloud: scope, "credentials": creds,
                           "approval": {"threshold": 0}, "cost": {"max_monthly_increase_usd": 100}}
    if match:
        env["match"] = match
    return {"version": 1, "audit": {"chain": "cctl"}, "environments": {name: env}}


_PROD_HINT = """\
# A prod environment needs, and `cloudctl gate validate` enforces:
#   - short-lived federated credentials (aws assume_role, azure workload_identity or
#     managed_identity, gcp impersonation);
#   - an immutable audit sink, for example
#       audit: {chain: cctl, sink: {type: s3, bucket: my-audit, region: us-east-1, retain_days: 400}}
#     (azure_blob with account_url/container, or gcs with bucket, also work);
#   - at least one named approver with a public key from `cloudctl gate keygen`;
#   - a pinned baseline scanner, for example
#       policy: {engines: {checkov: {enabled: true, version: "3.4.6"}}}
"""


@app.command("init")
def init(
    cloud: str = typer.Option(..., "--cloud", help="aws, azure or gcp."),
    name: str = typer.Option("dev", "--name", help="Environment name."),
    account_id: Optional[str] = typer.Option(None, "--account-id", help="AWS account id."),
    region: Optional[str] = typer.Option(None, "--region", help="AWS or GCP region."),
    profile: Optional[str] = typer.Option(None, "--profile", help="AWS profile (dev tier only)."),
    tenant_id: Optional[str] = typer.Option(None, "--tenant-id", help="Azure tenant id."),
    subscription_id: Optional[str] = typer.Option(None, "--subscription-id", help="Azure subscription id."),
    resource_group: Optional[str] = typer.Option(None, "--resource-group", help="Azure resource group."),
    project_id: Optional[str] = typer.Option(None, "--project-id", help="GCP project id."),
    iac_root: Optional[str] = typer.Option(None, "--iac-root", help="IaC directory this environment owns."),
    path: Optional[str] = _CONFIG_OPT,
    force: bool = typer.Option(False, "--force", help="Overwrite an existing config."),
) -> None:
    """Write a starter config with one dev-tier environment. Edit it to add
    staging and prod; `validate` tells you what prod still needs."""
    import yaml  # noqa: PLC0415

    from cloudctl.gate.config import config_path, parse_config  # noqa: PLC0415
    from cloudctl.gate.models import ConfigError  # noqa: PLC0415

    if cloud == "aws":
        if not (account_id and region and profile):
            raise typer.BadParameter("--cloud aws needs --account-id, --region and --profile")
        scope, creds = {"account_id": account_id, "region": region}, {"mode": "profile", "profile": profile}
    elif cloud == "azure":
        if not (tenant_id and subscription_id and resource_group):
            raise typer.BadParameter("--cloud azure needs --tenant-id, --subscription-id and --resource-group")
        scope = {"tenant_id": tenant_id, "subscription_id": subscription_id, "resource_group": resource_group}
        creds = {"mode": "cli"}
    elif cloud == "gcp":
        if not project_id:
            raise typer.BadParameter("--cloud gcp needs --project-id")
        scope = {"project_id": project_id, **({"region": region} if region else {})}
        creds = {"mode": "adc"}
    else:
        raise typer.BadParameter("--cloud must be aws, azure or gcp")

    doc = _starter(cloud, scope, creds, name, iac_root, profile if cloud == "aws" else None)
    try:
        parse_config(doc)
    except ConfigError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from None
    target = Path(path).expanduser() if path else config_path()
    if target.exists() and not force:
        console.print(f"[red]{target} already exists; pass --force to overwrite.[/red]")
        raise typer.Exit(1)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    text = "# cctl control-plane config. Every cloud change goes through this gate.\n" + _PROD_HINT + \
        yaml.safe_dump(doc, sort_keys=False)
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    console.print(f"[green]Wrote {target}[/green] with dev environment {name!r} ({cloud}).")


@app.command("validate")
def validate(path: Optional[str] = _CONFIG_OPT) -> None:
    """Validate the config. Exit 1 on any problem."""
    from cloudctl.gate.config import BASELINE_SCANNERS, engine_enabled  # noqa: PLC0415

    cfg = _load(path)
    t = Table(title=f"Environments ({cfg.source})")
    for col in ("name", "tier", "cloud", "scope", "credentials", "approval"):
        t.add_column(col)
    for e in cfg.environments.values():
        appr = ("always" if e.approval.always else f"> {e.approval.threshold} resources") + \
            (f" by {', '.join(e.approval.approvers)}" if e.approval.approvers else " (no approvers)")
        t.add_row(e.name, e.tier, e.cloud, ", ".join(f"{k}={v}" for k, v in e.scope.items()),
                  e.credentials.mode, appr)
    console.print(t)
    sink = cfg.audit.sink
    console.print(f"Audit: chain {cfg.audit.chain!r} -> "
                  + (f"{sink['type']} (immutable)" if sink else f"local file {cfg.audit.local_path} (tamper-evident only)"))
    if not any(engine_enabled(cfg.policy, n) for n in BASELINE_SCANNERS):
        console.print("[yellow]No baseline scanner (trivy or checkov) is enabled; prod environments need one.[/yellow]")
    console.print("[green]Config is valid.[/green]")


# ── engines ──────────────────────────────────────────────────────────────────

_BINARIES = {"trivy": "trivy", "checkov": "checkov", "cfn_guard": "cfn-guard", "kyverno": "kyverno",
             "infracost": "infracost"}
_MODULES = {"rego": "regopy", "aws_native": "boto3", "azure_native": "azure.mgmt.policyinsights",
            "gcp_native": "googleapiclient"}


def _installed(name: str) -> str:
    if name in _BINARIES:
        return "yes" if shutil.which(_BINARIES[name]) else "no (binary not on PATH)"
    mod = _MODULES.get(name)
    if name == "rego" and shutil.which("opa"):
        return "yes (opa)"
    try:
        found = bool(mod and importlib.util.find_spec(mod))
    except ModuleNotFoundError:
        found = False
    return "yes" if found else f"no (pip install {mod.split('.')[0]})"


@app.command("engines")
def engines(path: Optional[str] = _CONFIG_OPT) -> None:
    """List policy engines: enabled, version pin, installed, licence."""
    from cloudctl.gate.config import ENGINE_NAMES, engine_enabled  # noqa: PLC0415
    from cloudctl.gate.policy import ENGINE_LICENCES  # noqa: PLC0415

    cfg = _load(path)
    t = Table(title="Policy engines")
    for col in ("engine", "enabled", "version pin", "installed", "licence"):
        t.add_column(col)
    for n in ENGINE_NAMES:
        e = cfg.policy.engines.get(n)
        pin = str(e.params.get("version", "")) if e else ""
        t.add_row(n, "yes" if engine_enabled(cfg.policy, n) else "no", pin or "-", _installed(n),
                  ENGINE_LICENCES.get(n, ""))
    console.print(t)


# ── policy eval (offline, for CI) ────────────────────────────────────────────

@policy_app.command("eval")
def policy_eval(
    plan_json: str = typer.Argument(..., help="Output of `terraform show -json <planfile>` (or tofu)."),
    env_name: str = typer.Option(..., "--env", help="Environment the plan is for."),
    platform: str = typer.Option("terraform", "--platform", help="terraform or opentofu."),
    json_out: bool = typer.Option(False, "--json", help="Print the result as JSON."),
    path: Optional[str] = _CONFIG_OPT,
) -> None:
    """Run the policy engines on a plan file, with no cloud credentials.

    Engines that need the change's scoped credentials (the native AWS, Azure
    and GCP checks) are skipped and named; the gate runs them at apply time.
    Exit 2 when any HIGH/CRITICAL finding would reject the change."""
    from cloudctl.gate.gate import default_requester  # noqa: PLC0415
    from cloudctl.gate.models import ChangeRequest, EngineError, GateError, Plan  # noqa: PLC0415
    from cloudctl.gate.plan.terraform import parse_show_json  # noqa: PLC0415
    from cloudctl.gate.policy import build_policy  # noqa: PLC0415
    from cloudctl.gate.policy.engine import PolicyContext, evaluate_policy  # noqa: PLC0415

    cfg = _load(path)
    try:
        env = cfg.environment(env_name)
        doc = json.loads(Path(plan_json).read_text(encoding="utf-8"))
        plan = parse_show_json(doc, environment=env.name, source=plan_json, platform=platform)
        plan = Plan(platform=plan.platform, environment=plan.environment, changes=plan.changes,
                    source=plan.source, metadata=plan.metadata,
                    artifacts={"terraform_plan_json": str(Path(plan_json).resolve())})
        enrichers, engs = build_policy(cfg)
        skipped = [e.name for e in engs if e.name.endswith("_native")]
        engs = [e for e in engs if not e.name.endswith("_native")]
        req = ChangeRequest(kind="iac_pr", environment=env.name, summary=f"policy eval {plan_json}",
                            requester=default_requester())
        result = evaluate_policy(PolicyContext(plan=plan, env=env, request=req), enrichers=enrichers,
                                 engines=engs, severity_overrides=cfg.policy.severity_overrides,
                                 disabled_rules=env.disabled_rules)
    except (OSError, ValueError) as e:
        console.print(f"[red]Cannot read {plan_json}: {e}[/red]")
        raise typer.Exit(1) from None
    except EngineError as e:
        console.print(f"[red]Policy engine failed (fail closed): {e}[/red]")
        raise typer.Exit(1) from None
    except GateError as e:
        console.print(f"[red]{e}[/red]")
        raise typer.Exit(1) from None

    blocking = result.blocking
    if json_out:
        console.print_json(json.dumps({
            "environment": env.name, "counts": plan.to_dict()["counts"],
            "findings": [f.to_dict() for f in result.findings],
            "engines": [{"engine": r.engine, "ran": r.ran, "findings": r.findings, "detail": r.detail}
                        for r in result.runs],
            "skipped_need_credentials": skipped, "rejected": bool(blocking)}))
    else:
        c = plan.to_dict()["counts"]
        console.print(f"Plan for {env.name}: +{c['add']} ~{c['modify']} -{c['destroy']}")
        for r in result.runs:
            console.print(f"  engine {r.engine}: {'ran' if r.ran else 'skipped'}"
                          + (f", {r.findings} finding(s)" if r.ran else f" ({r.detail})"))
        for n in skipped:
            console.print(f"  engine {n}: skipped (needs the change's scoped credentials; runs at apply time)")
        for f in result.findings:
            colour = "red" if f.severity.blocking else "yellow"
            console.print(f"[{colour}][{f.severity.name}][/{colour}] {f.rule_id} {f.resource}: {f.message}"
                          + (f"\n    fix: {f.fix_hint}" if f.fix_hint else ""))
        console.print("[red]Rejected: HIGH/CRITICAL findings.[/red]" if blocking
                      else "[green]No HIGH/CRITICAL findings.[/green]")
    if blocking:
        raise typer.Exit(2)


# ── keys and approvals ───────────────────────────────────────────────────────

def _default_key(approver: str) -> Path:
    return Path.home() / ".cloudctl" / "keys" / f"{approver}.ed25519.pem"


def _passphrase(prompt: bool, confirm: bool = False) -> Optional[bytes]:
    env = os.environ.get("CLOUDCTL_APPROVER_PASSPHRASE")
    if env:
        return env.encode()
    if not prompt:
        return None
    return typer.prompt("Key passphrase", hide_input=True, confirmation_prompt=confirm).encode()


@app.command("keygen")
def keygen(
    approver: str = typer.Option(..., "--approver", help="Approver name, as used in the config."),
    out: Optional[str] = typer.Option(None, "--out", help="Private key path (default ~/.cloudctl/keys/<name>.ed25519.pem)."),
    no_passphrase: bool = typer.Option(False, "--no-passphrase", help="Store the key unencrypted (not advised)."),
) -> None:
    """Make an Ed25519 key pair. The private key never leaves this machine;
    put the printed public key in the config under `approvers`."""
    from cloudctl.gate.approval import generate_keypair, write_private_key  # noqa: PLC0415

    target = Path(out).expanduser() if out else _default_key(approver)
    if target.exists():
        console.print(f"[red]{target} already exists; refusing to overwrite a signing key.[/red]")
        raise typer.Exit(1)
    pem, pub = generate_keypair(None if no_passphrase else _passphrase(True, confirm=True))
    write_private_key(target, pem)
    console.print(f"[green]Private key written to {target} (mode 600).[/green]")
    console.print("Add this to the control-plane config:\n")
    console.print(f"approvers:\n  {approver}: {{public_key: \"{pub}\"}}", markup=False)


@approvals_app.command("list")
def approvals_list(path: Optional[str] = _CONFIG_OPT) -> None:
    """Approval requests waiting for a signature."""
    from cloudctl.gate.approval import LocalApprovalStore  # noqa: PLC0415

    cfg = _load(path)
    rows = list(LocalApprovalStore(cfg.approvals_dir).pending())
    if not rows:
        console.print("No approval requests are waiting.")
        return
    t = Table(title="Waiting for approval")
    for col in ("id", "environment", "requester", "changes", "max severity", "expires", "summary"):
        t.add_column(col)
    for r in rows:
        c = r.counts
        t.add_row(r.request_id, r.environment, r.requester,
                  f"+{c.get('add', 0)} ~{c.get('modify', 0)} -{c.get('destroy', 0)}", r.max_severity,
                  r.expires_at + (" (expired)" if r.expired() else ""), r.summary[:80])
    console.print(t)


@app.command("approve")
def approve(
    request_id: str = typer.Argument(..., help="Approval request id the gate printed."),
    approver: str = typer.Option(..., "--approver", help="Your approver name."),
    key: Optional[str] = typer.Option(None, "--key", help="Private key path."),
    yes: bool = typer.Option(False, "--yes", help="Sign without the confirmation prompt."),
    path: Optional[str] = _CONFIG_OPT,
) -> None:
    """Show an approval request, check you may approve it, and sign it."""
    from cloudctl.gate.approval import (  # noqa: PLC0415
        LocalApprovalStore, authorize_approval, load_private_key, public_key_b64, sign,
    )
    from cloudctl.gate.gate import build_audit_log  # noqa: PLC0415
    from cloudctl.gate.models import ApprovalError, AuditError  # noqa: PLC0415

    cfg = _load(path)
    store = LocalApprovalStore(cfg.approvals_dir)
    try:
        req = store.get_request(request_id)
        if store.get_approval(request_id) is not None or store.is_consumed(request_id):
            raise ApprovalError(f"request {request_id} is already approved or used")
        env = cfg.environment(req.environment)
        if approver not in env.approval.approvers:
            raise ApprovalError(f"{approver!r} is not a named approver for {env.name!r}")
        approver_envs = [n for n, e in cfg.environments.items() if approver in e.approval.approvers]
        authorize_approval(approver=approver, approver_environments=approver_envs, environment=env.name,
                           tier=env.tier, requester=req.requester, max_severity=req.max_severity, counts=req.counts,
                           expired=req.expired())
    except ApprovalError as e:
        console.print(f"[red]Cannot approve: {e}[/red]")
        raise typer.Exit(1) from None
    key_path = Path(key).expanduser() if key else _default_key(approver)
    try:
        priv = load_private_key(key_path, _passphrase(False))
    except ApprovalError as e:
        encrypted = key_path.is_file() and b"ENCRYPTED" in key_path.read_bytes()[:64]
        if not encrypted or os.environ.get("CLOUDCTL_APPROVER_PASSPHRASE"):
            console.print(f"[red]Cannot approve: {e}[/red]")
            raise typer.Exit(1) from None
        try:
            priv = load_private_key(key_path, _passphrase(True))
        except ApprovalError as e2:
            console.print(f"[red]Cannot approve: {e2}[/red]")
            raise typer.Exit(1) from None
    if public_key_b64(priv) != cfg.approvers.get(approver):
        console.print(f"[red]Cannot approve: this key is not the public key configured for {approver!r}.[/red]")
        raise typer.Exit(1)

    c = req.counts
    console.print(f"[bold]Request {req.request_id}[/bold] in {req.environment} ({req.tier})\n"
                  f"  requested by {req.requester} at {req.created_at}, expires {req.expires_at}\n"
                  f"  plan {req.plan_digest[:16]}…: +{c.get('add', 0)} ~{c.get('modify', 0)} "
                  f"-{c.get('destroy', 0)}, highest finding {req.max_severity}\n"
                  f"  {req.summary}")
    for r in req.reasons:
        console.print(f"  - {r}")
    if not yes and not typer.confirm("Sign this approval?", default=False):
        console.print("Not signed.")
        raise typer.Exit(1)
    signed = sign(req, approver, priv)
    try:
        build_audit_log(cfg, actor=approver).append(
            "approval.signed", {"request_id": req.request_id, "approver": approver,
                                "environment": req.environment, "plan_digest": req.plan_digest})
        store.put_approval(signed)
    except (AuditError, ApprovalError) as e:
        console.print(f"[red]Not stored: {e}[/red]")
        raise typer.Exit(1) from None
    console.print(f"[green]Signed.[/green] The requester re-runs the same command with --approval {req.request_id}.")


# ── audit ────────────────────────────────────────────────────────────────────

@audit_app.command("verify")
def audit_verify(
    diagnosis: bool = typer.Option(False, "--diagnosis", help="Verify the read-only diagnosis audit chain."),
    path: Optional[str] = _CONFIG_OPT,
) -> None:
    """Re-hash every audit record and check the chain is unbroken."""
    if diagnosis:
        from cloudctl.ai.guardrails import _AUDIT_LOG_PATH, _audit_log  # noqa: PLC0415
        log, where = _audit_log(), str(_AUDIT_LOG_PATH)
    else:
        from cloudctl.gate.gate import build_audit_log  # noqa: PLC0415
        cfg = _load(path)
        log = build_audit_log(cfg, actor="verify")
        where = log.sink.name
    try:
        res = log.verify()
    except Exception as e:  # noqa: BLE001
        console.print(f"[red]Cannot read the audit log at {where}: {e}[/red]")
        raise typer.Exit(1) from None
    if res.ok:
        console.print(f"[green]Audit chain intact:[/green] {res.records} record(s) in {where}, "
                      f"head seq {res.head.seq}.")
        return
    console.print(f"[red]Audit chain BROKEN in {where}:[/red]")
    for e in res.errors[:50]:
        console.print(f"  {e}")
    raise typer.Exit(1)
