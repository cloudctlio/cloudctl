"""CloudFormation and CDK planner: change sets.

``cdk diff`` prints human text with no stable machine format, so the gate
uses what CDK itself deploys through: ``cdk synth`` to templates, then a
CloudFormation change set per stack, read with ``DescribeChangeSet``. A change
set changes nothing until executed; the gate deletes it after reading unless
the caller keeps it for execution (stage 2 executes the *same* change set by
ID, so what was approved is exactly what runs).
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from cloudctl.gate.models import Action, Plan, PlanError, ResourceChange
from cloudctl.gate.plan.base import find_binary, run_tool, tool_version_matches

MAX_INLINE_TEMPLATE = 51_200


def map_cfn_change(rc: Mapping[str, Any]) -> Action:
    action = rc.get("Action")
    if action == "Add":
        return Action.CREATE
    if action == "Remove":
        return Action.DELETE
    if action in ("Modify", "Dynamic"):
        # Replacement True, or Conditional (may replace): treat as replace — the
        # conservative reading, so destroy-protecting policies see it.
        return Action.REPLACE if rc.get("Replacement") in ("True", "Conditional") else Action.UPDATE
    if action == "Import":
        return Action.UPDATE
    raise PlanError(f"unknown CloudFormation change action {action!r}")


def parse_change_set(pages: Iterable[Mapping[str, Any]], *, environment: str, stack: str,
                     region: str, platform: str = "cloudformation") -> list[ResourceChange]:
    out: list[ResourceChange] = []
    for page in pages:
        status = page.get("Status")
        if status == "FAILED":
            reason = page.get("StatusReason", "")
            if "didn't contain changes" in reason or "No updates are to be performed" in reason:
                return []
            raise PlanError(f"change set for {stack} failed: {reason}")
        for ch in page.get("Changes") or []:
            rc = ch.get("ResourceChange") or {}
            logical = rc.get("LogicalResourceId", "?")
            out.append(ResourceChange(
                address=f"{stack}/{logical}", type=rc.get("ResourceType", ""),
                action=map_cfn_change(rc), cloud="aws", name=rc.get("PhysicalResourceId") or logical,
                location=region,
                before=None,
                after={"replacement": rc.get("Replacement"),
                       "scope": rc.get("Scope", []),
                       "details": [
                           {"attribute": (d.get("Target") or {}).get("Name") or (d.get("Target") or {}).get("Attribute"),
                            "requires_recreation": (d.get("Target") or {}).get("RequiresRecreation"),
                            "change_source": d.get("ChangeSource")}
                           for d in rc.get("Details") or []]},
            ))
    return out


class CloudFormationPlanner:
    platform = "cloudformation"

    def __init__(self, stacks: Mapping[str, Path | str], *, keep_change_sets: bool = False,
                 template_bucket: Optional[str] = None, capabilities: tuple[str, ...] =
                 ("CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"),
                 poll_seconds: float = 3.0, timeout: int = 600) -> None:
        """``stacks`` maps stack name → template file."""
        self.stacks = {k: Path(v) for k, v in stacks.items()}
        self.keep = keep_change_sets
        self.template_bucket = template_bucket
        self.capabilities = capabilities
        self.poll_seconds = poll_seconds
        self.timeout = timeout

    def plan(self, *, env: Any, creds: Any, workdir: Path, platform: Optional[str] = None,
             source: str = "") -> Plan:
        region = env.scope["region"]
        session = creds.client("session")
        cfn = session.client("cloudformation", region_name=region)
        all_changes: list[ResourceChange] = []
        change_sets: dict[str, str] = {}
        for stack, template in self.stacks.items():
            body = template.read_text(encoding="utf-8")
            cs_id = self._create(cfn, session, stack, body, env)
            change_sets[stack] = cs_id
            try:
                self._wait(cfn, cs_id, stack)
                pages = cfn.get_paginator("describe_change_set").paginate(ChangeSetName=cs_id)
                all_changes += parse_change_set(pages, environment=env.name, stack=stack, region=region,
                                                platform=platform or self.platform)
            finally:
                if not self.keep:
                    try:
                        cfn.delete_change_set(ChangeSetName=cs_id)
                    except Exception:  # noqa: BLE001, S110 — best effort cleanup
                        pass
        return Plan(platform=platform or self.platform, environment=env.name, changes=tuple(all_changes),
                    source=source or ",".join(self.stacks),
                    artifacts={f"template:{k}": str(v) for k, v in self.stacks.items()},
                    metadata={"change_sets": change_sets if self.keep else {}, "region": region})

    def _create(self, cfn: Any, session: Any, stack: str, body: str, env: Any) -> str:
        exists = True
        try:
            cfn.describe_stacks(StackName=stack)
        except Exception as e:  # noqa: BLE001
            if "does not exist" in str(e):
                exists = False
            else:
                raise PlanError(f"cannot describe stack {stack}: {e}") from e
        name = "cctl-" + re.sub(r"[^A-Za-z0-9-]", "-", f"{int(time.time())}")[:100]
        kwargs: dict[str, Any] = dict(StackName=stack, ChangeSetName=name,
                                      ChangeSetType="UPDATE" if exists else "CREATE",
                                      Capabilities=list(self.capabilities), IncludeNestedStacks=True)
        if len(body.encode()) > MAX_INLINE_TEMPLATE:
            if not self.template_bucket:
                raise PlanError(f"template for {stack} exceeds {MAX_INLINE_TEMPLATE} bytes; "
                                "configure a template bucket")
            key = f"cctl-templates/{stack}/{name}.json"
            s3 = session.client("s3", region_name=env.scope["region"])
            s3.put_object(Bucket=self.template_bucket, Key=key, Body=body.encode(),
                          ExpectedBucketOwner=env.scope["account_id"])
            kwargs["TemplateURL"] = f"https://{self.template_bucket}.s3.amazonaws.com/{key}"
        else:
            kwargs["TemplateBody"] = body
        try:
            return cfn.create_change_set(**kwargs)["Id"]
        except Exception as e:  # noqa: BLE001
            raise PlanError(f"create_change_set for {stack} failed: {e}") from e

    def _wait(self, cfn: Any, cs_id: str, stack: str) -> None:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            d = cfn.describe_change_set(ChangeSetName=cs_id)
            if d.get("Status") in ("CREATE_COMPLETE", "FAILED"):
                return
            time.sleep(self.poll_seconds)
        raise PlanError(f"change set for {stack} did not finish within {self.timeout}s")


class CdkPlanner:
    """``cdk synth`` then a change set per stack (works for TypeScript, Python,
    Java, Go or C# CDK apps — synth output is the same cloud assembly)."""

    platform = "cdk"

    def __init__(self, root: Path | str, *, binary_path: Optional[str] = None,
                 pinned_version: Optional[str] = None, stacks: tuple[str, ...] = (),
                 template_bucket: Optional[str] = None, timeout: int = 900,
                 keep_change_sets: bool = False) -> None:
        self.root = Path(root).expanduser().resolve()
        self.binary_path = binary_path
        self.pinned_version = pinned_version
        self.only = stacks
        self.template_bucket = template_bucket
        self.timeout = timeout
        self.keep = keep_change_sets

    def plan(self, *, env: Any, creds: Any, workdir: Path) -> Plan:
        stacks = self.synth(env=env, creds=creds, workdir=workdir)
        inner = CloudFormationPlanner(stacks, template_bucket=self.template_bucket, keep_change_sets=self.keep)
        return inner.plan(env=env, creds=creds, workdir=workdir, platform="cdk", source=str(self.root))

    def synth(self, *, env: Any, creds: Any, workdir: Path) -> dict[str, Path]:
        """``cdk synth`` into *workdir*; returns stack name → template."""
        if not (self.root / "cdk.json").is_file():
            raise PlanError(f"{self.root} has no cdk.json")
        exe = find_binary("cdk", self.binary_path)
        senv = creds.subprocess_env()
        senv["CDK_DISABLE_VERSION_CHECK"] = "1"
        senv["CDK_DEFAULT_ACCOUNT"] = env.scope["account_id"]
        senv["CDK_DEFAULT_REGION"] = env.scope["region"]
        ver = run_tool([exe, "--version"], cwd=self.root, env=senv, timeout=120, what="cdk --version")
        if not tool_version_matches(ver.stdout, self.pinned_version):
            raise PlanError(f"cdk version mismatch: pinned {self.pinned_version}, found {ver.stdout.strip()}")
        out = workdir / "cdk.out"
        run_tool([exe, "synth", "--quiet", "--no-notices", "-o", str(out)], cwd=self.root, env=senv,
                 timeout=self.timeout, what="cdk synth")
        stacks = stacks_from_manifest(out, only=self.only)
        if not stacks:
            raise PlanError("cdk synth produced no stacks")
        return stacks


def stacks_from_manifest(assembly: Path, *, only: tuple[str, ...] = ()) -> dict[str, Path]:
    manifest = json.loads((assembly / "manifest.json").read_text(encoding="utf-8"))
    out: dict[str, Path] = {}
    for art_id, art in (manifest.get("artifacts") or {}).items():
        if art.get("type") != "aws:cloudformation:stack":
            continue
        props = art.get("properties") or {}
        name = props.get("stackName") or art_id
        if only and name not in only and art_id not in only:
            continue
        out[name] = assembly / props["templateFile"]
    return out
