"""Resolution agent — model-agnostic IaC fix after a confirmed diagnosis.

Flow:
  1. Receives the confirmed diagnosis dict (from debug_incident_agent)
  2. Creates a git branch
  3. Reads the relevant IaC file(s)
  4. Writes the minimal fix
  5. Validates the change
  6. Commits and pushes
  7. Opens a GitHub PR
  8. Returns structured result with PR URL

Safety rules enforced in the system prompt:
  - Always read before writing
  - Only change what fixes the root cause
  - Validate before committing
  - Never push to main/master/develop/production
  - If deployment_source is 'unknown' or 'manual', emit manual_steps instead
"""
from __future__ import annotations

import json
import re
from typing import Optional

_RESOLUTION_TOOLS = [
    {
        "toolSpec": {
            "name": "read_iac_file",
            "description": (
                "Read an IaC source file from disk (Terraform .tf/.tfvars, "
                "CloudFormation .yaml/.json, CDK .ts). "
                "Always call this before write_iac_change."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "path": {"type": "string",
                             "description": "Absolute or relative path to the IaC file"},
                },
                "required": ["path"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "write_iac_change",
            "description": (
                "Apply a targeted change to an IaC file. "
                "Replaces old_content (which must appear verbatim in the file) "
                "with new_content. Always read the file first."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "path":        {"type": "string"},
                    "old_content": {"type": "string",
                                   "description": "Exact text to replace (must exist verbatim)"},
                    "new_content": {"type": "string",
                                   "description": "Replacement text"},
                },
                "required": ["path", "old_content", "new_content"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "validate_change",
            "description": (
                "Validate the IaC after a change: "
                "terraform — runs terraform init -backend=false then terraform validate; "
                "cdk — runs npx cdk synth --quiet. "
                "Always run after write_iac_change and before git_commit_push."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "directory": {"type": "string",
                                 "description": "IaC root directory (where terraform init was run)"},
                    "tool":      {"type": "string", "enum": ["terraform", "cdk"],
                                 "description": "Which IaC tool to validate with"},
                },
                "required": ["directory", "tool"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "git_create_branch",
            "description": (
                "Create a new git branch from origin/<base_branch>. "
                "Always do this BEFORE any write_iac_change call."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "branch_name": {"type": "string",
                                   "description": "Name for the fix branch, e.g. fix/rds-connection-limit"},
                    "base_branch": {"type": "string",
                                   "description": "Branch to branch from (default: main)"},
                    "directory":   {"type": "string",
                                   "description": "Git repo root (default: iac_root_directory)"},
                },
                "required": ["branch_name"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "git_commit_push",
            "description": (
                "Stage the listed files, create a commit, and push to origin. "
                "Only call after validate_change returns success=true."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "message":   {"type": "string",
                                 "description": "Commit message (imperative, 1–72 chars)"},
                    "paths":     {"type": "array", "items": {"type": "string"},
                                 "description": "List of file paths to stage"},
                    "directory": {"type": "string"},
                },
                "required": ["message", "paths"],
            }},
        }
    },
    {
        "toolSpec": {
            "name": "create_pull_request",
            "description": (
                "Open a GitHub PR using the gh CLI. "
                "Call only after git_commit_push succeeds. "
                "PR body must reference the root cause and list evidence items."
            ),
            "inputSchema": {"json": {
                "type": "object",
                "properties": {
                    "title":       {"type": "string",
                                   "description": "PR title (under 72 chars)"},
                    "body":        {"type": "string",
                                   "description": "PR body (markdown) — include root_cause, evidence, fix summary"},
                    "base_branch": {"type": "string",
                                   "description": "Target branch for the PR (default: main)"},
                    "directory":   {"type": "string"},
                },
                "required": ["title", "body"],
            }},
        }
    },
]


_RESOLUTION_SYSTEM = """\
You are an expert IaC engineer applying a precise production fix in a Git repository based on a confirmed cloud incident diagnosis.

You receive a JSON object with:
  root_cause         — confirmed diagnosis sentence
  evidence           — list of log lines / metric values that prove it
  remediation_steps  — recommended fix actions
  deployment_source  — terraform | cdk | cloudformation | manual | unknown
  iac_file_hint      — where to find the IaC source
  iac_root_directory — local directory to work in
  base_branch        — git branch to base the fix on

MANDATORY SEQUENCE:
  1. git_create_branch   — branch name: fix/<resource>-<short-cause>
  2. read_iac_file       — read the relevant IaC file(s) before touching them
  3. write_iac_change    — apply the minimal change that fixes root_cause
  4. validate_change     — must succeed before committing
  5. git_commit_push     — stage only the changed files, not everything
  6. create_pull_request — PR body cites root_cause and evidence items

CRITICAL CODE REVIEW & TRACING RULES (To achieve 95%+ success):
  - **Codebase Searching**: Use `iac_file_hint` to find the target resource definition. If the file is not at the exact path, inspect common files in the workspace (e.g. `main.tf`, `variables.tf`, `locals.tf`, `lib/*.ts`, `bin/*.ts`) to trace the resource name.
  - **Trace Variable Definitions**: If the resource attribute you need to fix references a variable, local value, or environment configuration (e.g. `var.my_param`, `local.db_port`, or `process.env.TIMEOUT`), do NOT hardcode the fix directly in the resource file. Instead, call `read_iac_file` on the variables/locals files (e.g. `variables.tf`, `locals.tf`, `terraform.tfvars`, or CDK config files), find where the value is defined, and apply your fix there.
  - **Iterative Compile/Validation Check**: After using `write_iac_change`, always run `validate_change`. If the validation fails:
      1. Carefully read and parse the compiler/validation error messages returned by the tool.
      2. Identify the line, file, and syntax/logical error.
      3. Call `write_iac_change` again to fix the error (e.g., matching brackets, declaring missing variables, correcting types).
      4. Re-run `validate_change` until it returns success=true.
  - **Targeted Changes**: Keep changes minimal. Never reformat unrelated lines or change unrelated parameters. Ensure the `old_content` string in `write_iac_change` matches the existing file contents verbatim, including indentation and spacing.
  - **No Manual-Source Hacks**: If deployment_source is 'unknown' or 'manual', do NOT write any files or create PRs. Instead, immediately respond with status = "manual_required" and list detailed `manual_steps`.

When done, respond ONLY with a JSON object:
{
  "status": "success" | "manual_required" | "error",
  "pr_url":       "https://github.com/...",
  "branch":       "fix/...",
  "files_changed": ["path/to/file.tf"],
  "pr_summary":   "one-sentence description of the fix",
  "manual_steps": ["step 1", "step 2"]
}"""


def run(
    diagnosis:   dict,
    iac_root:    str,
    base_branch: str,
    profile:     Optional[str],
    region:      str,
    max_turns:   int = 14,
    approve=None,
    gate=None,
    gate_env:    Optional[str] = None,
    approval_id: Optional[str] = None,
    requester:   Optional[str] = None,
) -> dict:
    """
    Drive the resolution agent.

    Parameters
    ----------
    diagnosis:   Output dict from debug_incident_agent — must have at minimum
                 root_cause, evidence, deployment_source, iac_file_hint.
    iac_root:    Absolute path to the IaC root on local disk.
    base_branch: git branch to base the fix branch on (e.g. "develop").
    profile:     AWS profile (used when the model provider is Bedrock).
    region:      AWS region for a Bedrock model client.
    approve:     Optional callback (stage: str, detail: str) -> bool. Two
                 gates: "plan" before the FIRST file write (what will change,
                 where) and "push" before commit/push/PR (actual git diff +
                 fresh validation result). Returning False blocks that gate;
                 the agent is told to stop and emit manual steps instead.
                 None = no gates (library/test use).
    gate:        Optional cloudctl.gate.gate.PolicyGate. When set (the CLI
                 always sets it), the push gate first runs the change through
                 the policy gate: scoped credentials, the IaC tool's own plan,
                 policy engines and signed approval. The commit/push runs only
                 inside the gate's single-use authorization, and every model
                 call and tool call is written to the audit chain.
    gate_env:    Gate environment name (default: matched from --iac-root or profile).
    approval_id: Signed approval request id, when the environment requires one.
    """
    from pathlib import Path
    from cloudctl.ai.model_providers import default_model, make_model_client
    from cloudctl.mcp.tools.resolve import (
        read_iac_file, write_iac_change, validate_change,
        git_create_branch, git_commit_push, create_pull_request,
    )

    # Model-agnostic: same provider/model selection as the investigation
    # (CLOUDCTL_MODEL_PROVIDER / CLOUDCTL_MODEL), not a hardcoded Bedrock id.
    client = make_model_client(profile, region)
    model_id = default_model()
    root = Path(iac_root).resolve()

    user_content = json.dumps({
        "root_cause":         diagnosis.get("root_cause", ""),
        "evidence":           diagnosis.get("evidence", []),
        "remediation_steps":  diagnosis.get("remediation_steps", []),
        "deployment_source":  diagnosis.get("deployment_source", "unknown"),
        "iac_file_hint":      diagnosis.get("iac_file_hint", ""),
        "iac_root_directory": iac_root,
        "base_branch":        base_branch,
    }, indent=2)

    messages: list[dict] = [{"role": "user", "content": [{"text": user_content}]}]

    _DECLINED = json.dumps({
        "error": "The operator declined this step. Do NOT retry it. Stop and "
                 "respond with status='manual_required', listing the intended "
                 "fix as detailed manual_steps for the operator to apply."
    })
    gates = {"plan": approve is None, "push": approve is None}   # True = passed
    if gate is not None:
        gates["push"] = False      # the policy gate always runs before a push
    from cloudctl.gate.usage import ModelUsage
    usage = ModelUsage()
    holder: dict = {"auth": None}
    # What the TOOLS actually did. The final report is reconciled against this,
    # never taken from the model's own claim (a model can say "success" after a
    # failed commit, push or PR).
    actual: dict = {"branch": "", "files_written": [], "validated": None,
                    "pushed": False, "pr_url": "", "errors": []}

    def _ok(result: str) -> tuple[bool, dict]:
        try:
            d = json.loads(result)
        except (ValueError, TypeError):
            return False, {}
        return bool(isinstance(d, dict) and d.get("success")), d if isinstance(d, dict) else {}

    def _inside_root(path: str) -> bool:
        p = Path(path)
        p = (p if p.is_absolute() else root / p).resolve()
        return p == root or root in p.parents

    def _outside_error(path: str) -> str:
        return json.dumps({"error": f"{path!r} is outside the IaC root {str(root)!r}; "
                                    "only files under --iac-root can be read or changed."})

    def _iac_tool(directory: str) -> str:
        return "cdk" if (Path(directory) / "cdk.json").exists() else "terraform"

    def _gate_plan(tool_input: dict) -> bool:
        if gates["plan"]:
            return True
        detail = (
            f"PLANNED CHANGE\n"
            f"  file: {tool_input.get('path', '?')}\n"
            f"--- replace ---\n{tool_input.get('old_content', '')}\n"
            f"--- with ---\n{tool_input.get('new_content', '')}"
        )
        gates["plan"] = bool(approve("plan", detail))
        return gates["plan"]

    def _gate_push(directory: str) -> bool:
        if gates["push"] and gate is None:
            return True       # with a policy gate, every push is gated again
        import subprocess
        try:
            diff = subprocess.run(
                ["git", "diff"], cwd=directory,
                capture_output=True, text=True, timeout=30,
            ).stdout
        except Exception:  # noqa: BLE001
            diff = "(git diff unavailable)"
        validation = validate_change(directory, _iac_tool(directory))
        detail = (
            f"READY TO COMMIT / PUSH / PR\n"
            f"--- git diff ---\n{diff[:4000]}\n"
            f"--- validation ---\n{validation[:1000]}"
        )
        if not _ok(validation)[0]:
            actual["errors"].append("validation failed at the push gate; nothing was pushed")
            return False   # never push an invalid change, regardless of answer
        if gate is not None:
            verdict = _policy_gate(directory)
            if verdict is None:
                return False
            detail += f"\n--- policy gate ---\n{verdict}"
        if approve is None:
            gates["push"] = True
            return True
        gates["push"] = bool(approve("push", detail))
        if not gates["push"] and holder["auth"] is not None:
            holder["auth"].close()
            holder["auth"] = None
        return gates["push"]

    def _policy_gate(directory: str) -> Optional[str]:
        """Run the change through the policy gate. Returns a summary when
        authorized (the authorization is kept for the push), else None."""
        from cloudctl.gate.gate import default_requester
        from cloudctl.gate.models import ChangeRequest, GateError
        from cloudctl.gate.plan import detect_iac_planner
        try:
            env = gate.config.resolve_environment(name=gate_env, iac_root=directory, profile=profile)
            planner = detect_iac_planner(directory, env=env)
            req = ChangeRequest(kind="iac_pr", environment=env.name,
                                summary=f"IaC fix: {str(diagnosis.get('root_cause', ''))[:300]}",
                                requester=requester or default_requester(),
                                context={**usage.context(), "files": list(actual["files_written"])})
            res = gate.evaluate(req, planner, approval_id=approval_id)
        except GateError as e:
            actual["errors"].append(f"policy gate: {e}; nothing was pushed")
            return None
        d = res.decision
        actual["gate"] = d.to_dict()
        if not res.authorized:
            msg = f"policy gate {d.outcome.value} at {d.stage}: " + "; ".join(d.reasons)
            if d.outcome.value == "pending_approval":
                msg += (f". An approver runs `cloudctl gate approve {d.request_id}`, then re-run with "
                        f"--approval {d.request_id}")
            top = [f"[{f.severity.name}] {f.rule_id} {f.resource}" for f in d.findings[:5]]
            actual["errors"].append(msg + (f" ({', '.join(top)})" if top else "") + "; nothing was pushed")
            return None
        holder["auth"] = res.authorization
        counts = d.plan_counts
        return (f"authorized (request {d.request_id}): +{counts.get('add', 0)} ~{counts.get('modify', 0)} "
                f"-{counts.get('destroy', 0)}, {len(d.findings)} non-blocking finding(s)"
                + (f", approved by {d.approver}" if d.approver else ""))

    def _dispatch(tool_name: str, tool_input: dict) -> str:
        directory = tool_input.get("directory") or str(root)
        if tool_name in ("read_iac_file", "write_iac_change") and not _inside_root(tool_input.get("path", "")):
            return _outside_error(tool_input.get("path", ""))
        if tool_name in ("validate_change", "git_create_branch", "git_commit_push",
                         "create_pull_request") and not _inside_root(directory):
            return _outside_error(directory)
        path = tool_input.get("path", "")
        if path and not Path(path).is_absolute():
            path = str(root / path)
        if tool_name == "read_iac_file":
            return read_iac_file(path)
        if tool_name == "write_iac_change":
            if not _gate_plan(tool_input):
                return _DECLINED
            res = write_iac_change(path, tool_input["old_content"], tool_input["new_content"])
            if _ok(res)[0]:
                actual["files_written"].append(path)
            return res
        if tool_name == "validate_change":
            res = validate_change(directory, tool_input.get("tool") or _iac_tool(directory))
            actual["validated"] = _ok(res)[0]
            return res
        if tool_name == "git_create_branch":
            res = git_create_branch(
                tool_input["branch_name"],
                tool_input.get("base_branch", base_branch),
                directory,
            )
            ok, d = _ok(res)
            if ok:
                actual["branch"] = d.get("branch", tool_input["branch_name"])
            else:
                actual["errors"].append(f"git_create_branch: {d.get('error', res)[:300]}")
            return res
        if tool_name == "git_commit_push":
            if not _gate_push(directory):
                return _DECLINED
            push_args = (
                tool_input["message"],
                [p if Path(p).is_absolute() else str(root / p) for p in tool_input.get("paths", [])],
                directory,
            )
            if holder["auth"] is not None:
                auth, holder["auth"] = holder["auth"], None
                with auth:
                    res = auth.execute(lambda _creds, _plan: git_commit_push(*push_args),
                                       what="git_commit_push")
            elif gate is not None:
                return _DECLINED      # never push without the policy gate's authorization
            else:
                res = git_commit_push(*push_args)
            ok, d = _ok(res)
            actual["pushed"] = ok
            if not ok:
                actual["errors"].append(f"git_commit_push: {d.get('error', res)[:300]}")
            return res
        if tool_name == "create_pull_request":
            if not gates["push"] or not actual["pushed"]:
                return _DECLINED
            res = create_pull_request(
                tool_input["title"],
                tool_input["body"],
                tool_input.get("base_branch", base_branch),
                directory,
            )
            ok, d = _ok(res)
            if ok:
                actual["pr_url"] = d.get("pr_url", "")
            else:
                actual["errors"].append(f"create_pull_request: {d.get('error', res)[:300]}")
            return res
        return json.dumps({"error": f"Unknown tool: {tool_name}"})

    def _finish(claimed: dict) -> dict:
        return _reconcile(claimed, actual)

    def _audit(event: str, data: dict) -> None:
        if gate is not None:
            gate.record(event, data)      # AuditError propagates: fail closed

    from cloudctl.gate.models import AuditError
    try:
        return _loop(client, model_id, messages, _dispatch, _finish, _audit, usage, max_turns)
    except AuditError as e:
        actual["errors"].append(f"audit log unavailable, stopped: {e}")
        return _finish({"status": "error"})
    finally:
        if holder["auth"] is not None:
            holder["auth"].close()


def _loop(client, model_id, messages, _dispatch, _finish, _audit, usage, max_turns):
    for _ in range(max_turns):
        resp = client.converse(
            modelId=model_id,
            system=[{"text": _RESOLUTION_SYSTEM}],
            messages=messages,
            toolConfig={"tools": _RESOLUTION_TOOLS},
        )
        usage.add(resp)
        _audit("model.call", {"model": model_id, "stop_reason": resp.get("stopReason", ""),
                              "input_tokens": (resp.get("usage") or {}).get("inputTokens", 0),
                              "output_tokens": (resp.get("usage") or {}).get("outputTokens", 0)})
        stop_reason = resp["stopReason"]
        msg = resp["output"]["message"]
        messages.append(msg)

        if stop_reason == "end_turn":
            for block in msg.get("content", []):
                if "text" in block:
                    text = block["text"].strip()
                    claimed: dict | None = None
                    try:
                        m = re.search(r'\{[^{}]*"status"[^{}]*\}', text, re.DOTALL)
                        if m:
                            claimed = json.loads(m.group(0))
                        else:
                            m2 = re.search(r'\{.*"status".*\}', text, re.DOTALL)
                            if m2:
                                claimed = json.loads(m2.group(0))
                    except Exception:  # noqa: BLE001
                        claimed = None
                    return _finish(claimed or {"status": "error", "detail": text[:500]})
            return _finish({"status": "error", "detail": "end_turn with no text block"})

        if stop_reason == "tool_use":
            tool_results = []
            for block in msg.get("content", []):
                if "toolUse" in block:
                    tu = block["toolUse"]
                    result_str = _dispatch(tu["name"], tu["input"])
                    _audit("tool.call", {"tool": tu["name"], "result": str(result_str)[:300]})
                    tool_results.append({
                        "toolResult": {
                            "toolUseId": tu["toolUseId"],
                            "content":   [{"text": result_str}],
                        }
                    })
            if tool_results:
                messages.append({"role": "user", "content": tool_results})

    return _finish({"status": "error", "detail": f"max_turns ({max_turns}) reached without conclusion"})


def _reconcile(claimed: dict, actual: dict) -> dict:
    """Build the final result from what the tools did, using the model's JSON
    only for prose (summary, manual steps). Pure, so it is unit-testable.

    success      requires a successful push AND a PR URL returned by gh.
    manual_required is honoured only when nothing was pushed.
    Anything else is an error that names the real failure."""
    out = {k: v for k, v in (claimed or {}).items() if k in ("pr_summary", "manual_steps", "detail")}
    out["branch"] = actual.get("branch", "")
    out["files_changed"] = list(dict.fromkeys(actual.get("files_written") or []))
    out["pr_url"] = actual.get("pr_url", "")
    errors = list(actual.get("errors") or [])
    status = (claimed or {}).get("status", "error")

    if actual.get("pushed") and actual.get("pr_url"):
        out["status"] = "success"
    elif status == "manual_required" and not actual.get("pushed"):
        out["status"] = "manual_required"
        if out["files_changed"]:
            out.setdefault("manual_steps", []).insert(
                0, "Local files were edited on branch "
                   f"{out['branch'] or '(unknown)'} but not committed: {', '.join(out['files_changed'])}")
    else:
        out["status"] = "error"
        if status == "success":
            errors.append("the model reported success, but "
                          + ("the PR was not created" if actual.get("pushed")
                             else "nothing was committed and pushed"))
        out["detail"] = "; ".join(errors) or out.get("detail") or "resolution did not complete"
    if errors and out["status"] != "error":
        out["warnings"] = errors
    return out

