"""Resolution agent — Bedrock-driven IaC fix after a confirmed diagnosis.

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
You are an IaC engineer applying a production fix based on a confirmed incident diagnosis.

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

RULES:
  - Only change what is needed. No refactoring, no formatting, no extras.
  - Always read before writing. Never guess file content.
  - If validate_change fails, read the error, fix it, re-validate.
  - If deployment_source is 'unknown' or 'manual':
      Do NOT call write_iac_change, git_commit_push, or create_pull_request.
      Instead respond immediately with JSON using status = "manual_required".

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
) -> dict:
    """
    Drive the resolution agent.

    Parameters
    ----------
    diagnosis:   Output dict from debug_incident_agent — must have at minimum
                 root_cause, evidence, deployment_source, iac_file_hint.
    iac_root:    Absolute path to the IaC root on local disk.
    base_branch: git branch to base the fix branch on (e.g. "develop").
    profile:     AWS profile for Bedrock auth.
    region:      AWS region where Bedrock is called from.
    """
    import boto3
    from cloudctl.mcp.tools.resolve import (
        read_iac_file, write_iac_change, validate_change,
        git_create_branch, git_commit_push, create_pull_request,
    )

    if profile:
        session = boto3.Session(profile_name=profile, region_name=region)
    else:
        session = boto3.Session(region_name=region)

    bedrock = session.client("bedrock-runtime", region_name=region)

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

    def _dispatch(tool_name: str, tool_input: dict) -> str:
        directory = tool_input.get("directory") or iac_root
        if tool_name == "read_iac_file":
            return read_iac_file(tool_input["path"])
        if tool_name == "write_iac_change":
            return write_iac_change(
                tool_input["path"],
                tool_input["old_content"],
                tool_input["new_content"],
            )
        if tool_name == "validate_change":
            return validate_change(directory, tool_input.get("tool", "terraform"))
        if tool_name == "git_create_branch":
            return git_create_branch(
                tool_input["branch_name"],
                tool_input.get("base_branch", base_branch),
                directory,
            )
        if tool_name == "git_commit_push":
            return git_commit_push(
                tool_input["message"],
                tool_input.get("paths", []),
                directory,
            )
        if tool_name == "create_pull_request":
            return create_pull_request(
                tool_input["title"],
                tool_input["body"],
                tool_input.get("base_branch", base_branch),
                directory,
            )
        return json.dumps({"error": f"Unknown tool: {tool_name}"})

    for _ in range(max_turns):
        resp = bedrock.converse(
            modelId="us.anthropic.claude-sonnet-4-6",
            system=[{"text": _RESOLUTION_SYSTEM}],
            messages=messages,
            toolConfig={"tools": _RESOLUTION_TOOLS},
        )
        stop_reason = resp["stopReason"]
        msg = resp["output"]["message"]
        messages.append(msg)

        if stop_reason == "end_turn":
            for block in msg.get("content", []):
                if "text" in block:
                    text = block["text"].strip()
                    # Try to extract JSON result
                    try:
                        m = re.search(r'\{[^{}]*"status"[^{}]*\}', text, re.DOTALL)
                        if m:
                            return json.loads(m.group(0))
                        # Broader match for nested objects
                        m2 = re.search(r'\{.*"status".*\}', text, re.DOTALL)
                        if m2:
                            return json.loads(m2.group(0))
                    except Exception:
                        pass
                    return {"status": "error", "detail": text[:500]}
            return {"status": "error", "detail": "end_turn with no text block"}

        if stop_reason == "tool_use":
            tool_results = []
            for block in msg.get("content", []):
                if "toolUse" in block:
                    tu = block["toolUse"]
                    result_str = _dispatch(tu["name"], tu["input"])
                    tool_results.append({
                        "toolResult": {
                            "toolUseId": tu["toolUseId"],
                            "content":   [{"text": result_str}],
                        }
                    })
            if tool_results:
                messages.append({"role": "user", "content": tool_results})

    return {"status": "error", "detail": f"max_turns ({max_turns}) reached without conclusion"}
