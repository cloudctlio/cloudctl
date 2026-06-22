"""IaC resolution tools — safe file read/write, validation, git, and PR creation.

These are used exclusively by the resolution agent. They never execute cloud
writes (no AWS API mutations) — they only operate on the local filesystem,
git, and GitHub CLI.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

_ALLOWED_EXTS = {".tf", ".tfvars", ".yaml", ".yml", ".json", ".ts", ".py", ".hcl"}
_MAX_FILE_BYTES = 100_000  # 100 KB — large enough for any IaC file
_PROTECTED_BRANCHES = {"main", "master", "develop", "production", "prod", "release"}


def read_iac_file(path: str) -> str:
    """Read an IaC file. Returns content or an error dict."""
    p = Path(path).resolve()
    if p.suffix not in _ALLOWED_EXTS:
        return json.dumps({
            "error": f"File type {p.suffix!r} not allowed. Supported: {sorted(_ALLOWED_EXTS)}"
        })
    if not p.exists():
        return json.dumps({"error": f"File not found: {path}"})
    size = p.stat().st_size
    if size > _MAX_FILE_BYTES:
        return json.dumps({"error": f"File too large ({size} bytes). Max {_MAX_FILE_BYTES} bytes."})
    content = p.read_text(encoding="utf-8")
    return json.dumps({"path": str(p), "content": content, "size_bytes": size}, indent=2)


def write_iac_change(path: str, old_content: str, new_content: str) -> str:
    """Replace old_content with new_content in an IaC file.

    Requires exact match of old_content. Always read the file first so the
    content is fresh before attempting a write.
    """
    p = Path(path).resolve()
    if p.suffix not in _ALLOWED_EXTS:
        return json.dumps({"error": f"File type {p.suffix!r} not allowed."})
    if not p.exists():
        return json.dumps({"error": f"File not found: {path}"})

    current = p.read_text(encoding="utf-8")
    if old_content not in current:
        return json.dumps({
            "error": (
                "old_content not found verbatim in file. "
                "Re-read the file with read_iac_file and use exact text from the result."
            )
        })

    updated = current.replace(old_content, new_content, 1)
    p.write_text(updated, encoding="utf-8")
    return json.dumps({
        "success": True,
        "path": str(p),
        "bytes_before": len(current),
        "bytes_after": len(updated),
    }, indent=2)


def validate_change(directory: str, tool: str = "terraform") -> str:
    """Run IaC validation in a directory.

    terraform: runs `terraform init -backend=false` then `terraform validate`.
    cdk:       runs `npx cdk synth --quiet`.
    """
    d = Path(directory).resolve()
    if not d.is_dir():
        return json.dumps({"error": f"Directory not found: {directory}"})
    if tool not in ("terraform", "cdk"):
        return json.dumps({"error": f"Unknown tool: {tool!r}. Supported: terraform, cdk"})

    if tool == "terraform":
        steps = [
            ["terraform", "init", "-backend=false", "-input=false", "-no-color"],
            ["terraform", "validate", "-no-color"],
        ]
    else:
        steps = [["npx", "cdk", "synth", "--quiet"]]

    for cmd in steps:
        try:
            r = subprocess.run(
                cmd, cwd=str(d), capture_output=True, text=True, timeout=120,
            )
        except FileNotFoundError:
            return json.dumps({"error": f"'{cmd[0]}' not found — is {tool} installed?"})
        except subprocess.TimeoutExpired:
            return json.dumps({"error": f"Validation timed out after 120 s."})

        if r.returncode != 0:
            return json.dumps({
                "success": False,
                "tool": tool,
                "command": " ".join(cmd),
                "returncode": r.returncode,
                "stdout": r.stdout[-3000:],
                "stderr": r.stderr[-3000:],
            }, indent=2)

    return json.dumps({"success": True, "tool": tool, "directory": str(d)}, indent=2)


def git_create_branch(
    branch_name: str,
    base_branch: str = "main",
    directory: str = ".",
) -> str:
    """Create a new git branch from origin/<base_branch>."""
    if not re.match(r"^[a-zA-Z0-9/_\-\.]+$", branch_name):
        return json.dumps({
            "error": "Invalid branch name. Allowed chars: a-z A-Z 0-9 / _ - ."
        })
    if branch_name.lower() in _PROTECTED_BRANCHES:
        return json.dumps({"error": f"Cannot create branch with protected name: {branch_name!r}"})

    d = str(Path(directory).resolve())
    try:
        subprocess.run(["git", "fetch", "origin"], cwd=d, capture_output=True, timeout=30)
        r = subprocess.run(
            ["git", "checkout", "-b", branch_name, f"origin/{base_branch}"],
            cwd=d, capture_output=True, text=True, timeout=30,
        )
        if r.returncode != 0:
            return json.dumps({"error": r.stderr.strip()})
        return json.dumps({
            "success": True, "branch": branch_name, "base": base_branch,
        }, indent=2)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "git operation timed out"})
    except Exception as exc:
        return json.dumps({"error": str(exc)})


def git_commit_push(
    message: str,
    paths: list[str],
    directory: str = ".",
) -> str:
    """Stage specific paths, commit, and push to origin.

    Never stages everything (no git add -A). Only the listed paths are staged.
    """
    if not message or len(message) > 500:
        return json.dumps({"error": "Commit message must be 1–500 characters."})
    if not paths:
        return json.dumps({"error": "paths list is empty — specify which files to commit."})

    d = str(Path(directory).resolve())

    for path in paths:
        r = subprocess.run(
            ["git", "add", str(Path(path).resolve())],
            cwd=d, capture_output=True, text=True,
        )
        if r.returncode != 0:
            return json.dumps({"error": f"git add failed for {path}: {r.stderr.strip()}"})

    r = subprocess.run(
        ["git", "commit", "-m", message],
        cwd=d, capture_output=True, text=True,
    )
    if r.returncode != 0:
        return json.dumps({"error": f"git commit failed: {r.stderr.strip()}"})

    r = subprocess.run(
        ["git", "push", "-u", "origin", "HEAD"],
        cwd=d, capture_output=True, text=True, timeout=60,
    )
    if r.returncode != 0:
        return json.dumps({"error": f"git push failed: {r.stderr.strip()}"})

    return json.dumps({"success": True, "message": message, "paths": paths}, indent=2)


def create_pull_request(
    title: str,
    body: str,
    base_branch: str = "main",
    directory: str = ".",
) -> str:
    """Create a GitHub PR using the gh CLI."""
    if not title or len(title) > 200:
        return json.dumps({"error": "PR title must be 1–200 characters."})

    d = str(Path(directory).resolve())
    try:
        r = subprocess.run(
            ["gh", "pr", "create",
             "--title", title,
             "--body",  body,
             "--base",  base_branch],
            cwd=d, capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            return json.dumps({"error": f"gh pr create failed: {r.stderr.strip()}"})
        pr_url = r.stdout.strip()
        return json.dumps({"success": True, "pr_url": pr_url}, indent=2)
    except FileNotFoundError:
        return json.dumps({
            "error": "'gh' CLI not found. Install from https://cli.github.com then run gh auth login."
        })
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "gh pr create timed out after 60 s."})
    except Exception as exc:
        return json.dumps({"error": str(exc)})
