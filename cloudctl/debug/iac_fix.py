"""IaC-grounded fix suggestion — read-only.

After a diagnosis, find the resource the root cause blames in the operator's own
Terraform or CDK (Python) source and propose a concrete diff against it. Nothing
is written to the operator's tree, committed or applied.

Pipeline (each step generic across resource types, no service vocabulary):

  1. candidates  — names the diagnosis blames (resources_investigated /
                   affected_resources, ARN tails, distinctive identifiers in the
                   root cause).
  2. locate      — deterministic search of the IaC tree:
                   Terraform: terraform.tfstate (physical name/id/arn -> address),
                   a string literal equal to the name inside a resource block,
                   a var.X whose default equals the name, or the block label.
                   CDK Python: a construct call whose id or a keyword string
                   argument equals the name.
                   No match -> say so; never guess a file.
  3. propose     — the configured model (any provider, via make_model_client)
                   sees ONLY the located block(s) and returns exact old/new
                   text. Edits outside the located text are rejected.
  4. check       — apply to a temp copy and run `terraform validate` or
                   `cdk synth` when available. Otherwise the suggestion is
                   labelled UNVERIFIED. A passing check proves the change is
                   well-formed, not that it fixes the incident.

The suggestion is reported separately from the diagnosis and never changes
root-cause confidence.
"""
from __future__ import annotations

import ast
import difflib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

_SKIP_DIRS = {".git", ".terraform", "cdk.out", "node_modules", ".venv", "venv",
              "__pycache__", ".pytest_cache", "tests", "test"}
_MAX_FILES = 400
_MAX_FILE_BYTES = 200_000
_COPY_IGNORE = shutil.ignore_patterns(".git", ".terraform", "cdk.out", "node_modules",
                                      ".venv", "venv", "__pycache__")


@dataclass
class Located:
    kind: str                 # terraform | cdk
    address: str              # aws_dynamodb_table.orders | OrdersTable (Table)
    file: str                 # path relative to root
    start: int                # 1-based, inclusive
    end: int
    text: str
    matched: str              # the candidate name that matched
    how: str                  # why it matched
    score: int
    related: list[dict] = field(default_factory=list)   # variable blocks it reads


# ── 1. candidate names ────────────────────────────────────────────────────────

def candidate_names(diagnosis: dict) -> list[str]:
    """Names the diagnosis blames, most specific first. Shape-based only."""
    out: list[str] = []

    def add(v: str) -> None:
        v = (v or "").strip().strip("`'\".,;:()[]")
        if not v:
            return
        if v.startswith("arn:"):
            tail = re.split(r"[:/]", v)[-1]
            add(tail)
        if len(v) >= 2 and v not in out:
            out.append(v)

    for key in ("resources_investigated", "affected_resources"):
        for r in diagnosis.get(key) or []:
            r = str(r)
            add(r.split(" ")[0])           # "orders (dynamodb)" -> "orders"
            m = re.search(r"\(([^)]+)\)", r)
            if m and "/" in m.group(1):
                add(m.group(1).split("/")[-1])
    text = " ".join([str(diagnosis.get("root_cause") or "")] +
                    [str(e) for e in diagnosis.get("evidence") or []])
    for q in re.findall(r"[`'\"]([A-Za-z0-9][A-Za-z0-9_.:/\-]{1,})[`'\"]", text):
        add(q)
    for t in re.findall(r"\b[A-Za-z0-9][A-Za-z0-9_.:/\-]{2,}\b", text):
        if t.startswith("arn:") or (any(c in t for c in "-_") and any(c.isalpha() for c in t)):
            add(t)
    # The resource the root cause names first is the one it blames: order by
    # first whole-word mention in root_cause; names it never mentions go last.
    rc = str(diagnosis.get("root_cause") or "")

    def first_mention(name: str) -> int:
        m = re.search(rf"(?<![\w\-]){re.escape(name)}(?![\w\-])", rc)
        return m.start() if m else len(rc) + 1
    return sorted(out, key=first_mention)


# ── 2. locate ─────────────────────────────────────────────────────────────────

def _iter_files(root: Path, suffixes: tuple[str, ...]):
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS and not d.startswith(".")]
        for fn in sorted(filenames):
            if fn.endswith(suffixes):
                p = Path(dirpath) / fn
                if p.stat().st_size <= _MAX_FILE_BYTES:
                    n += 1
                    if n > _MAX_FILES:
                        return
                    yield p


def detect_kinds(root: str | Path) -> list[str]:
    root = Path(root)
    kinds = []
    if any(True for _ in _iter_files(root, (".tf",))):
        kinds.append("terraform")
    if (root / "cdk.json").exists():
        kinds.append("cdk")
    return kinds


_TF_BLOCK = re.compile(r'^(resource|data|module|variable|locals)\b\s*("([^"]+)"\s*)?("([^"]+)"\s*)?\{',
                       re.MULTILINE)


def _tf_blocks(text: str) -> list[dict]:
    """Top-level HCL blocks with line ranges. Brace matching skips strings,
    comments and heredocs well enough for real-world .tf files."""
    blocks = []
    for m in _TF_BLOCK.finditer(text):
        i, depth, n = m.end(), 1, len(text)
        in_str = False
        while i < n and depth:
            c = text[i]
            if in_str:
                if c == "\\":
                    i += 1
                elif c == '"':
                    in_str = False
            elif c == '"':
                in_str = True
            elif c == "#" or text.startswith("//", i):
                i = text.find("\n", i)
                if i < 0:
                    break
            elif text.startswith("/*", i):
                i = text.find("*/", i) + 1
                if i <= 0:
                    break
            elif text.startswith("<<", i):
                hm = re.match(r"<<-?(\w+)\n", text[i:])
                if hm:
                    end = re.search(rf"^\s*{hm.group(1)}\s*$", text[i + hm.end():], re.MULTILINE)
                    i = i + hm.end() + (end.end() if end else 0)
                    continue
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            i += 1
        start_line = text.count("\n", 0, m.start()) + 1
        end_line = text.count("\n", 0, i) + 1
        body = text[m.start():i]
        blocks.append({"type": m.group(1), "a": m.group(3) or "", "b": m.group(5) or "",
                       "start": start_line, "end": end_line, "text": body})
    return blocks


def _depth1_literals(block_text: str) -> set[str]:
    """String literals assigned at the block's own top level (not nested
    blocks such as environment { variables = {...} })."""
    out, depth = set(), 0
    for line in block_text.splitlines()[1:]:
        s = line.strip()
        if depth == 0:
            m = re.match(r'^[A-Za-z0-9_]+\s*=\s*"([^"$]*)"\s*$', s)
            if m:
                out.add(m.group(1))
        depth += s.count("{") - s.count("}")
    return out


def _state_addresses(root: Path, name: str) -> dict[str, bool]:
    """terraform.tfstate (local state only): addresses whose instance has this
    name/id/arn -> True when a value equals it exactly, False when one only
    ends with it (a log group "/aws/lambda/<name>" or an ARN tail). Remote
    state is not read."""
    hits: dict[str, bool] = {}
    for sf in [root / "terraform.tfstate"]:
        if not sf.exists():
            continue
        try:
            st = json.loads(sf.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for r in st.get("resources") or []:
            if r.get("mode") != "managed":
                continue
            for inst in r.get("instances") or []:
                a = inst.get("attributes") or {}
                vals = {str(a.get(k)) for k in ("name", "id", "arn", "function_name",
                                                 "bucket", "table_name", "cluster_identifier")
                        if a.get(k)}
                addr = f"{r.get('type')}.{r.get('name')}"
                if name in vals:
                    hits[addr] = True
                elif any(v.endswith(f":{name}") or v.endswith(f"/{name}") for v in vals):
                    hits.setdefault(addr, False)
    return hits


def _interpolate_vars(text: str, variables: dict[str, dict]) -> str:
    """Substitute "${var.x}" with the variable's literal default, so a name
    built as "${var.prefix}-api" can be matched without state."""
    def sub(m: re.Match) -> str:
        d = variables.get(m.group(1), {}).get("default")
        return d if d is not None and "$" not in d else m.group(0)
    return re.sub(r"\$\{var\.([A-Za-z0-9_]+)\}", sub, text)


def _block_address(b: dict) -> str:
    return f'{b["a"]}.{b["b"]}' if b["type"] == "resource" else f'{b["type"]}.{b["a"]}.{b["b"]}'


def _refs(text: str) -> set[str]:
    """Addresses a block references, ignoring depends_on (ordering, not data)."""
    body = re.sub(r"depends_on\s*=\s*\[[^\]]*\]", "", text)
    out = set(re.findall(r"\b((?:data\.)?[a-z0-9]+_[a-z0-9_]+\.[A-Za-z0-9_\-]+)\.", body))
    return {r for r in out if not r.startswith(("var.", "local.", "module."))}


def _family(rtype: str) -> str:
    """Provider plus service segment of a resource type: aws_iam_role -> aws_iam."""
    return "_".join(rtype.split("_")[:2])


_MAX_RELATED = 6
_MAX_RELATED_CHARS = 6000


def _related_blocks(root: Path, b: dict, blocks: list[dict]) -> list[dict]:
    """Resources that configure this one and live in the same service family:
    blocks that reference it (a role's aws_iam_role_policy and attachments, a
    function's permissions) and data/resource blocks it references (a policy
    document). The bad value is often in one of these, not the block itself.
    Structural only: references plus the provider_service prefix of the type."""
    addr, fam = _block_address(b), _family(b["a"])
    out = []
    for o in blocks:
        if o is b or o["type"] not in ("resource", "data") or _family(o["a"]) != fam:
            continue
        oaddr = _block_address(o)
        if addr in _refs(o["text"]) or oaddr in _refs(b["text"]):
            if len(o["text"]) > _MAX_RELATED_CHARS:
                continue
            out.append({"file": str(o["file"].relative_to(root)), "start": o["start"], "end": o["end"],
                        "text": o["text"], "address": oaddr})
        if len(out) >= _MAX_RELATED:
            break
    return out


def _locate_terraform(root: Path, names: list[str]) -> list[Located]:
    files = {p: p.read_text(encoding="utf-8", errors="replace") for p in _iter_files(root, (".tf",))}
    blocks = []
    variables: dict[str, dict] = {}
    for p, txt in files.items():
        for b in _tf_blocks(txt):
            b["file"] = p
            blocks.append(b)
            if b["type"] == "variable":
                dm = re.search(r'^\s*default\s*=\s*"?([^"\n]*)"?\s*$', b["text"], re.MULTILINE)
                variables[b["a"]] = {**b, "default": dm.group(1).strip() if dm else None}

    found: list[Located] = []
    for rank, name in enumerate(names):
        state_hits = _state_addresses(root, name)
        for b in blocks:
            if b["type"] != "resource":
                continue
            addr = f'{b["a"]}.{b["b"]}'
            how, score = "", 0
            if state_hits.get(addr):
                how, score = "terraform.tfstate maps it to this address", 5
            elif name in _depth1_literals(b["text"]) or \
                    name in _depth1_literals(_interpolate_vars(b["text"], variables)):
                how, score = f'the block sets an attribute to "{name}"', 4
            elif addr in state_hits:
                how, score = "terraform.tfstate has a value ending in it at this address", 3
            else:
                for v in re.findall(r"var\.([A-Za-z0-9_]+)", b["text"]):
                    if variables.get(v, {}).get("default") == name and \
                            re.search(rf"^\s*[A-Za-z0-9_]+\s*=\s*var\.{v}\s*$", b["text"], re.MULTILINE):
                        how, score = f'an attribute reads var.{v}, whose default is "{name}"', 4
                        break
                else:
                    if f'"{name}"' in b["text"]:
                        how, score = f'"{name}" appears inside the block', 2
                    elif b["b"] == name or b["b"].replace("_", "-") == name.replace("_", "-"):
                        how, score = "the resource label matches", 1
            if not score:
                continue
            related = []
            for v in dict.fromkeys(re.findall(r"var\.([A-Za-z0-9_]+)", b["text"])):
                vb = variables.get(v)
                if vb:
                    related.append({"file": str(vb["file"].relative_to(root)), "start": vb["start"],
                                    "end": vb["end"], "text": vb["text"], "address": f"var.{v}"})
            related += _related_blocks(root, b, blocks)
            found.append(Located("terraform", addr, str(b["file"].relative_to(root)), b["start"],
                                 b["end"], b["text"], name, how, score * 10 - rank, related))
    return found


def _locate_cdk_python(root: Path, names: list[str]) -> list[Located]:
    found: list[Located] = []
    for p in _iter_files(root, (".py",)):
        src = p.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        lines = src.splitlines()
        stmts = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.Expr)):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        stmts.setdefault(id(sub), node)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or len(node.args) < 2:
                continue
            cid = node.args[1]
            if not (isinstance(cid, ast.Constant) and isinstance(cid.value, str)):
                continue
            func = ast.unparse(node.func)
            kw_strs = {k.arg: k.value.value for k in node.keywords
                       if k.arg and isinstance(k.value, ast.Constant) and isinstance(k.value.value, str)}
            for rank, name in enumerate(names):
                norm = lambda s: re.sub(r"[-_\s]", "", s).lower()  # noqa: E731
                how, score = "", 0
                for k, v in kw_strs.items():
                    if v == name:
                        how, score = f'{k}="{name}"', 4
                        break
                else:
                    if norm(cid.value) == norm(name):
                        how, score = f'construct id "{cid.value}"', 2
                    elif norm(name) and norm(name) in norm(cid.value):
                        how, score = f'construct id "{cid.value}" contains it', 1
                if not score:
                    continue
                stmt = stmts.get(id(node), node)
                s, e = stmt.lineno, stmt.end_lineno or stmt.lineno
                found.append(Located("cdk", f'{cid.value} ({func})', str(p.relative_to(root)), s, e,
                                     "\n".join(lines[s - 1:e]), name, how, score * 10 - rank))
    return found


_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/*\-]{2,}")


def _evidence_tokens(diagnosis: dict, exclude: set[str]) -> set[str]:
    """Distinctive tokens from the root cause and evidence (not remediation,
    which may be wrong): identifiers with a separator, UPPER_CASE names and
    camelCase API names. Compared case-insensitively against IaC text."""
    text = " ".join([str(diagnosis.get("root_cause") or "")] +
                    [str(e) for e in diagnosis.get("evidence") or []])
    out = set()
    for t in _TOKEN_RE.findall(text):
        t = t.strip(".,;:()/")
        if len(t) < 3 or t.lower() in exclude:
            continue
        if any(c in t for c in "_-:/*") or re.search(r"[a-z][A-Z]", t):
            out.add(t.lower())
    return out


def _type_words(addr: str) -> list[str]:
    """aws_lambda_function.api -> ["lambda", "function"]; CDK "X (dynamodb.Table)" -> ["dynamodb", "table"]."""
    if "(" in addr:
        t = addr.split("(")[-1].rstrip(")").replace(".", "_").lower()
        return [w for w in t.split("_") if w]
    return addr.split(".")[0].split("_")[1:]


def _break_tie(top: list[Located], diagnosis: dict) -> tuple[list[Located], str]:
    """Pick one of several equally good matches using only structure and the
    diagnosis itself. Each stage keeps the best; stops when one is left.
      1. a block that references another tied block configures it (a Lambda
         permission naming its function) -> keep the referenced one;
      2. the most root-cause/evidence tokens appearing in the block itself
         (QUEUE_URL, s3:PutObject, invoices/*);
      3. the resource type the root cause and evidence name (a Lambda error
         -> aws_lambda_function, not its log group or API)."""
    reasons = []
    addrs = {h.address for h in top}
    if all(h.kind == "terraform" for h in top):
        kept = [h for h in top if not (_refs(h.text) & (addrs - {h.address}))]
        if kept and len(kept) < len(top):
            reasons.append("the others only reference it")
            top = kept
    if len(top) > 1:
        tokens = _evidence_tokens(diagnosis, {h.matched.lower() for h in top})

        def overlap(h: Located) -> int:
            blob = h.text.lower()
            return sum(1 for t in tokens if t in blob)
        scores = {id(h): overlap(h) for h in top}
        best = max(scores.values())
        if best > 0 and sum(1 for v in scores.values() if v == best) < len(top):
            reasons.append("it holds the most values the root cause and evidence name")
            top = [h for h in top if scores[id(h)] == best]
    if len(top) > 1:
        text = " ".join([str(diagnosis.get("root_cause") or "")] +
                        [str(e) for e in diagnosis.get("evidence") or []] +
                        [str(r) for r in diagnosis.get("resources_investigated") or []] +
                        [str(r) for r in diagnosis.get("affected_resources") or []]).lower()
        squashed = re.sub(r"[\s_\-]", "", text)
        words = set(re.findall(r"[a-z0-9]+", text))

        def type_score(h: Located) -> int:
            tw = _type_words(h.address)
            if not tw:
                return 0
            svc = re.sub(r"v\d+$", "", tw[0])
            score = 2 if svc and svc in squashed else 0
            score += sum(1 for w in tw[1:] if w in words)
            arn_hit = re.search(rf"arn:aws[a-z\-]*:{re.escape(svc)}:[^\s:]*:[^\s:]*:([a-z\-]+)[:/]", text)
            if arn_hit and arn_hit.group(1).replace("-", "") in "".join(tw[1:]):
                score += 3
            return score
        scores = {id(h): type_score(h) for h in top}
        best = max(scores.values())
        if best > 0 and sum(1 for v in scores.values() if v == best) == 1:
            reasons.append("its resource type is the one the root cause and evidence name")
            top = [h for h in top if scores[id(h)] == best]
    return top, "; ".join(reasons)


def locate(root: str | Path, names: list[str], diagnosis: dict | None = None) -> tuple[list[Located], list[str]]:
    """Return (best matches, kinds searched). Several matches come back only
    when they tie on the best score and the diagnosis can't separate them;
    the caller treats that as ambiguous."""
    root = Path(root).resolve()
    kinds = detect_kinds(root)
    hits: list[Located] = []
    if "terraform" in kinds:
        hits += _locate_terraform(root, names)
    if "cdk" in kinds:
        hits += _locate_cdk_python(root, names)
    if not hits:
        return [], kinds
    best = max(h.score for h in hits)
    top, seen = [], set()
    for h in sorted(hits, key=lambda h: -h.score):
        if h.score == best and (h.file, h.start) not in seen:
            seen.add((h.file, h.start))
            top.append(h)
    if len(top) > 1 and diagnosis:
        n = len(top)
        top, why = _break_tie(top, diagnosis)
        if len(top) == 1 and why:
            top[0].how += f"; chosen over {n - 1} other match{'es' if n > 2 else ''} because {why}"
    return top, kinds


# ── 3. propose ────────────────────────────────────────────────────────────────

def resource_type(address: str) -> str:
    """aws_lambda_function.api -> aws_lambda_function; "OrdersTable (dynamodb.Table)" -> dynamodb.Table."""
    if "(" in address:
        return address.split("(")[-1].rstrip(")")
    return address.split(".")[0]


_PROPOSE_SYSTEM = """\
You write the smallest change to an operator's infrastructure-as-code that fixes a
diagnosed incident. You are shown the diagnosis, the resolved resource (its IaC
address and type) and the exact IaC text of that resource plus the resources and
variables that configure it. Change only that text.

Rules:
- Each edit's "old" must be copied verbatim from the text shown (including
  indentation) and must appear exactly once in its file. Keep edits minimal.
- If an attribute takes its value from a variable that is shown, change the
  variable's default rather than hardcoding the value in the resource.
- Do not invent other resources, files or modules.
- If the root cause cannot be fixed by editing the shown text (for example the
  fix belongs in application code or in a resource not shown), return no edits
  and say why.
- Also write remediation_steps for an operator: concrete steps for THIS resource
  type and THIS IaC tool only (edit the file, then plan/apply or diff/deploy).
  Never name a different service or platform than the resolved resource's, and
  never change the cloud resource directly (console, CLI or API calls that
  modify it), because that bypasses the IaC and drifts. Read-only checks to
  confirm the fix afterwards are fine.

Respond ONLY with JSON:
{"edits": [{"file": "<path as given>", "old": "<exact text>", "new": "<replacement>"}],
 "summary": "<one sentence: what the change does and why it addresses the root cause>",
 "remediation_steps": ["<step>", "..."],
 "reason_if_no_edit": "<only when edits is empty>"}"""


def _propose(diagnosis: dict, loc: Located, client, model_id: str) -> dict:
    shown = [{"file": loc.file, "lines": f"{loc.start}-{loc.end}", "address": loc.address,
              "text": loc.text}]
    shown += [{"file": r["file"], "lines": f'{r["start"]}-{r["end"]}', "address": r["address"],
               "text": r["text"]} for r in loc.related]
    prompt = json.dumps({
        "root_cause": diagnosis.get("root_cause", ""),
        "evidence": (diagnosis.get("evidence") or [])[:8],
        "suggested_remediation_unchecked": diagnosis.get("remediation_steps") or [],
        "resolved_resource": {"address": loc.address, "type": resource_type(loc.address),
                              "file": loc.file},
        "iac_kind": loc.kind,
        "iac_text": shown,
    }, indent=2)
    resp = client.converse(
        modelId=model_id,
        system=[{"text": _PROPOSE_SYSTEM}],
        messages=[{"role": "user", "content": [{"text": prompt}]}],
        inferenceConfig={"maxTokens": 2000, "temperature": 0},
    )
    text = "".join(b.get("text", "") for b in resp["output"]["message"].get("content", []))
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        raise ValueError("model returned no JSON")
    return json.loads(m.group(0))


def _apply_edits(root: Path, loc: Located, edits: list[dict]) -> tuple[dict[str, tuple[str, str]], list[str]]:
    """Apply edits in memory. Each edit must target text inside the located
    block or a variable it reads, and must match exactly once in the file."""
    allowed = {loc.file: [loc.text]}
    for r in loc.related:
        allowed.setdefault(r["file"], []).append(r["text"])
    changed: dict[str, tuple[str, str]] = {}
    problems: list[str] = []
    for e in edits:
        f, old, new = str(e.get("file", "")), e.get("old", ""), e.get("new", "")
        f = f.lstrip("./")
        if f not in allowed:
            problems.append(f"edit to {f!r} rejected: not part of the located resource")
            continue
        if not old or not any(old in t for t in allowed[f]):
            problems.append(f"edit to {f} rejected: 'old' text is not inside the located resource")
            continue
        before, current = changed.get(f, (None, None))
        if current is None:
            before = current = (root / f).read_text(encoding="utf-8")
        if current.count(old) != 1:
            problems.append(f"edit to {f} rejected: 'old' text appears {current.count(old)} times")
            continue
        changed[f] = (before, current.replace(old, new, 1))
    return changed, problems


def _edited_addresses(loc: Located, edits: list[dict], problems: list[str]) -> list[str]:
    """Which shown blocks the accepted edits landed in (the located resource
    or a related one), in order."""
    blocks = [(loc.file, loc.text, loc.address)] + [(r["file"], r["text"], r["address"]) for r in loc.related]
    out: list[str] = []
    for e in edits:
        f, old = str(e.get("file", "")).lstrip("./"), e.get("old", "")
        for bf, bt, ba in blocks:
            if bf == f and old and old in bt and ba not in out:
                out.append(ba)
                break
    return out


# ── 4. check ──────────────────────────────────────────────────────────────────

_SHELL_SYNTAX = re.compile(r"[|&;<>`$(){}*?\n]")


def _app_argv(app: str) -> list[str] | None:
    """Turn the cdk.json ``app`` string into an argv list to run without a
    shell, or None when it needs one (pipes, &&, redirects, variables, globs).
    The executable is resolved on PATH so ``npx`` finds ``npx.cmd`` on Windows."""
    import shlex  # noqa: PLC0415
    if not app.strip() or _SHELL_SYNTAX.search(app):
        return None
    try:
        argv = shlex.split(app, posix=os.name != "nt")
    except ValueError:
        return None
    if not argv:
        return None
    exe = shutil.which(argv[0])
    if exe:
        argv[0] = exe
    return argv


_CHECK_TIMEOUT_S = 240.0


def _check(root: Path, kind: str, changed: dict[str, tuple[str, str]],
           deadline: float | None = None) -> dict:
    """Validate the edited copy. ``deadline`` (a time.monotonic() value) bounds
    the whole check, so it can't push the command past its time limit."""
    if os.environ.get("CLOUDCTL_IAC_FIX_CHECK", "1") == "0":
        return {"status": "not_run", "detail": "checks turned off (CLOUDCTL_IAC_FIX_CHECK=0)"}
    fallback: list[list[str]] = []
    if kind == "terraform":
        tf = os.environ.get("CLOUDCTL_TERRAFORM_BIN") or shutil.which("terraform")
        if not tf:
            return {"status": "not_run", "detail": "terraform not found on PATH"}
        init = [tf, "init", "-backend=false", "-input=false", "-no-color"]
        cmds = [init, [tf, "validate", "-no-color"]]
        installed = root / ".terraform" / "providers"
        if installed.is_dir():
            # Reuse the providers the IaC root already installed instead of
            # downloading them again into the temporary copy (slow, and it
            # needs the network). Fall back to a normal init if that fails.
            cmds[0] = init + [f"-plugin-dir={installed}"]
            fallback = init
        label = "terraform validate"
    else:
        cdk = os.environ.get("CLOUDCTL_CDK_BIN") or shutil.which("cdk")
        if cdk:
            cmds = [[cdk, "synth", "--quiet"]]
            label = "cdk synth"
        else:
            # No cdk CLI: run the app command from cdk.json with CDK_OUTDIR set,
            # which is what `cdk synth` does to produce the cloud assembly.
            try:
                app = json.loads((root / "cdk.json").read_text(encoding="utf-8")).get("app")
            except (OSError, ValueError):
                app = None
            if not app:
                return {"status": "not_run", "detail": "cdk not found on PATH and cdk.json has no app"}
            argv = _app_argv(str(app))
            if argv is None:
                return {"status": "not_run",
                        "detail": "cdk.json app needs a shell (pipes, &&, variables); "
                                  "install the cdk CLI so this check can run"}
            cmds = [argv]
            label = "CDK synth (cdk.json app)"
    with tempfile.TemporaryDirectory(prefix="cctl-iacfix-") as tmp:
        work = Path(tmp) / "iac"
        shutil.copytree(root, work, ignore=_COPY_IGNORE, symlinks=True)
        for f, (_, after) in changed.items():
            (work / f).write_text(after, encoding="utf-8")
        env = {**os.environ, "CDK_OUTDIR": str(Path(tmp) / "cdk.out")}
        for i, cmd in enumerate(cmds):
            r = None
            for attempt in ([cmd, fallback] if i == 0 and fallback else [cmd]):
                timeout = _CHECK_TIMEOUT_S
                if deadline is not None:
                    timeout = min(timeout, deadline - time.monotonic())
                    if timeout < 5:
                        return {"status": "not_run",
                                "detail": f"{label} skipped: no time left in the run's time limit"}
                try:
                    # Always an argv list, never a shell: the cdk.json app string is
                    # split by _app_argv, which refuses anything that needs a shell.
                    r = subprocess.run(attempt, cwd=work, capture_output=True, text=True,
                                       timeout=timeout, env=env)  # nosec B603 - argv list, no shell
                except FileNotFoundError:
                    return {"status": "not_run", "detail": f"{attempt[0]} not found"}
                except subprocess.TimeoutExpired:
                    return {"status": "not_run", "detail": f"{label} timed out"}
                if r.returncode == 0:
                    break
            if r is not None and r.returncode != 0:
                return {"status": "failed", "detail": f"{label} failed: "
                        + (r.stderr or r.stdout).strip()[-800:]}
    return {"status": "passed", "detail": f"{label} passed on a temporary copy"}


# ── entry point ───────────────────────────────────────────────────────────────

def suggest_fix(diagnosis: dict, iac_root: str, client=None, model_id: str | None = None,
                profile: str | None = None, region: str = "us-east-1",
                deadline: float | None = None) -> dict:
    """Read-only IaC fix suggestion for a diagnosis. Never raises; never writes
    to iac_root. Result keys:
      status   suggested | not_found | ambiguous | no_edit | error | no_iac
      verified True only when terraform validate / cdk synth passed
      resource, file, lines, matched, how, diff, summary, check, detail
    """
    root = Path(iac_root).expanduser().resolve()
    if not root.is_dir():
        return {"status": "error", "verified": False, "detail": f"{iac_root} is not a directory"}
    names = candidate_names(diagnosis)
    try:
        hits, kinds = locate(root, names, diagnosis)
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "verified": False, "detail": f"IaC search failed: {type(exc).__name__}"}
    base = {"iac_root": str(root), "searched_for": names[:8], "iac_kinds": kinds, "verified": False}
    if not kinds:
        return {**base, "status": "no_iac",
                "detail": "no Terraform (.tf) files or cdk.json found under the IaC root"}
    if not hits:
        return {**base, "status": "not_found",
                "detail": "none of the blamed resources were found in the IaC; no diff suggested"}
    if len(hits) > 1:
        return {**base, "status": "ambiguous",
                "candidates": [f"{h.address} ({h.file}:{h.start})" for h in hits],
                "detail": "more than one IaC resource matches equally well; no diff suggested"}
    loc = hits[0]
    found = {**base, "resource": loc.address, "resource_type": resource_type(loc.address),
             "kind": loc.kind, "file": loc.file,
             "lines": f"{loc.start}-{loc.end}", "matched": loc.matched, "how": loc.how,
             "related": [r["address"] for r in loc.related]}
    try:
        if client is None:
            from cloudctl.ai.model_providers import make_model_client  # noqa: PLC0415
            client = make_model_client(profile, region)
        if model_id is None:
            from cloudctl.ai.model_providers import default_model  # noqa: PLC0415
            model_id = default_model()
        if deadline is None:
            proposal = _propose(diagnosis, loc, client, model_id)
        else:
            # Leave a little time for the check; abandon a call that runs past it.
            from cloudctl.ai.budget import run_with_timeout  # noqa: PLC0415
            proposal = run_with_timeout(lambda: _propose(diagnosis, loc, client, model_id),
                                        deadline - time.monotonic() - 10)
    except Exception as exc:  # noqa: BLE001
        return {**found, "status": "error", "detail": f"could not get a proposal: {type(exc).__name__}: {str(exc)[:200]}"}
    steps = [str(x) for x in proposal.get("remediation_steps") or [] if str(x).strip()]
    if steps:
        found["remediation_steps"] = steps
    edits = proposal.get("edits") or []
    if not edits:
        return {**found, "status": "no_edit",
                "detail": proposal.get("reason_if_no_edit") or "the model proposed no change to this resource"}
    changed, problems = _apply_edits(root, loc, edits)
    if not changed:
        return {**found, "status": "error", "detail": "; ".join(problems) or "no usable edit"}
    diff = "".join(
        "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
                                     fromfile=f"a/{f}", tofile=f"b/{f}"))
        for f, (before, after) in changed.items())
    check = _check(root, loc.kind, changed, deadline=deadline)
    edited = _edited_addresses(loc, edits, problems)
    return {**found, "status": "suggested", "diff": diff, "summary": proposal.get("summary", ""),
            "edited_resources": edited,
            "check": check, "verified": check.get("status") == "passed",
            "rejected_edits": problems}
