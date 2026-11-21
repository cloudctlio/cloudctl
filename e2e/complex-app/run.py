#!/usr/bin/env python3
"""cctl complex-app harness: deploy, inject a fault, drive load, run cctl, revert, score, tear down.

Runs on Windows, macOS or Linux with Python 3.10+ and boto3 (the cctl venv has it).
Uses whatever AWS credentials boto3 and terraform find (set AWS_PROFILE to your SSO
profile). Every resource is tagged project=cctl-complexapp.

  python run.py preflight            check tools, credentials, Lambda concurrency headroom
  python run.py deploy               terraform init + apply (about 2 to 3 minutes)
  python run.py scenario s1          inject -> load -> wait for symptom -> cctl -> revert -> score
  python run.py all                  every fault scenario in order (s1..s5), then the score table
  python run.py teardown             terraform destroy + sweep for anything left behind

Step by step instead of `scenario`:
  python run.py inject s1 | load s1 --minutes 3 | check s1 | diagnose s1 | revert s1 | score s1

Nothing here pushes to git or calls GitHub. `diagnose` runs cctl read-only (no --resolve).
"""
from __future__ import annotations

import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
APP = Path(os.environ.get("CCTL_COMPLEXAPP_DIR", HERE / "app"))
RUNS = HERE / "runs"
STATE = HERE / ".state"
SCEN = json.loads((HERE / "scenarios.json").read_text(encoding="utf-8"))
REGION = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
PROJECT_TAG = "cctl-complexapp"
FAULT_IDS = ["s1", "s2", "s3", "s4", "s5"]


def scenario(sid: str) -> dict:
    for s in SCEN["scenarios"]:
        if s["id"] == sid:
            return s
    sys.exit(f"unknown scenario {sid}; known: {', '.join(s['id'] for s in SCEN['scenarios'])}")


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ── terraform ─────────────────────────────────────────────────────────────────

def tf_bin() -> str:
    tf = os.environ.get("TERRAFORM_BIN") or shutil.which("terraform")
    if not tf:
        sys.exit("terraform not found: put Terraform 1.9.x on PATH or set TERRAFORM_BIN")
    return tf


def tf(*args: str, capture: bool = False) -> str:
    cmd = [tf_bin(), f"-chdir={APP}", *args]
    env = {**os.environ, "AWS_REGION": REGION, "CHECKPOINT_DISABLE": "1"}
    if capture:
        r = subprocess.run(cmd, capture_output=True, text=True, env=env)
        if r.returncode:
            sys.exit(f"terraform {' '.join(args)} failed:\n{r.stderr or r.stdout}")
        return r.stdout
    r = subprocess.run(cmd, env=env)
    if r.returncode:
        sys.exit(f"terraform {' '.join(args)} failed (exit {r.returncode})")
    return ""


def outputs() -> dict:
    raw = json.loads(tf("output", "-json", capture=True) or "{}")
    if not raw:
        sys.exit("no terraform outputs: run `python run.py deploy` first")
    return {k: v["value"] for k, v in raw.items()}


def tf_apply() -> None:
    tf("apply", "-auto-approve", "-input=false", f"-var=region={REGION}")


# ── AWS clients ───────────────────────────────────────────────────────────────

def aws(service: str):
    import boto3  # noqa: PLC0415
    return boto3.client(service, region_name=REGION)


# ── fault injection ───────────────────────────────────────────────────────────

def _edit(edits: list[dict], forward: bool) -> None:
    """Apply (or undo) text edits to app/*.tf. Each 'before' must occur exactly once."""
    planned = []
    for e in edits:
        path = APP / e["file"]
        text = path.read_text(encoding="utf-8")
        old, new = (e["before"], e["after"]) if forward else (e["after"], e["before"])
        n = text.count(old)
        if n != 1:
            already = text.count(new) == 1
            state = "already applied" if already else f"found {n} times"
            sys.exit(f"{e['file']}: edit anchor {state}; expected exactly once. "
                     f"Is another scenario still injected? Try `python run.py revert <id>`.")
        planned.append((path, text.replace(old, new, 1)))
    for path, text in planned:
        path.write_text(text, encoding="utf-8", newline="\n")


def active() -> dict:
    p = STATE / "active.json"
    return json.loads(p.read_text()) if p.exists() else {}


def set_active(d: dict) -> None:
    STATE.mkdir(exist_ok=True)
    (STATE / "active.json").write_text(json.dumps(d, indent=1))


def inject(sid: str) -> None:
    s = scenario(sid)
    cur = active()
    if cur.get("scenario") and cur["scenario"] != sid:
        sys.exit(f"scenario {cur['scenario']} is still injected; run `python run.py revert {cur['scenario']}` first")
    start = time.time()
    if s["kind"] == "iac":
        _edit(s["edits"], forward=True)
        log(f"{sid}: applied the bad commit to {', '.join(sorted({e['file'] for e in s['edits']}))}; terraform apply")
        tf_apply()
    elif s["kind"] == "drift":
        out = outputs()
        if s["drift"]["action"] == "disable_event_source_mapping":
            aws("lambda").update_event_source_mapping(UUID=out["worker_event_source_mapping"], Enabled=False)
            log(f"{sid}: disabled event source mapping {out['worker_event_source_mapping']} outside Terraform")
    else:
        log(f"{sid}: control scenario, nothing injected")
    set_active({"scenario": sid, "injected_at": int(start), "inject_s": round(time.time() - start, 1)})


def revert(sid: str) -> None:
    s = scenario(sid)
    start = time.time()
    if s["kind"] == "iac":
        _edit(s["edits"], forward=False)
        log(f"{sid}: reverted the bad commit; terraform apply")
        tf_apply()
    elif s["kind"] == "drift":
        log(f"{sid}: terraform apply to put the drifted resource back")
        tf_apply()
    purge_queues()
    set_active({})
    log(f"{sid}: reverted in {time.time() - start:.0f} s")


def purge_queues() -> None:
    """Empty the queue and DLQ so the next scenario starts clean (SQS allows one purge per 60 s)."""
    out = outputs()
    sqs = aws("sqs")
    for key in ("orders_queue_url", "orders_dlq_url"):
        try:
            sqs.purge_queue(QueueUrl=out[key])
        except Exception as exc:  # noqa: BLE001
            log(f"purge {key}: {type(exc).__name__} (ok if a purge ran in the last 60 s)")


# ── load ──────────────────────────────────────────────────────────────────────

class Load:
    """Steady mixed traffic: POST /orders and GET /orders/{id}. Stdlib only."""

    def __init__(self, base_url: str, profile: dict):
        self.base = base_url.rstrip("/")
        self.p = profile
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.counts: dict[str, int] = {}
        self.created: list[str] = []
        self.pool = ThreadPoolExecutor(max_workers=16)
        self.thread: threading.Thread | None = None

    def _req(self, method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, {}
        except Exception:  # noqa: BLE001
            return 0, {}

    def _one(self) -> None:
        if random.random() < self.p.get("get_ratio", 0.2):
            with self.lock:
                oid = random.choice(self.created) if self.created else str(uuid.uuid4())
            code, _ = self._req("GET", f"/orders/{oid}")
            key = f"GET {code}"
        else:
            large = random.random() < self.p.get("large_ratio", 0.1)
            body = {"items": random.randint(8, 10) if large else random.randint(1, 3),
                    "receipt": random.random() < self.p.get("receipt_ratio", 0.2),
                    "customer": f"load-{random.randint(1, 500)}"}
            code, resp = self._req("POST", "/orders", body)
            key = f"POST {code}"
            if code == 202 and resp.get("order_id"):
                with self.lock:
                    self.created.append(resp["order_id"])
        with self.lock:
            self.counts[key] = self.counts.get(key, 0) + 1

    def _run(self) -> None:
        interval = 1.0 / max(self.p.get("rps", 5), 0.1)
        nxt = time.time()
        while not self.stop.is_set():
            self.pool.submit(self._one)
            nxt += interval
            time.sleep(max(0.0, nxt - time.time()))

    def start(self) -> "Load":
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        return self

    def finish(self) -> None:
        self.stop.set()
        if self.thread:
            self.thread.join()
        self.pool.shutdown(wait=True)

    def post_5xx_ratio(self) -> float:
        with self.lock:
            post = sum(v for k, v in self.counts.items() if k.startswith("POST"))
            bad = sum(v for k, v in self.counts.items() if k.startswith("POST 5"))
        return bad / post if post else 0.0

    def sample_status(self, n: int = 40, min_age_s: int = 20) -> dict:
        """Look up a sample of orders created at least min_age_s ago (what a user would see)."""
        with self.lock:
            ids = self.created[:-max(1, int(self.p.get("rps", 5) * min_age_s))] or self.created[:]
        ids = random.sample(ids, min(n, len(ids)))
        tally = {"PENDING": 0, "PROCESSED": 0, "PROCESSED_unnotified": 0, "other": 0}
        for oid in ids:
            code, item = self._req("GET", f"/orders/{oid}")
            st = item.get("status") if code == 200 else None
            if st == "PROCESSED":
                tally["PROCESSED"] += 1
                if "notified" not in item:
                    tally["PROCESSED_unnotified"] += 1
            elif st == "PENDING":
                tally["PENDING"] += 1
            else:
                tally["other"] += 1
        tally["sampled"] = len(ids)
        return tally

    def summary(self) -> dict:
        with self.lock:
            return {"requests": dict(sorted(self.counts.items())), "orders_created": len(self.created)}


# ── symptom check ─────────────────────────────────────────────────────────────

def queue_attrs(url: str) -> dict:
    a = aws("sqs").get_queue_attributes(QueueUrl=url, AttributeNames=["All"])["Attributes"]
    return {"visible": int(a.get("ApproximateNumberOfMessages", 0)),
            "in_flight": int(a.get("ApproximateNumberOfMessagesNotVisible", 0))}


def oldest_age_s(queue_name: str) -> float:
    cw = aws("cloudwatch")
    end = time.time()
    r = cw.get_metric_statistics(Namespace="AWS/SQS", MetricName="ApproximateAgeOfOldestMessage",
                                 Dimensions=[{"Name": "QueueName", "Value": queue_name}],
                                 StartTime=end - 600, EndTime=end, Period=60, Statistics=["Maximum"])
    return max((p["Maximum"] for p in r.get("Datapoints", [])), default=0.0)


def check(sid: str, load: Load | None = None) -> tuple[bool, dict]:
    s = scenario(sid)
    c = s.get("symptom_check") or {}
    out = outputs()
    q = queue_attrs(out["orders_queue_url"])
    dlq = queue_attrs(out["orders_dlq_url"])
    facts: dict = {"queue": q, "dlq": dlq}
    ok = True
    if "dlq_min" in c:
        ok &= dlq["visible"] >= c["dlq_min"]
    if "queue_age_s_min" in c:
        age = oldest_age_s(out["orders_queue_url"].rsplit("/", 1)[-1])
        facts["oldest_message_age_s"] = age
        ok_age = age >= c["queue_age_s_min"]
        ok &= ok_age or dlq["visible"] >= c.get("or_dlq_min", 10**9)
    if "queue_visible_min" in c:
        ok &= q["visible"] >= c["queue_visible_min"]
    if "and_esm_state" in c:
        st = aws("lambda").get_event_source_mapping(UUID=out["worker_event_source_mapping"])["State"]
        facts["esm_state"] = st
        ok &= st == c["and_esm_state"]
    if load is not None:
        facts["load"] = load.summary()
        if "post_5xx_ratio_min" in c:
            facts["post_5xx_ratio"] = round(load.post_5xx_ratio(), 2)
            ok &= facts["post_5xx_ratio"] >= c["post_5xx_ratio_min"]
        if "and_processed_unnotified_min" in c:
            st = load.sample_status()
            facts["sample"] = st
            ok &= st["PROCESSED_unnotified"] >= c["and_processed_unnotified_min"]
    elif "post_5xx_ratio_min" in c or "and_processed_unnotified_min" in c:
        facts["note"] = "part of this check needs the load running (use `scenario` or `load`)"
    return bool(ok), facts


# ── cctl ──────────────────────────────────────────────────────────────────────

def cctl_cmd(sid: str, out_json: Path) -> list[str]:
    exe = os.environ.get("CCTL_BIN") or shutil.which("cloudctl") or "cloudctl"
    cmd = [exe, "debug", "--agent", "--region", REGION, "--json-out", str(out_json),
           "--verdict", "skip", scenario(sid)["symptom"]]
    if os.environ.get("CCTL_NO_IAC_ROOT") != "1":
        cmd[3:3] = ["--iac-root", str(APP)]
    return cmd


class PauseWatch:
    """Counts time the host spent asleep while cctl ran.

    A thread wakes every few seconds; when the wall clock jumped much further
    than that between wakes, the machine was suspended (a sleeping thread does
    not run). The gap beyond the tick counts as paused time.
    """

    def __init__(self, tick_s: float = 5.0, slack_s: float = 25.0) -> None:
        self.tick_s, self.slack_s, self.paused_s = tick_s, slack_s, 0.0
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        last = time.time()
        while not self._stop.wait(self.tick_s):
            now = time.time()
            gap = now - last - self.tick_s
            if gap > self.slack_s:
                self.paused_s += gap
            last = now

    def __enter__(self) -> "PauseWatch":
        self._t.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._t.join(timeout=self.tick_s * 2)


def diagnose(sid: str) -> dict:
    RUNS.mkdir(exist_ok=True)
    out_json = RUNS / f"{sid}.json"
    log_path = RUNS / f"{sid}.log"
    cmd = cctl_cmd(sid, out_json)
    log(f"{sid}: running cctl (log: {log_path.name})")
    log("  " + " ".join(f'"{c}"' if " " in c else c for c in cmd))
    env = {**os.environ, "AWS_REGION": REGION, "PYTHONIOENCODING": "utf-8"}
    # Record what the diff-first checks read, for offline replay. The path is
    # built here in Python so it is a real Windows path even when the harness
    # is started from Git Bash (a POSIX path in the shell can't be opened by
    # Windows Python). CCTL_DIFF_FIRST_RECORD=0 turns recording off.
    df_rec = RUNS / f"{sid}.diff-first.json"
    if os.environ.get("CCTL_DIFF_FIRST_RECORD") != "0":
        env["CLOUDCTL_DIFF_FIRST_RECORD"] = str(df_rec.resolve())
    else:
        env.pop("CLOUDCTL_DIFF_FIRST_RECORD", None)
    start = time.time()
    with open(log_path, "w", encoding="utf-8") as fh, PauseWatch() as pw:
        r = subprocess.run(cmd, stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                           env=env)
    wall = round(time.time() - start, 1)
    meta = {"scenario": sid, "wall_seconds": wall, "host_paused_s": round(pw.paused_s, 1),
            "exit_code": r.returncode, "command": cmd,
            "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            # What the shell asked for, and what cctl says it called.
            "model_env": {k: os.environ[k] for k in ("CLOUDCTL_MODEL", "CLOUDCTL_CRITIC_MODEL",
                                                      "CLOUDCTL_LOG_MODEL") if os.environ.get(k)}}
    try:
        meta["models"] = json.loads(out_json.read_text(encoding="utf-8")).get("_models")
    except (OSError, ValueError, AttributeError):
        meta["models"] = None
    (RUNS / f"{sid}.meta.json").write_text(json.dumps(meta, indent=1))
    # The declared state cctl compared against, so the diff-first recording can
    # be replayed after teardown (terraform destroy empties the state file).
    st = APP / "terraform.tfstate"
    if st.exists():
        (RUNS / f"{sid}.tfstate.json").write_bytes(st.read_bytes())
    log(f"{sid}: cctl finished in {wall} s (exit {r.returncode})"
        + (f"; the host was asleep {pw.paused_s:.0f} s of that" if pw.paused_s else ""))
    if not out_json.exists():
        log(f"{sid}: cctl wrote no JSON; see {log_path}")
    else:
        log(f"{sid}: {diff_first_line(out_json)}")
    return meta


def diff_first_line(out_json: Path) -> str:
    """One line on whether the diff-first checks ran, so a skipped run shows."""
    try:
        df = json.loads(out_json.read_text(encoding="utf-8")).get("diff_first")
    except (OSError, ValueError):
        return "diff-first: could not read the result JSON"
    if not df:
        return "diff-first: no diff_first block in the result (older cctl, or the run stopped early)"
    if df.get("ran") is False:
        return f"diff-first: DID NOT RUN: {df.get('error')}"
    causes = "; ".join(c.get("summary", "")[:90] for c in df.get("causes") or []) or "none"
    extra = f"; recording not saved: {df['recording_error']}" if df.get("recording_error") else ""
    return (f"diff-first: ran ({df.get('expected_state')}), confidence {df.get('confidence')}, "
            f"causes: {causes}{extra}")


# ── orchestration ─────────────────────────────────────────────────────────────

def run_scenario(sid: str, warmup_max_min: float, load_after_s: int) -> None:
    s = scenario(sid)
    out = outputs()
    log(f"== {sid} {s['title']}")
    purge_queues()
    t0 = time.time()
    inject(sid)
    load = Load(out["api_url"], s["load"]).start()
    log(f"{sid}: load running at {s['load']['rps']} rps; waiting for the symptom (up to {warmup_max_min} min)")
    deadline = time.time() + warmup_max_min * 60
    seen, facts = False, {}
    time.sleep(60)
    while time.time() < deadline:
        seen, facts = check(sid, load)
        log(f"{sid}: symptom {'present' if seen else 'not yet'}: {json.dumps(facts)[:300]}")
        if seen:
            break
        time.sleep(30)
    if s["kind"] == "none":
        seen = True
    symptom_s = round(time.time() - t0, 1)
    meta = {"symptom_seen": seen, "symptom_facts": facts, "inject_to_symptom_s": symptom_s}
    if not seen:
        log(f"{sid}: symptom never showed; cctl is still run, but score it as 'fault did not manifest'")
    try:
        meta.update(diagnose(sid))
    finally:
        time.sleep(load_after_s)
        load.finish()
        meta["load"] = load.summary()
        revert(sid)
    meta["scenario_total_s"] = round(time.time() - t0, 1)
    (RUNS / f"{sid}.meta.json").write_text(json.dumps(meta, indent=1))
    # The declared state cctl compared against, so the diff-first recording can
    # be replayed after teardown (terraform destroy empties the state file).
    st = APP / "terraform.tfstate"
    if st.exists():
        (RUNS / f"{sid}.tfstate.json").write_bytes(st.read_bytes())
    score(sid)


def score(sid: str | None) -> None:
    cmd = [sys.executable, str(HERE / "score.py"), "--runs", str(RUNS)]
    if sid:
        cmd += ["--scenario", sid]
    subprocess.run(cmd)


_DF_GROUPS = ("causes", "likely_reverts", "one_off_actions", "unchecked_leads", "may_be_over", "standing",
              "unexplained")


def summary(runs: Path) -> str:
    """Per scenario: verdict, time, model ids and the diff-first keys and groups.

    Reads only files in runs/ (scorecard.json, s*.meta.json, s*.json); no AWS calls.
    """
    def read(p: Path):
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
    card = {r.get("scenario"): r for r in read(runs / "scorecard.json") or [] if isinstance(r, dict)}
    lines = [f"== summary of {runs}"]
    for sid in FAULT_IDS:
        meta, res = read(runs / f"{sid}.meta.json"), read(runs / f"{sid}.json")
        if meta is None and res is None:
            continue
        meta, res, sc = meta or {}, res if isinstance(res, dict) else {}, card.get(sid) or {}
        lines.append(f"{sid}: verdict {sc.get('verdict', '?')}, confidence {sc.get('confidence', '?')}, "
                     f"cctl {meta.get('wall_seconds', '?')} s wall, {meta.get('host_paused_s', 0)} s asleep "
                     f"(exit {meta.get('exit_code', '?')}), "
                     f"scenario {meta.get('scenario_total_s', '?')} s, symptom seen {meta.get('symptom_seen', '?')}")
        if sc.get("notes"):
            lines.append(f"  notes: {'; '.join(sc['notes'])}")
        lines.append(f"  model asked: {json.dumps(meta.get('model_env') or {})}")
        lines.append(f"  models used: {json.dumps(meta.get('models') or res.get('_models'))}")
        df = res.get("diff_first")
        if not isinstance(df, dict):
            lines.append("  diff_first: missing" + ("" if res else " (no result JSON)"))
            continue
        lines.append(f"  diff_first keys: {', '.join(sorted(df))}")
        if df.get("window"):
            lines.append(f"  window: {json.dumps(df['window'])}")
        if df.get("ran") is False:
            lines.append(f"  diff_first DID NOT RUN: {df.get('error')}")
        for g in _DF_GROUPS:
            items = df.get(g)
            if items is None:
                continue
            names = ([str(c.get("summary") if isinstance(c, dict) else c)[:100] for c in items]
                     if isinstance(items, list) else [str(items)[:100]])
            lines.append(f"  {g} ({len(names)}): {' | '.join(names) or '-'}")
    if len(lines) == 1:
        lines.append(f"no results in {runs}")
    return "\n".join(lines)


def preflight() -> None:
    import boto3  # noqa: PLC0415
    v = subprocess.run([tf_bin(), "version", "-json"], capture_output=True, text=True)
    tfv = json.loads(v.stdout or "{}").get("terraform_version", "?")
    log(f"terraform {tfv}" + ("" if tfv.startswith(("1.6", "1.7", "1.8", "1.9", "1.1")) else "  (need >= 1.6; 1.9.8 tested)"))
    ident = boto3.client("sts", region_name=REGION).get_caller_identity()
    log(f"AWS account {ident['Account']} as {ident['Arn'].split('/')[-2] if '/' in ident['Arn'] else ident['Arn']}, region {REGION}")
    lim = aws("lambda").get_account_settings()["AccountLimit"]
    log(f"Lambda concurrency limit {lim['ConcurrentExecutions']}, unreserved {lim['UnreservedConcurrentExecutions']}")
    if lim["UnreservedConcurrentExecutions"] < 11:
        log("WARNING: s2 needs to reserve 1 concurrency and keep 10 unreserved; it will fail to apply here")
    cctl = os.environ.get("CCTL_BIN") or shutil.which("cloudctl")
    log(f"cloudctl: {cctl or 'NOT FOUND (activate the cctl venv or set CCTL_BIN)'}")
    h = subprocess.run([cctl or "cloudctl", "debug", "--help"], capture_output=True, text=True) if cctl else None
    if h and "--iac-root" not in (h.stdout or ""):
        log("WARNING: this cctl has no --iac-root; check out the branch with PR #39 (feat/iac-fix-suggestion)")
    left = tagged_leftovers()
    if left:
        log(f"note: {len(left)} resources already tagged project={PROJECT_TAG} exist (earlier deploy?)")


def tagged_leftovers() -> list[str]:
    tag = aws("resourcegroupstaggingapi")
    arns: list[str] = []
    for page in tag.get_paginator("get_resources").paginate(
            TagFilters=[{"Key": "project", "Values": [PROJECT_TAG]}]):
        arns += [m["ResourceARN"] for m in page["ResourceTagMappingList"]]
    return arns


def teardown() -> None:
    cur = active()
    if cur.get("scenario") and scenario(cur["scenario"])["kind"] == "iac":
        log(f"reverting text edits of {cur['scenario']} before destroy")
        _edit(scenario(cur["scenario"])["edits"], forward=False)
    tf("destroy", "-auto-approve", "-input=false", f"-var=region={REGION}")
    set_active({})
    time.sleep(5)
    left = tagged_leftovers()
    logs = aws("logs").describe_log_groups(logGroupNamePrefix="/aws/lambda/cctl-complexapp")["logGroups"]
    if left or logs:
        log("LEFT BEHIND (the tagging API can lag a few minutes; rerun teardown to recheck):")
        for a in left:
            log(f"  {a}")
        for g in logs:
            log(f"  log group {g['logGroupName']}")
    else:
        log(f"clean: no resources tagged project={PROJECT_TAG} and no cctl-complexapp log groups remain")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["preflight", "deploy", "inject", "load", "check", "diagnose",
                                        "revert", "score", "scenario", "all", "teardown", "cmd",
                                        "summary"])
    ap.add_argument("sid", nargs="?")
    ap.add_argument("--minutes", type=float, default=3.0, help="load: how long to run")
    ap.add_argument("--warmup-max", type=float, default=6.0, help="scenario: max minutes to wait for the symptom")
    ap.add_argument("--load-after", type=int, default=0, help="scenario: seconds of load after cctl finishes")
    a = ap.parse_args()
    need_sid = {"inject", "load", "check", "diagnose", "revert", "scenario", "cmd"}
    if a.command in need_sid and not a.sid:
        sys.exit(f"{a.command} needs a scenario id, e.g. s1")
    if a.command == "preflight":
        preflight()
    elif a.command == "deploy":
        tf("init", "-input=false")
        tf_apply()
        log(f"deployed; API: {outputs()['api_url']}")
    elif a.command == "inject":
        inject(a.sid)
    elif a.command == "revert":
        revert(a.sid)
    elif a.command == "load":
        ld = Load(outputs()["api_url"], scenario(a.sid)["load"]).start()
        time.sleep(a.minutes * 60)
        ok, facts = check(a.sid, ld)
        ld.finish()
        print(json.dumps({"symptom_present": ok, **facts}, indent=1))
    elif a.command == "check":
        ok, facts = check(a.sid)
        print(json.dumps({"symptom_present": ok, **facts}, indent=1))
    elif a.command == "diagnose":
        diagnose(a.sid)
    elif a.command == "cmd":
        print(" ".join(f'"{c}"' if " " in c else c for c in cctl_cmd(a.sid, RUNS / f"{a.sid}.json")))
    elif a.command == "score":
        score(a.sid)
    elif a.command == "scenario":
        run_scenario(a.sid, a.warmup_max, a.load_after)
    elif a.command == "all":
        for sid in FAULT_IDS:
            run_scenario(sid, a.warmup_max, a.load_after)
        score(None)
    elif a.command == "teardown":
        teardown()
    elif a.command == "summary":
        print(summary(RUNS))


if __name__ == "__main__":
    main()
