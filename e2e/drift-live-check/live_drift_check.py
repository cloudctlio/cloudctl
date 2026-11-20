"""Live check for cctl PR 45 (monitor drift + who made each change).

Run from the repo root with the repo's venv, one case at a time:
    python e2e/drift-live-check/live_drift_check.py d3     # QUEUE_URL changed by hand with boto3
    python e2e/drift-live-check/live_drift_check.py c2     # the same change made by terraform apply
    python e2e/drift-live-check/live_drift_check.py alarm  # DLQ alarm threshold raised by hand
    python e2e/drift-live-check/live_drift_check.py final  # nothing left changed?

Each case: check the stack is clean, make the change, re-run cctl's diff-first
checks (read-only, no model calls) until CloudTrail shows the change, compare
the result with what is expected, then put everything back and check again.
Results go to e2e/complex-app/runs/drift-live-<case>.json.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO = Path.cwd()
APP = REPO / "e2e" / "complex-app" / "app"
RUNS = REPO / "e2e" / "complex-app" / "runs"
P = "cctl-complexapp"
API_FN = f"{P}-api"
ALARM = f"{P}-orders-dlq-not-empty"
API_KEY = "aws_lambda_function.api"
ALARM_KEY = "aws_cloudwatch_metric_alarm.dlq_depth"
TF_LINE = "QUEUE_URL  = aws_sqs_queue.orders.url"
TF_BAD = 'QUEUE_URL  = "${aws_sqs_queue.orders.url}-v2"'
WAIT_MIN = 25          # CloudTrail usually shows a call within 5 to 15 minutes


def env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        sys.exit(f"set {name} first")
    return v


PROFILE, REGION, TF = env("AWS_PROFILE"), os.environ.get("AWS_REGION", "us-east-1"), env("TERRAFORM_BIN")


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def client(svc: str):
    import boto3
    return boto3.Session(profile_name=PROFILE, region_name=REGION).client(svc)


def tf(*args: str, ok=(0,)) -> int:
    r = subprocess.run([TF, f"-chdir={APP}", *args, f"-var=region={REGION}"] if args[0] in ("apply", "plan")
                       else [TF, f"-chdir={APP}", *args],
                       env={**os.environ, "CHECKPOINT_DISABLE": "1"})
    if r.returncode not in ok:
        sys.exit(f"terraform {args[0]} failed (exit {r.returncode})")
    return r.returncode


def apply() -> None:
    log("terraform apply (put the stack back to what the IaC declares)")
    tf("apply", "-auto-approve", "-input=false")


def plan_clean() -> bool:
    return tf("plan", "-detailed-exitcode", "-input=false", "-lock=false", ok=(0, 2)) == 0


def _git(*args: str) -> bytes:
    return subprocess.run(["git", *args], capture_output=True, check=True).stdout


def git_dirty() -> list[str]:
    """Tracked files that really differ from the commit. A file that only
    differs in line endings (CRLF on Windows) doesn't count."""
    names = set(_git("diff", "--name-only", "HEAD").decode().split("\n")) - {""}
    dirty = []
    for name in sorted(names):
        path = REPO / name
        try:
            head = _git("show", f"HEAD:{name}")
        except subprocess.CalledProcessError:
            dirty.append(name)              # added and staged
            continue
        work = path.read_bytes() if path.exists() else None
        if work is None or work.replace(b"\r\n", b"\n") != head.replace(b"\r\n", b"\n"):
            dirty.append(name)
    return dirty


def preflight() -> None:
    if git_dirty():
        sys.exit(f"tracked files are changed: {', '.join(git_dirty())}. Finish or revert the earlier run first.")
    if not (APP / "terraform.tfstate").exists():
        sys.exit("no stack: run `python e2e/complex-app/run.py deploy` first")
    if not plan_clean():
        sys.exit("terraform plan shows changes before the test; run `python e2e/complex-app/run.py revert <id>` "
                 "for an unfinished scenario, or apply, then retry")


# ── the changes ───────────────────────────────────────────────────────────────

def wait_fn() -> None:
    client("lambda").get_waiter("function_updated_v2").wait(FunctionName=API_FN)


def d3_inject() -> None:
    lam = client("lambda")
    wait_fn()
    vars_ = lam.get_function_configuration(FunctionName=API_FN)["Environment"]["Variables"]
    vars_["QUEUE_URL"] = vars_["QUEUE_URL"] + "-v2"
    lam.update_function_configuration(FunctionName=API_FN, Environment={"Variables": vars_})
    wait_fn()
    log("D3: api QUEUE_URL changed by hand with boto3")


def c2_inject() -> None:
    f = APP / "lambda.tf"
    text = f.read_text(encoding="utf-8")
    if text.count(TF_LINE) != 1:
        sys.exit(f"expected exactly one `{TF_LINE}` in lambda.tf")
    f.write_text(text.replace(TF_LINE, TF_BAD), encoding="utf-8")
    log("C2: lambda.tf edited, applying with Terraform")
    apply()


def c2_revert() -> None:
    subprocess.run(["git", "checkout", "--", str(APP / "lambda.tf")], check=True)
    apply()


def alarm_inject() -> None:
    cw = client("cloudwatch")
    a = cw.describe_alarms(AlarmNames=[ALARM], AlarmTypes=["MetricAlarm"])["MetricAlarms"][0]
    keep = ["AlarmName", "AlarmDescription", "ActionsEnabled", "OKActions", "AlarmActions",
            "InsufficientDataActions", "MetricName", "Namespace", "Statistic", "Dimensions", "Period",
            "EvaluationPeriods", "DatapointsToAlarm", "ComparisonOperator", "TreatMissingData", "Unit"]
    body = {k: a[k] for k in keep if a.get(k) not in (None, "")}
    body["Threshold"] = 100.0
    cw.put_metric_alarm(**body)
    log("ALARM: DLQ alarm threshold raised 0 -> 100 by hand with boto3")


# ── what diff-first must say ─────────────────────────────────────────────────

def _t(s: str) -> datetime:
    return datetime.fromisoformat(str(s).replace("Z", "+00:00"))


def _new(rep: dict, key: str, prefix: str, since: datetime) -> list[dict]:
    return [c for c in rep.get("changes") or []
            if key in (c.get("resource_key") or "").split(",")
            and str(c.get("event_name", "")).startswith(prefix) and c.get("time") and _t(c["time"]) >= since]


def _app_drift(rep: dict, key: str) -> list[dict]:
    return [d for d in rep.get("drift") or [] if d.get("resource_key") == key and not d.get("observer")]


def _check(name: str, ok: bool, got) -> tuple[str, bool, str]:
    return name, bool(ok), json.dumps(got, default=str)[:300]


def check_d3(rep: dict, since: datetime) -> list | None:
    ch = _new(rep, API_KEY, "UpdateFunctionConfiguration", since)
    if not ch:
        return None
    c, dr = ch[-1], _app_drift(rep, API_KEY)
    return [
        _check("drift on api QUEUE_URL", any(f["field"].endswith("queueurl") for d in dr for f in d["fields"]),
               [f["field"] for d in dr for f in d["fields"]]),
        _check("drift labelled manual", bool(dr) and dr[0].get("route") == "manual", dr[0].get("route") if dr else None),
        _check("change route manual / sdk", (c.get("route"), c.get("route_how")) == ("manual", "sdk"),
               [c.get("route"), c.get("route_how"), c.get("route_confidence")]),
        _check("matches_iac False", c.get("matches_iac") is False, c.get("matches_iac")),
        _check("fix direction reapply_iac", c.get("fix_direction") == "reapply_iac", c.get("fix_direction")),
    ]


def check_c2(rep: dict, since: datetime) -> list | None:
    ch = _new(rep, API_KEY, "UpdateFunctionConfiguration", since)
    if not ch:
        return None
    c, dr = ch[-1], _app_drift(rep, API_KEY)
    return [
        _check("no drift on api", not dr, [f["field"] for d in dr for f in d["fields"]]),
        _check("change route iac / terraform", (c.get("route"), c.get("route_how")) == ("iac", "terraform"),
               [c.get("route"), c.get("route_how"), c.get("route_confidence"), c.get("user_agent", "")[:60]]),
        _check("matches_iac True", c.get("matches_iac") is True, c.get("matches_iac")),
        _check("fix direction edit_iac", c.get("fix_direction") == "edit_iac", c.get("fix_direction")),
    ]


def check_alarm(rep: dict, since: datetime) -> list | None:
    ch = _new(rep, ALARM_KEY, "PutMetricAlarm", since)
    if not ch:
        return None
    c = ch[-1]
    obs = [o for o in rep.get("observer_drift") or [] if o.get("resource_key") == ALARM_KEY]
    causes = (rep.get("explanation") or {}).get("causes") or []
    alts = (rep.get("explanation") or {}).get("alternatives") or []
    return [
        _check("monitor drift on threshold", any(f["field"] == "threshold" for o in obs for f in o["fields"]),
               [o["fields"] for o in obs]),
        _check("monitor drift labelled manual", bool(obs) and obs[0].get("route") == "manual",
               obs[0].get("route") if obs else None),
        _check("PutMetricAlarm status observer", c.get("status") == "observer", c.get("status")),
        _check("change route manual", c.get("route") == "manual", [c.get("route"), c.get("route_how")]),
        _check("alarm never a cause", not any(ALARM in str(x.get("summary")) or "PutMetricAlarm" in str(x.get("summary"))
                                              for x in causes + alts), [x.get("summary") for x in causes]),
    ]


def diff_first() -> dict:
    os.environ.setdefault("CLOUDCTL_DIFF_FIRST_BUDGET_S", "240")
    os.environ.setdefault("CLOUDCTL_TERRAFORM_BIN", TF)
    from cloudctl.debug.diff_first.run import run_for_agent
    return run_for_agent(PROFILE, REGION, str(APP))


def wait_and_check(case: str, check, since: datetime) -> bool:
    deadline = time.monotonic() + WAIT_MIN * 60
    rep, result = {}, None
    while time.monotonic() < deadline:
        rep = diff_first()
        if rep.get("error"):
            log(f"diff-first error: {rep['error']}")
        result = check(rep, since)
        if result is not None:
            break
        log("CloudTrail doesn't show the change yet; checking again in 60 s")
        time.sleep(60)
    RUNS.mkdir(parents=True, exist_ok=True)
    keep = {k: rep.get(k) for k in ("error", "expected_kind", "window", "drift", "observer_drift", "notes",
                                    "drift_stats", "clouds")}
    keep["changes"] = [c for c in rep.get("changes") or [] if c.get("time") and _t(c["time"]) >= since]
    keep["causes"] = [c.get("summary") for c in (rep.get("explanation") or {}).get("causes") or []]
    keep["checks"] = result
    out = RUNS / f"drift-live-{case}.json"
    out.write_text(json.dumps(keep, indent=1, default=str), encoding="utf-8")
    if result is None:
        log(f"FAIL: the change never showed in CloudTrail within {WAIT_MIN} min (saved {out})")
        return False
    for name, ok, got in result:
        log(f"{'PASS' if ok else 'FAIL'}  {name}  ({got})")
    log(f"saved {out}")
    return all(ok for _, ok, _ in result)


def final() -> bool:
    lam, cw, sqs = client("lambda"), client("cloudwatch"), client("sqs")
    good_url = sqs.get_queue_url(QueueName=f"{P}-orders")["QueueUrl"]
    qurl = lam.get_function_configuration(FunctionName=API_FN)["Environment"]["Variables"].get("QUEUE_URL")
    thr = cw.describe_alarms(AlarmNames=[ALARM])["MetricAlarms"][0]["Threshold"]
    checks = [("api QUEUE_URL is the real queue", qurl == good_url, qurl),
              ("DLQ alarm threshold is 0", thr == 0, thr),
              ("tracked files unchanged", not git_dirty(), git_dirty()),
              ("terraform plan shows no changes", plan_clean(), "")]
    for name, ok, got in checks:
        log(f"{'PASS' if ok else 'FAIL'}  {name}  {got}")
    return all(ok for _, ok, _ in checks)


CASES = {"d3": (d3_inject, apply, check_d3), "c2": (c2_inject, c2_revert, check_c2),
         "alarm": (alarm_inject, apply, check_alarm)}


def main() -> None:
    case = (sys.argv[1:] or [""])[0]
    if case == "final":
        sys.exit(0 if final() else 1)
    if case not in CASES:
        sys.exit(f"usage: python {Path(__file__).name} d3|c2|alarm|final")
    inject, revert, check = CASES[case]
    preflight()
    since = datetime.now(timezone.utc).replace(microsecond=0)
    passed = False
    try:
        inject()
        passed = wait_and_check(case, check, since)
    finally:
        log("putting it back")
        revert()
        ok = final()
        log(f"revert {'done, nothing left changed' if ok else 'INCOMPLETE: see FAIL lines above'}")
    log(f"{case.upper()}: {'ALL PASS' if passed else 'SOME CHECKS FAILED'}")
    sys.exit(0 if passed and ok else 1)


if __name__ == "__main__":
    main()
