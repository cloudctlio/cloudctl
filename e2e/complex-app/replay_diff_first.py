#!/usr/bin/env python3
"""Replay a scenario's diff-first checks offline and print what they saw.

    python e2e/complex-app/replay_diff_first.py s5            (from the repo root)
    python replay_diff_first.py s5 --runs runs --state my.tfstate

Read-only: it reads runs/<id>.diff-first.json (the inputs cctl recorded during
the run) and a Terraform state, and makes no AWS or model calls. The state is
the first that exists of: --state, runs/<id>.tfstate.json (saved by run.py
after each cctl run), app/terraform.tfstate if it still lists resources, and
app/terraform.tfstate.backup (after teardown it holds the state from before
destroy). The recording is overwritten by the next run of the same scenario.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _has_resources(p: Path) -> bool:
    try:
        return bool(json.loads(p.read_text(encoding="utf-8")).get("resources"))
    except (OSError, ValueError):
        return False


def pick_state(sid: str, runs: Path, app: Path, given: str | None) -> Path | None:
    cands = [Path(given)] if given else []
    cands += [runs / f"{sid}.tfstate.json", app / "terraform.tfstate", app / "terraform.tfstate.backup"]
    return next((p for p in cands if p.exists() and _has_resources(p)), None)


def replay(sid: str, runs: Path, app: Path, state: Path) -> dict:
    # Read the state file directly; never start terraform (no provider calls).
    os.environ["CLOUDCTL_TF_SHOW"] = "0"
    from cloudctl.debug.diff_first import run_diff_first
    from cloudctl.debug.diff_first.live import RecordedLive
    data = json.loads((runs / f"{sid}.diff-first.json").read_text(encoding="utf-8"))
    acct = re.search(r"arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:(\d{12}):", state.read_text(encoding="utf-8"))
    tmp = Path(tempfile.mkdtemp(prefix="cctl-replay-"))
    try:
        for tf in app.glob("*.tf"):
            shutil.copy(tf, tmp / tf.name)
        shutil.copy(state, tmp / "terraform.tfstate")
        rep = run_diff_first(RecordedLive(data), iac_root=str(tmp),
                             account=acct.group(1) if acct else "", region="us-east-1")
        out = rep.to_dict()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    out["_now"] = data.get("now")
    return out


def show(r: dict) -> str:
    w, ex, lines = r.get("window") or {}, r.get("explanation") or {}, []
    lines.append(f"now {r.get('_now')}; declared resources {r.get('resources')}")
    lines.append("window " + json.dumps({k: w.get(k) for k in
                                         ("last_healthy", "onset", "start", "end", "metrics_end", "method")}))
    for s in w.get("signals") or []:
        lines.append(f"  signal {s.get('node')} {s.get('metric')} onset {s.get('onset')} last_normal {s.get('last_normal')}")
    for s in r.get("symptoms") or []:
        lines.append(f"symptom {s['id']} {s['kind']} {s['node']}: {s['detail'][:110]}"
                     + (" [MAY BE OVER]" if s.get("may_be_over") else ""))
    for c in (r.get("changes") or [])[-40:]:
        flags = ",".join(f for f in ("restores", "one_off") if c.get(f))
        lines.append(f"  {c['time']} {c['event_name'][:30]:30} {c['resource_name'][:30]:30} {c['status']} {flags}")
    for g in ("causes", "alternatives", "likely_reverts", "one_off_actions", "newer_than_metrics", "unplaced_drift"):
        for c in ex.get(g) or []:
            lines.append(f"{g}: {c['summary'][:140]} -> {sorted(c.get('explains') or [])}")
    lines.append("drift " + json.dumps([(d.get("resource_key"), [f.get("field") for f in d.get("fields") or []][:4])
                                        for d in r.get("drift") or []]))
    lines.append(f"confidence {ex.get('confidence')}: {ex.get('confidence_reason')}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenario")
    ap.add_argument("--runs", default=str(HERE / "runs"))
    ap.add_argument("--app", default=str(HERE / "app"))
    ap.add_argument("--state")
    a = ap.parse_args()
    runs, app = Path(a.runs), Path(a.app)
    if not (runs / f"{a.scenario}.diff-first.json").exists():
        sys.exit(f"no recording at {runs / (a.scenario + '.diff-first.json')}")
    state = pick_state(a.scenario, runs, app, a.state)
    if state is None:
        sys.exit("no Terraform state with resources found (tried --state, runs/<id>.tfstate.json, "
                 "app/terraform.tfstate, app/terraform.tfstate.backup)")
    print(f"state: {state}")
    print(show(replay(a.scenario, runs, app, state)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
