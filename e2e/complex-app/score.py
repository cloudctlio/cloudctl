#!/usr/bin/env python3
"""Score cctl --json-out results against scenarios.json ground truth.

  python score.py --runs runs                 every runs/<id>.json present
  python score.py --runs runs --scenario s3   one scenario
  python score.py --result my.json --scenario s3 [--wall-seconds 212]
  python score.py --selftest                  check the scorer on fixtures/

Checks per scenario (each fault, for two-fault scenarios):
  root_cause   root_cause text names the actual cause (all regex groups match)
  localized    root_cause names the blamed resource
  confidence   HIGH / MEDIUM / LOW (and 'overconfident' if HIGH on a wrong answer)
  time         wall clock (runs/<id>.meta.json) or _timing.elapsed_s; pass <= 600 s
  iac_resource iac_fix.resource is the resource the fix belongs on
  iac_fix      iac_fix.diff removes the bad value and adds a correct one
  drift_safe   remediation doesn't tell you to change AWS directly without going through IaC
Extra: red herring (s3) not blamed; no-fault control (s0) not given a confident false cause;
  root cause does not also blame another scenario's fault (a leftover from an earlier scenario).

Verdict: PASS = root cause + localized + time + IaC resource + fix all pass (drift: no IaC change
and drift-safe); PARTIAL = root cause right but something else misses; FAIL = root cause wrong.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TIME_LIMIT_S = 600
CONF_POINTS = {"HIGH": 1.0, "MEDIUM": 0.5, "LOW": 0.0}


def _rx(p: str) -> re.Pattern:
    return re.compile(p, re.I | re.M)


def _any(patterns: list[str], text: str) -> bool:
    return any(_rx(p).search(text) for p in patterns)


def _sentences(text: str) -> list[str]:
    return [s for s in re.split(r"(?<=[.!?;])\s+", text) if s.strip()]


NEGATION = _rx(r"unrelated|not (the|a) (root )?cause|harmless|red herring|noise|benign|non-?fatal|"
               r"ruled out|can be ignored|not related|incidental|coincidental|separate and harmless")


def diff_lines(diff: str) -> tuple[str, str]:
    removed = "\n".join(l[1:] for l in diff.splitlines() if l.startswith("-") and not l.startswith("---"))
    added = "\n".join(l[1:] for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++"))
    return removed, added


def score_one(scen: dict, result: dict, meta: dict, cfg: dict) -> dict:
    gt = scen["ground_truth"]
    rc = str(result.get("root_cause") or "")
    rem = " ".join(str(x) for x in result.get("remediation_steps") or [])
    conf = str(result.get("confidence") or "").upper()
    fix = result.get("iac_fix") or {}
    fix_status = fix.get("status")
    diff = fix.get("diff") or ""
    removed, added = diff_lines(diff)
    fix_res = str(fix.get("resource") or "")

    wall = meta.get("wall_seconds")
    if wall is None:
        wall = (result.get("_timing") or {}).get("elapsed_s")
    out: dict = {"scenario": scen["id"], "name": scen["name"], "confidence": conf or "?",
                 "seconds": wall, "time_ok": wall is not None and wall <= TIME_LIMIT_S,
                 "iac_fix_status": fix_status or "absent", "iac_fix_resource": fix_res or None,
                 "iac_fix_check": (fix.get("check") or {}).get("status"), "notes": []}
    if meta.get("symptom_seen") is False:
        out["notes"].append("fault did not manifest before cctl ran; result may not be cctl's fault")
    if result.get("error") and not rc:
        out["notes"].append(f"cctl error: {str(result['error'])[:200]}")

    # drift safety: direct AWS changes in remediation without any IaC route
    drift_cmd = _rx(cfg["drift_risk_regex"]).search(rem)
    iac_said = _rx(cfg["iac_mention_regex"]).search(rem)
    out["drift_safe"] = not (drift_cmd and not iac_said)
    if drift_cmd:
        out["notes"].append(f"remediation changes AWS directly ('{drift_cmd.group(0)}')"
                            + ("" if iac_said else " and never mentions IaC/terraform: causes drift"))

    # control scenario: no fault exists
    if gt.get("expect_no_fault"):
        said_none = _rx(gt["no_fault_regex"]).search(rc) is not None
        out["root_cause_ok"] = said_none or conf == "LOW"
        out["localized_ok"] = None
        out["iac_resource_ok"] = fix_status in (None, "not_found", "no_edit", "ambiguous", "no_iac") or not diff
        out["iac_fix_ok"] = out["iac_resource_ok"]
        out["overconfident"] = (not said_none) and conf == "HIGH"
        if not out["root_cause_ok"]:
            out["notes"].append("named a cause for a healthy app")
        out["faults"] = []
        out["verdict"] = "PASS" if out["root_cause_ok"] and out["iac_fix_ok"] and out["time_ok"] else "FAIL"
        return out

    faults = []
    for f in gt["faults"]:
        groups = f["root_cause_all"]
        hit = [bool(_rx(g).search(rc)) for g in groups]
        loc = _any(f["localize_any"], rc)
        res_ok = fix_res in f["iac_resources"]
        if gt.get("expect_no_iac_change"):
            # drift: correct IaC is already there. No diff is right; a diff that only adds enabled = true is fine.
            harmless = bool(diff) and _any(f["fix_add_any"], added) and not removed.strip()
            fix_ok = (not diff) or harmless
            res_ok = res_ok or not diff
        else:
            rm_ok = (not f["fix_remove_any"]) or _any(f["fix_remove_any"], removed)
            add_ok = _any(f["fix_add_any"], added)
            wrong = _any(f.get("wrong_fix_any", []), added)
            fix_ok = bool(diff) and res_ok and rm_ok and add_ok and not wrong
            if wrong:
                out["notes"].append(f"fault {f['id']}: diff widens permissions instead of fixing the cause")
        anywhere = " ".join([rc, rem] + [str(e) for e in result.get("evidence") or []])
        faults.append({"id": f["id"], "root_cause_ok": all(hit), "groups_matched": f"{sum(hit)}/{len(hit)}",
                       "mentioned_anywhere": all(bool(_rx(g).search(anywhere)) for g in groups),
                       "localized_ok": loc, "iac_resource_ok": res_ok, "iac_fix_ok": fix_ok})
    out["faults"] = faults
    n = len(faults)
    found = sum(f["root_cause_ok"] for f in faults)
    out["root_cause_ok"] = found == n
    out["root_cause_found"] = f"{found}/{n}"
    out["localized_ok"] = all(f["localized_ok"] for f in faults if f["root_cause_ok"]) and found > 0
    # One IaC fix per run: for multi-fault scenarios it's enough to fix one of the faults correctly.
    out["iac_resource_ok"] = any(f["iac_resource_ok"] for f in faults)
    out["iac_fix_ok"] = any(f["iac_fix_ok"] for f in faults)
    out["overconfident"] = found == 0 and conf == "HIGH"

    # Scenarios run back to back in one deployment, so an earlier scenario's
    # fault (reverted before this one) can still show in logs and metrics. A
    # root-cause sentence that names another scenario's fault, and not this
    # scenario's, blames a leftover: at best PARTIAL.
    own = [f["root_cause_all"] for f in gt["faults"]]
    leftovers = []
    for other in cfg.get("scenarios", []):
        if other["id"] == scen["id"]:
            continue
        for of in other["ground_truth"].get("faults", []):
            for sent in _sentences(rc):
                if NEGATION.search(sent) or any(all(_rx(g).search(sent) for g in gs) for gs in own):
                    continue
                if all(_rx(g).search(sent) for g in of["root_cause_all"]):
                    leftovers.append(f"{other['id']}{of['id']}")
                    break
    out["blames_other_fault"] = sorted(set(leftovers))
    if leftovers:
        out["notes"].append("root cause also blames another scenario's fault ("
                            + ", ".join(out["blames_other_fault"]) + ")")

    rh = gt.get("red_herring_regex")
    if rh:
        blamed = [s for s in _sentences(rc) if _rx(rh).search(s) and not NEGATION.search(s)]
        rh_fix = bool(diff) and _rx(rh).search(removed + added) and not out["iac_fix_ok"]
        out["red_herring_avoided"] = not blamed and not rh_fix
        if blamed:
            out["notes"].append("root cause blames the red herring")
        if rh_fix:
            out["notes"].append("IaC diff only touches the red herring")

    core = [out["root_cause_ok"], out["localized_ok"], out["time_ok"], out["iac_resource_ok"],
            out["iac_fix_ok"], out["drift_safe"], out.get("red_herring_avoided", True),
            not out["blames_other_fault"]]
    if all(core):
        out["verdict"] = "PASS"
    elif found > 0:
        out["verdict"] = "PARTIAL"
    else:
        out["verdict"] = "FAIL"
    return out


def mark(v) -> str:
    return "-" if v is None else ("yes" if v else "NO")


def table(rows: list[dict]) -> str:
    head = ("| Scenario | Verdict | Root cause | Localized | Confidence | Seconds | IaC resource | "
            "Fix matches | Drift-safe | Notes |")
    lines = [head, "|" + "---|" * 10]
    for r in rows:
        rc = r.get("root_cause_found") or mark(r["root_cause_ok"])
        conf = r["confidence"] + (" (overconfident)" if r.get("overconfident") else "")
        notes = list(r["notes"])
        if "red_herring_avoided" in r:
            notes.insert(0, "red herring avoided" if r["red_herring_avoided"] else "fell for red herring")
        res = f"{mark(r['iac_resource_ok'])} ({r['iac_fix_resource'] or r['iac_fix_status']})"
        lines.append(f"| {r['scenario']} {r['name']} | {r['verdict']} | {rc} | {mark(r['localized_ok'])} | "
                     f"{conf} | {r['seconds'] if r['seconds'] is not None else '?'} | {res} | "
                     f"{mark(r['iac_fix_ok'])} | {mark(r['drift_safe'])} | {'; '.join(notes)} |")
    return "\n".join(lines)


def load_cfg() -> dict:
    return json.loads((HERE / "scenarios.json").read_text(encoding="utf-8"))


def by_id(cfg: dict, sid: str) -> dict:
    for s in cfg["scenarios"]:
        if s["id"] == sid:
            return s
    sys.exit(f"unknown scenario {sid}")


def selftest() -> int:
    """Score every fixtures/<id>.<label>.json; the label says what the verdict must be."""
    cfg = load_cfg()
    fails = 0
    files = sorted((HERE / "fixtures").glob("*.json"))
    for p in files:
        sid, label = p.stem.split(".", 1)
        want = label.split("-")[0].upper()
        got = score_one(by_id(cfg, sid), json.loads(p.read_text()), {}, cfg)
        ok = got["verdict"] == want
        fails += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {p.name}: want {want}, got {got['verdict']}"
              + ("" if ok else f"  {json.dumps(got)[:400]}"))
    print(f"{len(files) - fails}/{len(files)} fixtures scored as expected")
    return 1 if fails else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", default=str(HERE / "runs"))
    ap.add_argument("--scenario")
    ap.add_argument("--result", help="a single cctl --json-out file (needs --scenario)")
    ap.add_argument("--wall-seconds", type=float)
    ap.add_argument("--selftest", action="store_true")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    cfg = load_cfg()
    rows = []
    if a.result:
        if not a.scenario:
            sys.exit("--result needs --scenario")
        meta = {"wall_seconds": a.wall_seconds} if a.wall_seconds is not None else {}
        rows.append(score_one(by_id(cfg, a.scenario), json.loads(Path(a.result).read_text(encoding="utf-8")), meta, cfg))
    else:
        runs = Path(a.runs)
        ids = [a.scenario] if a.scenario else [s["id"] for s in cfg["scenarios"]]
        for sid in ids:
            rp = runs / f"{sid}.json"
            if not rp.exists():
                continue
            mp = runs / f"{sid}.meta.json"
            meta = json.loads(mp.read_text()) if mp.exists() else {}
            rows.append(score_one(by_id(cfg, sid), json.loads(rp.read_text(encoding="utf-8")), meta, cfg))
        if not rows:
            sys.exit(f"no results in {runs}")
        (runs / "scorecard.json").write_text(json.dumps(rows, indent=1))
        (runs / "scorecard.md").write_text(table(rows) + "\n", encoding="utf-8")
    print(table(rows))
    return 0


if __name__ == "__main__":
    sys.exit(main())
