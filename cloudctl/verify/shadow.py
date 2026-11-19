"""Shadow mode: run propose-then-verify beside agent mode and log what it
would have verified. Agent mode's output is never changed.

Turned on with ``CLOUDCTL_VERIFY_SHADOW=1``. Inputs:

  CLOUDCTL_VERIFY_SWEEP     path to a recorded evidence sweep (JSON, below).
                            Required in this pass: the AWS-backed evidence
                            source is not built yet, so without a sweep the
                            shadow run logs "skipped" and does nothing else.
  CLOUDCTL_IAC_PATHS        IaC artifacts (os.pathsep-separated): Terraform
                            state/plan JSON, CloudFormation templates, cdk.out
  CLOUDCTL_VERIFY_PROFILE   model profile for the proposer (see profiles.py)
  CLOUDCTL_VERIFY_ROUNDS    K, default 3
  CLOUDCTL_VERIFY_SHADOW_LOG  JSONL log path (default ~/.cloudctl/verify_shadow.jsonl)

Sweep file::

  {"incident": {"onset": ts, "end": ts, "lookback"?: s},
   "anchor"?: "<node id>",
   "graph": {"live_resources"?: [...], "dependency_graph"?: {...},
             "cloudtrail"?: [...], "enis"?: [...], "flow_logs"?: [...],
             "xray"?: {...}, "node_logs"?: {...}, "endpoints"?: {...},
             "physical_ids"?: {...}},
   "evidence": { FixtureEvidence data }}

Model calls made by the shadow proposer are recorded under tool
``_verify_model`` when CLOUDCTL_RECORD is set and can be replayed from
CLOUDCTL_REPLAY with CLOUDCTL_VERIFY_REPLAY_MODEL=1. They deliberately bypass
agent mode's model recorder and usage counters, so shadow runs never affect
agent mode's replay fidelity, spend budget or reported usage.
"""
from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import time
from datetime import UTC, datetime

from cloudctl.verify import observed as O
from cloudctl.verify.evidence import FixtureEvidence, Incident, to_ts
from cloudctl.verify.iac import load_iac_path
from cloudctl.verify.model import (
    SystemModel,
    live_from_dependency_graph,
    live_from_snapshot,
)
from cloudctl.verify.primitives import Context
from cloudctl.verify.verifier import Verifier, verify_loop

log = logging.getLogger("cloudctl.verify.shadow")


def build_model(sweep_graph: dict, iac_paths: list[str], all_fetched: dict | None = None) -> tuple[SystemModel, dict]:
    """Assemble the system model from IaC, live and observed inputs. Returns
    (model, discovery report)."""
    model = SystemModel()
    report: dict = {"iac": [], "errors": []}
    physical = sweep_graph.get("physical_ids") or {}
    for p in iac_paths:
        try:
            report["iac"].append({"path": p, **load_iac_path(model, p, physical)})
        except Exception as exc:  # noqa: BLE001 - one bad artifact must not stop discovery
            report["errors"].append(f"{p}: {type(exc).__name__}: {str(exc)[:200]}")
    live_from_snapshot(model, sweep_graph.get("live_resources") or [])
    dep = sweep_graph.get("dependency_graph")
    if not dep and all_fetched:
        for k, v in all_fetched.items():
            if str(k).startswith("get_dependency_graph"):
                try:
                    dep = json.loads(v) if isinstance(v, str) else v
                except json.JSONDecodeError:
                    dep = None
                break
    if isinstance(dep, dict):
        live_from_dependency_graph(model, dep)
    provided = {"cloudtrail": bool(sweep_graph.get("cloudtrail")),
                "flow_logs": bool(sweep_graph.get("flow_logs")),
                "xray": bool(sweep_graph.get("xray")),
                "logs": bool(sweep_graph.get("node_logs"))}
    report["observed_edges"] = {
        "cloudtrail": O.add_cloudtrail_edges(model, sweep_graph.get("cloudtrail") or []),
        "flow_logs": O.add_flow_log_edges(model, sweep_graph.get("flow_logs") or [],
                                          O.build_ip_index(model, sweep_graph.get("enis") or [])),
        "xray": O.add_xray_edges(model, sweep_graph.get("xray") or {}),
        "log_lines": O.add_log_line_edges(model, sweep_graph.get("node_logs") or {},
                                          sweep_graph.get("endpoints") or {}),
    }
    report["observability_gaps"] = O.observability_gaps(provided)
    report["stats"] = model.stats()
    return model, report


def pick_anchor(model: SystemModel, sweep: dict, failure_map: list | None) -> str | None:
    if sweep.get("anchor") and model.resolve(sweep["anchor"]):
        return model.resolve(sweep["anchor"])
    for entry in failure_map or []:
        comp = entry.get("component") if isinstance(entry, dict) else None
        if comp and model.resolve(comp):
            return model.resolve(comp)
    return None


def agent_names_node(report: dict, model: SystemModel, node: str | None) -> bool | None:
    """Does agent mode's root cause text name this node (by any identifier)?
    A coarse comparison for the shadow log only; never scored."""
    if not node:
        return None
    n = model.node(node)
    text = json.dumps({k: report.get(k) for k in ("root_cause", "resources_investigated")},
                      default=str).lower()
    idents = {i.lower() for i in (n.identifiers() | {n.name}) if i and len(i) >= 4}
    return any(i in text for i in idents)


class _ShadowModelClient:
    """Record/replay for the shadow proposer's model calls only."""

    def __init__(self, inner):
        self._inner = inner

    @staticmethod
    def _hash(kwargs: dict) -> str:
        return hashlib.sha256(json.dumps(kwargs, sort_keys=True, default=str).encode()).hexdigest()

    def converse(self, **kwargs):
        from cloudctl.mcp.tools.recorder import _record
        h = self._hash(kwargs)
        replay = os.environ.get("CLOUDCTL_REPLAY")
        if replay and os.environ.get("CLOUDCTL_VERIFY_REPLAY_MODEL") == "1":
            with open(replay, encoding="utf-8") as fh:
                for raw in fh:
                    try:
                        rec = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    if rec.get("tool") == "_verify_model" and (rec.get("input") or {}).get("hash") == h:
                        return json.loads(rec["output"])
            raise RuntimeError(f"shadow replay: no recorded proposer response for {h[:12]}")
        if self._inner is None:
            raise RuntimeError("no model client")
        resp = self._inner.converse(**kwargs)
        slim = {k: v for k, v in resp.items() if k != "ResponseMetadata"}
        _record("_verify_model", {"hash": h}, json.dumps(slim, default=str))
        return slim


def _write_log(entry: dict) -> str:
    path = os.environ.get("CLOUDCTL_VERIFY_SHADOW_LOG") or os.path.join(
        os.path.expanduser("~"), ".cloudctl", "verify_shadow.jsonl")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, default=str) + "\n")
    return path


def run_shadow(*, symptom: str, report: dict, final_state: dict, all_fetched: dict,
               aws_profile: str | None = None, client=None, model_profile=None) -> dict:
    """Run the verifier in shadow and log the result. Never raises, never
    mutates ``report`` (it works on a copy). Returns the logged entry."""
    report = copy.deepcopy(report)
    entry: dict = {"ts": datetime.now(UTC).isoformat(), "symptom": symptom[:300],
                   "agent_verdict": {"root_cause": str(report.get("root_cause", ""))[:400],
                                     "confidence": report.get("confidence")}}
    t0 = time.monotonic()
    try:
        sweep_path = os.environ.get("CLOUDCTL_VERIFY_SWEEP", "")
        if not sweep_path:
            entry.update(status="skipped",
                         reason="no evidence sweep (CLOUDCTL_VERIFY_SWEEP); the AWS-backed "
                                "evidence source is not built yet")
            entry["log"] = _write_log(entry)
            return entry
        with open(sweep_path, encoding="utf-8") as fh:
            sweep = json.load(fh)
        iac_paths = [p for p in os.environ.get("CLOUDCTL_IAC_PATHS", "").split(os.pathsep) if p]
        model, discovery = build_model(sweep.get("graph") or {}, iac_paths, all_fetched)
        entry["discovery"] = discovery
        anchor = pick_anchor(model, sweep, final_state.get("failure_map"))
        if not anchor:
            entry.update(status="skipped", reason="anchor not found in the discovered graph")
            entry["log"] = _write_log(entry)
            return entry
        inc = sweep.get("incident") or {}
        onset = to_ts(inc.get("onset")) or to_ts((final_state.get("observation") or {}).get("onset"))
        if onset is None:
            entry.update(status="skipped", reason="no symptom onset")
            entry["log"] = _write_log(entry)
            return entry
        incident = Incident(onset, to_ts(inc.get("end")) or int(time.time()),
                            int(inc.get("lookback", 3600)))
        ctx = Context(model, FixtureEvidence(sweep.get("evidence") or {}, model), incident)

        from cloudctl.verify.profiles import select_profile
        from cloudctl.verify.proposer import Proposer
        profile = model_profile or select_profile()
        if client is None:
            inner = None
            if not (os.environ.get("CLOUDCTL_REPLAY") and os.environ.get("CLOUDCTL_VERIFY_REPLAY_MODEL") == "1"):
                from cloudctl.ai.model_providers import make_model_client_for
                inner = make_model_client_for(profile, aws_profile)
            client = _ShadowModelClient(inner)
        context = {"observation": final_state.get("observation") or {},
                   "failure_map": (final_state.get("failure_map") or [])[:5],
                   "agent_hypotheses": [{"service": h.get("service"), "reason": h.get("reason")}
                                        for h in (final_state.get("hypotheses") or [])[:5]]}
        proposer = Proposer(client, profile, symptom, context=context)
        verifier = Verifier(ctx, anchor)
        rounds = int(os.environ.get("CLOUDCTL_VERIFY_ROUNDS", "3"))
        result = verify_loop(verifier, proposer, rounds=rounds)
        root = (result.get("verdict") or {}).get("node")
        entry.update(
            status="ran", profile=profile.name, model_id=profile.model_id,
            anchor=anchor, incident=incident.to_dict(),
            verdict=result.get("verdict"), decision_status=result.get("status"),
            candidates=result.get("candidates"), missing_signals=result.get("missing_signals"),
            rounds=result.get("rounds"), hypotheses_total=result.get("hypotheses_total"),
            hypotheses_dropped=result.get("hypotheses_dropped"),
            primitive_calls=result.get("primitive_calls"),
            usage=proposer.usage, cost_usd=proposer.cost(),
            agent_names_verified_node=agent_names_node(report, model, root),
            outcomes=result.get("outcomes"),
        )
    except Exception as exc:
        entry.update(status="error", error=f"{type(exc).__name__}: {str(exc)[:300]}")
        log.debug("verify shadow failed", exc_info=True)
    entry["elapsed_s"] = round(time.monotonic() - t0, 3)
    try:
        entry["log"] = _write_log(entry)
    except OSError as exc:
        entry["log_error"] = str(exc)
    return entry
