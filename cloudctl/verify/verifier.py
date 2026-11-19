"""The verifier: what makes a verdict, with no per-failure checks.

A hypothesis names one node of the discovered graph, a short property, a free
text claim (never scored) and predictions written in the nine primitives. The
verifier runs the predictions and applies five generic rules; none mentions a
service.

  1 predictions_hold  every prediction returns its expected result, and at
                      least one prediction is about the hypothesised node
  2 on_failing_path   the node is on a graph path from the anchor, and the
                      verifier's own path_health shows no failing node further
                      upstream of it that no hypothesis covers
  3 onset_link        a change on the node in the lookback window, or a
                      signal on the node that began by symptom onset, or
                      first-exercise evidence (calls through the node begin at
                      onset with none in the pre-onset window)
  4 controls          the same predictions re-run on the pre-onset window must
                      not all hold (at least one definitive contradiction is
                      required); where healthy peers exist, the predictions
                      re-run on each peer must not all hold either
  5 rivals_refuted    every other hypothesis on the failing path that did not
                      itself pass rules 1-4 has at least one prediction that
                      definitively contradicts it (INCONCLUSIVE/UNAVAILABLE is
                      not a refutation)

Reading of rule 5: a rival that passes rules 1-4 is not "unrefuted"; it is
either part of the same chain (reported as a consequence, ordered by the graph)
or an independent verified cause. Rule 5 is therefore checked against the
rivals that failed rules 1-4.

Decisions: VERIFIED (one chain; the most upstream node is the root),
MULTIPLE_VERIFIED (independent chains, fixed order), CANDIDATES (passes exist
but some rival is unrefuted; the predictions that would separate them are
listed), UNVERIFIED (nothing passed; top candidates and missing signals).

Results are cached by (primitive, canonical args, window/peer substitution) so
two models asking the same question get the identical answer.
"""
from __future__ import annotations

import copy
import json
from collections.abc import Callable
from dataclasses import dataclass, field

from cloudctl.verify import primitives as P
from cloudctl.verify.evidence import Unavailable, Window
from cloudctl.verify.primitives import (
    FAIL,
    INCONCLUSIVE,
    PASS,
    UNAVAILABLE,
    Context,
    Result,
)

VERIFIED = "VERIFIED"
MULTIPLE_VERIFIED = "MULTIPLE_VERIFIED"
CANDIDATES = "CANDIDATES"
UNVERIFIED = "UNVERIFIED"

RULES = ("predictions_hold", "on_failing_path", "onset_link", "controls", "rivals_refuted")


@dataclass
class Prediction:
    primitive: str
    args: dict
    expect: str = PASS

    def to_dict(self) -> dict:
        return {"primitive": self.primitive, "args": self.args, "expect": self.expect}


@dataclass
class Hypothesis:
    id: str
    node: str
    property: str
    claim: str
    predictions: list[Prediction]
    round: int = 1

    def signature(self) -> str:
        return json.dumps([self.node, self.property.strip().lower(),
                           sorted(json.dumps(p.to_dict(), sort_keys=True) for p in self.predictions)])

    def to_dict(self) -> dict:
        return {"id": self.id, "node": self.node, "property": self.property,
                "claim": self.claim, "round": self.round,
                "predictions": [p.to_dict() for p in self.predictions]}


# ── parsing proposer output ──────────────────────────────────────────────────


def parse_hypotheses(raw, model, start_id: int = 1, round_no: int = 1,
                     max_hypotheses: int = 5) -> tuple[list[Hypothesis], list[str]]:
    """Validate proposer output against the schema and the graph.

    Accepts ``{"hypotheses": [...]}``. Each prediction's ``args`` may be an
    object or a JSON string (``args_json``), since some providers' strict modes
    can't express a free-form object. Returns (valid hypotheses, errors). A
    hypothesis with any invalid prediction is rejected whole, with its errors.
    """
    errors: list[str] = []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            return [], [f"output is not JSON: {exc}"]
    if not isinstance(raw, dict) or not isinstance(raw.get("hypotheses"), list):
        return [], ['output must be an object {"hypotheses": [...]}']
    out: list[Hypothesis] = []
    items = raw["hypotheses"]
    if len(items) > max_hypotheses:
        errors.append(f"{len(items)} hypotheses given; only the first {max_hypotheses} are used")
        items = items[:max_hypotheses]
    for i, h in enumerate(items):
        tag = f"hypotheses[{i}]"
        if not isinstance(h, dict):
            errors.append(f"{tag}: not an object")
            continue
        node = model.resolve(str(h.get("node", "")))
        if not node:
            errors.append(f"{tag}.node: {h.get('node')!r} is not a node in the discovered graph")
            continue
        preds, perrs = [], []
        for j, p in enumerate(h.get("predictions") or []):
            ptag = f"{tag}.predictions[{j}]"
            if not isinstance(p, dict):
                perrs.append(f"{ptag}: not an object")
                continue
            args = p.get("args", p.get("args_json", {}))
            if isinstance(args, str):
                try:
                    args = json.loads(args) if args.strip() else {}
                except json.JSONDecodeError as exc:
                    perrs.append(f"{ptag}.args_json: not JSON ({exc})")
                    continue
            expect = str(p.get("expect", PASS)).upper()
            if expect not in (PASS, FAIL):
                perrs.append(f"{ptag}.expect must be PASS or FAIL")
                continue
            for e in P.validate(str(p.get("primitive", "")), args, model):
                perrs.append(f"{ptag}: {e}")
            preds.append(Prediction(str(p.get("primitive")), args, expect))
        if not preds and not perrs:
            perrs.append(f"{tag}: needs at least one prediction")
        if perrs:
            errors += perrs
            continue
        out.append(Hypothesis(id=f"h{start_id + len(out)}", node=node,
                              property=str(h.get("property", ""))[:120],
                              claim=str(h.get("claim", ""))[:600],
                              predictions=preds, round=round_no))
    return out, errors


# ── the verifier ─────────────────────────────────────────────────────────────


@dataclass
class HypothesisOutcome:
    hypothesis: Hypothesis
    results: list[dict] = field(default_factory=list)          # per prediction
    rules: dict = field(default_factory=dict)                 # rule -> {"ok": bool, "why": str}
    controls: dict = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)

    @property
    def passes_1_to_4(self) -> bool:
        return all(self.rules.get(r, {}).get("ok") for r in RULES[:4])

    @property
    def refuted(self) -> bool:
        return any(r["status"] in (PASS, FAIL) and r["status"] != r["expect"] for r in self.results)

    @property
    def n_holding(self) -> int:
        return sum(1 for r in self.results if r["status"] == r["expect"])

    def to_dict(self) -> dict:
        return {"hypothesis": self.hypothesis.to_dict(), "results": self.results,
                "rules": self.rules, "controls": self.controls,
                "missing": sorted(set(self.missing))}


class Verifier:
    def __init__(self, ctx: Context, anchor: str, *, path_depth: int = 4,
                 onset_grace: int = 120):
        self.ctx = ctx
        self.anchor = ctx.model.resolve(anchor)
        if not self.anchor:
            raise ValueError(f"anchor {anchor!r} is not in the discovered graph")
        self.path_depth = path_depth
        self.onset_grace = onset_grace
        self.cache: dict[str, Result] = {}
        self.calls = 0   # primitive executions (cache misses)

    # -- primitive execution with the shared cache --

    def run(self, name: str, args: dict) -> Result:
        canon = P.canonical_args(name, args, self.ctx.model) if name in P.SCHEMAS else args
        key = json.dumps([name, canon], sort_keys=True, default=str)
        if key not in self.cache:
            self.calls += 1
            self.cache[key] = P.run(self.ctx, name, args)
        return self.cache[key]

    @staticmethod
    def _swap_window(name: str, args: dict) -> dict | None:
        """Args for the pre-onset temporal control, or None if this primitive
        does not take part."""
        if not P.CONTROL[name]["temporal"]:
            return None
        a = copy.deepcopy(args)
        a["window"] = "pre_onset"
        return a

    def _swap_node(self, name: str, args: dict, node: str, peer: str) -> dict | None:
        a = copy.deepcopy(args)
        hit = False
        for k in P.CONTROL[name]["node_args"]:
            if k in a and self.ctx.model.resolve(a[k]) == node:
                a[k] = peer
                hit = True
        return a if hit else None

    def _about_node(self, pred: Prediction, node: str) -> bool:
        sch = {**P.SCHEMAS[pred.primitive]["required"], **P.SCHEMAS[pred.primitive]["optional"]}
        for k, t in sch.items():
            if t == "node" and k in pred.args and self.ctx.model.resolve(pred.args[k]) == node:
                return True
        if pred.primitive == "before":
            return any(self.ctx.model.resolve(str(pred.args.get(k, {}).get("node", ""))) == node
                       for k in ("a", "b"))
        return False

    # -- shared path health (rule 2) --

    def path_health(self) -> Result:
        return self.run("path_health", {"anchor": self.anchor, "depth": self.path_depth})

    # -- per-hypothesis rules 1-4 --

    def evaluate(self, h: Hypothesis, all_hyps: list[Hypothesis]) -> HypothesisOutcome:
        out = HypothesisOutcome(h)
        model = self.ctx.model
        for p in h.predictions:
            r = self.run(p.primitive, p.args)
            out.results.append({"primitive": p.primitive, "args": p.args, "expect": p.expect,
                                **r.to_dict()})
            if r.status == UNAVAILABLE and r.missing:
                out.missing.append(r.missing)

        # rule 1
        holds = all(r["status"] == r["expect"] for r in out.results)
        about = any(self._about_node(p, h.node) for p in h.predictions)
        if not about:
            out.rules["predictions_hold"] = {"ok": False, "why": "no prediction is about the hypothesised node"}
        elif not holds:
            bad = [f"{r['primitive']}={r['status']} (expected {r['expect']})"
                   for r in out.results if r["status"] != r["expect"]]
            out.rules["predictions_hold"] = {"ok": False, "why": "; ".join(bad)}
        else:
            out.rules["predictions_hold"] = {"ok": True, "why": f"{len(out.results)} prediction(s) hold"}

        # rule 2
        if not model.on_failing_path(self.anchor, h.node):
            out.rules["on_failing_path"] = {"ok": False, "why": f"{h.node} is not on a path from the anchor {self.anchor}"}
        else:
            ph = self.path_health()
            failing = (ph.detail or {}).get("failing") or []
            covered = {x.node for x in all_hyps}
            ignored = [n for n in failing if model.is_upstream_of(n, h.node) and n not in covered]
            if ignored:
                out.rules["on_failing_path"] = {"ok": False,
                                                "why": f"failing node(s) further upstream not covered by any hypothesis: {ignored}"}
            else:
                out.rules["on_failing_path"] = {"ok": True, "why": "on the failing path"}

        # rule 3
        out.rules["onset_link"] = self._onset_link(h, out)

        # rule 4
        out.rules["controls"] = self._controls(h, out)
        return out

    def _onset_link(self, h: Hypothesis, out: HypothesisOutcome) -> dict:
        inc = self.ctx.incident
        ch = self.run("changed", {"node": h.node, "window": "lookback"})
        if ch.status == PASS:
            return {"ok": True, "why": f"change on {h.node} at {ch.onset} before onset {inc.onset}"}
        if ch.status == UNAVAILABLE:
            out.missing.append(ch.missing)
        for p in h.predictions:
            if p.primitive != "signal" or self.ctx.model.resolve(p.args.get("node", "")) != h.node:
                continue
            if p.expect != PASS:
                continue
            # look from the start of the lookback through the incident
            win = Window(inc.window("lookback").start, inc.end)
            wide = P._eval_signal(self.ctx, h.node, p.args["query"], p.args["predicate"], win)
            if wide.status == PASS and wide.onset is not None and wide.onset <= inc.onset + self.onset_grace:
                return {"ok": True, "why": f"signal on {h.node} began at {wide.onset}, by onset {inc.onset}"}
        try:
            during = self.ctx.evidence.calls(h.node, inc.window("incident"))
            before = self.ctx.evidence.calls(h.node, inc.window("pre_onset"))
            first = min((c["ts"] for c in during), default=None)
            if first is not None and not before and abs(first - inc.onset) <= self.onset_grace:
                return {"ok": True, "why": f"first exercise: first call through {h.node} at {first}, none pre-onset"}
        except Unavailable as exc:
            out.missing.append(exc.signal)
        return {"ok": False, "why": "no change, signal onset or first exercise links this node to the onset"}

    def _controls(self, h: Hypothesis, out: HypothesisOutcome) -> dict:
        # temporal control
        temporal = []
        for p in h.predictions:
            a = self._swap_window(p.primitive, p.args)
            if a is None:
                continue
            r = self.run(p.primitive, a)
            temporal.append({"primitive": p.primitive, "expect": p.expect, "status": r.status,
                             "reason": r.reason, "missing": r.missing})
        out.controls["pre_onset"] = temporal
        if not temporal:
            return {"ok": False, "why": "no prediction can be checked against the pre-onset window"}
        contradicted = [t for t in temporal if t["status"] in (PASS, FAIL) and t["status"] != t["expect"]]
        if not contradicted:
            miss = [t["missing"] for t in temporal if t["status"] == UNAVAILABLE and t["missing"]]
            out.missing += miss
            if miss:
                return {"ok": False, "why": f"pre-onset control unavailable ({', '.join(sorted(set(miss)))})"}
            if all(t["status"] == t["expect"] for t in temporal):
                return {"ok": False, "why": "the same predictions also held before onset"}
            return {"ok": False, "why": "pre-onset control inconclusive"}

        # peer control (only where healthy, observable peers exist)
        peer_rows = []
        incident_w = self.ctx.incident.window("incident")
        for peer in self.ctx.model.peers(h.node):
            try:
                if self.ctx.evidence.failure_signals(peer, incident_w):
                    continue  # not healthy
            except Unavailable:
                continue      # health unknown: can't be a control
            rows = []
            for p in h.predictions:
                a = self._swap_node(p.primitive, p.args, h.node, peer)
                if a is None:
                    continue
                r = self.run(p.primitive, a)
                rows.append({"primitive": p.primitive, "expect": p.expect, "status": r.status})
            if not rows or all(r["status"] in (UNAVAILABLE, INCONCLUSIVE) for r in rows):
                continue
            peer_rows.append({"peer": peer, "rows": rows})
            if all(r["status"] == r["expect"] for r in rows):
                out.controls["peers"] = peer_rows
                return {"ok": False, "why": f"the same predictions hold on healthy peer {peer}"}
        out.controls["peers"] = peer_rows
        why = f"pre-onset contradicted by {contradicted[0]['primitive']}"
        if peer_rows:
            why += f"; checked against {len(peer_rows)} healthy peer(s)"
        else:
            why += "; no healthy observable peers to compare"
        return {"ok": True, "why": why}

    # -- rule 5 and the decision --

    def decide(self, hyps: list[Hypothesis]) -> dict:
        model = self.ctx.model
        outcomes = [self.evaluate(h, hyps) for h in hyps]
        passing = [o for o in outcomes if o.passes_1_to_4]
        rivals = [o for o in outcomes if not o.passes_1_to_4
                  and model.on_failing_path(self.anchor, o.hypothesis.node)]
        unrefuted = [o for o in rivals if not o.refuted]
        for o in outcomes:
            if o.passes_1_to_4:
                o.rules["rivals_refuted"] = (
                    {"ok": True, "why": f"{len(rivals)} rival(s), all refuted"} if not unrefuted else
                    {"ok": False, "why": "unrefuted: " + ", ".join(u.hypothesis.id for u in unrefuted)})
            else:
                o.rules["rivals_refuted"] = {"ok": False, "why": "not evaluated (rules 1-4 not met)"}

        def dist(nid: str) -> int:
            if nid == self.anchor:
                return 0
            return model.upstream(self.anchor).get(nid, 10**6)

        missing = sorted({m for o in outcomes for m in o.missing if m})
        base = {"anchor": self.anchor, "outcomes": [o.to_dict() for o in outcomes],
                "missing_signals": missing, "primitive_calls": self.calls,
                "path_health": self.path_health().to_dict()}

        if passing and not unrefuted:
            chains = _group_chains([o.hypothesis for o in passing], model)
            ordered = []
            for chain in chains:
                # most upstream first; tie by property for determinism
                chain.sort(key=lambda h: (-dist(h.node), h.node, h.property))
                ordered.append(chain)
            ordered.sort(key=lambda c: (-dist(c[0].node), c[0].node, c[0].property))
            if len(ordered) == 1:
                root, rest = ordered[0][0], ordered[0][1:]
                return {**base, "status": VERIFIED,
                        "verdict": _tuple(VERIFIED, root),
                        "root": root.to_dict(),
                        "consequences": [h.to_dict() for h in rest]}
            return {**base, "status": MULTIPLE_VERIFIED,
                    "verdict": {"status": MULTIPLE_VERIFIED,
                                "causes": [_tuple(VERIFIED, c[0]) for c in ordered]},
                    "chains": [[h.to_dict() for h in c] for c in ordered]}

        if passing:
            separating = {u.hypothesis.id: [r for r in u.results if r["status"] in (INCONCLUSIVE, UNAVAILABLE)]
                          for u in unrefuted}
            cands = sorted(passing + unrefuted, key=lambda o: (-o.n_holding, o.hypothesis.id))
            return {**base, "status": CANDIDATES,
                    "verdict": {"status": CANDIDATES, "node": None, "property": None},
                    "candidates": [_tuple(CANDIDATES, o.hypothesis) for o in cands],
                    "separating_predictions": separating}

        ranked = sorted((o for o in outcomes if not o.refuted),
                        key=lambda o: (-o.n_holding, o.hypothesis.id))[:3]
        return {**base, "status": UNVERIFIED,
                "verdict": {"status": UNVERIFIED, "node": None, "property": None},
                "candidates": [_tuple(UNVERIFIED, o.hypothesis) for o in ranked]}


def _tuple(status: str, h: Hypothesis) -> dict:
    return {"status": status, "node": h.node, "property": h.property, "hypothesis": h.id}


def _group_chains(hyps: list[Hypothesis], model) -> list[list[Hypothesis]]:
    """Union hypotheses whose nodes are the same or lie on one dependency chain."""
    groups: list[list[Hypothesis]] = []
    for h in hyps:
        joined = [g for g in groups
                  if any(x.node == h.node or model.same_chain(x.node, h.node) for x in g)]
        merged = [h]
        for g in joined:
            merged += g
            groups.remove(g)
        groups.append(merged)
    return groups


# ── the propose/verify loop ──────────────────────────────────────────────────

Proposer = Callable[[dict], object]


def verify_loop(verifier: Verifier, proposer: Proposer, *, rounds: int = 3,
                max_hypotheses: int = 5, seed: list[Hypothesis] | None = None) -> dict:
    """Up to ``rounds`` rounds: ask the proposer, validate (one repair retry per
    round), verify everything proposed so far, feed results back.

    ``proposer(request)`` gets ``{"round", "graph", "anchor", "incident",
    "previous": [outcomes], "repair": [errors] | None}`` and returns the raw
    output (dict or JSON text). Exceptions from the proposer end the loop with
    whatever has been verified so far."""
    model = verifier.ctx.model
    hyps: list[Hypothesis] = list(seed or [])
    seen = {h.signature() for h in hyps}
    trace: list[dict] = []
    decision: dict | None = verifier.decide(hyps) if hyps else None
    dropped = 0
    for rnd in range(1, rounds + 1):
        req = {"round": rnd, "graph": model.summary(), "anchor": verifier.anchor,
               "incident": verifier.ctx.incident.to_dict(),
               "previous": (decision or {}).get("outcomes", []), "repair": None}
        try:
            raw = proposer(req)
            new, errs = parse_hypotheses(raw, model, start_id=len(hyps) + 1,
                                         round_no=rnd, max_hypotheses=max_hypotheses)
            repaired = False
            if errs:
                raw2 = proposer({**req, "repair": errs})
                new2, errs2 = parse_hypotheses(raw2, model, start_id=len(hyps) + 1,
                                               round_no=rnd, max_hypotheses=max_hypotheses)
                repaired = True
                # keep whichever attempt produced more valid hypotheses
                if len(new2) >= len(new):
                    new, errs = new2, errs2
                dropped += len(errs)
        except Exception as exc:  # noqa: BLE001 - a failed proposer ends the loop, never the run
            trace.append({"round": rnd, "error": f"{type(exc).__name__}: {str(exc)[:200]}"})
            break
        fresh = [h for h in new if h.signature() not in seen]
        for h in fresh:
            seen.add(h.signature())
        # re-number to keep ids unique across rounds
        for i, h in enumerate(fresh):
            h.id = f"h{len(hyps) + i + 1}"
        hyps += fresh
        trace.append({"round": rnd, "proposed": len(new), "new": len(fresh),
                      "schema_errors": errs, "repaired": repaired})
        if not fresh:
            break
        decision = verifier.decide(hyps)
        if decision["status"] in (VERIFIED, MULTIPLE_VERIFIED):
            break
    if decision is None:
        decision = verifier.decide(hyps) if hyps else {
            "status": UNVERIFIED, "verdict": {"status": UNVERIFIED, "node": None, "property": None},
            "candidates": [], "outcomes": [], "missing_signals": [], "anchor": verifier.anchor,
            "primitive_calls": verifier.calls}
    return {**decision, "rounds": trace, "hypotheses_dropped": dropped,
            "hypotheses_total": len(hyps)}
