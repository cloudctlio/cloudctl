"""AWS/cloudctl adapter for the pure anchored ring search (causal_search.py).

Thin wiring layer only — ALL graph/ordering logic lives in the pure core
(``cloudctl.debug.causal_search``), which knows nothing about AWS. This module:

  1. Identifies the ANCHOR (where the failure was directly observed) from two
     generic, service-agnostic signals, in priority order:
       a. the localization failure map — the component observed emitting the
          failure IS the anchor;
       b. when the failure map is empty (an entry-point rejection before any
          downstream component logs anything), the resource a reproduction /
          probe call was made against — "the thing you tested, when nothing
          downstream shows activity, is the failure point";
       c. a caller-supplied hint (a model-chosen tool argument, treated as
          data) is used only when neither observed signal identifies a node.
     If none of these matches a graph node, the result is a graceful
     "no anchor identifiable" — never an exception, and the caller falls back
     to un-anchored behavior.
  2. Adapts ``get_dependency_graph`` output into the core's plain
     ``{"nodes": [...], "edges": [{"from","to"}]}`` shape. The "via" metadata
     is stripped here (the core tolerates extra keys, but stripping keeps the
     core's input contract minimal and documented in one place).
  3. Supplies the per-node INVESTIGATE callable: the existing differential
     tools ``get_prior_config`` + ``compare_peers`` against that node's
     resource. Each degrades to its own structured "unavailable" result; this
     adapter never crashes on that. Judgment call: ``native_reproduce_gated``
     is NOT auto-fired per node — it is operator-consent-gated per probe and
     draws from a shared budget, so auto-invoking it inside a breadth-first
     sweep would spam consent prompts and exhaust the budget on non-anchor
     nodes. The model can still call native_reproduce itself on the anchor.
  4. Supplies the CONCLUSIVE callable. The engine's mechanism-consistency
     standard (the MECHANISM & FRONTIER synthesis rule) is prompt-level, not
     callable as a pure function today — so, per the documented proxy, a node
     counts as a candidate finding when a differential result is available AND
     non-empty (an actual before→after or peer-vs-peer difference). The MODEL
     makes the final causal judgment on the returned trail; this adapter only
     orders and surfaces evidence, never judges which value is "right".

Everything here is read-only and graceful: every degradation path (no graph,
no anchor, tool unavailable/denied) returns a clean structured dict.
"""
from __future__ import annotations

import copy
import json

from cloudctl.debug.causal_search import ring_search

# Minimum identifier length for name matching between graph nodes and observed
# signals — purely structural (avoids trivial 1-3 char collisions), mirroring
# the boundary-match discipline get_dependency_graph itself uses.
_MIN_MATCH = 4

# Bounded cost defaults (same convention as branch turn limits / probe budget).
_DEFAULT_MAX_RINGS = 3
_MAX_RINGS_CEILING = 4
_DEFAULT_MAX_INVESTIGATIONS = 8


def _bare(node: str) -> str:
    """'namespace:name' -> 'name' (graph node ids carry a type prefix)."""
    return node.split(":", 1)[1] if ":" in node else node


def _names_match(a: str, b: str) -> bool:
    """Generic bidirectional identifier containment (case-insensitive, both
    sides at least _MIN_MATCH chars). No service vocabulary — string shape only."""
    a, b = (a or "").lower().strip(), (b or "").lower().strip()
    if len(a) < _MIN_MATCH or len(b) < _MIN_MATCH:
        return False
    return a in b or b in a


def adapt_dependency_graph(raw: dict | None) -> dict:
    """Adapt get_dependency_graph output to the pure core's input shape.

    Returns {"available", "nodes", "edges", "reason"}; edges keep only
    from/to (the "via" metadata is dropped — see module docstring)."""
    if not isinstance(raw, dict) or raw.get("error") or not raw.get("nodes"):
        reason = (raw or {}).get("error") if isinstance(raw, dict) else None
        return {"available": False, "nodes": [], "edges": [],
                "reason": str(reason or "dependency graph unavailable or empty")}
    edges = [
        {"from": str(e["from"]), "to": str(e["to"])}
        for e in raw.get("edges") or []
        if isinstance(e, dict) and e.get("from") and e.get("to")
    ]
    return {"available": True,
            "nodes": [str(n) for n in raw["nodes"] if n],
            "edges": edges, "reason": ""}


def _match_node(nodes: list, text: str) -> str | None:
    """The graph node whose bare name matches identifiers in ``text``;
    prefers the longest (most specific) matching name. None if no match."""
    best = None
    for node in nodes or []:
        if _names_match(_bare(node), text):
            if best is None or len(_bare(node)) > len(_bare(best)):
                best = node
    return best


def _reproduction_target_texts(evidence_store: dict | None) -> list:
    """Text descriptors of every reproduction/probe call recorded in the
    evidence store (key encodes the call's identifying inputs; the value may
    carry resolved identifiers). Generic: keys off the recording convention,
    not any service."""
    texts: list = []
    for key, value in (evidence_store or {}).items():
        base = str(key).split(":", 1)[0].split("#", 1)[0]
        if base in ("native_reproduce", "probe_http"):
            try:
                texts.append(str(key) + " " + json.dumps(value, default=str)[:2000])
            except Exception:  # noqa: BLE001
                texts.append(str(key))
    return texts


def identify_anchor(graph_nodes: list, failure_map: list | None = None,
                    evidence_store: dict | None = None,
                    anchor_hint: str | None = None) -> dict:
    """Hint-free anchor identification (see module docstring for the rules).
    Returns {"anchor": node-or-None, "source": str-or-None, "reason": str}."""
    # (a) A component OBSERVED emitting the failure is the anchor.
    for entry in failure_map or []:
        comp = str((entry or {}).get("component") or "") if isinstance(entry, dict) else ""
        if comp:
            node = _match_node(graph_nodes, comp)
            if node:
                return {"anchor": node, "source": "observed_emitting_component",
                        "reason": f"component '{comp}' is observed emitting failures"}
    # (b) Nothing downstream emitted — the resource the reproduction/probe was
    #     run against is where the symptom was measured: that is the anchor.
    for text in _reproduction_target_texts(evidence_store):
        node = _match_node(graph_nodes, text)
        if node:
            return {"anchor": node, "source": "reproduction_target",
                    "reason": "no component observed emitting failures; the "
                              "reproduction/probe target is the failure point"}
    # (c) Caller-supplied hint (model-chosen argument, treated as data).
    if anchor_hint:
        node = _match_node(graph_nodes, str(anchor_hint))
        if node:
            return {"anchor": node, "source": "caller_hint",
                    "reason": "no observed signal; using the caller-supplied hint"}
    return {"anchor": None, "source": None,
            "reason": ("no anchor identifiable: no component observed emitting "
                       "failures, no reproduction/probe target recorded, and no "
                       "hint matched a graph node")}


def _diff_present(probe: dict) -> bool:
    """Conclusive-proxy: does this node's differential result contain an actual
    available, non-empty difference? (Suppressed-only diffs do not count.)
    This surfaces a CANDIDATE finding — the model makes the causal judgment."""
    if not isinstance(probe, dict):
        return False

    def _nonempty_diff(d: dict) -> bool:
        return isinstance(d, dict) and bool(
            d.get("changed") or d.get("added") or d.get("removed"))

    pc = probe.get("prior_config") or {}
    vh = pc.get("version_history") or {}
    if vh.get("available"):
        if any(_nonempty_diff(x.get("diff") or {}) for x in vh.get("diffs") or []
               if isinstance(x, dict)):
            return True
    ct = pc.get("cloudtrail_reconstruction") or {}
    if ct.get("available"):
        if any(_nonempty_diff(x.get("diff") or {}) for x in
               ct.get("consecutive_diffs") or [] if isinstance(x, dict)):
            return True
    peers = probe.get("peer_comparison") or {}
    if not peers.get("peers_unavailable"):
        if any(_nonempty_diff(c.get("diff") or {}) for c in
               peers.get("comparisons") or [] if isinstance(c, dict)):
            return True
    return False


def _make_investigator(profile: str | None, region: str, minutes: int):
    """Per-node investigate callable: differential tools against the node's
    resource. Each tool already degrades to structured 'unavailable'; any
    unexpected exception is caught into the same shape (never raises)."""
    from cloudctl.mcp.tools.debug import get_prior_config, compare_peers  # noqa: PLC0415

    def investigate(node: str) -> dict:
        service_type, sep, name = node.partition(":")
        if not sep:
            service_type, name = "", node
        out: dict = {"node": node, "resource_name": name,
                     "service_type": service_type}
        try:
            out["prior_config"] = json.loads(get_prior_config(
                resource_name=name, service_type=service_type,
                profile=profile, region=region, minutes=minutes))
        except Exception as exc:  # noqa: BLE001
            out["prior_config"] = {
                "baseline_unavailable": True,
                "reason": f"prior_config failed: {type(exc).__name__}"}
        try:
            out["peer_comparison"] = json.loads(compare_peers(
                resource_name=name, service_type=service_type,
                profile=profile, region=region))
        except Exception as exc:  # noqa: BLE001
            out["peer_comparison"] = {
                "peers_unavailable": True,
                "reason": f"compare_peers failed: {type(exc).__name__}"}
        out["differential_available"] = _diff_present(out)
        return out

    return investigate


def causal_search_aws(profile: str | None, region: str,
                      failure_map: list | None = None,
                      evidence_store: dict | None = None,
                      anchor_hint: str | None = None,
                      minutes: int = 10080,
                      max_rings: int = _DEFAULT_MAX_RINGS,
                      max_investigations: int = _DEFAULT_MAX_INVESTIGATIONS) -> dict:
    """Run the anchored ring search against the live dependency graph.

    Read-only; bounded (rings and total differential calls); returns a
    structured dict on every path — including graph-unavailable and
    no-anchor — never an exception."""
    try:
        max_rings = min(max(0, int(max_rings)), _MAX_RINGS_CEILING)
    except Exception:  # noqa: BLE001
        max_rings = _DEFAULT_MAX_RINGS
    try:
        max_investigations = min(max(1, int(max_investigations)),
                                 _DEFAULT_MAX_INVESTIGATIONS)
    except Exception:  # noqa: BLE001
        max_investigations = _DEFAULT_MAX_INVESTIGATIONS

    from cloudctl.mcp.tools.debug import get_dependency_graph  # noqa: PLC0415
    try:
        raw = json.loads(get_dependency_graph(profile=profile, region=region))
    except Exception as exc:  # noqa: BLE001
        raw = {"error": f"get_dependency_graph failed: {type(exc).__name__}"}

    graph = adapt_dependency_graph(raw)
    if not graph["available"]:
        return {"available": False, "anchor": None,
                "reason": graph["reason"],
                "note": ("dependency graph unavailable — fall back to "
                         "un-anchored differential comparison, preferring the "
                         "resource where the failure was directly observed")}

    anch = identify_anchor(graph["nodes"], failure_map=failure_map,
                           evidence_store=evidence_store,
                           anchor_hint=anchor_hint)
    if not anch["anchor"]:
        return {"available": False, "anchor": None, "reason": anch["reason"],
                "note": ("no anchor identifiable — fall back to un-anchored "
                         "differential comparison, preferring the resource "
                         "where the failure was directly observed")}

    result = ring_search(
        {"nodes": graph["nodes"], "edges": graph["edges"]},
        anch["anchor"],
        _make_investigator(profile, region, minutes),
        _diff_present,
        max_rings=max_rings,
        max_investigations=max_investigations,
    )
    result["available"] = True
    result["anchor_source"] = anch["source"]
    result["anchor_reason"] = anch["reason"]
    result["note"] = (
        "ring-ordered differential trail outward from the failure anchor "
        "(ring 0 = where the failure was directly observed). A diff is a "
        "LEAD to verify against the observed failure mechanism, not a "
        "verdict; prefer the closest ring whose diff actually explains the "
        "symptom.")
    return result


# ── Deterministic enforcement (same shape as enforce_localization_anchor and
#    enforce_failure_grounding: soft confidence cap + structured note; never a
#    hard block, never an exception) ────────────────────────────────────────────

def _search_results(fetched_data: dict | None) -> list:
    out = []
    for key, value in (fetched_data or {}).items():
        base = str(key).split(":", 1)[0].split("#", 1)[0]
        if base == "causal_search" and isinstance(value, dict):
            if value.get("available") and value.get("anchor"):
                out.append(value)
    return out


def _ring0_checked(search: dict, fetched_data: dict | None) -> bool:
    """Was the anchor itself ever differential-checked? Either the search's own
    ring-0 trail entry produced an available differential read, or a manual
    differential call against the anchor's resource is in the corpus."""
    for entry in search.get("trail") or []:
        if isinstance(entry, dict) and entry.get("ring") == 0:
            probe = entry.get("investigate_result") or {}
            pc = probe.get("prior_config") or {}
            peers = probe.get("peer_comparison") or {}
            vh_ok = (pc.get("version_history") or {}).get("available")
            ct_ok = (pc.get("cloudtrail_reconstruction") or {}).get("available")
            peers_ok = bool(peers) and not peers.get("peers_unavailable")
            if vh_ok or ct_ok or peers_ok or probe.get("differential_available"):
                return True
    anchor_name = _bare(str(search.get("anchor", ""))).lower()
    if len(anchor_name) >= _MIN_MATCH:
        for key in (fetched_data or {}):
            base = str(key).split(":", 1)[0].split("#", 1)[0]
            if base in ("get_prior_config", "compare_peers") \
                    and anchor_name in str(key).lower():
                return True
    return False


def enforce_causal_anchor(agent_output: dict, fetched_data: dict | None) -> dict:
    """When anchored ring evidence exists but the verdict names a cause at ring
    distance > 0 from the anchor WITHOUT the anchor (ring 0) ever having been
    differential-checked, cap confidence ONE step and attach a structured note.
    Soft cap only — never a hard block, never an exception; conservative:
      * no causal_search evidence at all           → untouched (no false positive)
      * verdict names the anchor itself            → untouched
      * ring 0 was differential-checked (by the search or manually) → untouched
      * verdict's cause not tied to any ringed node → untouched
    """
    searches = _search_results(fetched_data)
    if not searches:
        return agent_output
    root = str(agent_output.get("root_cause", "")).lower()

    unanchored = []
    for search in searches:
        anchor_name = _bare(str(search.get("anchor", ""))).lower()
        anchor_named = len(anchor_name) >= _MIN_MATCH and anchor_name in root
        if anchor_named or _ring0_checked(search, fetched_data):
            return agent_output   # anchored investigation — leave the verdict alone
        unanchored.append(search)

    # Every available search: anchor never named, ring 0 never checked. Does the
    # verdict name a node at a known ring distance > 0?
    for search in unanchored:
        named, named_ring = None, None
        for node, ring in (search.get("rings") or {}).items():
            try:
                ring = int(ring)
            except Exception:  # noqa: BLE001
                continue
            if ring <= 0:
                continue
            name = _bare(str(node)).lower()
            if len(name) >= _MIN_MATCH and name in root:
                if named_ring is None or ring < named_ring:
                    named, named_ring = node, ring
        if named is None:
            continue
        claimed = agent_output.get("confidence", "MEDIUM")
        output = copy.deepcopy(agent_output)
        output["causal_anchor"] = {
            "anchored": False,
            "anchor": search.get("anchor"),
            "anchor_source": search.get("anchor_source"),
            "cause_node": named,
            "cause_ring_distance": named_ring,
            "ring0_differential_checked": False,
            "note": (f"The root cause names '{named}' at ring distance "
                     f"{named_ring} from the failure anchor "
                     f"'{search.get('anchor')}', but the anchor itself was "
                     "never differential-checked. Diff the anchor's own "
                     "configuration/history before attributing the failure to "
                     "a resource farther away in the dependency graph."),
        }
        step_down = {"HIGH": "MEDIUM", "MEDIUM": "LOW"}
        if claimed in step_down:
            output["confidence"] = step_down[claimed]
            output["confidence_override_reason"] = (
                f"Confidence capped from {claimed} to {output['confidence']}: "
                f"the verdict attributes the failure to a resource {named_ring} "
                "ring(s) away from the anchor (where the failure was directly "
                "observed) while the anchor's own configuration was never "
                "differential-checked.")
        return output
    return agent_output
