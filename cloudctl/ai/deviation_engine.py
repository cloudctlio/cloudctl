"""deviation_engine.py — deviation-first differential diagnosis (prototype).

Inverts the hypothesis-first paradigm. Instead of guessing ~3 causes from a
blind symptom and hoping the true cause is among them, this engine:

  1. Walks the REAL dependency graph of the deployed system (every node,
     not the nodes a triage guess happened to pick).
  2. Diffs each node's LIVE state against its INTENDED state, supplied by a
     pluggable BaselineProvider (IaC state, recorded-healthy snapshot, or
     peer consensus).
  3. Emits the deviations as a RANKED CANDIDATE SET. The true cause of any
     config-deviation incident is in the set BY CONSTRUCTION — coverage is
     guaranteed by enumeration, not by the quality of a guess.

The LLM's job then flips from intractable ("guess the cause from nothing")
to tractable ("here are N real, concrete deviations — which one causally
explains the measured symptom?").

Strictly hint-free by construction:
  - No AWS service names, resource names, field names, metric names, or
    error strings tied to any incident appear anywhere in this module.
  - All knowledge is STRUCTURAL: graph shape, diff kind (added / removed /
    changed), value shape (numeric, boolean, collection), and three generic
    SRE priors — capability CONTRACTION, RECENCY of change relative to
    onset, and graph PROXIMITY to the failing path. These are the same
    domain-agnostic rules a human SRE applies to any system.

All external I/O (live AWS reads, IaC parsing, change history) is behind
injectable Protocol interfaces, so the engine is fully unit-testable
offline. Thin live adapters are provided at the bottom of the module and
import their AWS dependencies lazily.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Mapping, Protocol, Sequence

# ── Data model ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ResourceNode:
    """One node of the dependency graph: a deployed resource."""
    service: str          # ARN namespace (generic — comes from the graph, not code)
    name: str
    arn: str = ""

    @property
    def node_id(self) -> str:
        return f"{self.service}:{self.name}"


@dataclass
class DependencyGraph:
    """Real dependency graph, e.g. parsed from the get_dependency_graph tool."""
    nodes: list[ResourceNode]
    edges: list[tuple[str, str]]          # (from_node_id, to_node_id)

    @classmethod
    def from_tool_output(cls, payload: Mapping | str) -> "DependencyGraph":
        """Parse the JSON emitted by the existing get_dependency_graph tool."""
        if isinstance(payload, str):
            payload = json.loads(payload)
        nodes = []
        for nid in payload.get("nodes", []):
            svc, _, name = str(nid).partition(":")
            nodes.append(ResourceNode(service=svc, name=name))
        edges = [
            (str(e.get("from", "")), str(e.get("to", "")))
            for e in payload.get("edges", [])
            if e.get("from") and e.get("to")
        ]
        return cls(nodes=nodes, edges=edges)

    def hops_from(self, entry_node_ids: Sequence[str]) -> dict[str, int]:
        """Undirected BFS distance (in hops) from any entry node. Nodes not
        reachable get no entry (treated as neutral by the ranker)."""
        adj: dict[str, set[str]] = {}
        for a, b in self.edges:
            adj.setdefault(a, set()).add(b)
            adj.setdefault(b, set()).add(a)
        dist: dict[str, int] = {}
        frontier = [nid for nid in entry_node_ids if nid]
        for nid in frontier:
            dist[nid] = 0
        while frontier:
            nxt: list[str] = []
            for nid in frontier:
                for nb in adj.get(nid, ()):
                    if nb not in dist:
                        dist[nb] = dist[nid] + 1
                        nxt.append(nb)
            frontier = nxt
        return dist


@dataclass(frozen=True)
class ChangeRecord:
    """Most recent out-of-band change to a resource (e.g. from audit history)."""
    at: datetime | None = None
    actor: str = ""
    event: str = ""


@dataclass(frozen=True)
class ChangeEvent:
    """One mutating change to a resource, as recorded by an audit trail
    (CloudTrail Event History). The event ITSELF is a deviation: the changed
    field and its NEW value come from `params` (the event's requestParameters),
    the time and actor come from the record. The prior value is usually not in
    the event — and is not needed: a deliberate mutation to a node on the
    failing path, close to onset, is a candidate on its own."""
    at: datetime | None
    actor: str
    event_name: str
    params: Mapping = field(default_factory=dict)   # requestParameters (new values)
    read_only: bool = False


# Deviation kinds — purely structural.
KIND_CHANGED = "changed"
KIND_REMOVED = "removed"     # present in intended state, absent live
KIND_ADDED = "added"         # present live, absent from intended state


@dataclass
class Deviation:
    """One concrete difference between intended and live state."""
    node_id: str
    path: str                       # dotted leaf path (live-side when aligned)
    kind: str                       # changed | removed | added
    intended: object
    live: object
    score: float = 0.0
    signals: dict = field(default_factory=dict)
    last_change: ChangeRecord | None = None

    def describe(self) -> str:
        if self.kind == KIND_REMOVED:
            body = f"intended={self.intended!r} is ABSENT from live state"
        elif self.kind == KIND_ADDED:
            body = f"live={self.live!r} is NOT in intended state"
        elif self.intended is None:
            # Event-derived: a change was observed but the prior value is unknown.
            body = f"changed to {self.live!r} (prior value unknown)"
        else:
            body = f"intended={self.intended!r} -> live={self.live!r}"
        when = ""
        if self.last_change and self.last_change.at:
            when = f" (changed {self.last_change.at.isoformat()}"
            if self.last_change.event:
                when += f" via {self.last_change.event}"
            if self.last_change.actor:
                when += f" by {self.last_change.actor}"
            when += ")"
        return f"{self.node_id} {self.path}: {body}{when}"


@dataclass
class CandidateSet:
    """The ranked output of a deviation scan — the differential-diagnosis
    candidate list handed to the reasoning layer."""
    deviations: list[Deviation]
    scanned_nodes: list[str]
    unscanned_nodes: dict[str, str]     # node_id -> reason (honest coverage gaps)
    baseline_sources: dict[str, str]    # node_id -> which baseline supplied intent
    onset: datetime | None = None

    def top(self, n: int) -> list[Deviation]:
        return self.deviations[:n]

    def to_dict(self) -> dict:
        return {
            "deviation_count": len(self.deviations),
            "deviations": [
                {
                    "node": d.node_id, "path": d.path, "kind": d.kind,
                    "intended": d.intended, "live": d.live,
                    "score": round(d.score, 4), "signals": d.signals,
                    "last_changed_at": (
                        d.last_change.at.isoformat()
                        if d.last_change and d.last_change.at else ""
                    ),
                    "last_changed_by": (
                        d.last_change.actor if d.last_change else ""
                    ),
                }
                for d in self.deviations
            ],
            "scanned_nodes": self.scanned_nodes,
            "unscanned_nodes": self.unscanned_nodes,
            "baseline_sources": self.baseline_sources,
        }

    def to_prompt_block(self, max_items: int = 10) -> str:
        """Render the candidate set as investigation DATA for the triage
        prompt. This is observed fact (live vs intended values from real
        reads), not encoded knowledge — the same text a diff tool would
        print for any system."""
        lines = ["DETECTED DEVIATIONS (live state vs intended baseline, ranked):"]
        if not self.deviations:
            lines.append(
                "  (none — every scanned node matches its baseline; the cause "
                "is likely runtime-only, load-driven, or on an unscanned node)"
            )
        for i, d in enumerate(self.deviations[:max_items], 1):
            lines.append(f"  {i}. [{d.score:.2f}] {d.describe()}")
        skipped = len(self.deviations) - max_items
        if skipped > 0:
            lines.append(f"  ... {skipped} lower-ranked deviations omitted")
        lines.append(
            f"COVERAGE: {len(self.scanned_nodes)} nodes diffed against a baseline"
            + (
                f"; NO baseline for {len(self.unscanned_nodes)} nodes: "
                + ", ".join(sorted(self.unscanned_nodes)[:8])
                if self.unscanned_nodes else ""
            )
        )
        return "\n".join(lines)


# ── Provider interfaces (all I/O is injectable) ────────────────────────────────


class LiveStateProvider(Protocol):
    def get_live_state(self, node: ResourceNode) -> Mapping | None:
        """Current observed configuration of the resource, or None."""
        ...  # pragma: no cover


class BaselineProvider(Protocol):
    name: str
    sparse: bool   # True => baseline declares only a subset of fields; live-only
                   # fields are then NOT deviations (IaC never mirrors full state)

    def get_intended_state(self, node: ResourceNode) -> Mapping | None:
        """Intended configuration of the resource, or None if unknown."""
        ...  # pragma: no cover


class ChangeHistoryProvider(Protocol):
    def get_last_change(self, node: ResourceNode) -> ChangeRecord | None:
        ...  # pragma: no cover


class ChangeEventProvider(Protocol):
    """PRIMARY baseline source: the audit trail. Returns the mutating change
    events touching a node within the provider's own look-back window. Unlike a
    state baseline it needs no prior-state store and no IaC — every account has
    CloudTrail Event History on by default, ~90 days, free to query."""
    name: str

    def get_changes(self, node: ResourceNode) -> Sequence[ChangeEvent]:
        ...  # pragma: no cover


class SnapshotStore(Protocol):
    """Backing store for cloudctl's OWN periodic/known-healthy config captures.
    Makes the engine self-sufficient when no change event exists (born-
    misconfigured, slow drift, or a change older than the audit window)."""

    def get(self, node: ResourceNode,
            before: datetime | None = None) -> Mapping | None:
        """Most recent snapshotted state for the node captured strictly BEFORE
        `before` (the onset), or the latest of all if `before` is None."""
        ...  # pragma: no cover

    def put(self, node: ResourceNode, state: Mapping,
            at: datetime) -> None:  # pragma: no cover
        ...


# ── Concrete baseline providers ────────────────────────────────────────────────


class StaticBaseline:
    """Recorded-healthy snapshot baseline: node_id -> full intended state.
    Snapshots are complete captures of live state, so sparse=False."""
    name = "healthy_snapshot"
    sparse = False

    def __init__(self, states: Mapping[str, Mapping]):
        self._states = dict(states)

    def get_intended_state(self, node: ResourceNode) -> Mapping | None:
        return self._states.get(node.node_id)


class TerraformStateBaseline:
    """Intended state from a Terraform state document (parsed JSON dict).

    IMPORTANT OPERATIONAL NOTE: point this at a KNOWN-GOOD state (for example
    the automatic `terraform.tfstate.backup` written before the most recent
    apply, or a state file archived while the system was healthy). If the
    incident itself was applied through IaC, the CURRENT state file already
    contains the fault and diffing against it yields nothing — intent must
    predate the change under suspicion.

    Parsing is format-generic: it reads the documented tfstate schema
    (resources[].instances[].attributes) and derives the node identity from
    the resource's own ARN when present (namespace + trailing name segment),
    falling back to the token after the IaC provider prefix. No resource
    types or attribute names are special-cased.
    """
    name = "terraform_state"
    sparse = True

    def __init__(self, state_document: Mapping):
        self._by_node: dict[str, dict] = {}
        for res in state_document.get("resources", []):
            if res.get("mode") != "managed":
                continue
            for inst in res.get("instances", []):
                attrs = inst.get("attributes") or {}
                node_id = self._identify(res.get("type", ""), attrs)
                if node_id:
                    self._by_node[node_id] = dict(attrs)

    @staticmethod
    def _identify(tf_type: str, attrs: Mapping) -> str:
        arn = str(attrs.get("arn", ""))
        parts = arn.split(":", 5)
        if len(parts) == 6:
            service = parts[2]
            tail = parts[5]
            name = tail.split("/")[-1] if "/" in tail else tail.split(":")[-1]
            if service and name:
                return f"{service}:{name}"
        # Fallback: "<provider>_<service>_<kind>" -> service token; name from a
        # generically-named identity attribute.
        tokens = tf_type.split("_")
        service = tokens[1] if len(tokens) > 1 else ""
        name = str(attrs.get("name") or attrs.get("id") or "")
        if service and name:
            return f"{service}:{name}"
        return ""

    def get_intended_state(self, node: ResourceNode) -> Mapping | None:
        return self._by_node.get(node.node_id)


class PeerBaseline:
    """Intended state inferred from PEER CONSENSUS: for each leaf where a
    strict majority of same-service peer resources agree on a value, that
    value is the intended one. Needs >= 2 peers besides the node itself.
    Baseline-of-last-resort when neither IaC nor a snapshot exists."""
    name = "peer_consensus"
    sparse = True

    def __init__(self, live_provider: LiveStateProvider,
                 nodes: Sequence[ResourceNode], min_peers: int = 2):
        self._live = live_provider
        self._nodes = list(nodes)
        self._min_peers = min_peers
        self._cache: dict[str, Mapping | None] = {}

    def get_intended_state(self, node: ResourceNode) -> Mapping | None:
        if node.node_id in self._cache:
            return self._cache[node.node_id]
        peers = [n for n in self._nodes
                 if n.service == node.service and n.node_id != node.node_id]
        if len(peers) < self._min_peers:
            self._cache[node.node_id] = None
            return None
        peer_leaves: list[dict[tuple, object]] = []
        for p in peers:
            state = self._live.get_live_state(p)
            if state:
                peer_leaves.append(_flatten(state))
        if len(peer_leaves) < self._min_peers:
            self._cache[node.node_id] = None
            return None
        intended: dict[str, object] = {}
        all_paths = {path for leaves in peer_leaves for path in leaves}
        for path in all_paths:
            values = [json.dumps(leaves[path], default=str)
                      for leaves in peer_leaves if path in leaves]
            if len(values) < self._min_peers:
                continue
            top, count = _mode(values)
            if count * 2 > len(peer_leaves):        # strict majority of peers
                intended[".".join(path)] = json.loads(top)
        self._cache[node.node_id] = intended or None
        return intended or None


class StaticChangeHistory:
    """Injectable change history: node_id -> ChangeRecord."""

    def __init__(self, records: Mapping[str, ChangeRecord]):
        self._records = dict(records)

    def get_last_change(self, node: ResourceNode) -> ChangeRecord | None:
        return self._records.get(node.node_id)


class StaticChangeEvents:
    """Injectable ChangeEventProvider: node_id -> [ChangeEvent, ...]. Offline
    test double for the CloudTrail-derived baseline path."""
    name = "cloudtrail_change"

    def __init__(self, events: Mapping[str, Sequence[ChangeEvent]]):
        self._events = {k: list(v) for k, v in events.items()}

    def get_changes(self, node: ResourceNode) -> Sequence[ChangeEvent]:
        return self._events.get(node.node_id, [])


class DictSnapshotStore:
    """In-memory SnapshotStore for tests and small deployments. Keeps a
    time-ordered history per node so `get(before=onset)` returns the most
    recent capture that predates the incident."""

    def __init__(self):
        self._by_node: dict[str, list[tuple[datetime, dict]]] = {}

    def put(self, node: ResourceNode, state: Mapping, at: datetime) -> None:
        series = self._by_node.setdefault(node.node_id, [])
        series.append((at, dict(state)))
        series.sort(key=lambda t: t[0])

    def get(self, node: ResourceNode,
            before: datetime | None = None) -> Mapping | None:
        series = self._by_node.get(node.node_id)
        if not series:
            return None
        if before is None:
            return series[-1][1]
        eligible = [s for (at, s) in series if at < before]
        return eligible[-1] if eligible else None


class SnapshotBaseline:
    """cloudctl SELF-SNAPSHOT baseline — the product answer for "no change
    event exists" (born-misconfigured, gradual drift, or a change older than
    the audit window). Diffs live-now against the most recent known-healthy
    snapshot that predates onset. Self-sufficient: independent of AWS Config,
    of CloudTrail retention, AND of any IaC tool.

    A snapshot is a full live capture, so `sparse=False` — a field present in
    the snapshot but gone from live is a genuine REMOVED, and a new live-only
    field is a genuine ADDED. `before` is set to the incident onset by the
    caller so a snapshot taken AFTER the fault landed is never used as intent.
    """
    name = "self_snapshot"
    sparse = False

    def __init__(self, store: SnapshotStore, before: datetime | None = None):
        self._store = store
        self._before = before

    def get_intended_state(self, node: ResourceNode) -> Mapping | None:
        return self._store.get(node, before=self._before)


class AwsConfigBaseline:
    """OPTIONAL enhancement — prior config item from AWS Config's configuration
    history. Richer than a CloudTrail delta (full before/after config items),
    BUT AWS Config is off by default, must be explicitly enabled, and bills per
    config item — so it is the LAST of the state sources and NEVER required.
    Only include it in the chain when the account is known to have Config on.

    `history_fn(node, before) -> Mapping|None` is injectable so the provider is
    unit-testable without AWS; the live default lazily queries Config and
    returns None on any failure (unmapped resource, Config disabled, etc.),
    letting the chain fall through cleanly.
    """
    name = "aws_config"
    sparse = False

    def __init__(self, before: datetime | None = None, *,
                 history_fn=None, profile: str | None = None,
                 region: str | None = None):
        self._before = before
        self._history_fn = history_fn
        self._profile = profile
        self._region = region

    def get_intended_state(self, node: ResourceNode) -> Mapping | None:
        if self._history_fn is not None:
            return self._history_fn(node, self._before)
        return self._live_history(node)

    def _live_history(self, node: ResourceNode) -> Mapping | None:
        try:
            from cloudctl.mcp.tools.debug import _make_session
            client = _make_session(self._profile, self._region).client("config")
            # Best-effort: list config items and pick the newest that predates
            # onset. resourceId derives from the node name; if Config cannot map
            # it, we return None and the chain falls through. No per-service
            # ResourceType table is hardcoded — we let Config resolve by id.
            resp = client.list_discovered_resources(
                resourceType="", resourceIds=[node.name], limit=1)
            resources = resp.get("resourceIdentifiers", [])
            if not resources:
                return None
            rid = resources[0]
            hist = client.get_resource_config_history(
                resourceType=rid["resourceType"],
                resourceId=rid["resourceId"], limit=25,
            ).get("configurationItems", [])
            for item in hist:               # newest-first per the API
                captured = item.get("configurationItemCaptureTime")
                if self._before and captured and captured >= self._before:
                    continue
                cfg = item.get("configuration")
                if isinstance(cfg, str):
                    cfg = json.loads(cfg)
                if isinstance(cfg, Mapping):
                    return cfg
        except Exception:  # noqa: BLE001
            return None
        return None


def _mode(values: list[str]) -> tuple[str, int]:
    counts: dict[str, int] = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    best = max(sorted(counts), key=lambda k: counts[k])
    return best, counts[best]


# ── Structural diff ────────────────────────────────────────────────────────────

# Value-shape volatility: timestamps/dates change on every read and are never
# intent. Detected by VALUE SHAPE, not by key name — no field literals.
_TS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}([T ]\d{2}:\d{2}(:\d{2})?([.,]\d+)?(Z|[+-]\d{2}:?\d{2})?)?$"
)

_CANON_RE = re.compile(r"[^a-z0-9]+")


def _canon(segment: str) -> str:
    return _CANON_RE.sub("", str(segment).lower())


def _is_volatile(value: object) -> bool:
    return isinstance(value, str) and bool(_TS_RE.match(value.strip()))


def _flatten(state: Mapping, _prefix: tuple = ()) -> dict[tuple, object]:
    """Flatten nested dict/list state into leaf paths.

    Lists of scalars become a single order-insensitive leaf (a sorted tuple of
    string forms) so that reordering is not a deviation but shrink/growth is.
    Lists of structures recurse with index segments."""
    leaves: dict[tuple, object] = {}
    for key, value in state.items():
        path = _prefix + (str(key),)
        if isinstance(value, Mapping):
            leaves.update(_flatten(value, path))
        elif isinstance(value, (list, tuple)):
            if all(not isinstance(i, (Mapping, list, tuple)) for i in value):
                leaves[path] = tuple(sorted(str(i) for i in value))
            else:
                for idx, item in enumerate(value):
                    ipath = path + (f"[{idx}]",)
                    if isinstance(item, Mapping):
                        leaves.update(_flatten(item, ipath))
                    else:
                        leaves[ipath] = item
        else:
            leaves[path] = value
    return leaves


def _norm(value: object) -> object:
    """Normalize for comparison: numeric strings equal their numbers; strings
    are stripped. Booleans are kept distinct from numbers."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        s = value.strip()
        try:
            return float(s)
        except ValueError:
            return s
    return value


@dataclass(frozen=True)
class RawDeviation:
    path: str
    kind: str
    intended: object
    live: object


def _is_self_reference(value: object, node: ResourceNode | None) -> bool:
    """A leaf whose value is the node's OWN identity (its name, id, or a
    self-ARN) is how the node was located, not intent to enforce — declarative
    baselines carry identity attributes that live API state does not mirror
    field-for-field. Generic: applies to any resource, names nothing."""
    if node is None or not isinstance(value, str):
        return False
    v = value.strip()
    if v in (node.name, node.arn, node.node_id):
        return True
    if v.startswith("arn:"):
        tail = v.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
        return tail == node.name
    return False


def diff_states(intended: Mapping, live: Mapping, *,
                sparse_baseline: bool,
                node: ResourceNode | None = None) -> list[RawDeviation]:
    """Structural diff of intended vs live state.

    Alignment is two-stage and purely lexical (no field knowledge):
      1. exact match on the canonicalized full path;
      2. for leaves still unmatched, a UNIQUE containment match on the
         canonicalized leaf key (so declarative snake_case intent aligns with
         live CamelCase API fields, e.g. `flush_interval` ~ FlushIntervalSeconds,
         without naming any specific field).

    With a sparse baseline (IaC / peer consensus declares only some fields),
    live-only leaves are NOT deviations; with a full snapshot they are ADDED.
    """
    fi = {k: v for k, v in _flatten(intended).items()
          if not _is_volatile(v) and not _is_self_reference(v, node)}
    fl = {k: v for k, v in _flatten(live).items()
          if not _is_volatile(v)}

    canon_int = {tuple(_canon(s) for s in path): path for path in fi}
    canon_live = {tuple(_canon(s) for s in path): path for path in fl}

    pairs: list[tuple[tuple, tuple]] = []
    matched_live: set[tuple] = set()

    # Stage 1: exact canonical-path match
    for cpath, ipath in canon_int.items():
        if cpath in canon_live:
            lpath = canon_live[cpath]
            pairs.append((ipath, lpath))
            matched_live.add(lpath)

    # Stage 2: unique leaf-key containment among the leftovers
    unmatched_int = [p for p in fi if p not in {a for a, _ in pairs}]
    unmatched_live = [p for p in fl if p not in matched_live]
    for ipath in list(unmatched_int):
        ikey = _canon(ipath[-1])
        if len(ikey) < 3:
            continue
        candidates = [
            lpath for lpath in unmatched_live
            if len(_canon(lpath[-1])) >= 3
            and (ikey in _canon(lpath[-1]) or _canon(lpath[-1]) in ikey)
        ]
        if len(candidates) == 1:
            lpath = candidates[0]
            pairs.append((ipath, lpath))
            matched_live.add(lpath)
            unmatched_live.remove(lpath)
            unmatched_int.remove(ipath)

    out: list[RawDeviation] = []
    for ipath, lpath in pairs:
        a, b = fi[ipath], fl[lpath]
        if _norm(a) != _norm(b):
            out.append(RawDeviation(
                path=".".join(lpath), kind=KIND_CHANGED, intended=a, live=b,
            ))
    for ipath in unmatched_int:
        out.append(RawDeviation(
            path=".".join(ipath), kind=KIND_REMOVED, intended=fi[ipath], live=None,
        ))
    if not sparse_baseline:
        for lpath in unmatched_live:
            out.append(RawDeviation(
                path=".".join(lpath), kind=KIND_ADDED, intended=None, live=fl[lpath],
            ))
    return out


# ── Ranking ────────────────────────────────────────────────────────────────────
#
# score = 0.50 * change_signal  (what kind of difference, how big, and does it
#                                CONTRACT a capability — removal/decrease/disable)
#       + 0.30 * temporal       (how close the node's last change is to onset;
#                                changes AFTER onset are near-vetoed)
#       + 0.20 * proximity      (graph hops from the failing path's entry node)
#
# All three are generic SRE priors; none encodes any service or incident.

_W_CHANGE, _W_TEMPORAL, _W_PROXIMITY = 0.50, 0.30, 0.20
_TEMPORAL_TAU_HOURS = 6.0


def _change_signal(d: RawDeviation) -> tuple[float, bool]:
    """Return (signal 0..1, contraction?). Contraction = a capability got
    smaller/disabled/removed — the classic outage shape."""
    if d.kind == KIND_REMOVED:
        return 1.0, True
    if d.kind == KIND_ADDED:
        return 0.35, False
    if d.intended is None:
        # Event-derived deviation: a deliberate mutation was observed but the
        # prior value is unknown, so magnitude/contraction cannot be judged.
        # A known recent change is a moderate-strong prior on its own; the
        # temporal + proximity signals do the ranking work.
        return 0.6, False
    a, b = _norm(d.intended), _norm(d.live)
    if isinstance(a, bool) or isinstance(b, bool):
        if bool(a) and not bool(b):
            return 1.0, True
        return 0.7, False
    if isinstance(a, float) and isinstance(b, float):
        rel = abs(a - b) / max(abs(a), abs(b), 1.0)
        contracted = b < a
        return min(1.0, rel + (0.25 if contracted else 0.0)), contracted
    if isinstance(d.intended, tuple) and isinstance(d.live, tuple):
        if len(d.live) < len(d.intended):
            return 0.9, True
        return 0.5, False
    return 0.45, False


def _temporal_signal(change: ChangeRecord | None,
                     onset: datetime | None) -> float:
    if not change or not change.at or not onset:
        return 0.5
    delta_h = (onset - change.at).total_seconds() / 3600.0
    if delta_h < 0:
        return 0.05           # changed AFTER onset — cannot have caused it
    return math.exp(-delta_h / _TEMPORAL_TAU_HOURS)


def _proximity_signal(node_id: str, hops: Mapping[str, int] | None) -> float:
    if not hops:
        return 0.5
    if node_id not in hops:
        return 0.25           # not reachable from the failing path
    return 1.0 / (1.0 + hops[node_id])


# ── Engine ─────────────────────────────────────────────────────────────────────


class DeviationEngine:
    """Graph-walk + per-node deviation detection -> ranked candidate set.

    Per node, sources are consulted in a strict priority order and the FIRST
    that yields anything wins (`build_default_engine` wires the recommended
    chain: CloudTrail change events -> self-snapshot -> peer -> Config -> IaC):

      0. change_event_provider (PRIMARY) — a mutating audit-trail event IS a
         deviation; needs no prior-state store and no IaC. Default-on in every
         account, free to query, ~90-day retention.
      1..N baseline_providers (state-diff, in the order given) — each yields an
         intended-state dict that is diffed against live. Recommended order:
         self-snapshot, peer-consensus, AWS Config (optional), IaC (optional).

    All collaborators are injected; the engine itself performs no I/O.
    """

    def __init__(
        self,
        live_provider: LiveStateProvider,
        baseline_providers: Sequence[BaselineProvider] = (),
        change_history: ChangeHistoryProvider | None = None,
        change_event_provider: ChangeEventProvider | None = None,
    ):
        self._live = live_provider
        self._baselines = list(baseline_providers)
        self._history = change_history
        self._change_source = change_event_provider

    def scan(
        self,
        graph: DependencyGraph | Mapping | str,
        entry_node_ids: Sequence[str] | None = None,
        onset: datetime | None = None,
    ) -> CandidateSet:
        if not isinstance(graph, DependencyGraph):
            graph = DependencyGraph.from_tool_output(graph)
        hops = graph.hops_from(entry_node_ids) if entry_node_ids else None

        deviations: list[Deviation] = []
        scanned: list[str] = []
        unscanned: dict[str, str] = {}
        sources: dict[str, str] = {}

        for node in graph.nodes:
            live = self._live.get_live_state(node)
            if live is None:
                unscanned[node.node_id] = "no live state readable"
                continue
            detected, source_name = self._detect(node, live)
            if detected is None:
                unscanned[node.node_id] = (
                    "no baseline source (no recent change event, snapshot, "
                    "peers, Config, or IaC)"
                )
                continue
            scanned.append(node.node_id)
            sources[node.node_id] = source_name
            for raw, change in detected:
                sig_change, contracted = _change_signal(raw)
                sig_temporal = _temporal_signal(change, onset)
                sig_prox = _proximity_signal(node.node_id, hops)
                score = (_W_CHANGE * sig_change
                         + _W_TEMPORAL * sig_temporal
                         + _W_PROXIMITY * sig_prox)
                deviations.append(Deviation(
                    node_id=node.node_id, path=raw.path, kind=raw.kind,
                    intended=raw.intended, live=raw.live,
                    score=score,
                    signals={
                        "change": round(sig_change, 4),
                        "contraction": contracted,
                        "temporal": round(sig_temporal, 4),
                        "proximity": round(sig_prox, 4),
                        "baseline": source_name,
                    },
                    last_change=change,
                ))

        # Deterministic order: score desc, then stable lexical tie-break.
        deviations.sort(key=lambda d: (-d.score, d.node_id, d.path))
        return CandidateSet(
            deviations=deviations,
            scanned_nodes=sorted(scanned),
            unscanned_nodes=unscanned,
            baseline_sources=sources,
            onset=onset,
        )

    def _detect(
        self, node: ResourceNode, live: Mapping
    ) -> tuple[list[tuple[RawDeviation, ChangeRecord | None]] | None, str]:
        """Resolve deviations for one node in priority order. Returns the list
        of (raw deviation, change record) pairs and the winning source name, or
        (None, "") if no source had anything."""
        # 0. PRIMARY: CloudTrail change events — the change itself is a deviation.
        if self._change_source is not None:
            events = [e for e in self._change_source.get_changes(node)
                      if not e.read_only]
            if events:
                pairs = self._deviations_from_events(node, events)
                if pairs:
                    return pairs, self._change_source.name

        # 1..N: state-diff baselines, in the given priority order.
        for provider in self._baselines:
            intended = provider.get_intended_state(node)
            if not intended:
                continue
            change = (self._history.get_last_change(node)
                      if self._history else None)
            raws = diff_states(intended, live,
                               sparse_baseline=provider.sparse, node=node)
            return [(r, change) for r in raws], provider.name
        return None, ""

    @staticmethod
    def _deviations_from_events(
        node: ResourceNode, events: Sequence[ChangeEvent]
    ) -> list[tuple[RawDeviation, ChangeRecord | None]]:
        """Turn mutating change events into deviations. Each changed field in an
        event's requestParameters is a deviation whose NEW value is observed and
        whose prior value is unknown. When the SAME field was changed more than
        once in the window, the previous event's value reconstructs the prior —
        recovering a real before->after diff (and its contraction signal) with
        no state store at all. Purely structural: no field/service literals."""
        from collections import defaultdict as _dd

        _MIN = datetime.min.replace(tzinfo=_tzinfo(events))
        timeline: dict[tuple, list[tuple[datetime, object, ChangeEvent]]] = _dd(list)
        for ev in sorted(events, key=lambda e: e.at or _MIN):
            for path, value in _flatten(ev.params or {}).items():
                if _is_volatile(value) or _is_self_reference(value, node):
                    continue
                timeline[path].append((ev.at, value, ev))

        out: list[tuple[RawDeviation, ChangeRecord | None]] = []
        for path, series in timeline.items():
            _at, value, ev = series[-1]                 # newest value = live intent
            prior = series[-2][1] if len(series) >= 2 else None
            change = ChangeRecord(at=ev.at, actor=ev.actor, event=ev.event_name)
            out.append((RawDeviation(
                path=".".join(path), kind=KIND_CHANGED,
                intended=prior, live=value,
            ), change))
        return out


def _tzinfo(events: Sequence[ChangeEvent]):
    """Match the sort sentinel's tz-awareness to the events' so sorting never
    raises on mixed aware/naive comparisons."""
    for e in events:
        if e.at is not None:
            return e.at.tzinfo
    return None


# ── Thin live adapters (lazy imports; excluded from unit-test surface) ─────────


class AwsLiveStateProvider:
    """Live state via the existing generic (service-agnostic) config fetcher."""

    def __init__(self, profile: str | None, region: str):
        self._profile = profile
        self._region = region
        self._fetcher = None

    def _get_fetcher(self):
        if self._fetcher is None:
            from cloudctl.mcp.tools.debug import _make_session
            from cloudctl.debug.fetcher import DebugFetcher
            self._fetcher = DebugFetcher(
                _make_session(self._profile, self._region))
        return self._fetcher

    def get_live_state(self, node: ResourceNode) -> Mapping | None:
        try:
            cfg = self._get_fetcher().generic_resource_config(
                node.service, node.name)
            return cfg or None
        except Exception:  # noqa: BLE001
            return None


class CloudTrailChangeHistory:
    """Last-change lookup via the audit trail (bounded, best-effort)."""

    def __init__(self, profile: str | None, region: str,
                 lookback_hours: int = 72):
        self._profile = profile
        self._region = region
        self._hours = lookback_hours

    def get_last_change(self, node: ResourceNode) -> ChangeRecord | None:
        import datetime as _dt
        try:
            from cloudctl.mcp.tools.debug import _make_session
            session = _make_session(self._profile, self._region)
            ct = session.client("cloudtrail")
            end = _dt.datetime.now(_dt.timezone.utc)
            start = end - _dt.timedelta(hours=self._hours)
            resp = ct.lookup_events(
                LookupAttributes=[{"AttributeKey": "ResourceName",
                                   "AttributeValue": node.name}],
                StartTime=start, EndTime=end, MaxResults=10,
            )
            # First event that is not read-only is the last mutation.
            for ev in resp.get("Events", []):
                detail = json.loads(ev.get("CloudTrailEvent", "{}"))
                if str(detail.get("readOnly", "")).lower() == "true":
                    continue
                at = ev.get("EventTime")
                return ChangeRecord(
                    at=at if isinstance(at, _dt.datetime) else None,
                    actor=str(ev.get("Username", "")),
                    event=str(ev.get("EventName", "")),
                )
        except Exception:  # noqa: BLE001
            return None
        return None


class CloudTrailChangeProvider:
    """PRIMARY live baseline source: mutating change events from CloudTrail
    Event History (default-on, ~90 days, no setup or cost to query). Emits
    clean ChangeEvents whose `params` carry the NEW values from each event's
    requestParameters — the CloudTrail-schema parsing lives here so the engine
    stays schema-agnostic."""
    name = "cloudtrail_change"

    def __init__(self, profile: str | None, region: str,
                 lookback_hours: int = 24 * 90, max_events: int = 25):
        self._profile = profile
        self._region = region
        self._hours = lookback_hours
        self._max = max_events

    def get_changes(self, node: ResourceNode) -> Sequence[ChangeEvent]:
        import datetime as _dt
        out: list[ChangeEvent] = []
        try:
            from cloudctl.mcp.tools.debug import _make_session
            ct = _make_session(self._profile, self._region).client("cloudtrail")
            end = _dt.datetime.now(_dt.timezone.utc)
            start = end - _dt.timedelta(hours=self._hours)
            resp = ct.lookup_events(
                LookupAttributes=[{"AttributeKey": "ResourceName",
                                   "AttributeValue": node.name}],
                StartTime=start, EndTime=end, MaxResults=self._max,
            )
            for ev in resp.get("Events", []):
                detail = json.loads(ev.get("CloudTrailEvent", "{}"))
                read_only = str(detail.get("readOnly", "")).lower() == "true"
                params = detail.get("requestParameters") or {}
                if not isinstance(params, Mapping):
                    params = {}
                at = ev.get("EventTime")
                out.append(ChangeEvent(
                    at=at if isinstance(at, _dt.datetime) else None,
                    actor=str(ev.get("Username", "")),
                    event_name=str(ev.get("EventName", "")),
                    params=params,
                    read_only=read_only,
                ))
        except Exception:  # noqa: BLE001
            return []
        return out


def load_terraform_state(path: str) -> TerraformStateBaseline:
    """Convenience: build a TerraformStateBaseline from a state file on disk.
    Point it at a KNOWN-GOOD state (see class docstring)."""
    with open(path, encoding="utf-8") as fh:
        return TerraformStateBaseline(json.load(fh))


def build_default_engine(
    profile: str | None,
    region: str,
    *,
    onset: datetime | None = None,
    graph_nodes: Sequence[ResourceNode] = (),
    snapshot_store: SnapshotStore | None = None,
    aws_config_enabled: bool = False,
    terraform_state: Mapping | None = None,
    cloudtrail_lookback_hours: int = 24 * 90,
) -> DeviationEngine:
    """Assemble the RECOMMENDED source chain with live adapters:

        CloudTrail change events (PRIMARY)
          -> self-snapshot (if a store is configured)
          -> peer consensus
          -> AWS Config (only if explicitly enabled)
          -> IaC parse (only if state/repo is reachable; Terraform shown, other
             tools are sibling providers added later)

    IaC and AWS Config are optional and NEVER default; if none of the sources
    yields anything for a node, that node stays in `unscanned_nodes` and the
    incident falls back to hypothesis-first quality (no fabricated diff)."""
    live = AwsLiveStateProvider(profile, region)
    baselines: list[BaselineProvider] = []
    if snapshot_store is not None:
        baselines.append(SnapshotBaseline(snapshot_store, before=onset))
    baselines.append(PeerBaseline(live, graph_nodes))
    if aws_config_enabled:
        baselines.append(AwsConfigBaseline(
            before=onset, profile=profile, region=region))
    if terraform_state is not None:
        baselines.append(TerraformStateBaseline(terraform_state))
    return DeviationEngine(
        live_provider=live,
        baseline_providers=baselines,
        change_history=CloudTrailChangeHistory(profile, region),
        change_event_provider=CloudTrailChangeProvider(
            profile, region, lookback_hours=cloudtrail_lookback_hours),
    )
