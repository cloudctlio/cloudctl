"""Unit tests for the deviation-first differential-diagnosis engine.

Everything here is MOCKED and offline: no AWS, no model. Node names, service
names, and field names are deliberately generic — the tests prove the
MECHANISM (a live-vs-intended diff surfaces capacity / policy / config
deviations and ranks them sensibly) with zero per-incident knowledge.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from cloudctl.ai.deviation_engine import (
    KIND_ADDED,
    KIND_CHANGED,
    KIND_REMOVED,
    AwsConfigBaseline,
    ChangeEvent,
    ChangeRecord,
    DependencyGraph,
    DeviationEngine,
    DictSnapshotStore,
    PeerBaseline,
    ResourceNode,
    SnapshotBaseline,
    StaticBaseline,
    StaticChangeEvents,
    StaticChangeHistory,
    TerraformStateBaseline,
    diff_states,
)

UTC = timezone.utc
ONSET = datetime(2026, 7, 4, 12, 0, tzinfo=UTC)


class DictLiveProvider:
    """Injectable fake live-state source: node_id -> state dict."""

    def __init__(self, states):
        self._states = dict(states)
        self.calls = []

    def get_live_state(self, node):
        self.calls.append(node.node_id)
        return self._states.get(node.node_id)


def make_graph(node_ids, edges=()):
    nodes = []
    for nid in node_ids:
        svc, _, name = nid.partition(":")
        nodes.append(ResourceNode(service=svc, name=name))
    return DependencyGraph(nodes=nodes, edges=[tuple(e) for e in edges])


def build_engine(live, intended, history=None):
    return DeviationEngine(
        live_provider=DictLiveProvider(live),
        baseline_providers=[StaticBaseline(intended)],
        change_history=StaticChangeHistory(history or {}),
    )


# ── Core diff behavior ─────────────────────────────────────────────────────────


def test_numeric_capacity_contraction_surfaces_and_outranks_cosmetic_change():
    """A capacity-style numeric drop (10 -> 1) must fall out of the diff and
    rank above an unrelated cosmetic string change on another node."""
    live = {
        "storage:alpha": {"capacity_units": 1, "description": "primary store"},
        "compute:beta": {"handler": "run_v2", "description": "worker"},
    }
    intended = {
        "storage:alpha": {"capacity_units": 10, "description": "primary store"},
        "compute:beta": {"handler": "run", "description": "worker"},
    }
    cs = build_engine(live, intended).scan(
        make_graph(["storage:alpha", "compute:beta"]))

    paths = {(d.node_id, d.path, d.kind) for d in cs.deviations}
    assert ("storage:alpha", "capacity_units", KIND_CHANGED) in paths
    top = cs.deviations[0]
    assert top.node_id == "storage:alpha"
    assert top.intended == 10 and top.live == 1
    assert top.signals["contraction"] is True
    # cosmetic string change scores strictly lower
    beta = next(d for d in cs.deviations if d.node_id == "compute:beta")
    assert top.score > beta.score


def test_removed_intended_setting_is_reported_as_removed():
    """Something declared in intent but absent live (a binding, a policy
    attachment, an encryption setting) must surface as REMOVED."""
    live = {"keystore:k1": {"rotation": {"interval_days": 30}}}
    intended = {"keystore:k1": {"rotation": {"interval_days": 30},
                                "access_binding": "reader-grant"}}
    cs = build_engine(live, intended).scan(make_graph(["keystore:k1"]))
    removed = [d for d in cs.deviations if d.kind == KIND_REMOVED]
    assert len(removed) == 1
    assert removed[0].path == "access_binding"
    assert removed[0].intended == "reader-grant"
    assert removed[0].signals["contraction"] is True
    assert removed[0].signals["change"] == 1.0


def test_boolean_disable_flip_detected_as_contraction():
    live = {"gateway:g1": {"enabled": False}}
    intended = {"gateway:g1": {"enabled": True}}
    cs = build_engine(live, intended).scan(make_graph(["gateway:g1"]))
    assert len(cs.deviations) == 1
    d = cs.deviations[0]
    assert d.kind == KIND_CHANGED and d.signals["contraction"] is True
    assert d.signals["change"] == 1.0


def test_policy_list_shrinkage_detected():
    """A statement dropped from a policy-like scalar list is a contraction;
    reordering alone is NOT a deviation."""
    live = {"queue:q1": {"allowed_principals": ["svc-b", "svc-a"]}}
    intended = {"queue:q1": {"allowed_principals": ["svc-a", "svc-b", "svc-c"]}}
    cs = build_engine(live, intended).scan(make_graph(["queue:q1"]))
    assert len(cs.deviations) == 1
    d = cs.deviations[0]
    assert d.signals["contraction"] is True

    # pure reorder -> no deviation
    live2 = {"queue:q1": {"allowed_principals": ["svc-b", "svc-a", "svc-c"]}}
    cs2 = build_engine(live2, intended).scan(make_graph(["queue:q1"]))
    assert cs2.deviations == []


def test_healthy_node_produces_no_deviations():
    state = {"nested": {"limit": 5, "mode": "auto"}, "tags": ["x", "y"]}
    cs = build_engine({"svc:n1": state}, {"svc:n1": state}).scan(
        make_graph(["svc:n1"]))
    assert cs.deviations == []
    assert cs.scanned_nodes == ["svc:n1"]


def test_added_field_scores_below_contraction():
    live = {"svc:n1": {"limit": 2, "extra_flag": "on"}}
    intended = {"svc:n1": {"limit": 8}}
    cs = DeviationEngine(
        live_provider=DictLiveProvider(live),
        baseline_providers=[StaticBaseline(intended)],   # full snapshot
    ).scan(make_graph(["svc:n1"]))
    kinds = {d.kind for d in cs.deviations}
    assert kinds == {KIND_CHANGED, KIND_ADDED}
    changed = next(d for d in cs.deviations if d.kind == KIND_CHANGED)
    added = next(d for d in cs.deviations if d.kind == KIND_ADDED)
    assert changed.score > added.score


def test_volatile_timestamp_values_are_suppressed():
    """Timestamps differ on every read; they are noise, not intent — and they
    are filtered by VALUE SHAPE, not by field name."""
    live = {"svc:n1": {"last_seen": "2026-07-04T11:59:03Z", "limit": 5}}
    intended = {"svc:n1": {"last_seen": "2026-07-01 08:00:00", "limit": 5}}
    cs = build_engine(live, intended).scan(make_graph(["svc:n1"]))
    assert cs.deviations == []


def test_sparse_baseline_ignores_live_only_fields():
    """IaC declares a subset of fields; the dozens of live-only API fields must
    NOT flood the candidate set."""
    tfstate = {
        "resources": [{
            "mode": "managed", "type": "aws_widget_thing",
            "instances": [{"attributes": {
                "arn": "arn:aws:widget:us-east-1:1:thing/w1",
                "name": "w1", "size": 4,
            }}],
        }],
    }
    baseline = TerraformStateBaseline(tfstate)
    live = {"widget:w1": {
        "size": 4, "status": "ACTIVE", "internal_id": "abc-123",
        "endpoint": "https://x", "replicas": 3,
    }}
    cs = DeviationEngine(
        live_provider=DictLiveProvider(live),
        baseline_providers=[baseline],
    ).scan(make_graph(["widget:w1"]))
    assert cs.deviations == []          # size matches; live-only fields ignored
    assert cs.baseline_sources["widget:w1"] == "terraform_state"


def test_lexical_alignment_snake_case_intent_to_camel_case_live():
    """Declarative snake_case intent must align with live CamelCase API fields
    through generic canonical containment — no field table anywhere."""
    devs = diff_states(
        intended={"flush_interval": 60},
        live={"FlushIntervalSeconds": 5},
        sparse_baseline=True,
    )
    assert len(devs) == 1
    assert devs[0].kind == KIND_CHANGED
    assert devs[0].intended == 60 and devs[0].live == 5


def test_numeric_string_vs_number_not_a_deviation():
    """tfstate often stores numbers as strings — '10' == 10."""
    devs = diff_states(intended={"limit": "10"}, live={"limit": 10},
                       sparse_baseline=True)
    assert devs == []


# ── Ranking signals ────────────────────────────────────────────────────────────


def test_change_near_onset_outranks_old_change():
    live = {"svc:a": {"limit": 1}, "svc:b": {"limit": 1}}
    intended = {"svc:a": {"limit": 10}, "svc:b": {"limit": 10}}
    history = {
        "svc:a": ChangeRecord(at=ONSET - timedelta(minutes=10)),
        "svc:b": ChangeRecord(at=ONSET - timedelta(days=3)),
    }
    cs = build_engine(live, intended, history).scan(
        make_graph(["svc:a", "svc:b"]), onset=ONSET)
    assert [d.node_id for d in cs.deviations] == ["svc:a", "svc:b"]
    assert cs.deviations[0].signals["temporal"] > cs.deviations[1].signals["temporal"]


def test_change_after_onset_is_near_vetoed():
    live = {"svc:a": {"limit": 1}, "svc:b": {"limit": 1}}
    intended = {"svc:a": {"limit": 10}, "svc:b": {"limit": 10}}
    history = {
        "svc:a": ChangeRecord(at=ONSET + timedelta(hours=1)),   # after onset
        "svc:b": ChangeRecord(at=ONSET - timedelta(hours=1)),
    }
    cs = build_engine(live, intended, history).scan(
        make_graph(["svc:a", "svc:b"]), onset=ONSET)
    a = next(d for d in cs.deviations if d.node_id == "svc:a")
    b = next(d for d in cs.deviations if d.node_id == "svc:b")
    assert a.signals["temporal"] <= 0.05
    assert b.score > a.score


def test_graph_proximity_boosts_nodes_near_failing_path():
    live = {"svc:near": {"limit": 1}, "svc:far": {"limit": 1},
            "app:entry": {"ok": True}}
    intended = {"svc:near": {"limit": 10}, "svc:far": {"limit": 10},
                "app:entry": {"ok": True}}
    graph = make_graph(
        ["app:entry", "svc:near", "svc:far"],
        edges=[("app:entry", "svc:near"), ("svc:near", "svc:far")],
    )
    cs = build_engine(live, intended).scan(graph, entry_node_ids=["app:entry"])
    near = next(d for d in cs.deviations if d.node_id == "svc:near")
    far = next(d for d in cs.deviations if d.node_id == "svc:far")
    assert near.signals["proximity"] > far.signals["proximity"]
    assert near.score > far.score


def test_ranking_is_deterministic():
    live = {"svc:a": {"x": 1, "y": 2}, "svc:b": {"x": 1}}
    intended = {"svc:a": {"x": 9, "y": 9}, "svc:b": {"x": 9}}
    e = build_engine(live, intended)
    g = make_graph(["svc:a", "svc:b"])
    order1 = [(d.node_id, d.path) for d in e.scan(g).deviations]
    order2 = [(d.node_id, d.path) for d in e.scan(g).deviations]
    assert order1 == order2 and len(order1) == 3


# ── Coverage honesty ───────────────────────────────────────────────────────────


def test_nodes_without_baseline_are_reported_not_silently_skipped():
    live = {"svc:known": {"limit": 5}, "svc:mystery": {"limit": 5}}
    intended = {"svc:known": {"limit": 5}}       # no baseline for svc:mystery
    cs = build_engine(live, intended).scan(
        make_graph(["svc:known", "svc:mystery"]))
    assert cs.scanned_nodes == ["svc:known"]
    assert list(cs.unscanned_nodes) == ["svc:mystery"]
    assert "no baseline source" in cs.unscanned_nodes["svc:mystery"]
    assert "svc:mystery" in cs.to_prompt_block()


def test_nodes_without_live_state_are_reported():
    cs = build_engine({}, {"svc:gone": {"x": 1}}).scan(make_graph(["svc:gone"]))
    assert cs.unscanned_nodes == {"svc:gone": "no live state readable"}


# ── Baseline providers ─────────────────────────────────────────────────────────


def test_terraform_state_baseline_identifies_nodes_via_arn():
    tfstate = {
        "resources": [
            {
                "mode": "managed", "type": "aws_widget_thing",
                "instances": [{"attributes": {
                    "arn": "arn:aws:widget:us-east-1:1:thing/w1",
                    "name": "w1", "capacity": 10,
                }}],
            },
            {   # data resources must be ignored
                "mode": "data", "type": "aws_widget_thing",
                "instances": [{"attributes": {"name": "ignored"}}],
            },
        ],
    }
    b = TerraformStateBaseline(tfstate)
    node = ResourceNode(service="widget", name="w1")
    intended = b.get_intended_state(node)
    assert intended is not None and intended["capacity"] == 10
    assert b.sparse is True
    assert b.get_intended_state(ResourceNode(service="widget", name="ignored")) is None


def test_peer_baseline_flags_the_outlier():
    """With no IaC and no snapshot, the intended value of a fleet member is
    what the majority of its peers agree on."""
    nodes = [ResourceNode("cache", f"n{i}") for i in range(3)]
    live = {
        "cache:n0": {"node_count": 3, "engine_tier": "std"},
        "cache:n1": {"node_count": 3, "engine_tier": "std"},
        "cache:n2": {"node_count": 1, "engine_tier": "std"},   # the outlier
    }
    provider = DictLiveProvider(live)
    peer = PeerBaseline(provider, nodes)
    engine = DeviationEngine(live_provider=provider, baseline_providers=[peer])
    cs = engine.scan(DependencyGraph(nodes=nodes, edges=[]))
    outliers = [d for d in cs.deviations if d.node_id == "cache:n2"]
    assert len(outliers) == 1
    assert outliers[0].path == "node_count"
    assert outliers[0].intended == 3 and outliers[0].live == 1
    # conforming members deviate on nothing
    assert all(d.node_id == "cache:n2" for d in cs.deviations)


def test_baseline_priority_first_provider_wins():
    node_states = {"svc:n1": {"limit": 7}}
    primary = StaticBaseline({"svc:n1": {"limit": 9}})
    secondary = StaticBaseline({"svc:n1": {"limit": 7}})
    cs = DeviationEngine(
        live_provider=DictLiveProvider(node_states),
        baseline_providers=[primary, secondary],
    ).scan(make_graph(["svc:n1"]))
    assert len(cs.deviations) == 1                    # diffed against primary
    assert cs.baseline_sources["svc:n1"] == "healthy_snapshot"


# ── Output surfaces ────────────────────────────────────────────────────────────


def test_graph_parses_tool_output_shape():
    payload = {
        "node_count": 2, "edge_count": 1,
        "nodes": ["storage:alpha", "compute:beta"],
        "edges": [{"from": "compute:beta", "to": "storage:alpha",
                   "via": "config_ref"}],
    }
    g = DependencyGraph.from_tool_output(payload)
    assert {n.node_id for n in g.nodes} == {"storage:alpha", "compute:beta"}
    assert g.hops_from(["compute:beta"]) == {"compute:beta": 0,
                                             "storage:alpha": 1}


def test_prompt_block_and_dict_carry_intended_vs_live_values():
    live = {"storage:alpha": {"capacity_units": 1}}
    intended = {"storage:alpha": {"capacity_units": 10}}
    history = {"storage:alpha": ChangeRecord(
        at=ONSET - timedelta(minutes=5), actor="deployer", event="ModifyThing")}
    cs = build_engine(live, intended, history).scan(
        make_graph(["storage:alpha"]), onset=ONSET)

    block = cs.to_prompt_block()
    assert "storage:alpha" in block
    assert "10" in block and "1" in block
    assert "deployer" in block

    d = cs.to_dict()
    assert d["deviation_count"] == 1
    assert d["deviations"][0]["intended"] == 10
    assert d["deviations"][0]["live"] == 1
    assert d["deviations"][0]["last_changed_by"] == "deployer"


# ── CloudTrail-derived baseline (PRIMARY, no prior-state source needed) ─────────


def ct_engine(live, events, history=None, baselines=None):
    """Engine with the CloudTrail change source as PRIMARY and, deliberately,
    NO state baseline unless one is passed — proving a change event alone
    produces candidates."""
    return DeviationEngine(
        live_provider=DictLiveProvider(live),
        baseline_providers=baselines or [],
        change_history=StaticChangeHistory(history or {}),
        change_event_provider=StaticChangeEvents(events),
    )


def test_cloudtrail_change_event_alone_yields_ranked_candidate():
    """A single mutating change event must become a candidate deviation with
    NO prior-state provider present — the new value + time come from the event
    itself; the prior value is unknown and not needed."""
    live = {"storage:alpha": {"capacity_units": 1}}
    events = {"storage:alpha": [ChangeEvent(
        at=ONSET - timedelta(minutes=2), actor="deployer",
        event_name="ModifyThing", params={"capacity_units": 1},
    )]}
    cs = ct_engine(live, events).scan(make_graph(["storage:alpha"]), onset=ONSET)

    assert len(cs.deviations) == 1
    d = cs.deviations[0]
    assert cs.baseline_sources["storage:alpha"] == "cloudtrail_change"
    assert d.intended is None                 # prior unknown
    assert d.live == 1                         # new value from the event
    assert d.last_change.actor == "deployer"
    assert d.signals["temporal"] > 0.9         # right before onset
    block = cs.to_prompt_block()
    assert "prior value unknown" in block and "deployer" in block


def test_cloudtrail_identity_and_timestamp_params_are_filtered():
    """requestParameters carrying only the resource's own identity (and volatile
    timestamps) must NOT manufacture deviations."""
    live = {"svc:res1": {"whatever": 1}}
    events = {"svc:res1": [ChangeEvent(
        at=ONSET - timedelta(minutes=1), actor="x", event_name="Touch",
        params={"targetName": "res1", "requestedAt": "2026-07-04T11:59:00Z"},
    )]}
    cs = ct_engine(live, events).scan(make_graph(["svc:res1"]), onset=ONSET)
    assert cs.deviations == []                  # nothing actionable in the event
    assert "svc:res1" in cs.unscanned_nodes     # fell through to no-source


def test_cloudtrail_repeated_change_reconstructs_before_after_contraction():
    """When the SAME field is changed twice in the window, the earlier event's
    value reconstructs the prior — recovering a real 10->1 contraction with no
    state store at all."""
    live = {"storage:alpha": {"capacity_units": 1}}
    events = {"storage:alpha": [
        ChangeEvent(at=ONSET - timedelta(days=2), actor="a",
                    event_name="ModifyThing", params={"capacity_units": 10}),
        ChangeEvent(at=ONSET - timedelta(minutes=3), actor="b",
                    event_name="ModifyThing", params={"capacity_units": 1}),
    ]}
    cs = ct_engine(live, events).scan(make_graph(["storage:alpha"]), onset=ONSET)
    assert len(cs.deviations) == 1
    d = cs.deviations[0]
    assert d.intended == 10 and d.live == 1
    assert d.signals["contraction"] is True     # magnitude recovered
    assert d.last_change.actor == "b"           # attributed to the newest change


def test_cloudtrail_readonly_events_are_ignored():
    live = {"svc:n1": {"x": 1}}
    events = {"svc:n1": [ChangeEvent(
        at=ONSET - timedelta(minutes=1), actor="x", event_name="DescribeThing",
        params={"x": 5}, read_only=True,
    )]}
    cs = ct_engine(live, events).scan(make_graph(["svc:n1"]), onset=ONSET)
    assert cs.deviations == []
    assert "svc:n1" in cs.unscanned_nodes


def test_cloudtrail_change_after_onset_is_near_vetoed():
    live = {"svc:a": {"v": 1}, "svc:b": {"v": 1}}
    events = {
        "svc:a": [ChangeEvent(at=ONSET + timedelta(hours=1), actor="x",
                              event_name="Modify", params={"v": 1})],
        "svc:b": [ChangeEvent(at=ONSET - timedelta(minutes=5), actor="y",
                              event_name="Modify", params={"v": 1})],
    }
    cs = ct_engine(live, events).scan(make_graph(["svc:a", "svc:b"]), onset=ONSET)
    a = next(d for d in cs.deviations if d.node_id == "svc:a")
    b = next(d for d in cs.deviations if d.node_id == "svc:b")
    assert a.signals["temporal"] <= 0.05
    assert b.score > a.score


# ── Self-snapshot baseline (no change event needed) ─────────────────────────────


def test_snapshot_self_diff_surfaces_drift_with_no_cloudtrail_event():
    """Born-misconfigured / slow-drift case: no change event exists, but a
    known-healthy snapshot that predates onset reveals the deviation."""
    store = DictSnapshotStore()
    node = ResourceNode("storage", "alpha")
    store.put(node, {"capacity_units": 10, "mode": "auto"},
              at=ONSET - timedelta(days=1))
    live = {"storage:alpha": {"capacity_units": 1, "mode": "auto"}}

    engine = DeviationEngine(
        live_provider=DictLiveProvider(live),
        baseline_providers=[SnapshotBaseline(store, before=ONSET)],
        change_event_provider=StaticChangeEvents({}),   # no events at all
    )
    cs = engine.scan(make_graph(["storage:alpha"]), onset=ONSET)
    assert len(cs.deviations) == 1
    d = cs.deviations[0]
    assert cs.baseline_sources["storage:alpha"] == "self_snapshot"
    assert d.intended == 10 and d.live == 1
    assert d.signals["contraction"] is True


def test_snapshot_store_selects_most_recent_snapshot_before_onset():
    store = DictSnapshotStore()
    node = ResourceNode("svc", "n1")
    store.put(node, {"limit": 10}, at=ONSET - timedelta(days=5))
    store.put(node, {"limit": 8}, at=ONSET - timedelta(hours=1))   # newest pre-onset
    store.put(node, {"limit": 1}, at=ONSET + timedelta(hours=1))   # post-onset: ignore
    assert store.get(node, before=ONSET) == {"limit": 8}

    live = {"svc:n1": {"limit": 1}}
    engine = DeviationEngine(
        live_provider=DictLiveProvider(live),
        baseline_providers=[SnapshotBaseline(store, before=ONSET)],
    )
    cs = engine.scan(make_graph(["svc:n1"]), onset=ONSET)
    assert cs.deviations[0].intended == 8            # diffed vs pre-onset snapshot


def test_snapshot_absent_falls_through_to_unscanned():
    store = DictSnapshotStore()                       # empty
    engine = DeviationEngine(
        live_provider=DictLiveProvider({"svc:n1": {"x": 1}}),
        baseline_providers=[SnapshotBaseline(store, before=ONSET)],
    )
    cs = engine.scan(make_graph(["svc:n1"]), onset=ONSET)
    assert cs.deviations == []
    assert "svc:n1" in cs.unscanned_nodes


# ── Chain priority: CloudTrail -> snapshot -> peer -> Config -> IaC ─────────────


def test_cloudtrail_wins_over_state_baselines_for_same_node():
    """When a change event exists, it is the source of record — the state
    baselines are not consulted for that node."""
    live = {"svc:n1": {"limit": 1}}
    snap = DictSnapshotStore()
    snap.put(ResourceNode("svc", "n1"), {"limit": 10},
             at=ONSET - timedelta(days=1))
    events = {"svc:n1": [ChangeEvent(
        at=ONSET - timedelta(minutes=1), actor="x", event_name="Modify",
        params={"limit": 1})]}
    engine = DeviationEngine(
        live_provider=DictLiveProvider(live),
        baseline_providers=[SnapshotBaseline(snap, before=ONSET)],
        change_event_provider=StaticChangeEvents(events),
    )
    cs = engine.scan(make_graph(["svc:n1"]), onset=ONSET)
    assert cs.baseline_sources["svc:n1"] == "cloudtrail_change"
    assert cs.deviations[0].intended is None          # NOT the snapshot's 10


def test_state_baselines_apply_in_priority_order_snapshot_then_peer_then_config():
    """No change events: snapshot beats peer beats Config, per list order."""
    nodes = [ResourceNode("cache", f"n{i}") for i in range(3)]
    live = {
        "cache:n0": {"size": 1}, "cache:n1": {"size": 4}, "cache:n2": {"size": 4},
    }
    provider = DictLiveProvider(live)
    snap = DictSnapshotStore()
    snap.put(nodes[0], {"size": 9}, at=ONSET - timedelta(days=1))   # only n0
    peer = PeerBaseline(provider, nodes)
    config = AwsConfigBaseline(
        before=ONSET, history_fn=lambda node, before: {"size": 7})

    engine = DeviationEngine(
        live_provider=provider,
        baseline_providers=[SnapshotBaseline(snap, before=ONSET), peer, config],
    )
    cs = engine.scan(DependencyGraph(nodes=nodes, edges=[]), onset=ONSET)
    by_node = {d.node_id: d for d in cs.deviations}

    # n0: snapshot present -> diffed vs 9 (snapshot wins over peer & config)
    assert cs.baseline_sources["cache:n0"] == "self_snapshot"
    assert by_node["cache:n0"].intended == 9
    # n1: no snapshot; peers (n0,n2) agree size=... n0=1,n2=4 -> no majority ->
    #     peer yields nothing -> Config supplies 7
    assert cs.baseline_sources["cache:n1"] == "aws_config"
    assert by_node["cache:n1"].intended == 7


def test_aws_config_baseline_used_only_when_earlier_sources_empty():
    """Config is last-of-state-sources: with a snapshot present it is never
    consulted."""
    calls = []

    def history_fn(node, before):
        calls.append(node.node_id)
        return {"limit": 99}

    store = DictSnapshotStore()
    store.put(ResourceNode("svc", "n1"), {"limit": 10},
              at=ONSET - timedelta(days=1))
    engine = DeviationEngine(
        live_provider=DictLiveProvider({"svc:n1": {"limit": 1}}),
        baseline_providers=[
            SnapshotBaseline(store, before=ONSET),
            AwsConfigBaseline(before=ONSET, history_fn=history_fn),
        ],
    )
    cs = engine.scan(make_graph(["svc:n1"]), onset=ONSET)
    assert cs.baseline_sources["svc:n1"] == "self_snapshot"
    assert calls == []                                # Config never queried


def test_terraform_is_lowest_priority_optional_provider():
    """IaC parse must sit LAST — only used when nothing else has intent."""
    tfstate = {"resources": [{
        "mode": "managed", "type": "aws_widget_thing",
        "instances": [{"attributes": {
            "arn": "arn:aws:widget:us-east-1:1:thing/w1", "name": "w1",
            "size": 10}}]}]}
    engine = DeviationEngine(
        live_provider=DictLiveProvider({"widget:w1": {"size": 1}}),
        baseline_providers=[
            PeerBaseline(DictLiveProvider({}), []),   # no peers -> yields nothing
            TerraformStateBaseline(tfstate),
        ],
    )
    cs = engine.scan(make_graph(["widget:w1"]), onset=ONSET)
    assert cs.baseline_sources["widget:w1"] == "terraform_state"
    assert cs.deviations[0].intended == 10


def test_no_source_at_all_stays_unscanned_never_fabricated():
    """The honest floor: no change event, no snapshot, no peers, no Config, no
    IaC -> the node is reported unscanned, never given a fabricated diff."""
    engine = DeviationEngine(
        live_provider=DictLiveProvider({"svc:lonely": {"x": 1}}),
        baseline_providers=[PeerBaseline(DictLiveProvider({}), [])],
        change_event_provider=StaticChangeEvents({}),
    )
    cs = engine.scan(make_graph(["svc:lonely"]), onset=ONSET)
    assert cs.deviations == []
    assert cs.scanned_nodes == []
    assert "svc:lonely" in cs.unscanned_nodes


def test_empty_candidate_set_prompt_says_so_honestly():
    cs = build_engine({"svc:n1": {"x": 1}}, {"svc:n1": {"x": 1}}).scan(
        make_graph(["svc:n1"]))
    block = cs.to_prompt_block()
    assert "none" in block
    assert "runtime-only" in block


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
