"""Drift loop: classification, confidence, the store, and full passes through
the real gate (real Rego rules, real hash-chained audit) on AWS, Azure and GCP
with scripted planners and fake executors. Nothing touches a cloud."""
import json
import os
import stat
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("regopy")

from cloudctl.controlplane import autonomy as A  # noqa: E402
from cloudctl.controlplane import drift as D  # noqa: E402
from cloudctl.controlplane import state as S  # noqa: E402
from cloudctl.controlplane.orchestrator import Orchestrator, QueuedRollback, RollbackRequest  # noqa: E402
from cloudctl.gate.audit import AuditLog, LocalFileSink  # noqa: E402
from cloudctl.gate.config import parse_config  # noqa: E402
from cloudctl.gate.gate import PolicyGate  # noqa: E402
from cloudctl.gate.models import Action, CredentialError, Finding, Plan, PlanError, ResourceChange, Severity  # noqa: E402
from cloudctl.gate.policy.rego import RegoEngine  # noqa: E402
from tests.controlplane.conftest import ENVF, iac_root  # noqa: E402
from tests.gate.conftest import FakeCredsBroker, config_doc  # noqa: E402

TYPES = {  # (tagged resource, identity resource, network resource) per cloud
    "aws": ("aws_instance", "aws_iam_role_policy", "aws_security_group"),
    "azure": ("Microsoft.Compute/virtualMachines", "Microsoft.Authorization/roleAssignments",
              "Microsoft.Network/networkSecurityGroups"),
    "gcp": ("google_compute_instance", "google_project_iam_member", "google_compute_firewall"),
}


def rc(cloud, rtype, action=Action.UPDATE, before=None, after=None, address=None):
    return ResourceChange(address=address or f"{rtype}.x", type=rtype, action=action, cloud=cloud,
                          before=before, after=after)


def tagdrift(cloud, n=1):
    return [rc(cloud, TYPES[cloud][0], before={"tags": {}}, after={"tags": {"team": "a"}}, address=f"vm.v{i}")
            for i in range(n)]


class ScriptedPlanner:
    """What the IaC tool would report: a list of changes per call (the last repeats)."""

    def __init__(self, platform: str, script: list[list[ResourceChange]], drift_addresses=None):
        self.platform = platform
        self.script = script
        self.drift_addresses = drift_addresses
        self.calls = 0

    def plan(self, *, env: Any, creds: Any, workdir: Path) -> Plan:
        assert creds.remaining_seconds > 0
        changes = self.script[min(self.calls, len(self.script) - 1)]
        self.calls += 1
        arts = {}
        if self.drift_addresses is not None:
            p = workdir / "plan.json"
            p.write_text(json.dumps({"resource_changes": [], "resource_drift": [
                {"address": a} for a in self.drift_addresses]}))
            arts["terraform_plan_json"] = str(p)
        return Plan(platform=self.platform, environment=env.name, changes=tuple(changes), source="x", artifacts=arts)


class FakeApply:
    def __init__(self, planner, log):
        self.planner = planner
        self.log = log
        self.kind = "iac_apply"

    def apply(self, creds, plan, env):
        self.log.append(plan.digest())
        return {"applied": len(plan.changes)}


class FakeBaselineScanner:
    """Stands in for checkov having run and found nothing (prod requires a baseline scanner)."""
    name = "checkov"
    last_detail = ""

    def applies_to(self, ctx):
        return True

    def evaluate(self, ctx):
        return []


class World:
    def __init__(self, tmp_path, cloud="aws", tier="dev", platform="terraform", names=("app",), envs=None):
        self.tmp = tmp_path
        self.cloud = cloud
        self.roots = {n: iac_root(tmp_path, n) for n in names}
        approval = {"approvers": ["alice"], "always": True} if tier == "prod" else {}
        e = ENVF[cloud](tier, match={"iac_roots": [str(r) for r in self.roots.values()]}, **(
            {"approval": approval} if approval else {}))
        prod = {"approvers": {"alice": {"public_key": _pub()}},
                "sink": {"type": "s3", "bucket": "audit", "region": "us-east-1", "retain_days": 400},
                "policy": {"engines": {"checkov": {"enabled": True, "version": "3.4.6"}}}} if tier == "prod" else {}
        self.cfg = parse_config(config_doc(envs or {"main": e}, tmp=tmp_path, **prod))
        self.brokers = {c: FakeCredsBroker(c) for c in ("aws", "azure", "gcp")}
        audit = AuditLog(LocalFileSink(tmp_path / "audit.jsonl"), chain="test", actor="loop")
        rego = RegoEngine.from_config(builtin=True, rule_paths=[], rego_paths=[], params={})
        engines = [rego] + ([FakeBaselineScanner()] if tier == "prod" else [])
        self.gate = PolicyGate(self.cfg, audit=audit, brokers=self.brokers, policy=([], engines))
        self.planners: dict[str, ScriptedPlanner] = {}
        self.platform = platform
        self.applied: list[str] = []
        self.runs = S.LocalRunStore(tmp_path / "runs")
        self.store = D.DriftStore(tmp_path / "drift")
        scanner = D.DriftScanner(self.cfg, brokers=self.brokers, planner_factory=self.planner_for,
                                 policy=self.gate.policy)
        self.loop = D.DriftLoop(self.gate, scanner=scanner, store=self.store, runs=self.runs,
                                executor_for=lambda p: FakeApply(p, self.applied), requester="cctl-drift-loop",
                                orchestrator_factory=lambda **k: Orchestrator(
                                    self.gate, self.runs, rollback=QueuedRollback(tmp_path / "rb"),
                                    executor_factory=k["executor_factory"], requester=k["requester"]))

    def script(self, name, *calls, drift_addresses=None, platform=None):
        self.planners[str(self.roots[name])] = ScriptedPlanner(platform or self.platform, list(calls),
                                                               drift_addresses)

    def planner_for(self, root, env):
        p = self.planners.get(str(Path(root).resolve()))
        if p is None:
            raise PlanError(f"no planner scripted for {root}")
        return p

    def events(self):
        return [r["event"] for r in self.gate.audit.sink.read_all()]


def _pub():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate().public_key()
    return k.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


# ── classification ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("cloud", ["aws", "azure", "gcp"])
def test_identity_and_exposed_network_drift_are_security_incidents(cloud):
    _, ident, net = TYPES[cloud]
    c, _ = D.classify([rc(cloud, ident, before={"role": "x"}, after={"role": "y"})])
    assert (c.drift_class, c.severity) == (A.SECURITY_INCIDENT, "CRITICAL")
    open_ = {"aws": {"ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 22}]},
             "azure": {"securityRules": [{"sourceAddressPrefix": "*", "destinationPortRange": "22"}]},
             "gcp": {"source_ranges": ["0.0.0.0/0"], "allow": [{"ports": ["22"]}]}}[cloud]
    c, items = D.classify([rc(cloud, net, before=open_, after={"ingress": []})])
    assert c.drift_class == A.SECURITY_INCIDENT and items[0].exposed
    c, items = D.classify([rc(cloud, net, before={"ingress": [{"cidr_blocks": ["10.0.0.0/8"]}]}, after={})])
    assert c.drift_class == A.CONFIG_DRIFT and not items[0].exposed


@pytest.mark.parametrize("rtype", ["aws_cloudtrail", "aws_kms_key", "google_logging_project_sink",
                                   "Microsoft.Insights/diagnosticSettings", "Microsoft.KeyVault/vaults",
                                   "google_secret_manager_secret", "kubernetes_cluster_role_binding"])
def test_audit_logging_keys_and_rbac_are_incidents(rtype):
    cloud = "azure" if rtype.startswith("Microsoft") else "gcp" if rtype.startswith("google") else "aws"
    c, _ = D.classify([rc(cloud, rtype, before={"a": 1}, after={"a": 2})])
    assert c.drift_class == A.SECURITY_INCIDENT


def test_severity_scale():
    assert D.classify(tagdrift("aws"))[0].severity == "LOW"
    assert D.classify([rc("aws", "aws_instance", before={"type": "t3.small"}, after={"type": "t3.large"})])[0].severity == "MEDIUM"
    assert D.classify([rc("aws", "aws_instance", Action.REPLACE, {"a": 1}, {"a": 2})])[0].severity == "HIGH"
    assert D.classify([rc("gcp", "google_sql_database_instance", Action.CREATE, None, {"a": 1})])[0].severity == "HIGH"
    c, _ = D.classify(tagdrift("aws"), failed_change=True)
    assert (c.drift_class, c.severity) == (A.FAILED_CHANGE, "HIGH")
    c, _ = D.classify(tagdrift("aws"), live_policy_ok=False)
    assert c.severity == "MEDIUM" and "could not run" in c.reasons[-1]
    f = Finding(rule_id="CCTL-NET-001", severity=Severity.HIGH, message="m", engine="rego", resource="vm.v0")
    assert D.classify(tagdrift("aws"), live_findings=[f])[0].drift_class == A.SECURITY_INCIDENT
    f = Finding(rule_id="CCTL-ENC-001", severity=Severity.MEDIUM, message="m", engine="rego", resource="vm.v0")
    c, _ = D.classify(tagdrift("aws"), live_findings=[f])
    assert (c.drift_class, c.severity) == (A.CONFIG_DRIFT, "MEDIUM")


def test_confidence_factors():
    items = D.classify(tagdrift("aws"), attributed={"vm.v0"})[1]
    assert D.confidence(items, sightings=2, active_run=False, live_policy_ok=True, platform="terraform")[0] == 1.0
    assert D.confidence(items, sightings=1, active_run=False, live_policy_ok=True, platform="terraform")[0] == 0.5
    assert D.confidence(items, sightings=5, active_run=True, live_policy_ok=True, platform="terraform")[0] == 0.0
    assert D.confidence(items, sightings=5, active_run=False, live_policy_ok=False, platform="terraform")[0] == 0.0
    mixed = D.classify(tagdrift("aws", 2), attributed={"vm.v0"})[1]           # v1 is undeployed code
    assert D.confidence(mixed, sightings=2, active_run=False, live_policy_ok=True, platform="terraform")[0] == 0.5
    unk = D.classify(tagdrift("azure"))[1]
    s, why = D.confidence(unk, sightings=2, active_run=False, live_policy_ok=True, platform="arm")
    assert s == 0.75 and "cannot tell drift" in why[0]
    big = D.classify(tagdrift("gcp", 11), attributed={f"vm.v{i}" for i in range(11)})[1]
    assert D.confidence(big, sightings=2, active_run=False, live_policy_ok=True, platform="terraform")[0] == 0.8


# ── store ───────────────────────────────────────────────────────────────────

def test_store_is_private_atomic_and_locked(tmp_path):
    st = D.DriftStore(tmp_path / "d")
    ev = D.DriftEvent(environment="e", tier="dev", cloud="aws", root="/r", platform="terraform", plan_digest="x",
                      drift_class=A.CONFIG_DRIFT, severity="LOW", confidence=0.5, factors=[], decision={},
                      items=[], reasons=[])
    st.save(ev)
    p = tmp_path / "d" / f"{ev.id}.json"
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert st.load(ev.id).to_dict() == ev.to_dict()
    with pytest.raises(KeyError):
        st.load("../../etc/passwd")
    (tmp_path / "d" / "junk.json").write_text("{nope")
    assert [e.id for e in st.list()] == [ev.id]
    with st.lock():
        with pytest.raises(RuntimeError, match="another drift pass"):
            with st.lock():
                pass


# ── full passes ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("cloud", ["aws", "azure", "gcp"])
def test_low_drift_in_dev_is_repaired_on_the_second_sighting_then_resolved(tmp_path, cloud):
    w = World(tmp_path, cloud)
    drift = tagdrift(cloud)
    w.script("app", drift, drift, drift, [], drift_addresses=["vm.v0"])
    (ev,) = w.loop.scan_once()
    assert ev.status == D.OPEN and ev.decision["mode"] == A.APPROVE and w.applied == []
    assert "below θ" in ev.decision["reasons"][-1]
    (ev2,) = w.loop.scan_once()
    assert ev2.id == ev.id and ev2.sightings == 2 and ev2.confidence == 1.0
    assert ev2.status == D.REPAIRED and len(w.applied) == 1 and ev2.run_id
    assert w.applied == [ev.plan_digest]                       # exactly the plan that was classified
    (ev3,) = w.loop.scan_once()
    assert ev3.id == ev.id and ev3.status == D.RESOLVED
    assert w.loop.scan_once() == []
    for c in w.brokers[cloud].issued:              # every scan and repair credential destroyed
        with pytest.raises(CredentialError):
            c.ensure_valid()
    ev_names = w.events()
    assert {"drift.scan.start", "drift.detected", "drift.repair.start", "drift.repair.end", "drift.resolved",
            "execution.end"} <= set(ev_names)
    assert w.gate.audit.verify().ok


@pytest.mark.parametrize("cloud", ["aws", "azure", "gcp"])
def test_security_incident_is_never_repaired_by_the_loop(tmp_path, cloud):
    w = World(tmp_path, cloud)
    ident = [rc(cloud, TYPES[cloud][1], before={"role": "Owner"}, after={"role": "Reader"})]
    w.script("app", ident, drift_addresses=[ident[0].address])
    for _ in range(4):
        (ev,) = w.loop.scan_once()
    assert ev.status == D.REPORTED and ev.sightings == 4 and w.applied == []
    with pytest.raises(RuntimeError, match="report-only"):
        w.loop.repair(ev.id, requester="bob")
    ev = w.loop.repair(ev.id, requester="bob", override="confirmed with security: our own break-glass change")
    assert ev.status == D.REPAIRED and len(w.applied) == 1
    ov = [r for r in w.gate.audit.sink.read_all() if r["event"] == "drift.override"]
    assert ov and ov[0]["data"]["requester"] == "bob"


def test_report_only_platform_cannot_be_overridden(tmp_path):
    w = World(tmp_path, "aws", platform="cdk")
    w.script("app", tagdrift("aws"))
    w.loop.scan_once()
    (ev,) = w.loop.scan_once()
    assert ev.status == D.REPORTED and "does not revert drift" in ev.decision["reasons"][-1]
    with pytest.raises(RuntimeError, match="does not revert drift"):
        w.loop.repair(ev.id, requester="bob", override="please")


def test_unattributed_tools_auto_in_dev_but_not_in_staging(tmp_path):
    for tier, want in (("dev", D.REPAIRED), ("staging", D.OPEN)):
        w = World(tmp_path / tier, "azure", tier=tier, platform="arm")
        w.script("app", tagdrift("azure"))
        w.loop.scan_once()
        (ev,) = w.loop.scan_once()
        assert ev.confidence == 0.75 and ev.status == want, tier


def test_medium_drift_in_prod_waits_and_manual_repair_needs_approval(tmp_path):
    w = World(tmp_path, "gcp", tier="prod")
    d = [rc("gcp", "google_compute_instance", before={"machine_type": "e2-small"}, after={"machine_type": "e2-medium"})]
    w.script("app", d, drift_addresses=[d[0].address])
    w.loop.scan_once()
    (ev,) = w.loop.scan_once()
    assert ev.status == D.OPEN and ev.decision["mode"] == A.APPROVE and w.applied == []
    ev = w.loop.repair(ev.id, requester="bob")
    assert ev.status == D.AWAITING_APPROVAL and w.applied == []     # approval.always: the gate wants a signature
    run = w.runs.load(ev.run_id)
    assert run.nodes["repair"].status == S.AWAITING_APPROVAL


def test_repair_is_pinned_to_the_classified_plan(tmp_path):
    w = World(tmp_path, "aws")
    a = tagdrift("aws")
    b = [rc("aws", "aws_instance", before={"type": "t3.small"}, after={"type": "t3.large"}, address="vm.v0")]
    w.script("app", a, a, drift_addresses=["vm.v0"])
    (ev,) = w.loop.scan_once(repair=False)
    w.planners[str(w.roots["app"])].script = [b]              # live state moves before the repair
    ev = w.loop.repair(ev.id, requester="bob")
    assert ev.status == D.REPAIR_REJECTED and w.applied == []
    assert "changed since the drift was classified" in json.dumps(ev.history)


def test_undeployed_code_lowers_confidence(tmp_path):
    w = World(tmp_path, "aws")
    w.script("app", tagdrift("aws", 2), drift_addresses=["vm.v0"])   # vm.v1 is merged code, not drift
    w.loop.scan_once()
    (ev,) = w.loop.scan_once()
    assert ev.confidence == 0.5 and ev.status == D.OPEN
    assert any(i["attributed"] is False for i in ev.items)


def test_live_state_rego_finds_what_the_drift_introduced(tmp_path):
    w = World(tmp_path, "aws")
    sg = rc("aws", "aws_security_group",
            before={"ingress": [{"cidr_blocks": ["10.0.0.0/8"], "from_port": 22, "to_port": 22, "protocol": "tcp"}],
                    "name": "web"},
            after={"ingress": [{"cidr_blocks": ["10.0.0.0/8"], "from_port": 22, "to_port": 22, "protocol": "tcp"}],
                   "name": "web2"})
    env = w.cfg.environment("main")
    plan = Plan(platform="terraform", environment="main", changes=(sg,))
    assert w.loop.scanner.live_policy(env, plan) == []
    opened = ResourceChange(address=sg.address, type=sg.type, action=Action.UPDATE, cloud="aws",
                            before={**sg.before, "ingress": [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 22,
                                                             "to_port": 22, "protocol": "tcp"}]},
                            after=sg.after)
    found = w.loop.scanner.live_policy(env, Plan(platform="terraform", environment="main", changes=(opened,)))
    assert [f.rule_id for f in found] == ["CCTL-NET-001"]


def test_policy_engine_failure_drops_confidence_to_zero(tmp_path):
    w = World(tmp_path, "aws")
    w.script("app", tagdrift("aws"), drift_addresses=["vm.v0"])
    w.loop.scanner.policy = lambda: ([], [])                     # no Rego engine available
    w.loop.scan_once()
    (ev,) = w.loop.scan_once()
    assert ev.confidence == 0.0 and ev.status == D.OPEN and ev.severity == "MEDIUM"
    assert "drift.live_policy.error" in w.events()


def test_active_change_run_blocks_auto_repair(tmp_path):
    w = World(tmp_path, "aws")
    w.script("app", tagdrift("aws"), drift_addresses=["vm.v0"])
    g = {"version": 1, "request": "x", "questions": [], "nodes": [
        {"id": "n", "kind": "iac_apply", "environment": "main", "summary": "s",
         "target": {"iac_root": str(w.roots["app"])}, "depends_on": []}]}
    run = S.RunState.new(g, "d" * 64, "alice", ["n"])
    run.nodes["n"].status = S.RUNNING
    w.runs.save(run)
    w.loop.scan_once()
    (ev,) = w.loop.scan_once()
    assert ev.confidence == 0.0 and ev.status == D.OPEN and w.applied == []


def test_drift_that_returns_after_a_repair_needs_a_person(tmp_path):
    w = World(tmp_path, "aws")
    d = tagdrift("aws")
    w.script("app", d, drift_addresses=["vm.v0"])
    w.loop.scan_once()
    (ev,) = w.loop.scan_once()
    assert ev.status == D.REPAIRED
    (ev,) = w.loop.scan_once()                                 # the repair did not stick
    assert ev.status == D.OPEN and len(w.applied) == 1 and "still there after a repair" in ev.decision["reasons"][-1]


def test_one_failing_root_does_not_stop_the_pass(tmp_path):
    w = World(tmp_path, "aws", names=("app", "broken"))
    w.script("app", tagdrift("aws"))
    (ev,) = w.loop.scan_once()                                 # "broken" has no planner: PlanError
    assert ev.root == str(w.roots["app"].resolve())
    errs = [r for r in w.gate.audit.sink.read_all() if r["event"] == "drift.scan.error"]
    assert len(errs) == 1 and "broken" in errs[0]["data"]["root"]


def test_rollback_requests_become_failed_change_events(tmp_path):
    w = World(tmp_path, "aws")
    w.script("app", tagdrift("aws"), drift_addresses=["vm.v0"])
    q = QueuedRollback(tmp_path / "rb")
    r1 = RollbackRequest(run_id="a" * 32, node_id="app", environment="main", kind="iac_apply",
                         target={"iac_root": str(w.roots["app"])}, gate_request_id="g", plan_digest="p",
                         error="apply failed half way", applied_before=[])
    r2 = RollbackRequest(run_id="a" * 32, node_id="fix", environment="main", kind="api_action",
                         target={"issue": {"issue": "open_sg"}, "fix": {}}, gate_request_id="g", plan_digest="p",
                         error="api call failed", applied_before=["app"])
    q.request(r1)
    q.request(r2)
    evs = w.loop.take_rollbacks(q)
    assert q.pending() == [] and len(list((tmp_path / "rb" / "done").glob("*.json"))) == 2
    by = {e.rollback_request_id: e for e in evs}
    assert by[r1.id].drift_class == A.FAILED_CHANGE and by[r1.id].status == D.OPEN
    assert by[r2.id].status == D.REPORTED and by[r2.id].platform == "api"
    # failed-change drift is never auto-repaired, even when seen again at full confidence
    (ev,) = w.loop.scan_once()
    assert w.applied == [] and ev.status == D.OPEN
    with pytest.raises(ValueError):
        q.done("../x")


def test_loop_interval_floor(tmp_path):
    w = World(tmp_path, "aws")
    with pytest.raises(ValueError, match="at least 60"):
        w.loop.run_forever(interval=5)
    w.script("app", [])
    slept = []
    assert w.loop.run_forever(interval=60, max_passes=2, sleep=slept.append) == 2 and slept == [60]


# ── CloudFormation drift API ────────────────────────────────────────────────

class FakeCfn:
    def __init__(self):
        self.polls = 0

    def detect_stack_drift(self, StackName):
        return {"StackDriftDetectionId": "det-1"}

    def describe_stack_drift_detection_status(self, StackDriftDetectionId):
        self.polls += 1
        return {"DetectionStatus": "DETECTION_COMPLETE" if self.polls > 1 else "DETECTION_IN_PROGRESS",
                "StackDriftStatus": "DRIFTED"}

    def get_paginator(self, name):
        class P:
            def paginate(self, **k):
                assert k["StackResourceDriftStatusFilters"] == ["MODIFIED", "DELETED"]
                return [{"StackResourceDrifts": [
                    {"LogicalResourceId": "Web", "ResourceType": "AWS::EC2::SecurityGroup",
                     "StackResourceDriftStatus": "MODIFIED", "PhysicalResourceId": "sg-1",
                     "ActualProperties": json.dumps({"SecurityGroupIngress": [{"CidrIp": "0.0.0.0/0"}]}),
                     "ExpectedProperties": json.dumps({"SecurityGroupIngress": []})},
                    {"LogicalResourceId": "Logs", "ResourceType": "AWS::S3::Bucket",
                     "StackResourceDriftStatus": "DELETED", "PhysicalResourceId": "b"}]}]
        return P()


def test_cfn_drift_detector_maps_modified_and_deleted(tmp_path):
    cfn = FakeCfn()

    class Creds:
        def client(self, kind):
            class Sess:
                def client(self, name, region_name):
                    assert name == "cloudformation" and region_name == "us-east-1"
                    return cfn
            return Sess()

    env = parse_config(config_doc({"main": ENVF["aws"]("dev")}, tmp=tmp_path)).environment("main")
    plan = D.CfnDriftDetector(poll_seconds=0).detect(env, Creds(), ["app"], platform="cdk", source="x")
    web, logs = plan.changes
    assert web.action == Action.UPDATE and "0.0.0.0/0" in json.dumps(web.before)
    assert logs.action == Action.CREATE and logs.before is None
    c, _ = D.classify(plan.changes)
    assert c.drift_class == A.SECURITY_INCIDENT
