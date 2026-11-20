"""The HTTP service end to end, offline: real gate (Rego, Cedar, Ed25519, hash
chain), shared state on the memory backend, OIDC tokens signed with a test
ES256 key, fake credential brokers and executors."""
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

pytest.importorskip("regopy")
pytest.importorskip("fastapi")
jwt = pytest.importorskip("jwt")

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from cloudctl.controlplane import kv as K  # noqa: E402
from cloudctl.controlplane.drift import DriftLoop, DriftScanner  # noqa: E402
from cloudctl.controlplane.shared import KvApprovalStore, KvDriftStore, KvRollbackQueue, KvRunStore  # noqa: E402
from cloudctl.gate.approval.signing import generate_keypair, write_private_key  # noqa: E402
from cloudctl.gate.audit import AuditLog, LocalFileSink  # noqa: E402
from cloudctl.gate.config import parse_config  # noqa: E402
from cloudctl.gate.gate import PolicyGate  # noqa: E402
from cloudctl.gate.models import ConfigError  # noqa: E402
from cloudctl.gate.policy.rego import RegoEngine  # noqa: E402
from cloudctl.service.app import ServiceContext, create_app  # noqa: E402
from cloudctl.service.auth import AuthSettings, OIDCVerifier  # noqa: E402
from cloudctl.service.settings import validate_settings  # noqa: E402
from tests.controlplane.conftest import ENVF, ExecutorFactory, FakeModel, graph_doc, iac_root, node  # noqa: E402
from tests.controlplane.test_drift import FakeApply, FakeBaselineScanner, ScriptedPlanner, tagdrift  # noqa: E402
from tests.gate.conftest import FakeCredsBroker, config_doc  # noqa: E402

ISS, AUD = "https://idp.example.com/", "cctl-control-plane"
ROLES = {"operator": ["ops"], "approver": ["leads"], "auditor": ["sec"]}


class Env:
    def __init__(self, tmp_path, cloud="aws"):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.tmp = tmp_path
        self.roots = {n: iac_root(tmp_path, n) for n in ("net", "app")}
        pem, pub = generate_keypair()
        kp = tmp_path / "carol.pem"
        write_private_key(kp, pem)
        roots = [str(r) for r in self.roots.values()]
        envs = {"dev": ENVF[cloud]("dev", match={"iac_roots": roots}),
                "prod": ENVF[cloud]("prod", match={"iac_roots": roots},
                                    approval={"approvers": ["carol"], "always": True})}
        self.cfg = parse_config(config_doc(
            envs, tmp=tmp_path, approvers={"carol": {"public_key": pub}},
            sink={"type": "s3", "bucket": "audit", "region": "us-east-1", "retain_days": 400},
            policy={"engines": {"checkov": {"enabled": True, "version": "3.4.6"}}}))
        self.kv = K.MemoryKV()
        audit = AuditLog(LocalFileSink(tmp_path / "audit.jsonl"), chain="test", actor="svc")
        rego = RegoEngine.from_config(builtin=True, rule_paths=[], rego_paths=[], params={})
        self.brokers = {c: FakeCredsBroker(c) for c in ("aws", "azure", "gcp")}
        self.gate = PolicyGate(self.cfg, audit=audit, brokers=self.brokers, approvals=KvApprovalStore(self.kv),
                               policy=([], [rego, FakeBaselineScanner()]))
        self.factory = ExecutorFactory(cloud)
        self.model = FakeModel()
        self.applied = []
        self.planners = {}
        verifier = OIDCVerifier(AuthSettings(issuer=ISS, audience=AUD, algorithms=("ES256",), role_map=ROLES),
                                key_resolver=lambda token: self.key.public_key())
        self.ctx = ServiceContext(gate=self.gate, kv=self.kv, verifier=verifier, runs=KvRunStore(self.kv),
                                  drift_store=KvDriftStore(self.kv), rollbacks=KvRollbackQueue(self.kv),
                                  model_factory=lambda: self.model, executor_factory=self.factory,
                                  drift_loop_factory=self.drift_loop, workers=2, max_body_bytes=200_000)
        self.client = TestClient(create_app(self.ctx))

    def drift_loop(self, requester):
        scanner = DriftScanner(self.cfg, brokers=self.brokers, policy=self.gate.policy,
                               planner_factory=lambda root, env: self.planners[str(Path(root).resolve())])
        return DriftLoop(self.gate, scanner=scanner, store=self.ctx.drift_store, runs=self.ctx.runs,
                         requester=requester, executor_for=lambda p: FakeApply(p, self.applied),
                         orchestrator_factory=lambda **k: self.ctx.orchestrator(k["requester"]).__class__(
                             self.gate, self.ctx.runs, rollback=self.ctx.rollbacks,
                             executor_factory=k["executor_factory"], requester=k["requester"]))

    def token(self, sub="alice@example.com", groups=("ops",), username=None, **over):
        now = datetime.now(timezone.utc)
        claims = {"iss": ISS, "aud": AUD, "sub": sub, "email": sub, "groups": list(groups),
                  "iat": now, "exp": now + timedelta(minutes=10)}
        if username:
            claims["preferred_username"] = username
        claims.update(over)
        return {"Authorization": "Bearer " + jwt.encode(claims, self.key, algorithm="ES256")}

    def drain(self):
        for f in list(self.ctx.jobs.values()):
            f.result(timeout=30)


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.ctx.pool.shutdown(wait=True)


def test_health_and_readiness_need_no_token(env):
    assert env.client.get("/healthz").json() == {"ok": True}
    r = env.client.get("/readyz")
    assert r.status_code == 200 and r.json()["ready"] is True
    assert r.headers["X-Content-Type-Options"] == "nosniff" and r.headers["Cache-Control"] == "no-store"
    env.kv.check_ready = lambda: (_ for _ in ()).throw(K.KVError("down"))
    r = env.client.get("/readyz")
    assert r.status_code == 503 and r.json()["failing"] == ["state"] and "down" not in r.text


@pytest.mark.parametrize("hdr", [
    None, "Basic abc", "Bearer not-a-jwt",
])
def test_requests_without_a_valid_token_are_refused(env, hdr):
    r = env.client.get("/v1/changes", headers={"Authorization": hdr} if hdr else {})
    assert r.status_code == 401 and r.headers["WWW-Authenticate"] == "Bearer"


def test_token_checks_issuer_audience_expiry_and_algorithm(env):
    assert env.client.get("/v1/changes", headers=env.token(iss="https://evil.example.com/")).status_code == 401
    assert env.client.get("/v1/changes", headers=env.token(aud="someone-else")).status_code == 401
    old = datetime.now(timezone.utc) - timedelta(hours=1)
    assert env.client.get("/v1/changes", headers=env.token(exp=old)).status_code == 401
    hs = jwt.encode({"iss": ISS, "aud": AUD, "sub": "x", "iat": int(time.time()), "exp": int(time.time()) + 60},
                    "secret-but-at-least-32-bytes-long-ok", algorithm="HS256")
    assert env.client.get("/v1/changes", headers={"Authorization": f"Bearer {hs}"}).status_code == 401
    with pytest.raises(ValueError, match="asymmetric"):
        AuthSettings(issuer=ISS, audience=AUD, algorithms=("HS256",))
    with pytest.raises(ValueError, match="https"):
        AuthSettings(issuer="http://idp", audience=AUD)


def test_roles_are_enforced(env):
    nobody = env.token(groups=("interns",))
    assert env.client.get("/v1/changes", headers=nobody).status_code == 403
    sec = env.token(sub="sec@example.com", groups=("sec",))
    assert env.client.get("/v1/changes", headers=sec).status_code == 200            # auditor reads
    r = env.client.post("/v1/changes", headers=sec, json={"graph": graph_doc([])})
    assert r.status_code == 403 and "operator" in r.json()["detail"]
    assert env.client.get("/v1/audit:verify", headers=env.token()).status_code == 403
    assert env.client.get("/v1/audit:verify", headers=sec).json()["ok"] is True


def test_compile_records_the_requester_from_the_token(env):
    doc = graph_doc([node("net", env.roots["net"]), node("app", env.roots["app"], deps=("net",))])
    env.model.replies.append(json.dumps(doc))
    r = env.client.post("/v1/changes:compile", headers=env.token(), json={"request": "ship it"})
    assert r.status_code == 200 and r.json()["ok"] and [n["id"] for n in r.json()["graph"]["nodes"]] == ["net", "app"]
    calls = [x for x in env.gate.audit.sink.read_all() if x["event"] == "compiler.model.call"]
    assert calls and calls[0]["data"]["requester"] == "alice@example.com"
    assert env.client.post("/v1/changes:compile", headers=env.token(), json={"request": ""}).status_code == 400


def test_run_a_graph_in_the_background_and_poll_it(env):
    g = graph_doc([node("net", env.roots["net"]), node("app", env.roots["app"], deps=("net",))])
    r = env.client.post("/v1/changes", headers=env.token(), json={"graph": g})
    assert r.status_code == 202
    rid = r.json()["run_id"]
    env.drain()
    run = env.client.get(f"/v1/changes/{rid}", headers=env.token()).json()
    assert run["status"] == "succeeded" and run["requester"] == "alice@example.com"
    assert env.factory.applied == ["net", "app"]
    assert [x["run_id"] for x in env.client.get("/v1/changes", headers=env.token()).json()] == [rid]
    assert env.client.get("/v1/changes/" + "0" * 32, headers=env.token()).status_code == 404
    bad = graph_doc([node("x", env.tmp / "elsewhere")])
    r = env.client.post("/v1/changes", headers=env.token(), json={"graph": bad})
    assert r.status_code == 400 and "not an IaC root" in r.json()["detail"]
    assert env.client.post("/v1/changes", headers=env.token(), json={"graph": "nope"}).status_code == 400


def test_prod_change_waits_for_a_signed_approval_made_offline(env):
    g = graph_doc([node("app", env.roots["app"], env="prod")])
    rid = env.client.post("/v1/changes", headers=env.token(), json={"graph": g}).json()["run_id"]
    env.drain()
    run = env.client.get(f"/v1/changes/{rid}", headers=env.token()).json()
    assert run["status"] == "awaiting_approval" and env.factory.applied == []
    appr_id = run["nodes"]["app"]["approval_id"]
    carol = env.token(sub="carol@example.com", groups=("leads",), username="carol")
    pending = env.client.get("/v1/approvals", headers=carol).json()
    assert [p["request_id"] for p in pending] == [appr_id]
    # on carol's laptop: fetch the request, sign it with `cloudctl gate sign`; the key never reaches the service
    reqdoc = env.client.get(f"/v1/approvals/{appr_id}", headers=carol).json()
    rf = env.tmp / "req.json"
    rf.write_text(json.dumps(reqdoc))
    from typer.testing import CliRunner
    from cloudctl.commands.gate_cmd import app as gate_app
    out = CliRunner().invoke(gate_app, ["sign", str(rf), "--approver", "carol",
                                                        "--key", str(env.tmp / "carol.pem"), "--yes"])
    assert out.exit_code == 0, out.stderr
    signed = type("S", (), json.loads(out.stdout))
    refused = CliRunner().invoke(gate_app, ["sign", str(rf), "--approver", "alice@example.com",
                                                            "--key", str(env.tmp / "carol.pem"), "--yes"])
    assert refused.exit_code == 1 and "you requested" in refused.stderr
    dave = env.token(sub="dave@example.com", groups=("leads",), username="dave")
    r = env.client.post(f"/v1/approvals/{appr_id}", headers=dave,
                        json={"signature": signed.signature, "signed_at": signed.signed_at})
    assert r.status_code == 403 and "not a configured approver" in r.json()["detail"]
    # an operator cannot approve, a forged signature is refused, the requester cannot self-approve
    assert env.client.post(f"/v1/approvals/{appr_id}", headers=env.token(),
                           json={"signature": signed.signature, "signed_at": signed.signed_at}).status_code == 403
    r = env.client.post(f"/v1/approvals/{appr_id}", headers=carol,
                        json={"signature": "AAAA" + signed.signature[4:], "signed_at": signed.signed_at})
    assert r.status_code == 400
    alice_appr = env.token(groups=("leads",), username="alice@example.com")
    assert env.client.post(f"/v1/approvals/{appr_id}", headers=alice_appr,
                           json={"signature": signed.signature, "signed_at": signed.signed_at}).status_code == 403
    r = env.client.post(f"/v1/approvals/{appr_id}", headers=carol,
                        json={"signature": signed.signature, "signed_at": signed.signed_at})
    assert r.status_code == 201
    # only the requester can resume
    bob = env.token(sub="bob@example.com")
    assert env.client.post(f"/v1/changes/{rid}:resume", headers=bob,
                           json={"approvals": {"app": appr_id}}).status_code == 403
    assert env.client.post(f"/v1/changes/{rid}:resume", headers=env.token(),
                           json={"approvals": {"app": appr_id}}).status_code == 202
    env.drain()
    run = env.client.get(f"/v1/changes/{rid}", headers=env.token()).json()
    assert run["status"] == "succeeded" and env.factory.applied == ["app"]
    events = [x["event"] for x in env.gate.audit.sink.read_all()]
    assert "service.approval.submitted" in events and "gate.approval.verified" in events


def test_drift_scan_and_repair_over_the_api(env):
    d = tagdrift("aws")
    env.planners[str(env.roots["app"].resolve())] = ScriptedPlanner("terraform", [d], drift_addresses=["vm.v0"])
    env.planners[str(env.roots["net"].resolve())] = ScriptedPlanner("terraform", [[]])
    r = env.client.post("/v1/drift:scan", headers=env.token(), json={"environments": ["dev"]})
    assert r.status_code == 202
    env.drain()
    (ev,) = env.client.get("/v1/drift", headers=env.token()).json()
    assert ev["status"] == "open" and ev["sightings"] == 1
    env.client.post("/v1/drift:scan", headers=env.token(), json={"environments": ["dev"]})
    env.drain()
    ev = env.client.get(f"/v1/drift/{ev['id']}", headers=env.token()).json()
    assert ev["status"] == "repaired" and len(env.applied) == 1
    assert env.client.post("/v1/drift:scan", headers=env.token(), json={"environments": ["nope"]}).status_code == 400
    scans = [x for x in env.gate.audit.sink.read_all() if x["event"] == "service.drift.scan"]
    assert scans[0]["data"]["asked_by"] == "alice@example.com"


def test_report_only_drift_needs_an_override_over_the_api(env):
    ident = [__import__("tests.controlplane.test_drift", fromlist=["rc"]).rc(
        "aws", "aws_iam_role_policy", before={"p": 1}, after={"p": 2})]
    env.planners[str(env.roots["app"].resolve())] = ScriptedPlanner("terraform", [ident], drift_addresses=[ident[0].address])
    env.planners[str(env.roots["net"].resolve())] = ScriptedPlanner("terraform", [[]])
    env.client.post("/v1/drift:scan", headers=env.token(), json={"environments": ["dev"]})
    env.drain()
    (ev,) = env.client.get("/v1/drift", headers=env.token()).json()
    assert ev["status"] == "reported"
    assert env.client.post(f"/v1/drift/{ev['id']}:repair", headers=env.token(), json={}).status_code == 409
    r = env.client.post(f"/v1/drift/{ev['id']}:repair", headers=env.token(), json={"override": "break-glass SEC-1"})
    assert r.status_code == 202
    env.drain()
    assert env.client.get(f"/v1/drift/{ev['id']}", headers=env.token()).json()["status"] == "repaired"


def test_oversized_bodies_and_internal_errors_leak_nothing(env):
    r = env.client.post("/v1/changes", headers={**env.token(), "Content-Type": "application/json"},
                        content=b"x" * 300_000)
    assert r.status_code == 413
    env.ctx.runs.list = lambda: (_ for _ in ()).throw(RuntimeError("secret detail"))
    r = env.client.get("/v1/changes", headers=env.token())
    assert r.status_code == 500 and "secret detail" not in r.text and r.json()["request_id"]


def test_settings_validation():
    base = {"gate_config": "/x.yaml", "auth": {"issuer": ISS, "audience": AUD},
            "state": {"backend": "dynamodb", "table": "t"}}
    assert validate_settings(base)["state"]["table"] == "t"
    for bad, msg in [({"state": {"backend": "redis"}}, "state.backend"),
                     ({"state": {"backend": "cosmos", "endpoint": "e"}}, "needs"),
                     ({"state": {"backend": "memory"}}, "allow_memory_state"),
                     ({"workers": 0}, "workers"), ({"drift": {"interval_seconds": 10}}, "interval"),
                     ({"bogus": 1}, "unknown key")]:
        with pytest.raises(ConfigError, match=msg):
            validate_settings({**base, **bad})
    with pytest.raises(ConfigError, match="auth is required"):
        validate_settings({k: v for k, v in base.items() if k != "auth"})
