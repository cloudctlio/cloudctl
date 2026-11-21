"""`cloudctl drift ...` commands, offline (scripted planners, fake brokers, fake executors)."""
import json

import pytest
from typer.testing import CliRunner

pytest.importorskip("regopy")

from cloudctl.commands import drift_cmd  # noqa: E402
from tests.controlplane.test_drift import TYPES, World, rc, tagdrift  # noqa: E402

runner = CliRunner()


@pytest.fixture
def w(tmp_path, monkeypatch):
    world = World(tmp_path, "azure")
    drift_cmd.console.width = 200
    monkeypatch.setattr(drift_cmd, "_gate", lambda path: world.gate)
    monkeypatch.setattr(drift_cmd, "_loop", lambda gate: world.loop)
    monkeypatch.setattr(drift_cmd, "_store", lambda: world.store)
    monkeypatch.setenv("CLOUDCTL_REQUESTER", "bob")
    return world


def _invoke(*args, input=None):
    return runner.invoke(drift_cmd.app, [str(a) for a in args], input=input, catch_exceptions=False)


def test_scan_list_show_and_exit_codes(w):
    w.script("app", tagdrift("azure"), tagdrift("azure"), tagdrift("azure"), [], drift_addresses=["vm.v0"])
    r = _invoke("scan", "--no-repair")
    assert r.exit_code == 5 and "config_drift" in r.output and "open" in r.output
    r = _invoke("scan", "--json")
    ev = json.loads(r.output)[0]
    assert r.exit_code == 0 and ev["status"] == "repaired" and w.applied
    r = _invoke("show", ev["id"][:8])
    assert r.exit_code == 0 and "confidence 1.00" in r.output and "vm.v0" in r.output
    assert _invoke("scan").exit_code == 0
    assert "No drift." in _invoke("list").output
    assert ev["id"][:12] in _invoke("list", "--all").output


def test_repair_needs_override_for_incidents(w):
    ident = [rc("azure", TYPES["azure"][1], before={"role": "Owner"}, after={"role": "Reader"})]
    w.script("app", ident, drift_addresses=[ident[0].address])
    r = _invoke("scan")
    assert r.exit_code == 5 and "reported" in r.output and "security incident" in r.output
    eid = w.store.list()[0].id
    r = _invoke("repair", eid, "--yes")
    assert r.exit_code == 1 and "report-only" in r.output and w.applied == []
    assert _invoke("repair", eid, input="n\n").exit_code == 1
    r = _invoke("repair", eid, "--yes", "--override", "our break-glass change, ticket SEC-1")
    assert r.exit_code == 0 and "repaired" in r.output and len(w.applied) == 1


def test_show_rejects_ambiguous_or_unknown_ids(w):
    assert _invoke("show", "abc").exit_code == 1
    assert _invoke("show", "0" * 32).exit_code == 1


def test_table(w):
    r = _invoke("table")
    assert r.exit_code == 0 and "prod" in r.output and "0.90" in r.output
    t = json.loads(_invoke("table", "--json").output)
    assert t["autonomy"]["dev"]["CRITICAL"] == "report"
