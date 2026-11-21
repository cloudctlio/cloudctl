"""--resolve without --base-branch must not crash before the resolution agent runs,
and --resolve never runs without a usable policy gate."""
import json
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from cloudctl.gate.models import ConfigError
from cloudctl.main import app

_DIAG = {"root_cause": "table at 1 WCU", "evidence": [], "confidence": "HIGH",
         "deployment_source": "terraform"}


def _invoke(tmp_path, *extra, gate_cfg=None):
    gate = MagicMock(name="PolicyGate")
    load = patch("cloudctl.gate.config.load_config",
                 side_effect=gate_cfg) if gate_cfg else patch("cloudctl.gate.config.load_config")
    with patch("cloudctl.commands.debug_cmd.require_init", return_value={}), \
         patch("cloudctl.ai.graph_agent.debug_incident_graph", return_value=(json.dumps(_DIAG), {})), \
         patch("cloudctl.ai.live_learner.on_confirmed_correct"), \
         load, patch("cloudctl.gate.gate.PolicyGate.from_config", return_value=gate), \
         patch("cloudctl.ai.resolution_agent.run",
               return_value={"status": "manual_required", "manual_steps": ["x"]}) as run:
        r = CliRunner().invoke(app, ["debug", "--agent", "--verdict", "y", "--resolve",
                                     "--iac-root", str(tmp_path), *extra, "orders throttled"])
    return r, run, gate


def test_resolve_without_base_branch_reaches_resolution_agent(tmp_path):
    r, run, gate = _invoke(tmp_path)
    assert r.exception is None or isinstance(r.exception, SystemExit), r.exception
    assert run.call_args.kwargs["base_branch"] == "develop"
    assert run.call_args.kwargs["gate"] is gate


def test_resolve_passes_env_and_approval_to_the_gate(tmp_path):
    _, run, _ = _invoke(tmp_path, "--env", "staging", "--approval", "abc123")
    assert run.call_args.kwargs["gate_env"] == "staging"
    assert run.call_args.kwargs["approval_id"] == "abc123"


def test_resolve_refuses_without_a_usable_gate(tmp_path):
    r, run, _ = _invoke(tmp_path, gate_cfg=ConfigError("no control-plane config"))
    assert run.call_count == 0
    assert r.exit_code == 1
    assert "policy gate is not usable" in r.output
