"""--resolve without --base-branch must not crash before the resolution agent runs."""
import json
from unittest.mock import patch

from typer.testing import CliRunner

from cloudctl.main import app


def test_resolve_without_base_branch_reaches_resolution_agent(tmp_path):
    diag = {"root_cause": "table at 1 WCU", "evidence": [], "confidence": "HIGH",
            "deployment_source": "terraform"}
    with patch("cloudctl.commands.debug_cmd.require_init", return_value={}), \
         patch("cloudctl.ai.graph_agent.debug_incident_graph", return_value=(json.dumps(diag), {})), \
         patch("cloudctl.ai.live_learner.on_confirmed_correct"), \
         patch("cloudctl.ai.resolution_agent.run", return_value={"status": "manual_required", "manual_steps": ["x"]}) as run:
        r = CliRunner().invoke(app, ["debug", "--agent", "--verdict", "y", "--resolve",
                                     "--iac-root", str(tmp_path), "orders throttled"])
    assert r.exception is None or isinstance(r.exception, SystemExit), r.exception
    assert run.call_args.kwargs["base_branch"] == "develop"
