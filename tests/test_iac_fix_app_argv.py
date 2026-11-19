"""The cdk.json app command runs as an argv list, never through a shell."""
import os

from cloudctl.debug.iac_fix import _app_argv


def test_plain_command_is_split():
    argv = _app_argv("python3 app.py")
    assert argv is not None and argv[-1] == "app.py"
    assert os.path.basename(argv[0]).startswith("python3")


def test_shell_syntax_is_refused():
    for app in ("python3 app.py && rm -rf /", "npx ts-node bin/app.ts | tee x",
                "python3 $APP", "python3 app.py > out", "echo `id`", "a; b"):
        assert _app_argv(app) is None, app


def test_empty_or_unbalanced_is_refused():
    assert _app_argv("") is None
    assert _app_argv("   ") is None
    if os.name != "nt":
        assert _app_argv("python3 'app.py") is None
