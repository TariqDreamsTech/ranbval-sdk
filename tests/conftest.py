"""Make ``src/ranbval_sdk`` importable when running the test suite from the repo root."""

import pathlib
import sys

import pytest

_SRC = pathlib.Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


@pytest.fixture(autouse=True)
def _reset_global_guard_state():
    """Leave no output-guard or audit state behind between tests.

    ``load_ranbval()`` installs the stdout guard by default, and both that guard and the audit log
    are process-global. Without this, one test's ``load_ranbval()`` patches ``builtins.print`` for
    every test that follows, and the accumulated audit log makes each later install look "late" and
    emit the partial-coverage warning. Neither happens in a real app, where ``load_ranbval()`` runs
    once at startup — it is purely an artefact of many loads in one process.
    """
    yield
    from ranbval_sdk.crypto.audit import clear_audit_log
    from ranbval_sdk.crypto.output_guards import uninstall_output_guards

    uninstall_output_guards()
    clear_audit_log()
