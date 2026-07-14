"""`environment=` must pick the stage for LOCAL files too, not just remote pulls.

It didn't. `load_ranbval(environment="production")` read only `mode` on the local path, fell back to
development, and loaded the wrong stage — silently. No error, no warning: your code just came up
pointing at the development database while believing it was in production. A feature that quietly
returns the wrong environment is worse than one that fails, because nothing tells you.
"""

import os
import subprocess
import sys

import pytest

STAGES = ["development", "staging", "production", "test", "qa"]

# Loading mutates os.environ, so each stage is resolved in its own interpreter.
CHILD = (
    "import os, sys;"
    "from ranbval_sdk import load_ranbval;"
    "load_ranbval(environment=sys.argv[1], start=sys.argv[2], override=True);"
    "print(os.environ.get('PUBLIC_DATABASE_URL', ''))"
)


@pytest.fixture
def project(tmp_path):
    (tmp_path / ".ranbval").write_text(
        "PUBLIC_APP_NAME=demo\nPUBLIC_DATABASE_URL=sqlite:///./default.db\n"
    )
    for stage in STAGES:
        (tmp_path / f".ranbval.{stage}").write_text(
            f"PUBLIC_DATABASE_URL=sqlite:///./{stage}.db\n"
        )
    return tmp_path


def resolve(stage: str, root) -> str:
    out = subprocess.run(
        [sys.executable, "-c", CHILD, stage, str(root)],
        capture_output=True,
        text=True,
        cwd=str(root),
        env={**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)},
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


@pytest.mark.parametrize("stage", STAGES)
def test_each_stage_loads_its_own_value(stage, project):
    assert resolve(stage, project) == f"sqlite:///./{stage}.db"


def test_production_never_silently_returns_development(project):
    """The exact failure: asking for production and getting development, with no complaint."""
    assert resolve("production", project) != "sqlite:///./development.db"


def test_no_two_stages_resolve_to_the_same_value(project):
    resolved = {s: resolve(s, project) for s in STAGES}
    assert len(set(resolved.values())) == len(STAGES), f"stages bled into each other: {resolved}"
