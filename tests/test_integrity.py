"""A modified installation is detected before the first secret is revealed.

Everything else here guards a secret. This guards the code doing the guarding — because editing
four lines of the installed package defeats all of it, which this project measured directly.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from ranbval_sdk._internal import integrity

PKG = Path(integrity.__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _reset():
    integrity._reset()
    yield
    integrity._reset()


def test_an_untouched_installation_verifies():
    assert integrity.verify() == []


def test_check_once_is_silent_when_intact():
    integrity.check_once()  # must not raise


def test_editing_any_shipped_file_is_detected(tmp_path):
    target = PKG / "crypto" / "enforcement.py"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b"\n# one appended comment\n")
        changed = integrity.verify()
        assert "crypto/enforcement.py" in changed
    finally:
        target.write_bytes(original)
    assert integrity.verify() == [], "restored file must verify again"


def test_a_missing_file_is_detected():
    target = PKG / "crypto" / "memory.py"
    original = target.read_bytes()
    try:
        target.unlink()
        assert any("memory.py" in c for c in integrity.verify())
    finally:
        target.write_bytes(original)


def test_line_endings_are_not_reported_as_tampering(tmp_path):
    # A checkout or install that rewrites CRLF must not look like an edit, or the check would be
    # useless on Windows and everyone would learn to ignore it.
    f = tmp_path / "sample.py"
    f.write_bytes(b"a = 1\nb = 2\n")
    lf = integrity.file_digest(f)
    f.write_bytes(b"a = 1\r\nb = 2\r\n")
    assert integrity.file_digest(f) == lf


def test_a_tampered_install_refuses_to_decrypt():
    # End to end, in a child process: the check runs during .use(), before any plaintext exists.
    target = PKG / "crypto" / "enforcement.py"
    original = target.read_bytes()
    try:
        target.write_bytes(original.replace(b"_enforced: bool = True", b"_enforced: bool = False"))
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "from ranbval_sdk import SecretString; "
                "SecretString('sk-live-demo-value', 'T').use()",
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert "installation has been modified" in result.stderr
    finally:
        target.write_bytes(original)


def test_there_is_no_environment_switch_to_soften_it(monkeypatch):
    # A modified installation defeats every other control here, so an off switch would be
    # reachable by exactly the code the check exists to catch.
    for name in ("RANBVAL_STRICT_INTEGRITY", "RANBVAL_SKIP_INTEGRITY", "RANBVAL_NO_INTEGRITY"):
        monkeypatch.setenv(name, "0")
    source = Path(integrity.__file__).read_text()
    assert "environ" not in source


def test_the_manifest_is_current():
    # A stale manifest either fails every install or passes while describing something else.
    root = PKG.parent.parent
    result = subprocess.run(
        [sys.executable, str(root / "scripts" / "gen_manifest.py"), "--check"],
        capture_output=True,
        text=True,
        cwd=root,
    )
    assert result.returncode == 0, result.stdout + result.stderr
