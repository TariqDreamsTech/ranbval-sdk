"""The root-key file must not be readable by other users on the machine.

The project secret is the one value that cannot be encrypted, so the only thing standing between
another account on the box and the whole vault is the file mode. A default umask of 022 creates
it `0644`.
"""

from __future__ import annotations

import os
import sys

import pytest

from ranbval_sdk.config.loader import (
    _check_secret_file_modes,
    secret_file_mode_problem,
)
from ranbval_sdk.exceptions import RanbvalConfigError

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="POSIX mode bits are not meaningful on Windows"
)


@pytest.fixture
def local(tmp_path):
    """A .ranbval.local holding a project secret, created 0600."""
    p = tmp_path / ".ranbval.local"
    p.write_text("RANBVAL_PROJECT_SECRET=ranbval-proj-abc123\n", encoding="utf-8")
    p.chmod(0o600)
    return p


@pytest.fixture(autouse=True)
def _no_strict(monkeypatch):
    monkeypatch.delenv("RANBVAL_STRICT_FILE_MODE", raising=False)


class TestModeDetection:
    @pytest.mark.parametrize("mode", [0o600, 0o400, 0o700])
    def test_owner_only_modes_are_clean(self, local, mode):
        local.chmod(mode)
        assert secret_file_mode_problem(local) is None

    @pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o666, 0o660])
    def test_group_or_other_readable_modes_are_flagged(self, local, mode):
        local.chmod(mode)
        assert secret_file_mode_problem(local) == mode

    def test_unreadable_path_is_not_reported_as_a_bad_mode(self, tmp_path):
        # A mode we cannot stat is not evidence of a wrong mode — don't invent a warning.
        assert secret_file_mode_problem(tmp_path / "does-not-exist") is None


class TestGuard:
    def test_clean_file_warns_nothing(self, local, recwarn):
        _check_secret_file_modes([local])
        assert len(recwarn) == 0

    def test_loose_file_warns_with_the_exact_fix(self, local):
        local.chmod(0o644)
        with pytest.warns(UserWarning, match=r"chmod 600 \.ranbval\.local"):
            _check_secret_file_modes([local])

    def test_strict_mode_raises_instead(self, local, monkeypatch):
        local.chmod(0o644)
        monkeypatch.setenv("RANBVAL_STRICT_FILE_MODE", "1")
        with pytest.raises(RanbvalConfigError) as exc:
            _check_secret_file_modes([local])
        assert exc.value.code == "secret_file_world_readable"

    def test_a_file_without_the_project_secret_is_ignored(self, tmp_path, recwarn):
        # .ranbval holds only sealed tokens and is meant to be world-readable and committed.
        sealed = tmp_path / ".ranbval"
        sealed.write_text("SECRET_API_KEY=ranbval.aaa.bbb.me\n", encoding="utf-8")
        sealed.chmod(0o644)
        _check_secret_file_modes([sealed])
        assert len(recwarn) == 0


class TestInitCreatesItPrivate:
    def test_ranbval_local_is_created_owner_only(self, tmp_path, monkeypatch, capsys):
        from ranbval_sdk.cli import init

        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(sys, "argv", ["ranbval", "init"])

        class Args:
            force = False

        assert init.handle(Args()) == 0
        local = tmp_path / ".ranbval.local"
        assert local.is_file()
        # 0600 from birth — never briefly world-readable while holding the secret.
        assert local.stat().st_mode & 0o777 == 0o600
        assert secret_file_mode_problem(local) is None

    def test_an_existing_local_file_is_left_alone(self, tmp_path, monkeypatch):
        from ranbval_sdk.cli import init

        monkeypatch.chdir(tmp_path)
        existing = tmp_path / ".ranbval.local"
        existing.write_text("RANBVAL_PROJECT_SECRET=mine\n", encoding="utf-8")

        class Args:
            force = False

        assert init.handle(Args()) == 0
        assert existing.read_text(encoding="utf-8") == "RANBVAL_PROJECT_SECRET=mine\n"


class TestTemplatesAreNotSecretFiles:
    """`.ranbval.example` is committed on purpose and holds a placeholder, not a key."""

    @pytest.mark.parametrize(
        "name", [".ranbval.example", ".ranbval.sample", ".ranbval.template", ".ranbval.dist"]
    )
    def test_a_template_is_not_treated_as_holding_the_project_secret(self, tmp_path, name, recwarn):
        from ranbval_sdk.config.loader import _file_holds_project_secret

        p = tmp_path / name
        p.write_text(
            "RANBVAL_PROJECT_SECRET=your_project_secret_from_dashboard\n", encoding="utf-8"
        )
        p.chmod(0o644)  # a template is meant to be world-readable and committed

        assert _file_holds_project_secret(p) is False
        _check_secret_file_modes([p])
        assert len(recwarn) == 0

    def test_a_real_file_with_the_same_content_is_still_flagged(self, tmp_path):
        from ranbval_sdk.config.loader import _file_holds_project_secret

        p = tmp_path / ".ranbval.local"
        p.write_text("RANBVAL_PROJECT_SECRET=ranbval-proj-real\n", encoding="utf-8")
        p.chmod(0o644)

        assert _file_holds_project_secret(p) is True
        with pytest.warns(UserWarning, match="chmod 600"):
            _check_secret_file_modes([p])
