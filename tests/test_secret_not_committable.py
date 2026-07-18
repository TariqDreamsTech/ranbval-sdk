"""The project secret must never be committable to git.

The project secret is the root key: it unseals every ranbval.* token. A committed .ranbval is
Ranbval's whole promise — but only because the file holds *sealed* tokens, never the key. If the
file carrying the key is not git-ignored, the vault is one `git add` from a public repo. So
load_ranbval refuses to run until it is ignored, rather than starting the app over a live landmine.
"""

import subprocess

import pytest

from ranbval_sdk import load_ranbval
from ranbval_sdk.exceptions import RanbvalConfigError


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=str(cwd), check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "t@t.co")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / ".ranbval").write_text("SECRET_X=ranbval.abc123def4.blob.ahsan\n")
    return tmp_path


def _load(cwd):
    return load_ranbval(start=str(cwd))


def test_secret_file_not_gitignored_is_refused(repo):
    (repo / ".ranbval.local").write_text("RANBVAL_PROJECT_SECRET=ranbval-proj-x\n")
    with pytest.raises(RanbvalConfigError) as e:
        _load(repo)
    assert "git-ignored" in str(e.value)
    assert ".ranbval.local" in str(e.value)


def test_gitignored_secret_file_loads_fine(repo):
    (repo / ".ranbval.local").write_text("RANBVAL_PROJECT_SECRET=ranbval-proj-x\n")
    (repo / ".gitignore").write_text(".ranbval.local\n")
    assert _load(repo) is True  # no raise


def test_secret_in_the_committed_ranbval_is_refused(repo):
    """The exact mistake of putting the root key in the committed file."""
    (repo / ".ranbval").write_text(
        "RANBVAL_PROJECT_SECRET=ranbval-proj-oops\nSECRET_X=ranbval.abc123def4.blob.ahsan\n"
    )
    with pytest.raises(RanbvalConfigError) as e:
        _load(repo)
    assert ".ranbval" in str(e.value)


def test_no_secret_file_means_no_guard(repo):
    """A project whose secret comes from an env var (no .local file) is fine."""
    assert _load(repo) is True


def test_not_a_git_repo_has_no_commit_risk(tmp_path):
    """Outside a git repo there is nothing to commit into, so the guard stays silent."""
    (tmp_path / ".ranbval").write_text("SECRET_X=ranbval.abc123def4.blob.ahsan\n")
    (tmp_path / ".ranbval.local").write_text("RANBVAL_PROJECT_SECRET=ranbval-proj-x\n")
    assert load_ranbval(start=str(tmp_path)) is True


def test_override_env_var_bypasses_the_guard(repo, monkeypatch):
    (repo / ".ranbval.local").write_text("RANBVAL_PROJECT_SECRET=ranbval-proj-x\n")
    monkeypatch.setenv("RANBVAL_ALLOW_COMMITTABLE_SECRET", "1")
    assert _load(repo) is True  # override → no raise
