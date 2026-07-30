"""RANBVAL_ALLOWED_PATHS confines a config to a subtree, with subdirectories inheriting.

`.ranbval` is discovered by walking *upward*, so a config placed high in a tree is picked up by
every project beneath it — including ones that should never see those credentials. This key
confines it, and anything created under an allowed path is allowed with no config change.
"""

from __future__ import annotations

import pytest

from ranbval_sdk import load_ranbval
from ranbval_sdk.exceptions import RanbvalConfigError


@pytest.fixture
def tree(tmp_path):
    """A root holding .ranbval, with `content/` allowed and `other/` not."""
    (tmp_path / "content" / "api" / "v1").mkdir(parents=True)
    (tmp_path / "other").mkdir()
    (tmp_path / "content-backup").mkdir()  # shares a prefix with `content` — must NOT match
    (tmp_path / ".ranbval").write_text(
        "RANBVAL_ALLOWED_PATHS=./content\nPUBLIC_APP=demo\n", encoding="utf-8"
    )
    return tmp_path


@pytest.mark.parametrize("sub", ["content", "content/api", "content/api/v1"])
def test_the_allowed_path_and_every_depth_below_it_load(tree, monkeypatch, sub):
    monkeypatch.chdir(tree / sub)
    assert load_ranbval() is True


@pytest.mark.parametrize("sub", [".", "other"])
def test_anything_outside_is_refused(tree, monkeypatch, sub):
    monkeypatch.chdir(tree / sub)
    with pytest.raises(RanbvalConfigError) as exc:
        load_ranbval()
    assert exc.value.code == "path_not_allowed"


def test_a_sibling_sharing_a_name_prefix_is_not_allowed(tree, monkeypatch):
    # `content-backup` starts with `content`. A string-prefix check would wrongly admit it;
    # the comparison is on resolved path components, so it does not.
    monkeypatch.chdir(tree / "content-backup")
    with pytest.raises(RanbvalConfigError) as exc:
        load_ranbval()
    assert exc.value.code == "path_not_allowed"


def test_a_directory_created_later_inherits_without_a_config_change(tree, monkeypatch):
    new = tree / "content" / "jobs" / "nightly"
    new.mkdir(parents=True)
    monkeypatch.chdir(new)
    assert load_ranbval() is True


def test_several_subtrees_can_be_listed(tree, monkeypatch):
    (tree / "jobs").mkdir()
    (tree / ".ranbval").write_text(
        "RANBVAL_ALLOWED_PATHS=./content:./jobs\nPUBLIC_APP=demo\n", encoding="utf-8"
    )
    for sub in ("content", "jobs"):
        monkeypatch.chdir(tree / sub)
        assert load_ranbval() is True
    monkeypatch.chdir(tree / "other")
    with pytest.raises(RanbvalConfigError):
        load_ranbval()


def test_absolute_entries_work_too(tree, monkeypatch):
    (tree / ".ranbval").write_text(
        f"RANBVAL_ALLOWED_PATHS={tree / 'content'}\nPUBLIC_APP=demo\n", encoding="utf-8"
    )
    monkeypatch.chdir(tree / "content" / "api")
    assert load_ranbval() is True


def test_dot_means_here_and_below(tree, monkeypatch):
    (tree / ".ranbval").write_text("RANBVAL_ALLOWED_PATHS=.\nPUBLIC_APP=demo\n", encoding="utf-8")
    for sub in (".", "content", "other"):
        monkeypatch.chdir(tree / sub)
        assert load_ranbval() is True


def test_no_key_means_no_restriction(tree, monkeypatch):
    (tree / ".ranbval").write_text("PUBLIC_APP=demo\n", encoding="utf-8")
    monkeypatch.chdir(tree / "other")
    assert load_ranbval() is True


def test_an_empty_value_is_not_a_lockout(tree, monkeypatch):
    # An empty setting must not mean "nothing is allowed" — that would brick a config on a typo.
    (tree / ".ranbval").write_text("RANBVAL_ALLOWED_PATHS=\nPUBLIC_APP=demo\n", encoding="utf-8")
    monkeypatch.chdir(tree / "other")
    assert load_ranbval() is True
