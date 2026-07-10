"""Ranbval must be the sole config/secret loader — competing .env files and dotenv-style
libraries are rejected. (A bare os.getenv cannot be detected and is not covered.)"""

from __future__ import annotations

import sys

import pytest

from ranbval_sdk import load_ranbval
from ranbval_sdk.exceptions import RanbvalConfigError


def _write(tmp_path, name, text):
    (tmp_path / name).write_text(text, encoding="utf-8")


def test_competing_env_file_rejected(tmp_path, monkeypatch):
    _write(tmp_path, ".ranbval", "PUBLIC_X=1\n")
    _write(tmp_path, ".env", "SECRET=leaked\n")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(RanbvalConfigError) as ei:
        load_ranbval()
    assert ei.value.code == "competing_env_file"


def test_competing_env_file_variants_rejected(tmp_path, monkeypatch):
    _write(tmp_path, ".ranbval", "PUBLIC_X=1\n")
    _write(tmp_path, ".env.production", "SECRET=leaked\n")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(RanbvalConfigError) as ei:
        load_ranbval()
    assert ei.value.code == "competing_env_file"


def test_sole_loader_false_allows_env_file(tmp_path, monkeypatch):
    _write(tmp_path, ".ranbval", "PUBLIC_X=1\n")
    _write(tmp_path, ".env", "SECRET=leaked\n")
    monkeypatch.chdir(tmp_path)
    assert load_ranbval(sole_loader=False) is True  # must not raise


def test_ranbval_files_are_not_competing(tmp_path, monkeypatch):
    # Our own .ranbval / .ranbval.* layers must never be flagged as competing.
    _write(tmp_path, ".ranbval", "PUBLIC_X=1\n")
    _write(tmp_path, ".ranbval.production", "PUBLIC_Y=2\n")
    monkeypatch.chdir(tmp_path)
    assert load_ranbval() is True


def test_competing_loader_module_rejected(tmp_path, monkeypatch):
    _write(tmp_path, ".ranbval", "PUBLIC_X=1\n")
    monkeypatch.chdir(tmp_path)
    # Simulate python-dotenv being imported by the app.
    monkeypatch.setitem(sys.modules, "dotenv", object())
    with pytest.raises(RanbvalConfigError) as ei:
        load_ranbval()
    assert ei.value.code == "competing_env_loader"


def test_competing_loader_module_allowed_when_off(tmp_path, monkeypatch):
    _write(tmp_path, ".ranbval", "PUBLIC_X=1\n")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setitem(sys.modules, "dotenv", object())
    assert load_ranbval(sole_loader=False) is True
