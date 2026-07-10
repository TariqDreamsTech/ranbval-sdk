"""Tests for the ``ranbval`` CLI (init / check / run)."""

from __future__ import annotations

import sys

from ranbval_sdk.cli import main


def test_init_creates_files(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init"]) == 0
    assert (tmp_path / ".ranbval").is_file()
    gi = (tmp_path / ".gitignore").read_text()
    assert ".ranbval.local" in gi
    assert "PUBLIC_APP_NAME" in (tmp_path / ".ranbval").read_text()


def test_init_refuses_overwrite_without_force(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".ranbval").write_text("PUBLIC_X=1\n", encoding="utf-8")
    assert main(["init"]) == 1
    assert main(["init", "--force"]) == 0


def test_check_passes_on_clean_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".ranbval").write_text(
        "RANBVAL_PROJECT_SECRET=proj-x\nPUBLIC_APP=demo\nSECRET_KEY=ranbval.aa.bb.ahsan\n",
        encoding="utf-8",
    )
    assert main(["check"]) == 0
    out = capsys.readouterr().out
    assert "1 public, 1 secret" in out


def test_check_fails_on_unclassified(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".ranbval").write_text("FOO=bar\n", encoding="utf-8")
    assert main(["check"]) == 1
    assert "no class prefix" in capsys.readouterr().out


def test_check_flags_competing_env_file(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".ranbval").write_text("PUBLIC_X=1\n", encoding="utf-8")
    (tmp_path / ".env").write_text("SECRET=leak\n", encoding="utf-8")
    assert main(["check"]) == 1
    assert "competing env file" in capsys.readouterr().out


def test_check_warns_on_section_header(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".ranbval").write_text("[secrets]\nSECRET_X=ranbval.aa.bb.cc\n", encoding="utf-8")
    assert main(["check"]) == 1
    assert "section" in capsys.readouterr().out.lower()


def test_run_injects_and_execs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".ranbval").write_text("PUBLIC_APP_NAME=demo\n", encoding="utf-8")
    code = main(["run", "--", sys.executable, "-c",
                 "import os,sys; sys.exit(0 if os.environ.get('PUBLIC_APP_NAME')=='demo' else 3)"])
    assert code == 0


def test_run_without_command_errors(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".ranbval").write_text("PUBLIC_X=1\n", encoding="utf-8")
    assert main(["run"]) == 2
