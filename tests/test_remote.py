"""Tests for remote env-set fetch (load_ranbval(remote=True))."""

from __future__ import annotations

import json
import os

import pytest

from ranbval_sdk import fetch_env_set, load_ranbval, push_env
from ranbval_sdk.exceptions import RanbvalConfigError


class _FakeResp:
    def __init__(self, payload: dict):
        self._data = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._data


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for n in list(os.environ):
        if n.startswith(("PUBLIC_", "SECRET_", "PROXY_")) or n.endswith("_PROJECT_SECRET"):
            monkeypatch.delenv(n, raising=False)
    yield


def _mock_pull(monkeypatch, payload):
    import ranbval_sdk.remote.client as rc

    monkeypatch.setattr(rc._transport, "urlopen", lambda req, timeout=None: _FakeResp(payload))


def test_fetch_env_set_maps_names(monkeypatch):
    _mock_pull(monkeypatch, {"project": "demo", "envs": [
        {"name": "PUBLIC_DB_URL", "value": "postgres://x", "kind": "public"},
        {"name": "SECRET_OPENAI", "value": "ranbval.aa.bb.ahsan", "kind": "secret"},
    ]})
    envs = fetch_env_set(project_secret="ranbval-proj-x")
    assert envs == {"PUBLIC_DB_URL": "postgres://x", "SECRET_OPENAI": "ranbval.aa.bb.ahsan"}


def test_fetch_requires_secret():
    with pytest.raises(RanbvalConfigError) as ei:
        fetch_env_set(project_secret="")
    assert ei.value.code == "remote_no_secret"


def test_fetch_with_dev_api_key(monkeypatch):
    captured = {}

    def _fake(req, timeout=None):
        captured["body"] = json.loads(req.data.decode())
        return _FakeResp({"envs": [{"name": "PUBLIC_X", "value": "1"}]})

    import ranbval_sdk.remote.client as rc

    monkeypatch.setattr(rc._transport, "urlopen", _fake)
    envs = fetch_env_set(api_key="ranbval-dev-abc")
    assert envs == {"PUBLIC_X": "1"}
    assert captured["body"] == {"api_key": "ranbval-dev-abc"}


def test_push_env(monkeypatch):
    captured = {}

    def _fake(req, timeout=None):
        captured["url"] = req.get_full_url()
        captured["body"] = json.loads(req.data.decode())
        return _FakeResp({"name": "PUBLIC_FLAG", "kind": "public", "added_by": "dev-jane"})

    import ranbval_sdk.remote.client as rc

    monkeypatch.setattr(rc._transport, "urlopen", _fake)
    out = push_env("PUBLIC_FLAG", "on", api_key="ranbval-dev-abc")
    assert out["added_by"] == "dev-jane"
    assert captured["url"].endswith("/api/envs/add")
    assert captured["body"] == {"name": "PUBLIC_FLAG", "value": "on", "api_key": "ranbval-dev-abc"}


def test_load_ranbval_remote_dev_key(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    _mock_pull(monkeypatch, {"envs": [{"name": "PUBLIC_APP", "value": "demo"}]})
    monkeypatch.delenv("RANBVAL_PROJECT_SECRET", raising=False)
    assert load_ranbval(remote=True, api_key="ranbval-dev-abc") is True
    assert os.environ["PUBLIC_APP"] == "demo"


def test_load_ranbval_remote_populates_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # no local .ranbval
    _mock_pull(monkeypatch, {"project": "demo", "envs": [
        {"name": "PUBLIC_APP", "value": "demo", "kind": "public"},
        {"name": "SECRET_KEY", "value": "ranbval.aa.bb.ahsan", "kind": "secret"},
    ]})
    monkeypatch.delenv("RANBVAL_PROJECT_SECRET", raising=False)
    ok = load_ranbval(remote=True, project_secret="ranbval-proj-x")
    assert ok is True
    assert os.environ["PUBLIC_APP"] == "demo"
    assert os.environ["SECRET_KEY"] == "ranbval.aa.bb.ahsan"


def test_load_ranbval_remote_still_validates_prefixes(monkeypatch, tmp_path):
    # A malformed remote payload with an unclassified key is rejected by the same pipeline.
    monkeypatch.chdir(tmp_path)
    _mock_pull(monkeypatch, {"envs": [{"name": "FOO", "value": "bar", "kind": "public"}]})
    with pytest.raises(RanbvalConfigError) as ei:
        load_ranbval(remote=True, project_secret="ranbval-proj-x")
    assert ei.value.code == "unclassified_key"
