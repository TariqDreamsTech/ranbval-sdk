"""Environment selection: which stage a remote pull fetches."""

import os

import pytest

from ranbval_sdk.remote import client as remote_client


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("RANBVAL_ENV", raising=False)
    monkeypatch.delenv("RANBVAL_HOST", raising=False)


def _capture(monkeypatch):
    """Record the payload the SDK posts, and return a canned env-set."""
    seen = {}

    def fake_post(url, payload, timeout):
        seen["url"] = url
        seen["payload"] = payload
        return {"envs": [{"name": "PUBLIC_X", "value": "1"}]}

    monkeypatch.setattr(remote_client, "_post", fake_post)
    return seen


def test_environment_is_sent_when_given(monkeypatch):
    seen = _capture(monkeypatch)
    remote_client.fetch_env_set(project_secret="ranbval-proj-abc", environment="production")
    assert seen["payload"]["environment"] == "production"
    assert seen["payload"]["project_secret"] == "ranbval-proj-abc"


def test_environment_falls_back_to_ranbval_env(monkeypatch):
    seen = _capture(monkeypatch)
    monkeypatch.setenv("RANBVAL_ENV", "staging")
    remote_client.fetch_env_set(project_secret="ranbval-proj-abc")
    assert seen["payload"]["environment"] == "staging"


def test_explicit_environment_beats_env_var(monkeypatch):
    seen = _capture(monkeypatch)
    monkeypatch.setenv("RANBVAL_ENV", "staging")
    remote_client.fetch_env_set(project_secret="ranbval-proj-abc", environment="production")
    assert seen["payload"]["environment"] == "production"


def test_no_environment_omits_the_field(monkeypatch):
    """Server then falls back to the project's first environment — old clients keep working."""
    seen = _capture(monkeypatch)
    remote_client.fetch_env_set(project_secret="ranbval-proj-abc")
    assert "environment" not in seen["payload"]


def test_push_env_carries_the_environment(monkeypatch):
    seen = _capture(monkeypatch)
    remote_client.push_env(
        "PUBLIC_DATABASE_URL", "postgres://prod", api_key="ranbval-dev-x", environment="production"
    )
    assert seen["payload"]["environment"] == "production"
    assert seen["payload"]["name"] == "PUBLIC_DATABASE_URL"
    assert seen["payload"]["api_key"] == "ranbval-dev-x"


def test_blank_environment_is_treated_as_unset(monkeypatch):
    seen = _capture(monkeypatch)
    remote_client.fetch_env_set(project_secret="ranbval-proj-abc", environment="   ")
    assert "environment" not in seen["payload"]
