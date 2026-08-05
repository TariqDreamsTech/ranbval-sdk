"""The environment must not be able to redirect the control plane.

Every server-side control here — the repo allowlist above all — is only as trustworthy as the
server being asked. Reading `RANBVAL_HOST` without constraint meant anyone who could set an
environment variable could point the SDK at a server of their own, have it answer
`{"enforce_allowlist": false}`, and walk past the allowlist. Demonstrated with a nine-line local
HTTP server before this was written.
"""

from __future__ import annotations

import pytest

from ranbval_sdk._internal.defaults import DEFAULT_RANBVAL_HOST
from ranbval_sdk._internal.host import (
    allow_host_override,
    is_host_override_allowed,
    resolve_host,
)
from ranbval_sdk.exceptions import RanbvalConfigError


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    monkeypatch.delenv("RANBVAL_HOST", raising=False)
    allow_host_override(False)
    yield
    allow_host_override(False)


def test_no_configuration_uses_the_official_host():
    assert resolve_host() == DEFAULT_RANBVAL_HOST


def test_a_host_passed_in_code_is_honoured():
    # Code is the same trust boundary as the SDK; someone who can edit it has already won.
    assert resolve_host("https://my-plane.example") == "https://my-plane.example"


def test_the_env_var_may_repeat_the_official_host(monkeypatch):
    monkeypatch.setenv("RANBVAL_HOST", DEFAULT_RANBVAL_HOST + "/")
    assert resolve_host() == DEFAULT_RANBVAL_HOST


@pytest.mark.parametrize(
    "hostile",
    [
        "http://127.0.0.1:8799",
        "https://evil.example",
        "https://api.secret.ranbval.com.evil.example",  # suffix trick
    ],
)
def test_the_env_var_cannot_redirect_to_anything_else(monkeypatch, hostile):
    monkeypatch.setenv("RANBVAL_HOST", hostile)
    with pytest.raises(RanbvalConfigError) as exc:
        resolve_host()
    assert exc.value.code == "host_not_allowed"


def test_code_can_opt_in_for_a_self_hosted_plane(monkeypatch):
    monkeypatch.setenv("RANBVAL_HOST", "https://my-plane.example")
    with pytest.raises(RanbvalConfigError):
        resolve_host()

    allow_host_override()
    assert is_host_override_allowed() is True
    assert resolve_host() == "https://my-plane.example"


def test_the_opt_in_is_not_reachable_from_the_environment(monkeypatch):
    # The whole asymmetry: an attacker holding the environment must not be able to grant it.
    for name in ("RANBVAL_ALLOW_HOST_OVERRIDE", "RANBVAL_HOST_OVERRIDE", "RANBVAL_ALLOW_HOST"):
        monkeypatch.setenv(name, "1")
    monkeypatch.setenv("RANBVAL_HOST", "https://evil.example")
    with pytest.raises(RanbvalConfigError):
        resolve_host()
