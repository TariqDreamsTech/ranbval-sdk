"""Tests for the hardening/privacy/maintainability pass.

Covers the token parser, structured exceptions, the crypto round-trip and its error
codes, telemetry privacy switches, and the now-opt-in stdout guards.
"""

from __future__ import annotations

import base64
import os

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import ranbval_sdk.crypto.cipher as cip
from ranbval_sdk.crypto.cipher import (
    _parse_token,
    _strip_expiry_and_check_ttl,
    derive_key,
    safe_decrypt,
)
from ranbval_sdk.exceptions import (
    MissingKeyError,
    RanbvalConfigError,
    RanbvalDecryptError,
    RanbvalError,
)


# --------------------------------------------------------------------------- #
# structured exceptions
# --------------------------------------------------------------------------- #
def test_error_carries_code_and_context():
    err = RanbvalDecryptError("boom", code="decrypt_failed", env_var="X")
    assert err.code == "decrypt_failed"
    assert err.context == {"env_var": "X"}
    assert isinstance(err, RanbvalError)
    assert isinstance(err, ValueError)  # drop-in compatibility preserved


def test_error_default_code():
    assert RanbvalConfigError("x").code == "config_error"


def test_missing_key_error_str_has_no_quotes():
    # KeyError.__str__ normally wraps its arg in repr() (adds quotes); we override it.
    err = MissingKeyError("OPENAI_KEY is not set")
    assert str(err) == "OPENAI_KEY is not set"
    assert isinstance(err, KeyError)


# --------------------------------------------------------------------------- #
# token parser
# --------------------------------------------------------------------------- #
def test_parse_token_four_part_any_label():
    parsed = _parse_token("ranbval.SALT123456.BLOB.stripe")
    assert (parsed.salt, parsed.blob) == ("SALT123456", "BLOB")


def test_parse_token_legacy_five_part():
    parsed = _parse_token("ranbval.noise.SALT.BLOB.ahsan")
    assert (parsed.salt, parsed.blob) == ("SALT", "BLOB")


@pytest.mark.parametrize("bad", ["nope.a.b.c", "ranbval.only.three", "ranbval"])
def test_parse_token_rejects_bad_shapes(bad):
    with pytest.raises(RanbvalDecryptError) as ei:
        _parse_token(bad)
    assert ei.value.code == "invalid_token_format"


def test_strip_expiry_passthrough_without_line():
    assert _strip_expiry_and_check_ttl("plain-secret") == "plain-secret"


def test_strip_expiry_malformed_line_is_ignored():
    # Malformed expiry → treated as "no TTL", body returned, no raise.
    assert _strip_expiry_and_check_ttl("s\nranbval-expiry:notanint") == "s"


# --------------------------------------------------------------------------- #
# crypto round-trip (policy gate stubbed — it is exercised separately)
# --------------------------------------------------------------------------- #
@pytest.fixture
def no_network_gate(monkeypatch):
    monkeypatch.setattr(cip, "_enforce_repo_allowlist_if_configured", lambda salt: None)


def _make_token(secret: str, salt: str, plaintext: str) -> str:
    iv = os.urandom(12)
    ct = AESGCM(derive_key(secret, salt)).encrypt(iv, plaintext.encode(), None)
    blob = base64.urlsafe_b64encode(iv + ct).decode().rstrip("=")
    return f"ranbval.{salt}.{blob}.stripe"


def test_round_trip_decrypt(no_network_gate):
    token = _make_token("proj-secret", "ABCDEFGHIJ", "sk-live-REAL")
    assert safe_decrypt(token, "proj-secret").use() == "sk-live-REAL"


def test_wrong_secret_raises_decrypt_failed(no_network_gate):
    token = _make_token("proj-secret", "ABCDEFGHIJ", "sk-live-REAL")
    with pytest.raises(RanbvalDecryptError) as ei:
        safe_decrypt(token, "wrong-secret")
    assert ei.value.code == "decrypt_failed"


def test_expired_token_raises(no_network_gate):
    secret, salt = "proj-secret", "ABCDEFGHIJ"
    iv = os.urandom(12)
    body = "sk-live-REAL\nranbval-expiry:1"  # far in the past
    ct = AESGCM(derive_key(secret, salt)).encrypt(iv, body.encode(), None)
    blob = base64.urlsafe_b64encode(iv + ct).decode().rstrip("=")
    with pytest.raises(RanbvalDecryptError) as ei:
        safe_decrypt(f"ranbval.{salt}.{blob}.ahsan", secret)
    assert ei.value.code == "token_expired"


# --------------------------------------------------------------------------- #
# secret cannot leak via serialization / duplication
# --------------------------------------------------------------------------- #
def test_secretstring_blocks_pickle_and_copy():
    import copy
    import pickle

    from ranbval_sdk import SecretString

    s = SecretString("sk-super-secret", label="openai")
    for call in (lambda: pickle.dumps(s), lambda: copy.copy(s), lambda: copy.deepcopy(s)):
        with pytest.raises(TypeError):
            call()


def test_protectedstr_blocks_pickle_but_allows_sdk_use():
    import copy
    import pickle

    from ranbval_sdk import SecretString

    x = SecretString("sk-super-secret").use()
    # SDK header construction must keep working
    assert f"Bearer {x}" == "Bearer sk-super-secret"
    # display paths masked
    assert str(x) == "[ranbval:secret]"
    # copy allowed (immutable str), pickle refused (would carry plaintext)
    assert copy.copy(x) is not None
    with pytest.raises(TypeError):
        pickle.dumps(x)


def test_secretstring_masks_percent_and_format():
    from ranbval_sdk import SecretString

    s = SecretString("sk-super-secret")
    assert "%s" % s == "[ranbval:secret]"  # noqa: UP031 — deliberately testing %-format masking
    assert f"{s}" == "[ranbval:secret]"
    assert "sk-super" not in repr(s)


# --------------------------------------------------------------------------- #
# telemetry privacy switches
# --------------------------------------------------------------------------- #
def test_telemetry_disabled_flag(monkeypatch):
    from ranbval_sdk.telemetry.settings import telemetry_disabled

    monkeypatch.delenv("RANBVAL_TELEMETRY_DISABLED", raising=False)
    assert telemetry_disabled() is False
    monkeypatch.setenv("RANBVAL_TELEMETRY_DISABLED", "1")
    assert telemetry_disabled() is True


def test_identity_opt_in_default_off(monkeypatch):
    from ranbval_sdk.telemetry.context import _get_git_email
    from ranbval_sdk.telemetry.settings import identity_opt_in

    monkeypatch.delenv("RANBVAL_TELEMETRY_IDENTITY", raising=False)
    assert identity_opt_in() is False
    assert _get_git_email() is None  # PII not collected without explicit opt-in


def test_disabled_telemetry_makes_emit_a_noop(monkeypatch):
    """With telemetry disabled, emit_telemetry must not attempt any network transport."""
    monkeypatch.setenv("RANBVAL_TELEMETRY_DISABLED", "1")
    from ranbval_sdk.telemetry import client

    def _boom(*a, **k):  # pragma: no cover - must never be called
        raise AssertionError("transport should not be called when telemetry is disabled")

    monkeypatch.setattr(client._transport, "urlopen", _boom)
    client.emit_telemetry(client_salt="anything", background=False)  # no raise = pass


# --------------------------------------------------------------------------- #
# stdout guards are opt-in
# --------------------------------------------------------------------------- #
def test_load_ranbval_does_not_patch_print_by_default(tmp_path, monkeypatch):
    import builtins

    from ranbval_sdk import load_ranbval

    (tmp_path / ".ranbval").write_text("APP_NAME=demo\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    before = builtins.print
    load_ranbval()
    assert builtins.print is before  # no global monkeypatch as a side effect
