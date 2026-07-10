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
    # display paths raise under enforcement (strict default)
    from ranbval_sdk import RanbvalSecurityError

    with pytest.raises(RanbvalSecurityError):
        str(x)
    # copy allowed (immutable str), pickle refused (would carry plaintext)
    assert copy.copy(x) is not None
    with pytest.raises(TypeError):
        pickle.dumps(x)


def test_secretstring_masks_percent_and_format():
    from ranbval_sdk import RanbvalSecurityError, SecretString, set_enforcement

    s = SecretString("sk-super-secret")
    # Under enforcement, str-based display (str()/'%s') raises; f-string/format stays masked.
    with pytest.raises(RanbvalSecurityError):
        _ = "%s" % s  # noqa: UP031 — deliberately testing %-format under enforcement
    assert f"{s}" == "[ranbval:secret]"
    assert "sk-super" not in repr(s)
    # With enforcement off, %-format masks as before.
    set_enforcement(False)
    try:
        assert "%s" % s == "[ranbval:secret]"  # noqa: UP031
    finally:
        set_enforcement(True)


def test_secretstring_buffer_is_obfuscated():
    # Reading the internal buffer directly must NOT yield the plaintext (it is XOR-masked).
    from ranbval_sdk import SecretString

    s = SecretString("Ahsan07248988@", label="DB")
    raw = bytes(object.__getattribute__(s, "_b"))
    assert raw != b"Ahsan07248988@"
    assert b"Ahsan" not in raw
    assert s.use() == "Ahsan07248988@"  # but .use() still reconstructs the real value
    assert len(s) == len("Ahsan07248988@")


def test_secretstring_eq_hash_across_pads():
    # Two equal secrets have different per-instance pads but must still compare/hash equal.
    from ranbval_sdk import SecretString

    a, b, c = SecretString("same"), SecretString("same"), SecretString("different")
    assert a == b and a != c
    assert hash(a) == hash(b)
    assert bytes(object.__getattribute__(a, "_b")) != bytes(object.__getattribute__(b, "_b"))


# --------------------------------------------------------------------------- #
# telemetry: always-on; only the developer-identity opt-in is configurable
# --------------------------------------------------------------------------- #
def test_identity_opt_in_default_off(monkeypatch):
    from ranbval_sdk.telemetry.context import _get_git_email
    from ranbval_sdk.telemetry.settings import identity_opt_in

    monkeypatch.delenv("RANBVAL_TELEMETRY_IDENTITY", raising=False)
    assert identity_opt_in() is False
    assert _get_git_email() is None  # PII not collected without explicit opt-in


def test_telemetry_has_no_disable_switch():
    # Usage reporting is the leak-detection control plane — there is no client off switch.
    import ranbval_sdk.telemetry.settings as settings

    assert not hasattr(settings, "telemetry_disabled")


# --------------------------------------------------------------------------- #
# universal decrypt flow: decrypt_key() resolves the project secret from the
# in-memory store after load_ranbval() moved it out of os.environ
# --------------------------------------------------------------------------- #
def test_decrypt_key_after_load_ranbval(tmp_path, monkeypatch):
    """The project secret is moved out of os.environ into the in-memory store by
    load_ranbval(); decrypt_key() must still resolve it. This is the one universal path
    a developer uses with ANY provider: decrypt_key('X').use()."""
    import base64

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    import ranbval_sdk as r
    import ranbval_sdk.crypto.cipher as cipher
    from ranbval_sdk.crypto.cipher import derive_key

    monkeypatch.setattr(cipher, "_enforce_repo_allowlist_if_configured", lambda salt: None)
    monkeypatch.setattr(cipher, "_auto_report_usage", lambda *a, **k: None)  # no telemetry in test

    secret, salt, real_key = "proj-secret-xyz", "ABCDEFGHIJ", "sk-proj-REAL"
    iv = os.urandom(12)
    ct = AESGCM(derive_key(secret, salt)).encrypt(iv, real_key.encode(), None)
    blob = base64.urlsafe_b64encode(iv + ct).decode().rstrip("=")
    token = f"ranbval.{salt}.{blob}.openai"

    (tmp_path / ".ranbval").write_text(
        f"RANBVAL_PROJECT_SECRET={secret}\nSECRET_OPENAI_API_KEY={token}\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("SECRET_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("RANBVAL_PROJECT_SECRET", raising=False)
    r.load_ranbval()

    assert r.decrypt_key("SECRET_OPENAI_API_KEY").use() == real_key


# --------------------------------------------------------------------------- #
# stdout guards are opt-in
# --------------------------------------------------------------------------- #
def test_load_ranbval_does_not_patch_print_by_default(tmp_path, monkeypatch):
    import builtins

    from ranbval_sdk import load_ranbval

    (tmp_path / ".ranbval").write_text("PUBLIC_APP_NAME=demo\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    before = builtins.print
    load_ranbval()
    assert builtins.print is before  # no global monkeypatch as a side effect
