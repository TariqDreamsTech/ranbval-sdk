"""Tests for [public]/[secret] section declarations and the public() accessor."""

from __future__ import annotations

import warnings

import pytest

from ranbval_sdk import is_public, load_ranbval, public, public_config
from ranbval_sdk.config import manifest
from ranbval_sdk.exceptions import MissingKeyError, RanbvalConfigError

_SECTIONED = """\
RANBVAL_PROJECT_SECRET=proj-xxx

[public]
DATABASE_URL=postgresql://localhost/mydb
CORS_ORIGINS=https://a.com,https://b.com
PORT=8000

[secrets]
OPENAI_API_KEY=ranbval.4ii0a0.BLOB.stripe
"""


@pytest.fixture
def clean_manifest():
    manifest.clear()
    yield
    manifest.clear()


@pytest.fixture
def sectioned_env(tmp_path, monkeypatch, clean_manifest):
    (tmp_path / ".ranbval").write_text(_SECTIONED, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    for key in ("DATABASE_URL", "CORS_ORIGINS", "PORT", "OPENAI_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    assert load_ranbval() is True


def test_public_returns_plaintext(sectioned_env):
    assert public("DATABASE_URL") == "postgresql://localhost/mydb"
    assert public("PORT") == "8000"
    assert public("CORS_ORIGINS") == "https://a.com,https://b.com"


def test_public_config_only_public_keys(sectioned_env):
    cfg = public_config()
    assert set(cfg) == {"DATABASE_URL", "CORS_ORIGINS", "PORT"}
    assert "OPENAI_API_KEY" not in cfg


def test_is_public_flags(sectioned_env):
    assert is_public("DATABASE_URL") is True
    assert is_public("OPENAI_API_KEY") is False


def test_public_refuses_declared_secret(sectioned_env):
    with pytest.raises(RanbvalConfigError) as ei:
        public("OPENAI_API_KEY")
    assert ei.value.code == "not_a_public_key"


def test_public_refuses_token_value(tmp_path, monkeypatch, clean_manifest):
    # A ranbval.* value must never be returned as "plaintext", even if undeclared.
    (tmp_path / ".ranbval").write_text("API_KEY=ranbval.aa.bb.stripe\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("API_KEY", raising=False)
    load_ranbval()
    with pytest.raises(RanbvalConfigError) as ei:
        public("API_KEY")
    assert ei.value.code == "not_a_public_key"


def test_public_default_for_missing(sectioned_env):
    assert public("NOT_SET", "fallback") == "fallback"
    with pytest.raises(MissingKeyError):
        public("NOT_SET")


def test_warns_on_token_under_public(tmp_path, monkeypatch, clean_manifest):
    f = tmp_path / ".ranbval"
    f.write_text("[public]\nBADKEY=ranbval.aa.bb.stripe\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        load_ranbval(str(f))
    assert any("BADKEY" in str(w.message) for w in caught)


def test_warns_on_plaintext_under_secret(tmp_path, monkeypatch, clean_manifest):
    f = tmp_path / ".ranbval"
    f.write_text("[secrets]\nPLAINSECRET=just-text\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        load_ranbval(str(f))
    assert any("PLAINSECRET" in str(w.message) for w in caught)


def test_backward_compat_flat_file(tmp_path, monkeypatch, clean_manifest):
    # No sections at all — keys are unlabelled, everything still loads and reads.
    f = tmp_path / ".ranbval"
    f.write_text("APP_NAME=demo\nDATABASE_URL=postgres://x\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("APP_NAME", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert load_ranbval(str(f)) is True
    assert manifest.kind_of("APP_NAME") is None
    assert is_public("APP_NAME") is False
    assert public("DATABASE_URL") == "postgres://x"  # undeclared plaintext is allowed


def test_vault_public_method(sectioned_env):
    from ranbval_sdk import Vault

    v = Vault()
    assert v.public("DATABASE_URL") == "postgresql://localhost/mydb"
    assert v.public_config() == {
        "DATABASE_URL": "postgresql://localhost/mydb",
        "CORS_ORIGINS": "https://a.com,https://b.com",
        "PORT": "8000",
    }
    assert v.public("MISSING", "fb") == "fb"


def test_vault_public_refuses_secret(sectioned_env):
    from ranbval_sdk import Vault

    with pytest.raises(RanbvalConfigError) as ei:
        Vault().public("OPENAI_API_KEY")
    assert ei.value.code == "not_a_public_key"


def test_unknown_section_header_is_unlabelled(tmp_path, monkeypatch, clean_manifest):
    f = tmp_path / ".ranbval"
    f.write_text("[weird]\nFOO=bar\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FOO", raising=False)
    load_ranbval(str(f))
    assert manifest.kind_of("FOO") is None  # unknown header → no declaration
    assert public("FOO") == "bar"
