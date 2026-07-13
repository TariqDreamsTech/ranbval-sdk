"""Tests for PUBLIC_/SECRET_/PROXY_ name-prefix classification and the public() accessor."""

from __future__ import annotations

import os
import warnings

import pytest

from ranbval_sdk import is_public, load_ranbval, public, public_config
from ranbval_sdk.config import manifest
from ranbval_sdk.exceptions import MissingKeyError, RanbvalConfigError


@pytest.fixture(autouse=True)
def _isolate_ranbval_env(monkeypatch):
    # Classification now derives from os.environ names, so clear any prefixed keys other
    # tests left behind before each test here (monkeypatch restores them afterwards).
    for name in list(os.environ):
        if name.startswith(("PUBLIC_", "SECRET_", "PROXY_")) or name.endswith("_PROJECT_SECRET"):
            monkeypatch.delenv(name, raising=False)
    yield

_PREFIXED = """\
RANBVAL_PROJECT_SECRET=proj-xxx

PUBLIC_DATABASE_URL=postgresql://localhost/mydb
PUBLIC_CORS_ORIGINS=https://a.com,https://b.com
PUBLIC_PORT=8000

SECRET_OPENAI_API_KEY=ranbval.4ii0a0.BLOB.stripe
"""


@pytest.fixture
def prefixed_env(tmp_path, monkeypatch):
    (tmp_path / ".ranbval").write_text(_PREFIXED, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    for key in ("PUBLIC_DATABASE_URL", "PUBLIC_CORS_ORIGINS", "PUBLIC_PORT", "SECRET_OPENAI_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    assert load_ranbval() is True


def test_public_returns_plaintext(prefixed_env):
    assert public("PUBLIC_DATABASE_URL") == "postgresql://localhost/mydb"
    assert public("PUBLIC_PORT") == "8000"
    assert public("PUBLIC_CORS_ORIGINS") == "https://a.com,https://b.com"


def test_public_config_only_public_keys(prefixed_env):
    cfg = public_config()
    assert set(cfg) == {"PUBLIC_DATABASE_URL", "PUBLIC_CORS_ORIGINS", "PUBLIC_PORT"}
    assert "SECRET_OPENAI_API_KEY" not in cfg


def test_is_public_flags(prefixed_env):
    assert is_public("PUBLIC_DATABASE_URL") is True
    assert is_public("SECRET_OPENAI_API_KEY") is False


def test_public_refuses_secret(prefixed_env):
    with pytest.raises(RanbvalConfigError) as ei:
        public("SECRET_OPENAI_API_KEY")
    assert ei.value.code == "not_a_public_key"


def test_public_default_for_missing(prefixed_env):
    assert public("PUBLIC_NOT_SET", "fallback") == "fallback"
    with pytest.raises(MissingKeyError):
        public("PUBLIC_NOT_SET")


def test_unclassified_key_rejected(tmp_path, monkeypatch):
    # Every variable must carry a class prefix — an unprefixed key fails to load.
    (tmp_path / ".ranbval").write_text("FOO=bar\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(RanbvalConfigError) as ei:
        load_ranbval()
    assert ei.value.code == "unclassified_key"


def test_section_header_rejected(tmp_path, monkeypatch):
    # [section] headers are no longer supported.
    (tmp_path / ".ranbval").write_text("[public]\nPUBLIC_X=1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(RanbvalConfigError) as ei:
        load_ranbval()
    assert ei.value.code == "section_not_supported"


def test_infra_keys_exempt(tmp_path, monkeypatch):
    # RANBVAL_* and *_PROJECT_SECRET need no class prefix.
    (tmp_path / ".ranbval").write_text(
        "RANBVAL_PROJECT_SECRET=proj-xxx\nMYAPP_PROJECT_SECRET=proj-yyy\n"
        "RANBVAL_HOST=https://api.secret.ranbval.com\nPUBLIC_X=1\n",
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    assert load_ranbval() is True  # must not raise


def test_warns_on_token_under_public(tmp_path, monkeypatch):
    f = tmp_path / ".ranbval"
    f.write_text("PUBLIC_BADKEY=ranbval.aa.bb.stripe\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        load_ranbval(str(f))
    assert any("PUBLIC_BADKEY" in str(w.message) for w in caught)


def test_warns_on_plaintext_under_secret(tmp_path, monkeypatch):
    f = tmp_path / ".ranbval"
    f.write_text("SECRET_PLAINSECRET=just-text\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        load_ranbval(str(f))
    assert any("SECRET_PLAINSECRET" in str(w.message) for w in caught)


def test_vault_public_method(prefixed_env):
    from ranbval_sdk import Vault

    v = Vault()
    assert v.public("PUBLIC_DATABASE_URL") == "postgresql://localhost/mydb"
    assert v.public_config() == {
        "PUBLIC_DATABASE_URL": "postgresql://localhost/mydb",
        "PUBLIC_CORS_ORIGINS": "https://a.com,https://b.com",
        "PUBLIC_PORT": "8000",
    }
    assert v.public("PUBLIC_MISSING", "fb") == "fb"


def test_vault_public_refuses_secret(prefixed_env):
    from ranbval_sdk import Vault

    with pytest.raises(RanbvalConfigError) as ei:
        Vault().public("SECRET_OPENAI_API_KEY")
    assert ei.value.code == "not_a_public_key"


_PROXY = """\
RANBVAL_PROJECT_SECRET=proj-xxx

PUBLIC_DATABASE_URL=postgresql://localhost/mydb
SECRET_DASHBOARD_PASSWORD=ranbval.aa.bb.ahsan
PROXY_OPENAI_KEY=ranbval.cc.dd.openai
"""


@pytest.fixture
def proxy_env(tmp_path, monkeypatch):
    (tmp_path / ".ranbval").write_text(_PROXY, encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    for key in ("PUBLIC_DATABASE_URL", "SECRET_DASHBOARD_PASSWORD", "PROXY_OPENAI_KEY"):
        monkeypatch.delenv(key, raising=False)
    assert load_ranbval() is True


def test_proxy_decrypt_key_refused(proxy_env):
    import ranbval_sdk as r

    with pytest.raises(RanbvalConfigError) as ei:
        r.decrypt_key("PROXY_OPENAI_KEY")
    assert ei.value.code == "proxy_only"


def test_public_decrypt_key_refused(proxy_env):
    import ranbval_sdk as r

    with pytest.raises(RanbvalConfigError) as ei:
        r.decrypt_key("PUBLIC_DATABASE_URL")
    assert ei.value.code == "not_a_secret"


def test_proxy_public_refused(proxy_env):
    with pytest.raises(RanbvalConfigError):
        public("PROXY_OPENAI_KEY")


def test_proxy_token_returns_ciphertext(proxy_env):
    import ranbval_sdk as r

    tok = r.proxy_token("PROXY_OPENAI_KEY")
    assert tok == "ranbval.cc.dd.openai"
    assert tok.startswith("ranbval.")


def test_proxy_token_refuses_public(proxy_env):
    import ranbval_sdk as r

    with pytest.raises(RanbvalConfigError) as ei:
        r.proxy_token("PUBLIC_DATABASE_URL")
    assert ei.value.code == "not_a_proxy_token"


def test_proxy_token_refuses_secret(proxy_env):
    # A SECRET_ key (meant for local decrypt) must NOT be proxied.
    import ranbval_sdk as r

    with pytest.raises(RanbvalConfigError) as ei:
        r.proxy_token("SECRET_DASHBOARD_PASSWORD")
    assert ei.value.code == "not_a_proxy_token"


def test_is_proxy_flags(proxy_env):
    assert manifest.is_proxy("PROXY_OPENAI_KEY")
    assert not manifest.is_proxy("SECRET_DASHBOARD_PASSWORD")
    assert manifest.is_secret("SECRET_DASHBOARD_PASSWORD")


def test_warns_on_plaintext_under_proxy(tmp_path, monkeypatch):
    f = tmp_path / ".ranbval"
    f.write_text("PROXY_BADKEY=just-plaintext\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        load_ranbval(str(f))
    assert any("PROXY_BADKEY" in str(w.message) for w in caught)
