"""``use.NAME`` — the one-word form: shorter code, same guards."""

from __future__ import annotations

import pickle

import pytest

from ranbval_sdk import SecretString, set_enforcement, set_strict_encode
from ranbval_sdk.config.quick import Use
from ranbval_sdk.exceptions import MissingKeyError, RanbvalConfigError, RanbvalSecurityError


@pytest.fixture
def u(monkeypatch):
    """A Use bound to a pre-populated env, with loading stubbed out."""
    monkeypatch.setenv("SECRET_API_TOKEN", "sk-live-token-value")
    monkeypatch.setenv("PUBLIC_REGION", "eu-west-1")
    monkeypatch.setenv("PLAIN_HOST", "db.internal")
    monkeypatch.setenv("PROXY_STRIPE_KEY", "ranbval.abc.def.ahsan")
    inst = Use()
    object.__setattr__(inst, "_loaded", True)  # skip .ranbval discovery in tests
    return inst


@pytest.fixture(autouse=True)
def _strict():
    set_enforcement(True)
    set_strict_encode(False)
    yield
    set_enforcement(True)
    set_strict_encode(False)


class TestNameResolution:
    def test_short_name_finds_the_secret_prefixed_key(self, u, monkeypatch):
        monkeypatch.setattr(
            "ranbval_sdk.config.access._is_token", lambda v: False
        )  # treat as plain
        assert u.API_TOKEN == "sk-live-token-value"

    def test_short_name_finds_the_public_prefixed_key(self, u):
        assert u.REGION == "eu-west-1"

    def test_exact_name_still_works(self, u):
        assert u.PUBLIC_REGION == "eu-west-1"

    def test_unprefixed_key_is_found_as_written(self, u):
        assert u.PLAIN_HOST == "db.internal"

    def test_item_access_matches_attribute_access(self, u):
        assert u["REGION"] == u.REGION

    def test_missing_key_names_every_spelling_it_tried(self, u):
        with pytest.raises(MissingKeyError) as exc:
            u.NOPE
        for spelling in ("'NOPE'", "'SECRET_NOPE'", "'PUBLIC_NOPE'"):
            assert spelling in str(exc.value)

    def test_proxy_secret_is_refused_not_decrypted(self, u):
        # The whole point of PROXY_ is that the plaintext never reaches this machine.
        with pytest.raises(RanbvalConfigError) as exc:
            u.STRIPE_KEY
        assert exc.value.code == "proxy_secret_not_revealable"

    def test_contains_and_get(self, u):
        assert "REGION" in u
        assert "NOPE" not in u
        assert u.get("NOPE", "fallback") == "fallback"


class TestStillSealed:
    """Shorter code must not mean weaker code."""

    @pytest.fixture
    def secret(self, u, monkeypatch):
        monkeypatch.setattr(
            "ranbval_sdk.crypto.decrypt_key",
            lambda name: SecretString("sk-live-token-value", label=name),
        )
        monkeypatch.setattr("ranbval_sdk.config.access._is_token", lambda v: True)
        return u.API_TOKEN

    def test_is_a_real_str_so_clients_accept_it(self, secret):
        assert isinstance(secret, str)

    def test_repr_is_masked(self, secret):
        assert "sk-live" not in repr(secret)

    @pytest.mark.parametrize(
        "attack",
        [
            pytest.param(lambda s: "".join(c for c in s), id="iteration"),
            pytest.param(lambda s: s[:], id="slice"),
            pytest.param(lambda s: str(s), id="str"),
        ],
    )
    def test_extraction_paths_still_raise(self, secret, attack):
        with pytest.raises(RanbvalSecurityError):
            attack(secret)

    def test_pickling_still_raises(self, secret):
        with pytest.raises(TypeError):
            pickle.dumps(secret)

    def test_values_are_cached_and_wipeable(self, u, secret):
        assert u.API_TOKEN is secret
        u.wipe()
        assert u._cache == {}

    def test_repr_of_use_never_shows_values(self, u):
        u.REGION
        assert "eu-west-1" not in repr(u)


class TestEncodeIsAHandoffNotAnExtraction:
    """httpx encodes every header value; blocking that only forced enforcement off globally."""

    def test_encode_is_allowed_by_default(self):
        s = SecretString("sk-live-abc", label="T")
        assert s.use().encode() == b"sk-live-abc"

    def test_strict_encode_restores_the_old_loud_failure(self):
        set_strict_encode(True)
        s = SecretString("sk-live-abc", label="T")
        with pytest.raises(RanbvalSecurityError):
            s.use().encode()

    def test_the_other_guards_are_untouched_by_the_encode_change(self):
        s = SecretString("sk-live-abc", label="T")
        with pytest.raises(RanbvalSecurityError):
            "".join(c for c in s.use())
