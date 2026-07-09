"""Tests for reveal scopes — pin a secret's reveal to exactly the approved line(s)."""

from __future__ import annotations

import threading

import pytest

from ranbval_sdk import SecretString, require_reveal_scope, reveal_scope
from ranbval_sdk.config.reveal import clear_reveal_requirements
from ranbval_sdk.exceptions import RanbvalConfigError


@pytest.fixture
def restricted():
    require_reveal_scope("DATABASE_PASSWORD")
    yield
    clear_reveal_requirements()


def test_reveal_inside_scope(restricted):
    s = SecretString("Ahsan07248988@", label="DATABASE_PASSWORD")
    with reveal_scope("DATABASE_PASSWORD"):
        assert s.use() == "Ahsan07248988@"


def test_reveal_outside_scope_blocked(restricted):
    s = SecretString("Ahsan07248988@", label="DATABASE_PASSWORD")
    with pytest.raises(RanbvalConfigError) as ei:
        s.use()
    assert ei.value.code == "reveal_out_of_scope"


def test_blocked_again_after_scope_closes(restricted):
    s = SecretString("x", label="DATABASE_PASSWORD")
    with reveal_scope("DATABASE_PASSWORD"):
        s.use()
    with pytest.raises(RanbvalConfigError):
        s.use()


def test_unrestricted_secret_works_everywhere(restricted):
    # A different secret that was never restricted must still reveal anywhere.
    other = SecretString("sk-open", label="OPENAI_API_KEY")
    assert other.use() == "sk-open"


def test_scope_is_thread_local(restricted):
    s = SecretString("x", label="DATABASE_PASSWORD")
    leaked: list = []

    def worker():
        # No scope open on THIS thread → must be blocked even if the main thread is in one.
        try:
            s.use()
            leaked.append("revealed")
        except RanbvalConfigError:
            leaked.append("blocked")

    with reveal_scope("DATABASE_PASSWORD"):
        t = threading.Thread(target=worker)
        t.start()
        t.join()
    assert leaked == ["blocked"]


def test_no_restriction_means_use_works(restricted):
    # DATABASE_PASSWORD is restricted, but a key we never named is unaffected.
    assert SecretString("v", label="SOMETHING_ELSE").use() == "v"
