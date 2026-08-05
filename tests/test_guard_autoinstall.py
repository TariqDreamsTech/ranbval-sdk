"""The guard arrives with the first secret, not only via load_ranbval().

Installing it in load_ranbval() alone left a real gap: `safe_decrypt(token, secret)` called
directly — a script, a notebook cell, a REPL — produced a fully unguarded value, and a
`print(f"{v}")` emitted the plaintext. A guard that only protects the recommended entry point
protects the people who were already being careful.
"""

from __future__ import annotations

import pytest

from ranbval_sdk import SecretString
from ranbval_sdk.crypto import output_guards as og

SECRET = "sk-live-a-long-enough-secret-value"


@pytest.fixture(autouse=True)
def _clean():
    og.uninstall_output_guards()
    og.set_opted_out(False)
    yield
    og.uninstall_output_guards()
    og.set_opted_out(False)


def test_the_first_reveal_installs_the_guard():
    assert og._GUARD_INSTALLED is False
    SecretString(SECRET, label="T").use()
    assert og._GUARD_INSTALLED is True


def test_a_value_revealed_without_load_ranbval_is_still_guarded():
    revealed = SecretString(SECRET, label="T").use()
    with pytest.raises(PermissionError):
        print(f"{revealed}")


def test_the_value_that_triggered_the_install_is_itself_registered():
    # The install must happen before the plaintext exists, or the very first secret — the one
    # most likely to be printed while debugging — would be the one the guard cannot recognise.
    SecretString(SECRET, label="T").use()
    assert SECRET in og._revealed


def test_an_explicit_opt_out_is_not_undone_by_the_next_decrypt():
    og.set_opted_out(True)
    SecretString(SECRET, label="T").use()
    assert og._GUARD_INSTALLED is False


def test_uninstalling_counts_as_opting_out():
    SecretString(SECRET, label="T").use()
    assert og._GUARD_INSTALLED is True

    og.uninstall_output_guards()
    SecretString(SECRET, label="T").use()  # must not silently reinstall
    assert og._GUARD_INSTALLED is False
