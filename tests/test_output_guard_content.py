"""The stdout guard must catch a secret however it was formatted, not only when still typed.

`__format__` and `str.__add__` cannot be blocked at the source — a client library has to build
`Authorization: Bearer <key>` out of the value, and `str` is immutable so its base methods cannot
be intercepted. Guarding the type therefore catches only `print(key.use())`. This guards the
destination instead.
"""

from __future__ import annotations

import builtins
import sys

import pytest

from ranbval_sdk import SecretString
from ranbval_sdk.crypto import install_output_guards, uninstall_output_guards

SECRET = "sk-live-a-long-enough-secret-value"


@pytest.fixture
def guarded():
    """Guard installed, then a secret revealed (order matters — only then is it registered)."""
    install_output_guards()
    revealed = SecretString(SECRET, label="T").use()
    yield revealed
    uninstall_output_guards()


@pytest.mark.parametrize(
    "build",
    [
        pytest.param(lambda v: v, id="the-value-itself"),
        pytest.param(lambda v: f"{v}", id="f-string"),
        pytest.param(lambda v: "Bearer " + v, id="concatenation"),
        pytest.param(lambda v: "%s" % v, id="percent-format"),
        pytest.param(lambda v: "{}".format(v), id="str-format"),  # noqa: UP032
        pytest.param(lambda v: str({"key": f"{v}"}), id="nested-in-a-dict"),
        pytest.param(lambda v: f"prefix {v} suffix", id="embedded-in-a-sentence"),
    ],
)
def test_every_formatting_path_is_blocked(guarded, build):
    with pytest.raises(PermissionError):
        print(build(guarded))


def test_stdout_write_is_guarded_too(guarded):
    with pytest.raises(PermissionError):
        sys.stdout.write(f"{guarded}")


def test_ordinary_output_still_works(guarded, capsys):
    print("nothing secret here")
    assert "nothing secret here" in capsys.readouterr().out


def test_a_short_value_is_not_tracked(guarded):
    # Below the length floor a "secret" collides with ordinary output more often than not.
    short = SecretString("abc", label="T").use()
    print(f"value is {short}")  # must not raise


class TestLifecycle:
    def test_uninstall_restores_print_and_drops_the_plaintext(self):
        original = builtins.print
        install_output_guards()
        SecretString(SECRET, label="T").use()
        assert builtins.print is not original

        uninstall_output_guards()
        assert builtins.print is original

        from ranbval_sdk.crypto import output_guards

        assert output_guards._revealed == set()  # nothing retained once switched off

    def test_nothing_is_retained_while_the_guard_is_off(self):
        from ranbval_sdk.crypto import output_guards

        uninstall_output_guards()
        SecretString(SECRET, label="T").use()
        assert output_guards._revealed == set()

    def test_installing_twice_is_safe(self):
        install_output_guards()
        first = builtins.print
        install_output_guards()
        assert builtins.print is first
        uninstall_output_guards()
