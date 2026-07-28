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


class TestTruncationCannotSlipPast:
    """`f"{key:.8}"` yields a *prefix*, which no content check can recognise."""

    @pytest.mark.parametrize("spec", [".8", ".1", ">20.10", "^30.5"])
    def test_a_precision_spec_is_blocked(self, spec):
        from ranbval_sdk.exceptions import RanbvalSecurityError

        secret = SecretString(SECRET, label="T").use()
        with pytest.raises(RanbvalSecurityError):
            format(secret, spec)

    @pytest.mark.parametrize("spec", ["", ">40", "<40", "^40", ".<40", ".>40"])
    def test_padding_and_dot_fill_still_work(self, spec):
        # A '.' may be a fill character (".<40" pads with dots) — that truncates nothing, and
        # blocking it would break legitimate formatting.
        secret = SecretString(SECRET, label="T").use()
        assert SECRET in format(secret, spec)


class TestStderrAndLogging:
    def test_stderr_write_is_guarded(self, guarded):
        with pytest.raises(PermissionError):
            sys.stderr.write(f"{guarded}")

    def test_logging_cannot_put_a_secret_on_stderr(self, capsys):
        import logging

        # Install *after* capsys has swapped sys.stderr, so the guard patches the stream the
        # handler will actually use. This mirrors the real ordering — load_ranbval() runs at
        # startup, before anything redirects a stream — and the limitation it implies is
        # documented: a stream replaced after installation is not covered.
        install_output_guards()
        revealed = SecretString(SECRET, label="T").use()

        logger = logging.getLogger("ranbval-test")
        logger.handlers = [logging.StreamHandler(sys.stderr)]
        logger.setLevel(logging.INFO)
        logger.propagate = False

        # logging swallows handler exceptions, so this does not raise — what matters is that the
        # credential does not reach the stream. It prints "--- Logging error ---" instead.
        logger.info("token=%s", f"{revealed}")
        assert SECRET not in capsys.readouterr().err

    def test_a_stream_replaced_after_install_is_not_covered(self, guarded):
        """The honest limit, asserted so it cannot regress into a false promise silently."""
        import io

        replacement = io.StringIO()
        original, sys.stderr = sys.stderr, replacement
        try:
            sys.stderr.write(f"{guarded}")  # no guard on this object — does not raise
            assert SECRET in replacement.getvalue()
        finally:
            sys.stderr = original
