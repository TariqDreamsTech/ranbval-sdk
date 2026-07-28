"""Opt-in global output guards: stop a secret from reaching stdout, however it got there.

``SecretString``/``_ProtectedStr`` block the *typed* paths — ``print(key.use())`` raises, ``repr``
is masked. But the moment a secret is formatted, the result is an ordinary ``str`` that carries no
marker at all::

    print(key.use())        # blocked — the argument is still a _ProtectedStr
    print(f"{key.use()}")   # a plain str containing the plaintext
    print("Bearer " + key.use())

``__format__`` and ``str.__add__`` cannot be blocked at the source: a client library has to be able
to build ``Authorization: Bearer <key>`` out of the value, and ``str`` is immutable so its base
methods cannot be intercepted. Guarding the *type* therefore catches only the first spelling.

This module guards the **destination** instead. Every value a ``.use()`` reveals is registered, and
anything written to stdout is checked for those values — so all three lines above raise, along with
``"%s" % key``, a f-string inside an f-string, and a dict printed with the secret nested in it.

Off by default, and deliberately so:

- Patching ``builtins.print`` / ``sys.stdout.write`` is invasive — it can surprise other libraries,
  test capture, and REPLs.
- The registry holds the revealed plaintext for the life of the process. ``str`` subclasses cannot
  be weak-referenced, so there is no way to track a value without keeping it. That is an acceptable
  trade when you have opted into leak-proofing stdout, and a bad one to impose by default.

Enable with ``load_ranbval(guard_stdout=True)`` or :func:`install_output_guards`.

Honest limits: this covers stdout, not stderr, not a file the app writes itself, not a network
call. It is a guard against the accident — a debug ``print`` left in, a secret in a logged dict —
not against code that is deliberately exfiltrating. Only a ``PROXY_`` secret keeps the value off
the machine entirely.
"""

from __future__ import annotations

import builtins
import sys

from ranbval_sdk.crypto.secret_string import _ProtectedStr, set_reveal_sink

_GUARD_INSTALLED = False
_orig_print = builtins.print
_orig_stdout_write: object = None

#: Plaintext values revealed by ``.use()`` while the guard is installed. Populated only then —
#: with the guard off, nothing is retained and this module costs nothing.
_revealed: set[str] = set()

#: Below this length a "secret" is more likely to collide with ordinary output than to be one.
#: An 8-character floor keeps ``print("abc")`` from tripping on a 3-character test fixture.
_MIN_TRACKED_LEN = 8

_ERR = (
    "Ranbval: cannot output a protected secret. "
    "Pass it directly to the SDK — e.g. OpenAI(api_key=key.use())"
)
_LEAK_ERR = (
    "Ranbval: this output contains a decrypted secret. It reached stdout as an ordinary string "
    "(an f-string, concatenation, or '%s'), which the value itself cannot block — a client "
    "library has to be able to build a header out of it. Remove the print, or log a masked "
    "value. To turn this guard off, don't pass guard_stdout=True."
)


def _register_revealed(value: str) -> None:
    """Remember a revealed plaintext so stdout can be checked against it. No-op when off."""
    if _GUARD_INSTALLED and len(value) >= _MIN_TRACKED_LEN:
        _revealed.add(value)


def _contains_secret(text: str) -> bool:
    """True when ``text`` carries any revealed secret — the check the type test cannot do."""
    return any(secret in text for secret in _revealed)


def _check(arg: object) -> None:
    # A still-typed secret: blocked on identity, without stringifying it (which would raise).
    if isinstance(arg, _ProtectedStr):
        raise PermissionError(_ERR)
    # A plain str that happens to carry one: the f-string / concatenation case.
    if type(arg) is str and _contains_secret(arg):
        raise PermissionError(_LEAK_ERR)


def _guarded_print(*args: object, **kwargs: object) -> None:
    for arg in args:
        _check(arg)
    _orig_print(*args, **kwargs)


def _make_guarded_write(original_write):
    def _guarded_write(s: str) -> int:
        _check(s)
        return original_write(s)

    return _guarded_write


def install_output_guards() -> None:
    """Patch ``builtins.print`` / ``sys.stdout.write`` so a secret cannot reach stdout.

    Raises ``PermissionError`` both for a revealed secret passed directly and for an ordinary
    string that contains one. Opt-in; safe to call twice.
    """
    global _GUARD_INSTALLED, _orig_stdout_write
    if _GUARD_INSTALLED:
        return
    builtins.print = _guarded_print
    _orig_stdout_write = sys.stdout.write
    sys.stdout.write = _make_guarded_write(sys.stdout.write)
    _GUARD_INSTALLED = True
    # Only now start retaining plaintext — see the module docstring on why this is opt-in.
    set_reveal_sink(_register_revealed)


def uninstall_output_guards() -> None:
    """Restore the original ``print``/``stdout.write`` and drop every retained plaintext."""
    global _GUARD_INSTALLED, _orig_stdout_write
    if not _GUARD_INSTALLED:
        return
    builtins.print = _orig_print
    if _orig_stdout_write is not None:
        sys.stdout.write = _orig_stdout_write  # type: ignore[method-assign]
        _orig_stdout_write = None
    set_reveal_sink(None)
    _revealed.clear()
    _GUARD_INSTALLED = False
