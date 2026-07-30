"""Global output guards: stop a secret from reaching a terminal or log, however it got there.

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
anything written to **stdout or stderr** is checked for those values — so all three lines above
raise, along with ``"%s" % key``, ``"{}".format(key)``, a dict printed with the secret nested in
it, and a ``logging`` call that formatted one into its message.

Truncation is handled at the source rather than here: ``f"{key:.8}"`` produces a *prefix*, which is
not the value and so cannot be recognised by any content check. A precision spec on a secret raises
(see ``_ProtectedStr.__format__``) — no client library truncates a credential to build a request.

**On by default** — ``load_ranbval()`` installs it during load, which is also the only point at
which it is guaranteed to be in place before the first decrypt. A stray ``print(f"{key}")`` leaking
a live credential is a routine accident, and nothing in the value itself can stop it.

Two costs come with that, and neither is hidden:

- Patching ``builtins.print`` and the stream writes is invasive — it can surprise other libraries,
  test capture, and REPLs. The patch records which stream objects it mutated and refuses to restore
  onto different ones, so a framework that swaps a stream is left intact.
- While installed, the registry holds each revealed plaintext for the life of the process. ``str``
  subclasses cannot be weak-referenced, so a value cannot be tracked without being kept. Nothing is
  retained while the guard is off.

Opt out with ``load_ranbval(guard_stdout=False)``, or :func:`uninstall_output_guards` at runtime.
The opt-out is deliberately not an environment variable: an attacker able to set the environment
should not be able to switch a security control off for free.

Honest limits:

- Covers ``sys.stdout`` and ``sys.stderr`` **as they were when the guard was installed**. A stream
  replaced afterwards — a redirect, a capture fixture, a custom handler opened on a new file
  object — is a different object and is not patched.
- Not a file the app writes itself, not an outbound request, not a subprocess's output.
- ``logging`` is covered only because its default handler writes to ``sys.stderr``. The write
  raises, but ``logging`` swallows handler exceptions, so you get ``--- Logging error ---``
  rather than a propagated failure. The credential still does not reach the stream.

It is a guard against the accident — a debug ``print`` left in, a secret in a logged dict — not
against code that is deliberately exfiltrating. Only a ``PROXY_`` secret keeps the value off the
machine entirely.
"""

from __future__ import annotations

import builtins
import sys
import warnings
from typing import Any

from ranbval_sdk.crypto.secret_string import _ProtectedStr, set_reveal_sink

_GUARD_INSTALLED = False
_orig_print = builtins.print

#: ``{stream_name: (the object we patched, its original write)}``. Both streams are guarded:
#: stdout is where a stray ``print`` goes, stderr is where ``logging`` goes by default — and a
#: credential in a log line is the leak that outlives the terminal.
_patched_streams: dict[str, tuple[Any, Any]] = {}

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
    "Ranbval: this output contains a decrypted secret. It reached the stream as an ordinary string "
    "(an f-string, concatenation, or '%s'), which the value itself cannot block — a client "
    "library has to be able to build a header out of it. Remove the print, or log a masked "
    "value, or pass load_ranbval(guard_stdout=False) if this guard is not for you."
)


def _register_revealed(value: str) -> None:
    """Remember a revealed plaintext so output can be checked against it. No-op when off."""
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


def _guarded_print(*args: Any, **kwargs: Any) -> None:
    for arg in args:
        _check(arg)
    _orig_print(*args, **kwargs)


def _make_guarded_write(original_write):
    def _guarded_write(s: str) -> int:
        _check(s)
        return original_write(s)

    return _guarded_write


def install_output_guards() -> None:
    """Patch ``builtins.print`` and the ``sys.stdout``/``sys.stderr`` writes so a secret
    cannot reach a terminal or a log.

    Raises ``PermissionError`` both for a revealed secret passed directly and for an ordinary
    string that contains one. Safe to call twice. ``load_ranbval()`` calls this for you unless you
    pass ``guard_stdout=False``.

    **Install this before your first ``.use()``.** Only values revealed while the guard is on are
    registered, so a secret decrypted earlier is invisible to the content check — its formatted
    form is an ordinary string this module has never seen. Installing late therefore gives partial
    coverage that looks like full coverage, which is worse than none; a warning is emitted if any
    reveal already happened. ``RANBVAL_GUARD_STDOUT=1`` or ``load_ranbval(guard_stdout=True)``
    installs it at load time, ahead of every decrypt.
    """
    global _GUARD_INSTALLED
    if _GUARD_INSTALLED:
        return

    # Values revealed before this point can never be recognised — say so rather than let the
    # caller believe stdout is covered when it is only partly covered.
    from ranbval_sdk.crypto.audit import get_audit_log

    already = len(get_audit_log())
    if already:
        warnings.warn(
            f"Ranbval: the output guard was installed after {already} secret(s) had already been "
            "revealed. Those values cannot be recognised in formatted output — only reveals from "
            "now on are covered. Install the guard before your first .use(), or set "
            "RANBVAL_GUARD_STDOUT=1 so it is in place at load time.",
            stacklevel=2,
        )

    builtins.print = _guarded_print
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name)
        original = stream.write
        _patched_streams[name] = (stream, original)
        stream.write = _make_guarded_write(original)
    _GUARD_INSTALLED = True
    # Only now start retaining plaintext — see the module docstring on why this is opt-in.
    set_reveal_sink(_register_revealed)


def uninstall_output_guards() -> None:
    """Restore the original ``print`` and stream writes, and drop every retained plaintext."""
    global _GUARD_INSTALLED
    if not _GUARD_INSTALLED:
        return
    builtins.print = _orig_print
    # Only un-patch the object we actually patched. pytest, IPython and logging redirects all
    # replace sys.stdout/stderr; our write went with the old object, and assigning the saved one
    # onto a different object would break a stream we never touched.
    for name, (stream, original) in _patched_streams.items():
        if getattr(sys, name, None) is stream:
            stream.write = original
    _patched_streams.clear()
    set_reveal_sink(None)
    _revealed.clear()
    _GUARD_INSTALLED = False
