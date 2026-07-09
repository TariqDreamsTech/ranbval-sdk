"""Reveal scopes — pin a secret's plaintext to exactly the line(s) you approve.

For a value your app genuinely must decrypt locally (a DB password, a signing key) but that
you don't want an engineer to be able to read anywhere else: mark it with
:func:`require_reveal_scope`, then reveal it only inside a :func:`reveal_scope` block. Any
``.use()`` outside such a block raises — so the plaintext is produced at exactly the approved
call site and nowhere else::

    from ranbval_sdk import require_reveal_scope, reveal_scope, decrypt_key

    require_reveal_scope("DATABASE_PASSWORD")            # once, at startup

    with reveal_scope("DATABASE_PASSWORD"):              # the ONLY approved place
        conn = psycopg2.connect(password=decrypt_key("DATABASE_PASSWORD").use())

    decrypt_key("DATABASE_PASSWORD").use()               # anywhere else -> RanbvalConfigError

Why this helps against an untrusted engineer: without it, ``.use()`` works anywhere, so an
engineer can extract the value from any line, invisibly. With it, ``reveal_scope("NAME")`` is
the *only* place a reveal is allowed — an explicit, greppable, reviewable marker you can
enforce in CI ("this token must appear in exactly one file"). Combined with the access monitor
(:mod:`ranbval_sdk.telemetry.monitor`), every reveal is both **restricted** and **logged**.

Honest limit: this gates ``.use()`` — the normal, audited access point. It does not stop a
determined insider who bypasses the class entirely (reads the internal buffer, calls
``str.__str__``); that is unpreventable in-process for any tool. What it does is shrink the
reveal surface from "any line, invisibly" to "one approved, auditable block."
"""

from __future__ import annotations

import contextlib
import threading
from collections.abc import Iterator

from ranbval_sdk.crypto.secret_string import set_reveal_gate
from ranbval_sdk.exceptions import RanbvalConfigError

_lock = threading.Lock()
_required: set[str] = set()  # labels that may only be revealed inside a reveal_scope
_active = threading.local()  # per-thread set of currently-open scope names


def _open_scopes() -> set[str]:
    scopes = getattr(_active, "scopes", None)
    if scopes is None:
        scopes = set()
        _active.scopes = scopes
    return scopes


def _gate(label: str) -> None:
    """Called inside ``SecretString.use()``. Raise if ``label`` is restricted and out of scope."""
    with _lock:
        restricted = label in _required
    if restricted and label not in _open_scopes():
        raise RanbvalConfigError(
            f"{label!r} may only be revealed inside `with reveal_scope({label!r}): ...`. "
            "A .use() here is outside any approved reveal scope.",
            code="reveal_out_of_scope",
        )


def require_reveal_scope(*names: str) -> None:
    """Restrict each named secret so its plaintext is revealed only inside a :func:`reveal_scope`.

    Idempotent; call once at startup. Installs the gate on ``SecretString.use()`` the first
    time it is used.
    """
    with _lock:
        _required.update(names)
    set_reveal_gate(_gate)


def clear_reveal_requirements() -> None:
    """Lift all reveal-scope restrictions (test/reset helper)."""
    with _lock:
        _required.clear()
    set_reveal_gate(None)


@contextlib.contextmanager
def reveal_scope(name: str) -> Iterator[None]:
    """Permit ``decrypt_key(name).use()`` (and ``safe_decrypt`` of the same label) inside this block.

    Re-entrant and thread-local: the permission applies only to the current thread for the
    duration of the block, then is removed — so a reveal cannot leak to other code paths.
    """
    scopes = _open_scopes()
    added = name not in scopes
    if added:
        scopes.add(name)
    try:
        yield
    finally:
        if added:
            scopes.discard(name)
