"""Extraction enforcement + the reveal-signal notifier for revealed secrets.

When enforcement is on (the default), a detected extraction of a revealed value — iteration,
``.encode()``, slicing/indexing, ``str()``/``print()``, or a raw ``_buf``/``_pad`` read — raises
:class:`~ranbval_sdk.exceptions.RanbvalSecurityError` instead of silently handing over the
plaintext. The **notifier** (set by the opt-in access monitor) is fired first so the Live Monitor
records the attempt before the caller crashes.

Honest limit: this stops the *naive* vectors. The base ``str`` methods (``str.__str__(val)``,
``str.__getitem__(val, ...)``) and the real slot ``object.__getattribute__(s, "_b")`` still reach
the plaintext in-process and cannot be blocked. Only ``PROXY_`` secrets are absolute.

When a legitimate client trips a guard (``httpx`` encodes header values, AWS SigV4 signs with the
key), relax the guards around **that line only** with :func:`enforcement_scope` — not process-wide
with :func:`set_enforcement`, which leaves every later line unguarded for the app's whole lifetime.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

# ── Reveal notifier (set by ranbval_sdk.telemetry.monitor) ─────────────────────
_reveal_notifier: object = None


def set_reveal_notifier(fn: object) -> None:
    """Register (or clear with ``None``) a callback ``fn(method)`` for reveal-side signals."""
    global _reveal_notifier
    _reveal_notifier = fn


def notify_reveal(method: str) -> None:
    """Fire the reveal-side signal (if a monitor is installed); never raises into the caller."""
    if _reveal_notifier is not None:
        try:
            _reveal_notifier(method)
        except Exception:
            pass


# ── Enforcement flag (strict by default) ───────────────────────────────────────
_enforced: bool = True


def set_enforcement(enabled: bool) -> None:
    """Turn extraction enforcement on/off process-wide (default: on).

    On  → a detected extraction (iteration / encode / slice / str / raw buffer read) raises
          :class:`RanbvalSecurityError`.
    Off → the extraction is only reported to the access monitor (detect + notify) and the real
          value is returned — legacy behaviour, for when a legitimate library trips it.
    """
    global _enforced
    _enforced = bool(enabled)


def is_enforced() -> bool:
    """True when extraction attempts raise (strict mode). See :func:`set_enforcement`."""
    return _enforced


@contextlib.contextmanager
def enforcement_scope(enabled: bool = False) -> Iterator[None]:
    """Set enforcement for the duration of a block, then restore the previous setting.

    Some legitimate clients must convert a credential to bytes — ``httpx`` encodes every header
    value (``value.encode("ascii")``), AWS SigV4 signs with the key, some DB drivers encode the
    password. Those calls trip the ``encode``/``slice`` guards. The fix is **not** to disable
    enforcement for the whole process: wrap only the construction/handoff line, so the guards are
    live again for every other line of the app::

        with enforcement_scope(False):                # the ONLY unguarded window
            client = create_client(url.use(), key.use())
            client.postgrest                          # force lazy header build here too

        # strict again from here on — extraction attempts raise as normal

    Pair it with :func:`~ranbval_sdk.config.reveal.reveal_scope` to restrict *where* the plaintext
    may be produced as well as *when* the guards are relaxed.

    Honest limit: enforcement is a single process-wide flag, so this window is process-wide too —
    it is not thread-local isolation. Concurrent threads running inside the block see the relaxed
    setting. Keep the block to the handoff line, do the work outside it, and use a ``PROXY_``
    secret when the value must never exist in the process at all.
    """
    global _enforced
    previous = _enforced
    _enforced = bool(enabled)
    try:
        yield
    finally:
        _enforced = previous


_EXTRACTION_MESSAGE = {
    "iteration": (
        "Ranbval: character-by-character iteration of a secret is blocked — this is how "
        "in-memory extraction (''.join(c for c in key.use())) works. Pass the value straight "
        "to your SDK/HTTP client instead. If a legitimate library needs to iterate it, call "
        "set_enforcement(False); for absolute safety use a PROXY_ secret."
    ),
    "encode": (
        "Ranbval: encoding a secret to bytes is blocked (an extraction path). Pass key.use() "
        "directly to the client that needs it. If a legitimate signer/driver must encode it "
        "(e.g. AWS SigV4, a DB driver), call set_enforcement(False); a PROXY_ secret avoids "
        "the plaintext entirely."
    ),
    "slice": (
        "Ranbval: slicing/indexing a secret (val[:], val[0]) is blocked — it reads the plaintext "
        "out character by character. Pass key.use() straight to your client; f-strings still work. "
        "(set_enforcement(False) to disable; a PROXY_ secret is the only absolute guarantee.)"
    ),
    "str": (
        "Ranbval: str()/print()/'%s' of a secret is blocked under enforcement (it is masked when "
        "enforcement is off). Pass key.use() straight to your client; f-strings build headers fine. "
        "Note: the base str.__str__(val) call CANNOT be intercepted (the str type is immutable) — "
        "only a PROXY_ secret keeps the value off the client entirely. (set_enforcement(False) to disable.)"
    ),
    "truncate": (
        "Ranbval: truncating a secret in a format spec (f\"{key:.8}\") is blocked. The result is a "
        "prefix rather than the value, so the stdout guard cannot recognise it and it would print "
        "straight past every check — while no client library truncates a credential to build a "
        "request. Format it without a precision (f\"Bearer {key}\") or pass key.use() directly."
    ),
    "buffer_read": (
        "Ranbval: reading a secret's internal buffer (_buf/_pad) is blocked — no legitimate "
        "caller touches these. Use key.use() at the point of use. (set_enforcement(False) to "
        "disable; a PROXY_ secret is the only absolute guarantee.)"
    ),
}


def raise_extraction(method: str) -> None:
    """Raise the extraction error (no notify). Used by paths — like ``str()`` — that are masked
    (and frequent) when enforcement is off, so we must not flood the monitor with events."""
    from ranbval_sdk.exceptions import RanbvalSecurityError

    raise RanbvalSecurityError(
        _EXTRACTION_MESSAGE.get(method, f"Ranbval: blocked secret extraction via {method}."),
        code="secret_extraction_blocked",
        method=method,
    )


# ── Handoff methods: audited, but not blocked ─────────────────────────────────
# ``.encode()`` is how every HTTP client turns a header value into bytes (httpx does exactly
# ``value.encode("ascii")`` in ``_normalize_header_value``). Blocking it bought no real secrecy —
# ``f"{key}"`` and ``"{}".format(key)`` already return the full plaintext through ``__format__``,
# with no guard and no monitor event — while its only practical effect was to push callers into
# ``set_enforcement(False)`` for the whole process, which disables the guards that *do* work.
# So encode is audited (the monitor sees it) rather than fatal. Restore the old behaviour with
# ``set_strict_encode(True)`` if your threat model prefers the loud failure.
_handoff_methods: set[str] = {"encode"}


def set_strict_encode(strict: bool) -> None:
    """Make ``.encode()`` raise again (``True``) instead of only notifying (``False``, default).

    Turning this on means any ``httpx``/``requests``-based client must be constructed inside an
    :func:`enforcement_scope` block, because header building always encodes.
    """
    if strict:
        _handoff_methods.discard("encode")
    else:
        _handoff_methods.add("encode")


def guard_reveal(method: str) -> None:
    """Report the reveal-side signal, then (in enforcement mode) raise to stop the extraction.

    The notify runs first so the Live Monitor still records the attempt before the caller
    crashes; the raise is what converts silent theft into a loud, alerting failure.

    Methods in ``_handoff_methods`` are recorded but allowed through — see the note above.
    """
    notify_reveal(method)
    if _enforced and method not in _handoff_methods:
        raise_extraction(method)
