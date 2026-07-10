"""Extraction enforcement + the reveal-signal notifier for revealed secrets.

When enforcement is on (the default), a detected extraction of a revealed value — iteration,
``.encode()``, slicing/indexing, ``str()``/``print()``, or a raw ``_buf``/``_pad`` read — raises
:class:`~ranbval_sdk.exceptions.RanbvalSecurityError` instead of silently handing over the
plaintext. The **notifier** (set by the opt-in access monitor) is fired first so the Live Monitor
records the attempt before the caller crashes.

Honest limit: this stops the *naive* vectors. The base ``str`` methods (``str.__str__(val)``,
``str.__getitem__(val, ...)``) and the real slot ``object.__getattribute__(s, "_b")`` still reach
the plaintext in-process and cannot be blocked. Only ``PROXY_`` secrets are absolute. Turn
enforcement off with :func:`set_enforcement`.
"""

from __future__ import annotations

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


def guard_reveal(method: str) -> None:
    """Report the reveal-side signal, then (in enforcement mode) raise to stop the extraction.

    The notify runs first so the Live Monitor still records the attempt before the caller
    crashes; the raise is what converts silent theft into a loud, alerting failure.
    """
    notify_reveal(method)
    if _enforced:
        raise_extraction(method)
