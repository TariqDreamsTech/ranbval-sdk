"""Cryptography & sealed-secret errors — decrypt failures and extraction enforcement.

Mirrors :mod:`ranbval_sdk.crypto`.
"""

from __future__ import annotations

from ranbval_sdk.exceptions.base import RanbvalError


class RanbvalDecryptError(RanbvalError, ValueError):
    """A vault token could not be decrypted (bad project secret, corrupt token, or expired)."""

    default_code = "decrypt_failed"


class RanbvalSecurityError(RanbvalError, PermissionError):
    """A revealed secret was manipulated in a way that signals in-memory extraction
    (char-by-char iteration, ``.encode()`` to bytes, slicing, ``str()``, or a direct read of the
    internal buffer) while enforcement is on. Raised to turn silent theft into a loud failure.

    This is a **naive-attacker deterrent, not a guarantee** — once ``.use()`` returns a real
    ``str``, the base ``str`` methods (``str.__str__(val)``, ``str.__getitem__(val, ...)``) and
    the real buffer slot (``object.__getattribute__(s, "_b")``) still reach the plaintext
    in-process and cannot be blocked. Only ``PROXY_`` secrets (plaintext never enters the client)
    are absolute. Disable with ``set_enforcement(False)`` if a legitimate library trips it.
    """

    default_code = "secret_extraction_blocked"
