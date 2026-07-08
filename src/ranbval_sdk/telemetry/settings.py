"""User-facing telemetry switches (privacy controls).

The SDK reports credential usage to the Live Monitor for leak detection. Two
environment switches let operators and privacy-conscious users control that:

- ``RANBVAL_TELEMETRY_DISABLED=1`` — turn usage reporting **off** entirely. Every
  telemetry path becomes a no-op. Decryption still works fully offline-of-monitoring
  (the repo-allowlist check is a separate control-plane concern).
- ``RANBVAL_TELEMETRY_IDENTITY=1`` — **opt in** to attaching the developer identity
  (``git config user.email``) to events. It is **off by default**: personal identifiers
  are not collected unless you explicitly enable it. The hashed, non-reversible
  ``device_id`` (the actual leak-detection signal) is always sent regardless.

Accepted truthy values for both: ``1``, ``true``, ``yes``, ``on`` (case-insensitive).
"""

from __future__ import annotations

import os

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _flag(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in _TRUTHY


def telemetry_disabled() -> bool:
    """True when the user has opted out of all usage reporting."""
    return _flag("RANBVAL_TELEMETRY_DISABLED")


def identity_opt_in() -> bool:
    """True when the user has explicitly opted in to sending ``git user.email``."""
    return _flag("RANBVAL_TELEMETRY_IDENTITY")
