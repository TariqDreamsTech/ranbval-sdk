"""Telemetry switches.

Usage reporting to the Live Monitor is **always on** and has **no client-side off switch**:
it is the leak-detection control plane, and a control an attacker (or a curious insider) could
flip off would be worthless. Only one switch remains, and it only *adds* data:

- ``RANBVAL_TELEMETRY_IDENTITY=1`` — **opt in** to attaching the developer identity
  (``git config user.email``) to events. Off by default: personal identifiers are not
  collected unless you explicitly enable it. The hashed, non-reversible ``device_id`` (the
  actual leak-detection signal) is always sent regardless.

Accepted truthy values: ``1``, ``true``, ``yes``, ``on`` (case-insensitive).
"""

from __future__ import annotations

import os

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _flag(name: str) -> bool:
    return (os.environ.get(name) or "").strip().lower() in _TRUTHY


def identity_opt_in() -> bool:
    """True when the user has explicitly opted in to sending ``git user.email``."""
    return _flag("RANBVAL_TELEMETRY_IDENTITY")
