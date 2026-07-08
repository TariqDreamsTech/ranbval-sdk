"""Internal diagnostics — opt-in stderr warnings for otherwise-silent failures.

The SDK never prints by default. Setting ``RANBVAL_TELEMETRY_DEBUG=1`` surfaces why a
best-effort telemetry POST failed, so CI can debug it without changing code.
"""

import os
import sys


def warn_telemetry_send_failed(host: str, exc: BaseException) -> None:
    """If ``RANBVAL_TELEMETRY_DEBUG=1``, print why POST /api/telemetry failed (default is silent)."""
    v = (os.environ.get("RANBVAL_TELEMETRY_DEBUG") or "").strip().lower()
    if v not in ("1", "true", "yes", "on"):
        return
    url = f"{host.rstrip('/')}/api/telemetry"
    print(f"[Ranbval] Telemetry POST failed ({url}): {exc!r}", file=sys.stderr)
