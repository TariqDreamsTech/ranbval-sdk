"""Shared defaults for optional configuration.

Override with environment variables when needed (e.g. self-hosted or local dev).
"""

import os
import sys

# Password-manager origin only — no ``/api`` suffix (SDK appends ``/api/...`` paths).
DEFAULT_RANBVAL_HOST = "https://api.ranbval.com"


def warn_telemetry_send_failed(host: str, exc: BaseException) -> None:
    """If ``RANBVAL_TELEMETRY_DEBUG=1``, print why POST /api/telemetry failed (default is silent)."""
    v = (os.environ.get("RANBVAL_TELEMETRY_DEBUG") or "").strip().lower()
    if v not in ("1", "true", "yes", "on"):
        return
    url = f"{host.rstrip('/')}/api/telemetry"
    print(f"[Ranbval] Telemetry POST failed ({url}): {exc!r}", file=sys.stderr)
