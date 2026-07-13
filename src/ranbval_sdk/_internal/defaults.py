"""Shared default constants for optional configuration.

Override with environment variables when needed (e.g. self-hosted or local dev).
"""

# Password-manager origin only — no ``/api`` suffix (SDK appends ``/api/...`` paths).
DEFAULT_RANBVAL_HOST = "https://api.secret.ranbval.com"

# The stderr debug warning moved to ``_internal.logging``; re-exported here so any
# existing ``from ranbval_sdk._internal.defaults import warn_telemetry_send_failed`` keeps working.
from ranbval_sdk._internal.logging import warn_telemetry_send_failed  # noqa: E402,F401
