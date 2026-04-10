"""Shared defaults for optional configuration.

Override with environment variables when needed (e.g. self-hosted or local dev).
"""

# Password-manager origin only — no ``/api`` suffix (SDK appends ``/api/...`` paths).
DEFAULT_RANBVAL_HOST = "https://ranbval-password-manager.onrender.com"
