"""Configuration & lookup errors — ``.ranbval`` loading, classification, missing keys.

Mirrors :mod:`ranbval_sdk.config`.
"""

from __future__ import annotations

from ranbval_sdk.exceptions.base import RanbvalError


class RanbvalConfigError(RanbvalError, ValueError):
    """A value is missing or misconfigured: env var not set, no project secret, an unclassified
    key, a ``[section]`` header, or a competing env loader."""

    default_code = "config_error"


class MissingKeyError(RanbvalError, KeyError):
    """An expected environment variable or vault token is absent (raised by attribute/item access)."""

    default_code = "missing_key"

    def __str__(self) -> str:
        # ``KeyError.__str__`` wraps its argument in ``repr()`` (adds quotes), producing ugly
        # messages like ``"'OPENAI_KEY is not set'"``. Bypass it so the message reads naturally.
        return self.args[0] if self.args else ""
