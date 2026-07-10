"""Secure-proxy errors.

Mirrors :mod:`ranbval_sdk.integrations.proxy`.
"""

from __future__ import annotations

from ranbval_sdk.exceptions.base import RanbvalError


class ProxyError(RanbvalError, RuntimeError):
    """The Ranbval secure proxy rejected the request or could not be reached."""

    default_code = "proxy_error"
