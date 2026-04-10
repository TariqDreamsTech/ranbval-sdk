"""Ranbval SDK — load ``.ranbval*`` into env, decrypt vault tokens, optional telemetry."""

from ranbval_sdk.crypto import safe_decrypt

from ranbval_sdk.dot_ranbval import (
    find_ranbval_directory,
    find_ranbval_file,
    load_ranbval,
    resolve_ranbval_mode,
)

from ranbval_sdk.telemetry import emit_telemetry

from .integrations.factory import secure_client
from .integrations.universal import build_secure_client

__all__ = [
    "emit_telemetry",
    "safe_decrypt",
    "build_secure_client",
    "secure_client",
    "load_ranbval",
    "find_ranbval_file",
    "find_ranbval_directory",
    "resolve_ranbval_mode",
]
