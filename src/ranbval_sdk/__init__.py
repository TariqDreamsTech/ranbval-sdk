"""Ranbval SDK — loads ``.ranbval`` from cwd (or parents) before exposing clients."""

from ranbval_sdk.dot_ranbval import find_ranbval_file, load_ranbval

load_ranbval()

from .integrations.openai_client import SecureOpenAI
from .integrations.universal import build_secure_client
from .integrations.platforms import SecureAnthropic, SecureMistral, SecureSupabase

__all__ = [
    "SecureOpenAI",
    "build_secure_client",
    "SecureAnthropic",
    "SecureMistral",
    "SecureSupabase",
    "load_ranbval",
    "find_ranbval_file",
]
