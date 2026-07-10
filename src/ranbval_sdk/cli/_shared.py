"""Shared rendering for the ``ranbval`` CLI: terminal colours + the ``.ranbval`` template."""

from __future__ import annotations

import sys

_ANSI = {"green": "\033[32m", "red": "\033[31m", "yellow": "\033[33m", "dim": "\033[2m"}
_RESET = "\033[0m"


def color(text: str, kind: str) -> str:
    """Wrap *text* in an ANSI colour when stdout is a TTY, else return it plain."""
    code = _ANSI.get(kind, "")
    return f"{code}{text}{_RESET}" if code and sys.stdout.isatty() else text


TEMPLATE = """\
# .ranbval — Ranbval configuration. Every variable must start with a class prefix:
#   PUBLIC_  plaintext config (public() reads it)
#   SECRET_  encrypted; decrypt_key("SECRET_…").use() reveals it locally
#   PROXY_   encrypted; plaintext never on the client — proxy_token("PROXY_…") + proxy
# RANBVAL_* and *_PROJECT_SECRET are exempt (infrastructure).

# Keep the project secret in .ranbval.local (git-ignored), not here.
# RANBVAL_PROJECT_SECRET=ranbval-proj-xxxx

PUBLIC_APP_NAME=my-app
# SECRET_OPENAI_KEY=ranbval.xxxx.blob.ahsan     # paste a token from the Ranbval dashboard
# PROXY_STRIPE_KEY=ranbval.yyyy.blob.ahsan
"""
