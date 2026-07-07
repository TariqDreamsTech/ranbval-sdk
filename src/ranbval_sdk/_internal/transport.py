"""HTTPS via urllib with certifi's CA bundle (fixes common macOS SSL verify failures)."""

from __future__ import annotations

import ssl
import urllib.request
from typing import Any


def urlopen(req: urllib.request.Request, timeout: float | None = None) -> Any:
    full = req.get_full_url()
    if full.lower().startswith("https:"):
        import certifi

        ctx = ssl.create_default_context(cafile=certifi.where())
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)
    return urllib.request.urlopen(req, timeout=timeout)
