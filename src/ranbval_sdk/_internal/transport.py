"""HTTPS via urllib with certifi's CA bundle (fixes common macOS SSL verify failures)."""

from __future__ import annotations

import ssl
import urllib.request
from typing import Any

from ranbval_sdk.exceptions import RanbvalConfigError

#: The only schemes this transport will open. ``urlopen`` otherwise honours ``file:``, ``ftp:``
#: and any registered custom scheme — so a host taken from configuration (``RANBVAL_HOST``, a
#: ``host_url=`` argument) could be pointed at ``file:///etc/passwd`` and the SDK would dutifully
#: read it. Every caller here is talking to the control plane over the network; nothing legitimate
#: needs another scheme, so the set is closed rather than audited.
_ALLOWED_SCHEMES = frozenset({"https", "http"})


def urlopen(req: urllib.request.Request, timeout: float | None = None) -> Any:
    full = req.get_full_url()
    scheme = full.split(":", 1)[0].lower() if ":" in full else ""

    if scheme not in _ALLOWED_SCHEMES:
        raise RanbvalConfigError(
            f"Refusing to open {scheme or 'a schemeless'}: URL — Ranbval talks to the control "
            f"plane over http(s) only. A host pointed at file:, ftp: or a custom scheme would "
            "make the SDK read local or attacker-chosen resources. Check RANBVAL_HOST.",
            code="disallowed_url_scheme",
        )

    if scheme == "https":
        import certifi

        ctx = ssl.create_default_context(cafile=certifi.where())
        # Scheme is constrained to the allowlist above.
        return urllib.request.urlopen(req, timeout=timeout, context=ctx)  # nosec B310

    # Plain http remains available for a self-hosted or local control plane; it is the caller's
    # deployment choice, and the scheme check above is what this function is responsible for.
    return urllib.request.urlopen(req, timeout=timeout)  # nosec B310
