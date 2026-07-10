"""Fetch a project's env-set from the Ranbval control plane over HTTPS.

Owner auth is the project secret itself (``ranbval-proj-…``) — the same secret that decrypts the
tokens. The response carries the env vars exactly as they would sit in a ``.ranbval`` file:
``SECRET_``/``PROXY_`` values are still encrypted ``ranbval.*`` tokens, ``PUBLIC_`` values are
plaintext. Nothing here decrypts anything.
"""

from __future__ import annotations

import json
import os
import urllib.request

from ranbval_sdk._internal import transport as _transport
from ranbval_sdk._internal.defaults import DEFAULT_RANBVAL_HOST
from ranbval_sdk.exceptions import RanbvalConfigError


def _host(host: str | None) -> str:
    return (host or os.environ.get("RANBVAL_HOST") or DEFAULT_RANBVAL_HOST).rstrip("/")


def fetch_env_set(
    *,
    project_secret: str,
    host: str | None = None,
    timeout: float = 10.0,
) -> dict[str, str]:
    """Return ``{name: value}`` for every env var in the project this secret belongs to.

    Raises :class:`RanbvalConfigError` on auth failure or an unreachable control plane.
    """
    if not project_secret or not project_secret.strip():
        raise RanbvalConfigError(
            "remote=True needs a project_secret (the ranbval-proj-… key).",
            code="remote_no_secret",
        )
    url = f"{_host(host)}/api/envs/pull"
    data = json.dumps({"project_secret": project_secret.strip()}).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with _transport.urlopen(req, timeout=timeout) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = "Invalid or revoked project_secret." if e.code == 403 else f"HTTP {e.code}"
        raise RanbvalConfigError(
            f"Could not fetch env-set from {url}: {detail}", code="remote_fetch_failed"
        ) from e
    except Exception as e:
        raise RanbvalConfigError(
            f"Could not reach the Ranbval control plane at {url}: {e}",
            code="remote_unreachable",
        ) from e

    envs = body.get("envs") or []
    return {e["name"]: e["value"] for e in envs if e.get("name")}
