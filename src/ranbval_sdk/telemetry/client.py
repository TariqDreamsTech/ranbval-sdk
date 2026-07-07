"""Telemetry client: build and POST a usage event to ``/api/telemetry``.

Works with any HTTP stack after ``load_ranbval()``. The synchronous
:func:`emit_telemetry` can fire in the background; :func:`aemit_telemetry` offloads it to a
worker thread for asyncio/FastAPI. Only a non-reversible token salt is sent — never plaintext.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import socket
import sys
import threading
import time
import urllib.request
import uuid
from typing import Any, Optional
from urllib.parse import urlparse

from ranbval_sdk._internal import transport as _transport
from ranbval_sdk._internal.defaults import (
    DEFAULT_RANBVAL_HOST,
    warn_telemetry_send_failed,
)
from ranbval_sdk.crypto.repo_policy import get_git_remote_origin as _get_git_remote


def _get_git_branch() -> str | None:
    try:
        import subprocess

        return subprocess.check_output(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
    except Exception:
        return None


def _get_git_email() -> str | None:
    """Developer identity from ``git config user.email`` (who ran this), if available."""
    try:
        import subprocess

        return (
            subprocess.check_output(
                ["git", "config", "user.email"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
            or None
        )
    except Exception:
        return None


def _timezone() -> str:
    """Coarse geo hint from the local timezone (no network). Precise geo is derived server-side."""
    try:
        return time.tzname[0] or ""
    except Exception:
        return ""


_DEVICE_ID: Optional[str] = None


def _device_id() -> str:
    """Stable, hashed device fingerprint (from the MAC) so the control plane can detect the same
    credential being used from multiple distinct devices — the core signal for leak detection.
    The raw MAC is never sent; only a truncated SHA-256."""
    global _DEVICE_ID
    if _DEVICE_ID is None:
        try:
            _DEVICE_ID = hashlib.sha256(str(uuid.getnode()).encode()).hexdigest()[:16]
        except Exception:
            _DEVICE_ID = ""
    return _DEVICE_ID


def _sdk_version() -> str:
    try:
        from importlib.metadata import version

        return version("ranbval-sdk")
    except Exception:
        return ""


def salt_from_ranbval_token(raw: str) -> Optional[str]:
    """Return client salt segment from ``ranbval.<salt>.<cipher>.<label>`` or ``None``."""
    if not raw or not str(raw).startswith("ranbval."):
        return None
    parts = str(raw).split(".")
    if len(parts) < 2:
        return None
    return parts[1]


def emit_telemetry(
    *,
    client_salt: Optional[str] = None,
    vault_token_env: Optional[str] = None,
    model_used: str = "custom.request",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    host_url: Optional[str] = None,
    event_kind: str = "custom.request",
    item_count: int = 1,
    roundtrip_ms: Optional[float] = None,
    background: bool = False,
) -> None:
    """
    Notify the password-manager of an outbound use (any vendor or custom API).

    Resolve ``client_salt`` explicitly, or pass ``vault_token_env`` (e.g. ``\"OPENAI_API_KEY\"``)
    when that env var holds a ``ranbval.*`` token — salt is taken from the token. If no salt
    can be resolved, this is a no-op (silent).

    Call after **your** ``requests`` / ``httpx`` / SDK call when you want the Live Monitor to see it.
    ``secure_client(..., method_path_to_patch=...)`` calls this automatically for patched methods.
    """

    def _post() -> None:
        # Telemetry is mandatory — usage is always reported to the Live Monitor.
        # (There is no local opt-out; the control plane owns retention & policy.)
        salt = client_salt
        if not salt and vault_token_env:
            raw = os.environ.get(str(vault_token_env).strip(), "")
            salt = salt_from_ranbval_token(raw)
        if not salt:
            return

        h = (host_url or os.environ.get("RANBVAL_HOST") or DEFAULT_RANBVAL_HOST).rstrip(
            "/"
        )
        repo_path = os.getcwd()
        machine_name = socket.gethostname()
        git_url = _get_git_remote()

        parsed = urlparse(h)
        transport = (parsed.scheme or "http").lower()
        ci_environment = any(
            os.environ.get(k)
            for k in (
                "CI",
                "GITHUB_ACTIONS",
                "GITLAB_CI",
                "BUILDKITE",
                "CIRCLECI",
                "JENKINS_URL",
            )
        )

        sec = {
            "event_kind": event_kind,
            "sdk_version": _sdk_version(),
            "client_platform": sys.platform,
            "python_version": sys.version.split()[0],
            "transport": transport,
            "vault_token_format": "ranbval",
            "git_branch": _get_git_branch(),
            "git_email": _get_git_email(),  # developer identity
            "timezone": _timezone(),  # coarse geo hint (precise geo derived server-side from IP)
            "device_id": _device_id(),  # hashed device fingerprint → multi-device leak detection
            "ci_environment": bool(ci_environment),
        }
        if roundtrip_ms is not None:
            sec["roundtrip_ms"] = round(float(roundtrip_ms), 2)  # decrypt latency

        payload = {
            "client_salt": salt,
            "machine_name": machine_name,
            "repo_path": repo_path,
            "git_url": git_url,
            "model_used": model_used,
            "prompt_tokens": int(prompt_tokens),
            "completion_tokens": int(completion_tokens),
            # Adaptive-sampling weight: this event represents `item_count` actual uses.
            # The control plane multiplies by this to reconstruct true totals.
            "item_count": max(1, int(item_count)),
            "security": sec,
        }

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{h}/api/telemetry",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with _transport.urlopen(req, timeout=5) as resp:
                resp.read()
        except Exception as e:
            warn_telemetry_send_failed(h, e)

    if background:
        threading.Thread(target=_post, daemon=True).start()
    else:
        _post()


async def aemit_telemetry(**kwargs: Any) -> None:
    """Async, non-blocking telemetry for event loops (FastAPI, asyncio).

    Same arguments as :func:`emit_telemetry`, but the blocking POST runs on a worker
    thread via ``asyncio.to_thread`` so the event loop is never stalled::

        await aemit_telemetry(vault_token_env="OPENAI_API_KEY", model_used="gpt-4o")
    """
    kwargs.setdefault("background", False)
    await asyncio.to_thread(emit_telemetry, **kwargs)
