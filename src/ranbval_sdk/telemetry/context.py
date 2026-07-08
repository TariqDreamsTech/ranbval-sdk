"""Client-context detection for telemetry (resource-detector pattern).

Gathers the client-side runtime signals that describe *where* a usage event came from —
SDK/Python version, git branch and committer email, coarse timezone, and a hashed device
fingerprint. This is the data-*gathering* layer; :mod:`ranbval_sdk.serializers.telemetry`
does the data-*shaping* into the wire payload. Nothing here is a secret.
"""

from __future__ import annotations

import hashlib
import sys
import time
import uuid
from typing import Any


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
    """Developer identity from ``git config user.email`` (who ran this), if available.

    Privacy: only collected when the user has explicitly opted in via
    ``RANBVAL_TELEMETRY_IDENTITY=1``. Off by default — returns ``None`` so no
    personal identifier ever leaves the machine unless enabled.
    """
    from ranbval_sdk.telemetry.settings import identity_opt_in

    if not identity_opt_in():
        return None
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


_DEVICE_ID: str | None = None


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


def collect_client_context() -> dict[str, Any]:
    """Snapshot the client runtime signals that go into a telemetry event's security block."""
    return {
        "sdk_version": _sdk_version(),
        "client_platform": sys.platform,
        "python_version": sys.version.split()[0],
        "git_branch": _get_git_branch(),
        "git_email": _get_git_email(),  # developer identity
        "timezone": _timezone(),  # coarse geo hint (precise geo derived server-side from IP)
        "device_id": _device_id(),  # hashed device fingerprint → multi-device leak detection
    }
