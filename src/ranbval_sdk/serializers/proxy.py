"""Serialize a secure-proxy call into the ``/api/execute`` request body.

The control plane decrypts ``token`` server-side with ``project_secret`` and forwards the call
to ``target_url`` — the plaintext key is never returned to the caller.
"""

from __future__ import annotations

from typing import Any


def build_proxy_payload(
    *,
    project_secret: str,
    token: str,
    target_url: str,
    method: str,
    headers: dict[str, str] | None = None,
    body: Any = None,
    inject_as: str = "bearer",
    model_used: str = "",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
) -> dict[str, Any]:
    """Shape the ``/api/execute`` request body from already-resolved values."""
    return {
        "project_secret": project_secret,
        "token": token,
        "target_url": target_url,
        "method": method.upper(),
        "headers": headers or {},
        "body": body,
        "inject_as": inject_as,
        "model_used": model_used,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
    }
