"""
Ranbval Secure Proxy — route any HTTP request through /api/execute.

The real API key is NEVER on the caller's machine. Ranbval decrypts it
server-side, injects it into the outbound request, and returns the response.

Works from anywhere: Python scripts, n8n, Postman, curl, CI pipelines, etc.

Usage::

    from ranbval_sdk import load_ranbval, proxy_request

    load_ranbval()

    resp = proxy_request(
        token="ranbval.xxxx.….ahsan",      # vault token from session card
        target_url="https://api.openai.com/v1/chat/completions",
        method="POST",
        inject_as="bearer",                 # injects real key as Authorization: Bearer …
        body={"model": "gpt-4o", "messages": [{"role": "user", "content": "Hello"}]},
    )
    print(resp["body"])

Inject modes
------------
    "bearer"         → Authorization: Bearer <secret>
    "basic"          → Authorization: Basic <secret>
    "header:X-Name"  → X-Name: <secret>
    "query:api_key"  → ?api_key=<secret> appended to target_url
"""

from __future__ import annotations

import asyncio
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from ranbval_sdk._internal import transport
from ranbval_sdk.crypto.cipher import _find_project_secret_for
from ranbval_sdk._internal.defaults import DEFAULT_RANBVAL_HOST
from ranbval_sdk.exceptions import ProxyError
from ranbval_sdk.serializers.proxy import build_proxy_payload

__all__ = ["proxy_request", "aproxy_request", "ProxyError"]


def proxy_request(
    token: str,
    target_url: str,
    *,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    body: Any = None,
    inject_as: str = "bearer",
    # Credentials — auto-read from env when omitted
    api_key: str | None = None,
    project_secret: str | None = None,
    # Which env var holds the token (used to auto-discover project_secret)
    token_env_var: str | None = None,
    # Ranbval host override
    host_url: str | None = None,
    # Optional telemetry fields
    model_used: str = "http.proxy",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
) -> dict[str, Any]:
    """
    Send an HTTP request through the Ranbval secure proxy.

    The vault token (``token``) identifies which session secret to inject.
    The real API key is decrypted server-side and **never** returned.

    Parameters
    ----------
    token:
        Vault token from the session card (``ranbval.xxxx.….ahsan``).
    target_url:
        The real API endpoint to call.
    method:
        HTTP verb (GET, POST, PUT, PATCH, DELETE …). Default ``"POST"``.
    headers:
        Extra headers to forward to the target (do NOT include Authorization —
        that is injected by the proxy based on ``inject_as``).
    body:
        Request body. Dict → JSON, str → plain text, None → no body.
    inject_as:
        How to inject the decrypted secret:
        ``"bearer"`` | ``"basic"`` | ``"header:X-Name"`` | ``"query:param"``.
    api_key:
        Your Ranbval API key (``ranbvalahsantariq…``). Defaults to
        ``RANBVAL_API_KEY`` env var.
    project_secret:
        The ``ranbval-proj-…`` key for the project. Defaults to
        ``{TOKEN_ENV_VAR prefix}_PROJECT_SECRET`` → ``RANBVAL_PROJECT_SECRET``.
    token_env_var:
        Name of the env var that holds ``token`` — used ONLY to auto-discover
        the project secret when ``project_secret`` is omitted.
    host_url:
        Override the Ranbval server. Defaults to ``RANBVAL_HOST`` env var or
        ``https://api.ranbval.com``.

    Returns
    -------
    dict with keys:
        ``status``       int   — HTTP status from the target
        ``ok``           bool  — True when 2xx
        ``body``         any   — parsed JSON or raw string from target
        ``headers``      dict  — response headers (auth headers stripped)
        ``session_name`` str   — name of the session used
        ``project``      str   — project name

    Raises
    ------
    ProxyError
        The proxy rejected the request (bad credentials, unknown token, etc.)
        or the proxy itself was unreachable.
    """
    host = (host_url or os.environ.get("RANBVAL_HOST") or DEFAULT_RANBVAL_HOST).rstrip(
        "/"
    )

    # ── Resolve api_key ──────────────────────────────────────────────────────
    resolved_api_key = (api_key or os.environ.get("RANBVAL_API_KEY") or "").strip()
    if not resolved_api_key:
        raise ProxyError(
            "No Ranbval API key found. Set RANBVAL_API_KEY in your .ranbval file "
            "or pass api_key= to proxy_request()."
        )

    # ── Resolve project_secret ───────────────────────────────────────────────
    resolved_project_secret = (project_secret or "").strip()
    if not resolved_project_secret:
        if token_env_var:
            try:
                resolved_project_secret = _find_project_secret_for(token_env_var)
            except ValueError:
                pass
        if not resolved_project_secret:
            resolved_project_secret = os.environ.get(
                "RANBVAL_PROJECT_SECRET", ""
            ).strip()
    if not resolved_project_secret:
        raise ProxyError(
            "No project secret found. Set RANBVAL_PROJECT_SECRET in your .ranbval file "
            "or pass project_secret= to proxy_request()."
        )

    # ── Build request ────────────────────────────────────────────────────────
    payload = build_proxy_payload(
        project_secret=resolved_project_secret,
        token=token,
        target_url=target_url,
        method=method,
        headers=headers,
        body=body,
        inject_as=inject_as,
        model_used=model_used,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
    )

    url = f"{host}/api/execute"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Ranbval-API-Key": resolved_api_key,
        },
        method="POST",
    )

    try:
        with transport.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        body_text = ""
        try:
            body_text = e.read().decode("utf-8", errors="replace")
        except Exception:
            pass
        try:
            detail = json.loads(body_text).get("detail", body_text)
        except Exception:
            detail = body_text
        raise ProxyError(f"Ranbval proxy returned HTTP {e.code}: {detail}") from e
    except urllib.error.URLError as e:
        raise ProxyError(f"Could not reach Ranbval proxy at {host!r}: {e}") from e


async def aproxy_request(token: str, target_url: str, **kwargs: Any) -> dict[str, Any]:
    """Async, non-blocking variant of :func:`proxy_request` for event loops.

    Runs the blocking request on a worker thread so FastAPI / asyncio callers never
    stall the loop. Accepts the same keyword arguments as :func:`proxy_request`::

        result = await aproxy_request(token, "https://api.openai.com/v1/...", body={...})
    """
    return await asyncio.to_thread(proxy_request, token, target_url, **kwargs)
