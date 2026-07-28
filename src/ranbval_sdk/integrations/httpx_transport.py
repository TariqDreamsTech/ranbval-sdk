"""Route a normal ``httpx``-based SDK through the Ranbval secure proxy.

The gap this closes: :func:`~ranbval_sdk.proxy_request` keeps a ``PROXY_`` secret off the machine
entirely, but it only speaks raw HTTP — so you lose the client library (``supabase``, ``openai``,
``stripe``, anything built on ``httpx``) and hand-roll requests instead. That is a bad trade: the
libraries exist for a reason.

:class:`RanbvalProxyTransport` is an ``httpx`` transport, so the library keeps working exactly as
written while every request it makes is forwarded through Ranbval, which injects the real
credential server-side::

    from supabase import create_client, ClientOptions
    from ranbval_sdk import proxy_token
    from ranbval_sdk.integrations.httpx_transport import ranbval_httpx_client

    supabase = create_client(
        url, "unused-placeholder",
        options=ClientOptions(httpx_client=ranbval_httpx_client(
            token=proxy_token("PROXY_SUPABASE_TOKEN"),
            inject_as="header:apikey",
        )),
    )
    supabase.table("profiles").select("*").execute()   # normal SDK call, key never local

Why this is stronger than ``enforcement_scope``: there is no plaintext in the process to guard,
so there is nothing to reveal — no window, no flag, no honour system. The credential is decrypted
inside Ranbval and injected into the outbound request there.

Limits worth knowing:
- Every request takes an extra hop through Ranbval, and each one counts against your plan.
- Streaming/websocket transports are not proxied (Supabase Realtime, SSE) — those still need a
  local credential.
- The placeholder key you pass the library is never used; the proxy overwrites that header.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from ranbval_sdk.integrations.proxy import proxy_request

__all__ = ["RanbvalProxyTransport", "ranbval_httpx_client"]

# Hop-by-hop / recomputed headers that must not be forwarded to the target: the proxy sets the
# credential itself, and the length/host of the re-issued request will differ from this one's.
_DROP_HEADERS = frozenset(
    {"host", "content-length", "connection", "authorization", "apikey", "accept-encoding"}
)


class RanbvalProxyTransport(httpx.BaseTransport):
    """An ``httpx`` transport that forwards every request through the Ranbval secure proxy.

    Parameters mirror :func:`~ranbval_sdk.proxy_request`: ``token`` is the encrypted
    ``ranbval.*`` vault token (get it with :func:`~ranbval_sdk.proxy_token`), and ``inject_as``
    says how Ranbval should attach the decrypted credential (``"bearer"``, ``"basic"``,
    ``"header:X-Name"``, ``"query:param"``). Extra keyword arguments are passed straight to
    ``proxy_request`` (``api_key``, ``project_secret``, ``host_url``, ``token_env_var``…).
    """

    def __init__(
        self,
        token: str,
        *,
        inject_as: str = "bearer",
        **proxy_kwargs: Any,
    ) -> None:
        self._token = token
        self._inject_as = inject_as
        self._proxy_kwargs = proxy_kwargs

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        raw = request.read()
        body: Any = None
        if raw:
            text = raw.decode("utf-8", errors="replace")
            # Send JSON bodies as objects so the proxy forwards them as JSON, not a quoted string.
            try:
                body = json.loads(text)
            except ValueError:
                body = text

        headers = {
            k: v for k, v in request.headers.items() if k.lower() not in _DROP_HEADERS
        }

        result = proxy_request(
            token=self._token,
            target_url=str(request.url),
            method=request.method,
            headers=headers,
            body=body,
            inject_as=self._inject_as,
            **self._proxy_kwargs,
        )

        payload = result.get("body")
        if isinstance(payload, (dict, list)):
            content = json.dumps(payload).encode("utf-8")
            content_type = "application/json"
        else:
            content = ("" if payload is None else str(payload)).encode("utf-8")
            content_type = "text/plain; charset=utf-8"

        # Rebuild the response headers: keep what the target sent, but drop anything describing an
        # encoding/length that no longer matches the body we are handing back to the client.
        out_headers = {
            k: v
            for k, v in (result.get("headers") or {}).items()
            if k.lower() not in {"content-length", "content-encoding", "transfer-encoding"}
        }
        out_headers.setdefault("content-type", content_type)

        return httpx.Response(
            status_code=int(result.get("status", 200)),
            headers=out_headers,
            content=content,
            request=request,
        )


def ranbval_httpx_client(
    token: str,
    *,
    inject_as: str = "bearer",
    timeout: float | httpx.Timeout = 60.0,
    **proxy_kwargs: Any,
) -> httpx.Client:
    """Build an ``httpx.Client`` wired to :class:`RanbvalProxyTransport`.

    Hand the result to any library that accepts a custom client (``supabase``'s
    ``ClientOptions(httpx_client=…)``, ``openai``'s ``http_client=…``) and its requests will run
    through the proxy with no other code changes.
    """
    return httpx.Client(
        transport=RanbvalProxyTransport(token, inject_as=inject_as, **proxy_kwargs),
        timeout=timeout,
    )
