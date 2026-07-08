"""Telemetry client: build and POST a usage event to ``/api/telemetry``.

Works with any HTTP stack after ``load_ranbval()``. The synchronous
:func:`emit_telemetry` can fire in the background; :func:`aemit_telemetry` offloads it to a
worker thread for asyncio/FastAPI. Only a non-reversible token salt is sent — never plaintext.
"""

from __future__ import annotations

import asyncio
import json
import os
import socket
import threading
import urllib.request
from typing import Any
from urllib.parse import urlparse

from ranbval_sdk._internal import transport as _transport
from ranbval_sdk._internal.defaults import DEFAULT_RANBVAL_HOST
from ranbval_sdk._internal.logging import warn_telemetry_send_failed
from ranbval_sdk.policy.repo import get_git_remote_origin as _get_git_remote
from ranbval_sdk.serializers.telemetry import build_telemetry_payload

# Re-exported for backwards compatibility: the token parser lives in the serializers
# package now, but ``from ranbval_sdk.telemetry import salt_from_ranbval_token`` and
# ``from ranbval_sdk.telemetry.client import salt_from_ranbval_token`` must keep working.
from ranbval_sdk.serializers.token import salt_from_ranbval_token  # noqa: F401
from ranbval_sdk.telemetry.context import collect_client_context


def emit_telemetry(
    *,
    client_salt: str | None = None,
    vault_token_env: str | None = None,
    model_used: str = "custom.request",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    host_url: str | None = None,
    event_kind: str = "custom.request",
    item_count: int = 1,
    roundtrip_ms: float | None = None,
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
        # Respect the user's privacy opt-out: RANBVAL_TELEMETRY_DISABLED=1 makes
        # every telemetry path a silent no-op (decryption itself is unaffected).
        from ranbval_sdk.telemetry.settings import telemetry_disabled

        if telemetry_disabled():
            return
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

        payload = build_telemetry_payload(
            client_salt=salt,
            machine_name=machine_name,
            repo_path=repo_path,
            git_url=git_url,
            model_used=model_used,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            item_count=item_count,
            context=collect_client_context(),
            event_kind=event_kind,
            transport=transport,
            ci_environment=ci_environment,
            roundtrip_ms=roundtrip_ms,
        )

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
