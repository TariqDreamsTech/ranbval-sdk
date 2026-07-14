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
import time
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


#: Background emits that have not landed yet. Joined at exit so a short-lived process — the shape
#: every credential theft takes — still reports the use that would trip a canary.
_inflight: "set[threading.Thread]" = set()
_inflight_lock = threading.Lock()


def flush_inflight(timeout: float = 3.0) -> None:
    """Wait, briefly, for in-flight telemetry to land. Best-effort and strictly bounded.

    Bounded because the alternative is worse: a non-daemon thread would hang the process on a slow
    or unreachable control plane, and a security tool that can freeze your app on exit will simply
    be removed.
    """
    deadline = time.monotonic() + timeout
    with _inflight_lock:
        threads = list(_inflight)
    for t in threads:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        t.join(remaining)


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
    (``decrypt_key()`` already auto-reports each decrypt; this is for richer custom events.)
    """

    def _post() -> None:
        # Usage reporting is always on (leak detection) — there is no client-side off switch.
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
        finally:
            with _inflight_lock:
                _inflight.discard(threading.current_thread())

    if background:
        # Daemon, so a hung control plane can never stop the host process from exiting. But daemon
        # threads are KILLED at interpreter shutdown — so a short-lived process would drop this
        # event entirely, and the first use of a credential is exactly the event that matters: it is
        # the one a canary fires on. A theft is a smash-and-grab
        # (`python -c "print(decrypt_key('SECRET_X').use())"`), which is precisely the case that
        # exits too fast to send. The alarm stayed silent exactly when it was needed.
        #
        # So we track the thread and join it, briefly, at exit (see flush_inflight).
        t = threading.Thread(target=_post, daemon=True)
        with _inflight_lock:
            _inflight.add(t)
        t.start()
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
