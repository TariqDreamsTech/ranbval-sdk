"""POST /api/telemetry — use with any HTTP stack after ``load_ranbval()``."""

from __future__ import annotations

import asyncio
import contextlib
import functools
import inspect
import json
import os
import socket
import sys
import threading
from typing import Any, Callable, Iterator, Optional
from urllib.parse import urlparse
import urllib.request

from ranbval_sdk.defaults import DEFAULT_RANBVAL_HOST, warn_telemetry_send_failed
from ranbval_sdk import http_tls
from ranbval_sdk.repo_policy import get_git_remote_origin as _get_git_remote


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
        off = (os.environ.get("RANBVAL_TELEMETRY") or "").strip().lower()
        if off in ("0", "false", "off", "no"):
            return

        salt = client_salt
        if not salt and vault_token_env:
            raw = os.environ.get(str(vault_token_env).strip(), "")
            salt = salt_from_ranbval_token(raw)
        if not salt:
            return

        h = (host_url or os.environ.get("RANBVAL_HOST") or DEFAULT_RANBVAL_HOST).rstrip("/")
        repo_path = os.getcwd()
        machine_name = socket.gethostname()
        git_url = _get_git_remote()

        parsed = urlparse(h)
        transport = (parsed.scheme or "http").lower()
        ci_environment = any(
            os.environ.get(k)
            for k in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "JENKINS_URL")
        )

        sec = {
            "event_kind": event_kind,
            "sdk_version": _sdk_version(),
            "client_platform": sys.platform,
            "python_version": sys.version.split()[0],
            "transport": transport,
            "vault_token_format": "ranbval",
            "git_branch": _get_git_branch(),
            "ci_environment": bool(ci_environment),
        }

        payload = {
            "client_salt": salt,
            "machine_name": machine_name,
            "repo_path": repo_path,
            "git_url": git_url,
            "model_used": model_used,
            "prompt_tokens": int(prompt_tokens),
            "completion_tokens": int(completion_tokens),
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
            with http_tls.urlopen(req, timeout=5) as resp:
                resp.read()
        except Exception as e:
            warn_telemetry_send_failed(h, e)

    if background:
        threading.Thread(target=_post, daemon=True).start()
    else:
        _post()


# ---------------------------------------------------------------------------
# High-level, ergonomic telemetry
#
# Wrap a call site once and let usage be reported automatically — no manual
# emit_telemetry() after every request.
# ---------------------------------------------------------------------------


def track(
    *,
    client_salt: Optional[str] = None,
    vault_token_env: Optional[str] = None,
    model_used: str = "custom.request",
    event_kind: str = "custom.request",
    host_url: Optional[str] = None,
    background: bool = True,
) -> Callable:
    """Decorator: emit telemetry automatically after the wrapped call returns.

    ::

        @track(vault_token_env="OPENAI_API_KEY", model_used="gpt-4o")
        def ask(prompt): ...

    Fire-and-forget by default (``background=True``). Works on sync **and** async
    functions; telemetry is skipped silently if no salt can be resolved.
    """

    def _emit() -> None:
        emit_telemetry(
            client_salt=client_salt,
            vault_token_env=vault_token_env,
            model_used=model_used,
            event_kind=event_kind,
            host_url=host_url,
            background=background,
        )

    def decorator(fn: Callable) -> Callable:
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                result = await fn(*args, **kwargs)
                _emit()
                return result

            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            result = fn(*args, **kwargs)
            _emit()
            return result

        return wrapper

    return decorator


@contextlib.contextmanager
def tracked(
    *,
    client_salt: Optional[str] = None,
    vault_token_env: Optional[str] = None,
    model_used: str = "custom.request",
    event_kind: str = "custom.request",
    host_url: Optional[str] = None,
    background: bool = True,
) -> Iterator[None]:
    """Context manager: emit telemetry once when the block exits.

    ::

        with tracked(vault_token_env="OPENAI_API_KEY"):
            client.chat.completions.create(...)
    """
    try:
        yield
    finally:
        emit_telemetry(
            client_salt=client_salt,
            vault_token_env=vault_token_env,
            model_used=model_used,
            event_kind=event_kind,
            host_url=host_url,
            background=background,
        )


async def aemit_telemetry(**kwargs: Any) -> None:
    """Async, non-blocking telemetry for event loops (FastAPI, asyncio).

    Same arguments as :func:`emit_telemetry`, but the blocking POST runs on a worker
    thread via ``asyncio.to_thread`` so the event loop is never stalled::

        await aemit_telemetry(vault_token_env="OPENAI_API_KEY", model_used="gpt-4o")
    """
    kwargs.setdefault("background", False)
    await asyncio.to_thread(emit_telemetry, **kwargs)
