"""Telemetry decorators and context manager.

Wrap a call site once and let usage be reported automatically — no manual
``emit_telemetry()`` after every request.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
from typing import Any, Callable, Iterator, Optional

from ranbval_sdk.telemetry.client import emit_telemetry


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
