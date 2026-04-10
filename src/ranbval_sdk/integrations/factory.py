"""
Single entrypoint: built-in providers or any SDK class — all driven from env via one API.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Callable, Literal, Type

ProviderName = Literal["openai", "anthropic", "mistral", "supabase"]

_DEFAULT_ENV: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "supabase": "SUPABASE_KEY",
}


@contextmanager
def _alias_env(canonical: str, alias_from: str | None):
    """Temporarily set ``canonical`` from ``alias_from`` if they differ (for client init)."""
    if not alias_from or alias_from == canonical:
        yield
        return
    val = os.environ.get(alias_from)
    if val is None or val == "":
        raise ValueError(
            f"Ranbval secure_client: environment variable {alias_from!r} is missing or empty "
            f"(needed for {canonical!r}).",
        )
    old = os.environ.get(canonical)
    os.environ[canonical] = val
    try:
        yield
    finally:
        if old is None:
            del os.environ[canonical]
        else:
            os.environ[canonical] = old


def secure_client(
    provider: ProviderName | str | None = None,
    *,
    env_var: str | None = None,
    sdk_class: Type[Any] | None = None,
    key_kwarg: str | None = None,
    method_path_to_patch: str | None = None,
    **kwargs: Any,
) -> Any:
    """
    One entry for every client — built-in or custom.

    **Built-in** (string provider)::

        secure_client("openai")
        secure_client("openai", env_var="MY_LLM_KEY")
        secure_client("anthropic")

    **Custom** (any third-party class — same as ``build_secure_client``, no extra factory in your code)::

        import stripe
        secure_client(
            sdk_class=stripe.StripeClient,
            env_var="STRIPE_SECRET_KEY",
            key_kwarg="api_key",
        )

    Optional ``method_path_to_patch`` (e.g. ``"charges.create"``) enables platform telemetry on that call.

    Call ``load_ranbval()`` first so ``.ranbval*`` populates the environment.
    """
    if sdk_class is not None:
        if not env_var or not str(env_var).strip():
            raise ValueError("secure_client(sdk_class=...): env_var is required.")
        if not key_kwarg or not str(key_kwarg).strip():
            raise ValueError("secure_client(sdk_class=...): key_kwarg is required (constructor kwarg for the secret).")
        ev = str(env_var).strip()
        if os.environ.get(ev) in (None, ""):
            raise ValueError(
                f"secure_client(sdk_class={sdk_class.__name__}): set {ev!r} in the environment or .ranbval.",
            )
        from ranbval_sdk.integrations.universal import build_secure_client

        Proxy = build_secure_client(
            sdk_class,
            ev,
            str(key_kwarg).strip(),
            method_path_to_patch,
        )
        return Proxy(**kwargs)

    if provider is None or str(provider).strip() == "":
        raise ValueError(
            "secure_client: pass a built-in provider (e.g. 'openai') or sdk_class=... with env_var and key_kwarg.",
        )

    p = str(provider).lower().strip()
    if p not in _DEFAULT_ENV:
        raise ValueError(
            f"Unknown provider {provider!r}. Use one of {', '.join(sorted(_DEFAULT_ENV))} "
            f"or sdk_class=YourSDK with env_var and key_kwarg.",
        )

    canonical = _DEFAULT_ENV[p]
    source = env_var or canonical
    if os.environ.get(source) in (None, ""):
        raise ValueError(
            f"Ranbval secure_client({p!r}): set {source!r} in the environment or .ranbval.",
        )

    def _build_openai() -> Any:
        from ranbval_sdk.integrations.openai_client import SecureOpenAI

        return SecureOpenAI(**kwargs)

    def _build_anthropic() -> Any:
        from ranbval_sdk.integrations.platforms import SecureAnthropic

        if SecureAnthropic is None:
            raise ImportError("Install the anthropic package to use secure_client('anthropic').")
        return SecureAnthropic(**kwargs)

    def _build_mistral() -> Any:
        from ranbval_sdk.integrations.platforms import SecureMistral

        if SecureMistral is None:
            raise ImportError("Install the mistralai package to use secure_client('mistral').")
        return SecureMistral(**kwargs)

    def _build_supabase() -> Any:
        from ranbval_sdk.integrations.platforms import SecureSupabase

        if SecureSupabase is None:
            raise ImportError("Install the supabase package to use secure_client('supabase').")
        return SecureSupabase(**kwargs)

    builders: dict[str, Callable[[], Any]] = {
        "openai": _build_openai,
        "anthropic": _build_anthropic,
        "mistral": _build_mistral,
        "supabase": _build_supabase,
    }

    with _alias_env(canonical, None if source == canonical else source):
        return builders[p]()
