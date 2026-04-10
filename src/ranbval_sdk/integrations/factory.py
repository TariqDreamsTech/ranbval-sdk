"""
Single entrypoint: pick provider + optional env var name — no separate imports per vendor.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Callable, Literal

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
    provider: ProviderName | str,
    *,
    env_var: str | None = None,
    **kwargs: Any,
) -> Any:
    """
    Build one secure client instance for the given provider.

    Reads the API key from ``env_var`` (default: standard name per provider, e.g.
    ``OPENAI_API_KEY``). Use ``load_ranbval()`` first so ``.ranbval*`` values are in the environment.

    Examples::

        from ranbval_sdk import load_ranbval, secure_client
        load_ranbval()
        client = secure_client("openai")
        client = secure_client("openai", env_var="MY_LLM_KEY")
        client = secure_client("anthropic")
        db = secure_client("supabase", supabase_url=os.environ["SUPABASE_URL"])
    """
    p = str(provider).lower().strip()
    if p not in _DEFAULT_ENV:
        raise ValueError(
            f"Unknown provider {provider!r}. Choose one of: {', '.join(sorted(_DEFAULT_ENV))}.",
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
