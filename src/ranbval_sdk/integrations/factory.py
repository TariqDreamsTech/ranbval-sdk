"""
Single entry: wrap **your** SDK class (OpenAI, Stripe, Anthropic, …) — Ranbval ships zero vendor deps.
"""

from __future__ import annotations

import os
from typing import Any, Type


def secure_client(
    sdk_class: Type[Any],
    *,
    env_var: str,
    key_kwarg: str,
    method_path_to_patch: str | None = None,
    **kwargs: Any,
) -> Any:
    """
    Build one secure client: read Ranbval token (or plain key) from ``env_var``, decrypt if needed,
    pass to ``sdk_class`` via ``key_kwarg``, return an instance.

    You install **openai**, **stripe**, **anthropic**, etc. in your own project — this package does not.

    Examples::

        import openai
        from ranbval_sdk import load_ranbval, secure_client

        load_ranbval()
        client = secure_client(
            openai.OpenAI,
            env_var="OPENAI_API_KEY",
            key_kwarg="api_key",
            method_path_to_patch="chat.completions.create",
        )

        import anthropic
        claude = secure_client(
            anthropic.Anthropic,
            env_var="ANTHROPIC_API_KEY",
            key_kwarg="api_key",
            method_path_to_patch="messages.create",
        )
    """
    ev = str(env_var).strip()
    kk = str(key_kwarg).strip()
    if not ev or not kk:
        raise ValueError("secure_client requires non-empty env_var and key_kwarg.")
    if os.environ.get(ev) in (None, ""):
        raise ValueError(
            f"secure_client({sdk_class.__name__}): set {ev!r} in the environment or .ranbval.",
        )

    from ranbval_sdk.integrations.universal import build_secure_client

    Proxy = build_secure_client(sdk_class, ev, kk, method_path_to_patch)
    return Proxy(**kwargs)
