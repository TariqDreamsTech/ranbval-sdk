"""Classify every ``.ranbval`` variable by a **required name prefix**.

Each variable declares, in its own name, how much of its value may ever be seen in plaintext —
there are no ``[section]`` headers and no parser state. The class is derived purely from the
prefix::

    PUBLIC_DATABASE_URL = postgresql://localhost/db   # plaintext config — public() returns it
    SECRET_DASHBOARD_PW = ranbval.4ii0a0.p1GO…ahsan    # encrypted; decrypt_key().use() reveals it
    PROXY_OPENAI_KEY    = ranbval.7cc2b9.xNz…ahsan     # encrypted; plaintext NEVER on the client

Accessors honour the declared class:

- ``PUBLIC_*`` — :func:`ranbval_sdk.public` returns the plaintext; ``decrypt_key`` refuses it.
- ``SECRET_*`` — ``decrypt_key(name).use()`` returns the plaintext; ``public()`` refuses it.
- ``PROXY_*``  — ``decrypt_key`` **refuses**; usable only via :func:`ranbval_sdk.proxy_request`
  (``proxy_token(name)``). ``public()`` refuses it.

Two families are **exempt** from the prefix rule because they are infrastructure, not user
secrets to classify: ``RANBVAL_*`` (SDK settings like ``RANBVAL_HOST``) and ``*_PROJECT_SECRET``
(the ``ranbval-proj-…`` project key). Any other unprefixed key in a ``.ranbval`` file is rejected
at load time (see :func:`ranbval_sdk.config.loader.load_ranbval`).
"""

from __future__ import annotations

import os

#: Required class prefixes (matched case-insensitively at the start of the variable name).
PUBLIC_PREFIX = "PUBLIC_"
SECRET_PREFIX = "SECRET_"
PROXY_PREFIX = "PROXY_"


def kind_of(name: str) -> str | None:
    """Return ``"public"`` / ``"secret"`` / ``"proxy"`` from the name prefix, else ``None``."""
    upper = name.upper()
    if upper.startswith(PUBLIC_PREFIX):
        return "public"
    if upper.startswith(SECRET_PREFIX):
        return "secret"
    if upper.startswith(PROXY_PREFIX):
        return "proxy"
    return None


def is_public(name: str) -> bool:
    """True when *name* starts with ``PUBLIC_``."""
    return kind_of(name) == "public"


def is_secret(name: str) -> bool:
    """True when *name* starts with ``SECRET_``."""
    return kind_of(name) == "secret"


def is_proxy(name: str) -> bool:
    """True when *name* starts with ``PROXY_``."""
    return kind_of(name) == "proxy"


def is_exempt(name: str) -> bool:
    """Infrastructure keys that need no class prefix: ``RANBVAL_*`` and ``*_PROJECT_SECRET``."""
    upper = name.upper()
    return upper.startswith("RANBVAL_") or upper.endswith("_PROJECT_SECRET")


def is_classified(name: str) -> bool:
    """True when *name* carries a valid class prefix or is an exempt infrastructure key."""
    return kind_of(name) is not None or is_exempt(name)


def public_names() -> list[str]:
    """Every ``PUBLIC_*`` variable currently in the environment (sorted, stable)."""
    return sorted(n for n in os.environ if is_public(n))


def proxy_names() -> list[str]:
    """Every ``PROXY_*`` variable currently in the environment (sorted, stable)."""
    return sorted(n for n in os.environ if is_proxy(n))
