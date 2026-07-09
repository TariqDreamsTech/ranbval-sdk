"""Records which keys the user declared ``[public]`` / ``[secrets]`` / ``[proxy]`` in ``.ranbval``.

``.ranbval`` files may group keys under three section headers, by how much the value may ever
be seen in plaintext::

    [public]                 # plaintext config — anyone may read it (e.g. shown in a UI)
    DATABASE_URL=postgresql://localhost/mydb

    [secrets]                # encrypted at rest; your app CAN decrypt & view it at runtime
    DASHBOARD_PASSWORD=ranbval.4ii0a0.p1GO...ahsan

    [proxy]                  # encrypted; plaintext NEVER reaches the client — proxy-only
    OPENAI_API_KEY=ranbval.7cc2b9.xNz...stripe

The parser (:func:`ranbval_sdk.config.loader._parse_ranbval_file`) reports the section each key
came from; :func:`load_ranbval` records it here so accessors can honour the declared intent:

- ``[public]`` — :func:`ranbval_sdk.config.access.public` returns the plaintext; ``decrypt_key``
  passes it through unchanged.
- ``[secrets]`` — ``decrypt_key(name).use()`` returns the plaintext (the app may view/use it);
  ``public()`` refuses it.
- ``[proxy]`` — ``decrypt_key`` **refuses** to produce plaintext; the value is usable only via
  :func:`ranbval_sdk.proxy_request` (the real key is injected server-side). ``public()`` refuses it.

Keys outside any section are *unlabelled* (kind ``None``) and keep the historical auto-detect
behaviour (``ranbval.*`` ⇒ secret, otherwise plain).
"""

from __future__ import annotations

import threading

# Section-header aliases → canonical kind. Case-insensitive, matched by the loader.
PUBLIC_SECTIONS = frozenset({"public", "plain", "plaintext", "config"})
SECRET_SECTIONS = frozenset({"secret", "secrets", "vault", "encrypted"})
PROXY_SECTIONS = frozenset({"proxy", "proxy-only", "proxyonly", "sealed"})

_lock = threading.Lock()
_declared: dict[str, str] = {}  # env-var name -> "public" | "secret" | "proxy"


def record(kinds: dict[str, str]) -> None:
    """Merge a batch of ``name -> kind`` declarations from a parsed file (later wins)."""
    with _lock:
        _declared.update(kinds)


def kind_of(name: str) -> str | None:
    """Return ``"public"``, ``"secret"``, ``"proxy"``, or ``None`` if never declared."""
    return _declared.get(name)


def is_public(name: str) -> bool:
    """True only when the key was explicitly declared under a ``[public]`` section."""
    return _declared.get(name) == "public"


def is_secret(name: str) -> bool:
    """True only when the key was explicitly declared under a ``[secrets]`` section."""
    return _declared.get(name) == "secret"


def is_proxy(name: str) -> bool:
    """True only when the key was explicitly declared under a ``[proxy]`` section."""
    return _declared.get(name) == "proxy"


def public_names() -> list[str]:
    """Every key the user declared ``[public]`` (sorted, stable)."""
    with _lock:
        return sorted(n for n, k in _declared.items() if k == "public")


def proxy_names() -> list[str]:
    """Every key the user declared ``[proxy]`` (sorted, stable)."""
    with _lock:
        return sorted(n for n, k in _declared.items() if k == "proxy")


def clear() -> None:
    """Forget all declarations (test/reset helper)."""
    with _lock:
        _declared.clear()
