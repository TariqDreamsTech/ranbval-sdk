"""Records which keys the user declared ``[public]`` vs ``[secret]`` in ``.ranbval``.

``.ranbval`` files may group keys under section headers::

    [public]                 # intentionally plaintext — never decrypted
    DATABASE_URL=postgresql://localhost/mydb
    CORS_ORIGINS=https://a.com,https://b.com

    [secrets]                # encrypted vault tokens
    OPENAI_API_KEY=ranbval.4ii0a0.p1GO...ahsan

The parser (:func:`ranbval_sdk.config.loader._parse_ranbval_file`) reports the section each
key came from; :func:`load_ranbval` records it here so accessors can honour the declared
intent — e.g. :func:`ranbval_sdk.config.access.public` refuses to hand back a key the user
declared as a ``[secret]``. Keys outside any section are *unlabelled* (kind ``None``) and keep
the historical auto-detect behaviour (``ranbval.*`` ⇒ secret, otherwise plain).
"""

from __future__ import annotations

import threading

# Section-header aliases → canonical kind. Case-insensitive, matched by the loader.
PUBLIC_SECTIONS = frozenset({"public", "plain", "plaintext", "config"})
SECRET_SECTIONS = frozenset({"secret", "secrets", "vault", "encrypted"})

_lock = threading.Lock()
_declared: dict[str, str] = {}  # env-var name -> "public" | "secret"


def record(kinds: dict[str, str]) -> None:
    """Merge a batch of ``name -> kind`` declarations from a parsed file (later wins)."""
    with _lock:
        _declared.update(kinds)


def kind_of(name: str) -> str | None:
    """Return ``"public"``, ``"secret"``, or ``None`` if the key was never declared."""
    return _declared.get(name)


def is_public(name: str) -> bool:
    """True only when the key was explicitly declared under a ``[public]`` section."""
    return _declared.get(name) == "public"


def is_secret(name: str) -> bool:
    """True only when the key was explicitly declared under a ``[secret]`` section."""
    return _declared.get(name) == "secret"


def public_names() -> list[str]:
    """Every key the user declared ``[public]`` (sorted, stable)."""
    with _lock:
        return sorted(n for n, k in _declared.items() if k == "public")


def clear() -> None:
    """Forget all declarations (test/reset helper)."""
    with _lock:
        _declared.clear()
