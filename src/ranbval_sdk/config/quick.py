"""``use`` — one word per secret, nothing else to write.

The full-control API (``load_ranbval`` → ``decrypt_key`` → ``.use()``, plus ``reveal_scope`` and
``enforcement_scope``) is correct but long, and every line of it is a line someone can get wrong.
For the ordinary case — hand a credential to a client library — this is the whole program::

    from ranbval_sdk import use
    from supabase import create_client

    supabase = create_client(use.SUPABASE_URL, use.SUPABASE_TOKEN)

``use.NAME`` does all of it: loads ``.ranbval`` on first touch, finds the key whatever prefix it
carries, decrypts it, caches it, and returns a value the client can use directly.

Name resolution
---------------
Write the short name. ``use.SUPABASE_TOKEN`` finds ``SECRET_SUPABASE_TOKEN`` — the ``SECRET_``,
``PUBLIC_`` and bare spellings are all tried, so renaming a key's prefix in ``.ranbval`` does not
break your code. Exact names still work (``use.SECRET_SUPABASE_TOKEN``).

What it does NOT relax
----------------------
- ``PROXY_`` secrets are refused. They are meant never to be decrypted on this machine, so
  handing one back as a string would defeat the point — use ``proxy_token`` + ``proxy_request``
  (or :mod:`ranbval_sdk.integrations.httpx_transport`) instead.
- The returned value is still a sealed ``_ProtectedStr``: ``repr`` is masked, pickling raises,
  and iteration / slicing / ``str()`` still trip the extraction guards. You get shorter code,
  not weaker code.
- Every access is still written to the audit log and seen by the access monitor.

Honest limit, unchanged from the long form: ``f"{use.SUPABASE_TOKEN}"`` returns the plaintext,
because a client library has to be able to build a header out of it. If a value must never exist
in this process, that is what ``PROXY_`` is for.
"""

from __future__ import annotations

import threading
from typing import Any

from ranbval_sdk.exceptions import MissingKeyError, RanbvalConfigError

__all__ = ["Use", "use"]

#: Tried in order against the short name the caller wrote.
_PREFIXES = ("", "SECRET_", "PUBLIC_")


class Use:
    """Attribute/item access over ``.ranbval``, returning values ready to hand to a client.

    ``use`` is the ready-made singleton; construct your own only to pin a stage::

        staging = Use(mode="staging")
        client = create_client(staging.SUPABASE_URL, staging.SUPABASE_TOKEN)
    """

    __slots__ = ("_mode", "_cache", "_lock", "_loaded")

    def __init__(self, *, mode: str | None = None) -> None:
        self._mode = mode
        self._cache: dict[str, Any] = {}
        self._lock = threading.Lock()
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if not self._loaded:
                from ranbval_sdk.config.loader import load_ranbval

                load_ranbval(mode=self._mode)
                self._loaded = True

    def _resolve_name(self, short: str) -> str:
        """Return the real ``.ranbval`` key for the (possibly prefix-less) name written by the
        caller, or raise a MissingKeyError naming every spelling that was tried."""
        import os

        for prefix in _PREFIXES:
            candidate = f"{prefix}{short}"
            if candidate in os.environ:
                return candidate
        if f"PROXY_{short}" in os.environ or short.startswith("PROXY_"):
            raise RanbvalConfigError(
                f"{short!r} is a PROXY_ secret — it is never decrypted on this machine, which is "
                "the whole point of the PROXY_ prefix. Send the request through Ranbval instead: "
                "proxy_request(token=proxy_token(...), ...), or pass "
                "ranbval_httpx_client(...) to your client library.",
                code="proxy_secret_not_revealable",
            )
        tried = ", ".join(repr(f"{p}{short}") for p in _PREFIXES)
        raise MissingKeyError(
            f"No key for {short!r} in your .ranbval — tried {tried}. "
            "Check the name, or run `ranbval check` to list what is loaded."
        )

    def _get(self, short: str) -> Any:
        self._ensure_loaded()
        if short not in self._cache:
            import os

            from ranbval_sdk.config.access import _is_token

            name = self._resolve_name(short)
            raw = os.environ.get(name)
            if not _is_token(raw):
                self._cache[short] = raw  # ordinary, safe-to-commit config value
            else:
                from ranbval_sdk.crypto import decrypt_key

                # .use() here, not the SecretString: the caller is handing this straight to a
                # client library, and a SecretString would fail every isinstance(x, str) check.
                self._cache[short] = decrypt_key(name).use()
        return self._cache[short]

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        return self._get(name)

    def __getitem__(self, name: str) -> Any:
        return self._get(name)

    def __contains__(self, name: str) -> bool:
        self._ensure_loaded()
        try:
            self._resolve_name(name)
        except (MissingKeyError, RanbvalConfigError):
            return False
        return True

    def get(self, name: str, default: Any = None) -> Any:
        """Like ``dict.get`` — the value, or ``default`` when the key is absent."""
        try:
            return self._get(name)
        except (MissingKeyError, RanbvalConfigError):
            return default

    def wipe(self) -> None:
        """Drop every cached plaintext. Later accesses decrypt again."""
        with self._lock:
            self._cache.clear()

    def __repr__(self) -> str:  # names would be harmless, values never
        return f"Use(mode={self._mode!r}, cached={len(self._cache)})"


#: Ready-made singleton — ``from ranbval_sdk import use``.
use = Use()
