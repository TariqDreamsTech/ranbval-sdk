"""High-level, ergonomic access to your ``.ranbval`` configuration surface.

Thin, readable wrappers over :func:`~ranbval_sdk.config.loader.load_ranbval` and
:func:`~ranbval_sdk.crypto.decrypt_key` so applications consume secrets with almost no
boilerplate — a :class:`Vault` mapping, an ``@inject`` decorator, a ``secrets()`` context
manager, and a :class:`Secret` descriptor. Decryption still happens only in
``crypto.safe_decrypt``; these are pure convenience. Secrets stay sealed by default.
"""

from __future__ import annotations

import contextlib
import functools
import inspect
import os
import threading
from dataclasses import dataclass
from typing import Any, Callable, Iterator, Protocol, runtime_checkable

from ranbval_sdk.config.loader import load_ranbval
from ranbval_sdk.crypto.secret_string import SecretString
from ranbval_sdk.exceptions import MissingKeyError

_loaded_modes: set[str] = set()
_load_lock = threading.Lock()


def _is_token(value: str | None) -> bool:
    """A value is a Ranbval vault token when it carries the ``ranbval.`` prefix."""
    return bool(value) and value.startswith("ranbval.")


def _ensure_env_loaded(mode: str | None = None) -> None:
    """Load ``.ranbval*`` files for ``mode`` exactly once per process (thread-safe)."""
    marker = mode or "__default__"
    if marker in _loaded_modes:
        return
    with _load_lock:
        if marker not in _loaded_modes:
            load_ranbval(mode=mode)
            _loaded_modes.add(marker)


def _resolve(env_var: str, *, reveal: bool) -> Any:
    """Decrypt a vault token or pass a plain value through; optionally reveal plaintext."""
    raw = os.environ.get(env_var)
    if raw is None:
        raise MissingKeyError(
            f"{env_var!r} is not set — did you create it in your .ranbval file?"
        )
    if not _is_token(raw):
        return raw  # ordinary, safe-to-commit config value
    from ranbval_sdk.crypto import decrypt_key

    secret = decrypt_key(env_var)
    return secret.use() if reveal else secret


@runtime_checkable
class SecretProvider(Protocol):
    """Anything that can hand back a plaintext secret by name."""

    def reveal(self, name: str) -> str: ...


@dataclass(frozen=True, slots=True)
class _Options:
    mode: str | None = None
    override: bool = False
    autoload: bool = True


class Vault:
    """A lazy, dunder-rich view over your configuration surface.

    Loads ``.ranbval*`` on first access, then serves values by attribute or item —
    plain config as ``str``, secrets as :class:`SecretString` (decrypted once, cached)::

        vault = Vault()
        vault.OPENAI_API_KEY            # -> SecretString
        vault["DATABASE_URL"]            # -> str (plain value)
        vault.reveal("OPENAI_API_KEY")  # -> plaintext str, one line
        "STRIPE_KEY" in vault            # membership test
    """

    __slots__ = ("_cache", "_loaded", "_opts", "_lock")

    def __init__(
        self, *, mode: str | None = None, override: bool = False, autoload: bool = True
    ):
        self._cache: dict[str, Any] = {}
        self._loaded = False
        self._lock = threading.Lock()
        self._opts = _Options(mode=mode, override=override, autoload=autoload)

    def _ensure_loaded(self) -> None:
        if self._opts.autoload and not self._loaded:
            with self._lock:
                if not self._loaded:
                    load_ranbval(mode=self._opts.mode, override=self._opts.override)
                    self._loaded = True

    def _get(self, name: str) -> Any:
        self._ensure_loaded()
        if name not in self._cache:
            self._cache[name] = _resolve(name, reveal=False)
        return self._cache[name]

    # -- mapping protocol ---------------------------------------------------
    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return self._get(name)
        except KeyError as exc:
            raise AttributeError(str(exc)) from exc

    def __getitem__(self, name: str) -> Any:
        return self._get(name)

    def __contains__(self, name: str) -> bool:
        self._ensure_loaded()
        return name in os.environ

    def __iter__(self) -> Iterator[str]:
        self._ensure_loaded()
        return iter(os.environ)

    # -- ergonomic helpers --------------------------------------------------
    def reveal(self, name: str) -> str:
        """Return the plaintext value in a single call (decrypts if needed)."""
        value = self._get(name)
        return value.use() if isinstance(value, SecretString) else value

    async def areveal(self, name: str) -> str:
        """Async, non-blocking :meth:`reveal` — decrypt + policy fetch run off-loop.

        The vault-token decrypt makes a network call for repo policy; on an event
        loop use this so FastAPI / asyncio callers don't block::

            key = await vault.areveal("OPENAI_API_KEY")
        """
        import asyncio

        return await asyncio.to_thread(self.reveal, name)

    def get(self, name: str, default: Any = None) -> Any:
        try:
            return self._get(name)
        except KeyError:
            return default

    def wipe(self) -> None:
        """Zero every cached secret from memory."""
        for value in self._cache.values():
            if isinstance(value, SecretString):
                value.wipe()
        self._cache.clear()

    def __repr__(self) -> str:  # never prints values — names only
        return f"<Vault loaded={self._loaded} cached={list(self._cache)}>"


#: Ready-to-use module singleton, e.g. ``ranbval_sdk.env.reveal("OPENAI_API_KEY")``.
env = Vault()


def inject(
    *names: str, reveal: bool = False, mode: str | None = None, **aliases: str
) -> Callable:
    """Decorator that injects decrypted secrets into a function as keyword arguments.

    ::

        @inject("OPENAI_API_KEY")             # -> kwarg `openai_api_key` (SecretString)
        def main(openai_api_key):
            client = OpenAI(api_key=openai_api_key.use())   # reveal only at the call site

    **Security-first default:** injects a sealed :class:`SecretString` — it refuses to be
    printed or logged, and wipes itself from memory. Plaintext is never handed out by
    default; call ``.use()`` at the exact point you pass it to an API. ``reveal=True`` is
    an explicit opt-in that injects a guarded ``_ProtectedStr`` (still refuses to print) —
    use it only when a library needs a plain ``str`` and you accept the trade-off.

    Works on sync **and** async functions. Any argument the caller passes explicitly is
    left untouched.
    """
    mapping: dict[str, str] = {name.lower(): name for name in names}
    mapping.update(aliases)

    def _fill(kwargs: dict[str, Any]) -> None:
        _ensure_env_loaded(mode)
        for param, env_var in mapping.items():
            if param not in kwargs:
                kwargs[param] = _resolve(env_var, reveal=reveal)

    def decorator(fn: Callable) -> Callable:
        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                _fill(kwargs)
                return await fn(*args, **kwargs)

            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            _fill(kwargs)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


@contextlib.contextmanager
def secrets(*, mode: str | None = None, override: bool = False) -> Iterator[Vault]:
    """Context manager: load config, yield a :class:`Vault`, wipe secrets on exit.

    ::

        with secrets() as vault:
            client = OpenAI(api_key=vault.reveal("OPENAI_API_KEY"))
        # every decrypted secret is zeroed here
    """
    vault = Vault(mode=mode, override=override, autoload=True)
    vault._ensure_loaded()
    try:
        yield vault
    finally:
        vault.wipe()


def iter_secrets(*, mode: str | None = None) -> Iterator[tuple[str, SecretString]]:
    """Yield ``(name, SecretString)`` for every vault token in the environment.

    ::

        for name, secret in iter_secrets():
            print(name)          # names only — values stay sealed
    """
    _ensure_env_loaded(mode)
    from ranbval_sdk.crypto import decrypt_key

    for name, raw in os.environ.items():
        if _is_token(raw):
            yield name, decrypt_key(name)


# The declarative, class-based API (``Secret`` / ``SecretConfig``) lives in
# ``ranbval_sdk.config.declarative`` — a distinct access style from the imperative
# ``Vault`` / ``inject`` / ``secrets`` above. Both are re-exported from ``config``.
