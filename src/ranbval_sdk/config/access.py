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
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from ranbval_sdk.config.loader import load_ranbval
from ranbval_sdk.crypto.secret_string import SecretString
from ranbval_sdk.exceptions import MissingKeyError, RanbvalConfigError

_loaded_modes: set[str] = set()
_load_lock = threading.Lock()

#: Sentinel so ``public(name)`` can tell "no default given" apart from ``default=None``.
_UNSET = object()


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

    # -- public (unencrypted) access ---------------------------------------
    def public(self, name: str, default: Any = _UNSET) -> str:
        """Return a **plaintext** config value the public way — same policy as :func:`public`.

        A key declared ``SECRET_`` (or any ``ranbval.*`` token) is refused, so a secret can
        never be read through this public path::

            env.public("DATABASE_URL")     # -> plain str
            env.public("OPENAI_API_KEY")   # -> RanbvalConfigError (it's a secret)
        """
        self._ensure_loaded()
        return _lookup_public(name, default)

    def public_config(self) -> dict[str, str]:
        """Every ``PUBLIC_``-declared key as ``{name: plaintext}`` (secrets never included)."""
        self._ensure_loaded()
        return _lookup_public_config()

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


# -- public (unencrypted) configuration --------------------------------------
def _lookup_public(name: str, default: Any) -> str:
    """The single place that enforces the public-access policy (env assumed loaded).

    A key declared ``SECRET_`` or ``PROXY_`` — or any ``ranbval.*`` token value — is
    **never** returned here; all raise. This is what guarantees a secret can never leak
    through a public path, no matter which surface (function or ``Vault`` method) was used.
    """
    from ranbval_sdk.config import manifest

    if manifest.is_secret(name):
        raise RanbvalConfigError(
            f"{name!r} is a SECRET_ value; use decrypt_key({name!r}) instead. "
            "public() only returns plaintext configuration.",
            code="not_a_public_key",
        )
    if manifest.is_proxy(name):
        raise RanbvalConfigError(
            f"{name!r} is a PROXY_ value; its plaintext never reaches the client. "
            f"Use proxy_request(token=proxy_token({name!r}), ...) instead.",
            code="not_a_public_key",
        )

    raw = os.environ.get(name)
    if raw is None:
        if default is not _UNSET:
            return default
        raise MissingKeyError(
            f"{name!r} is not set — did you create it in your .ranbval file?"
        )
    if _is_token(raw):
        raise RanbvalConfigError(
            f"{name!r} holds an encrypted vault token, not a plaintext value. "
            f"Use decrypt_key({name!r}) to decrypt it.",
            code="not_a_public_key",
        )
    return raw


def _lookup_public_config() -> dict[str, str]:
    """Collect all ``PUBLIC_``-declared plaintext values (env assumed loaded)."""
    from ranbval_sdk.config import manifest

    out: dict[str, str] = {}
    for name in manifest.public_names():
        raw = os.environ.get(name)
        if raw is not None and not _is_token(raw):
            out[name] = raw
    return out


def public(name: str, default: Any = _UNSET, *, mode: str | None = None) -> str:
    """Return a **plaintext** config value — never decrypts, never a :class:`SecretString`.

    For values you intentionally keep unencrypted (``DATABASE_URL``, ``CORS_ORIGINS``,
    ``PORT``, …). Give them a ``PUBLIC_`` prefix in ``.ranbval`` to make the intent explicit::

        # .ranbval
        PUBLIC_DATABASE_URL=postgresql://localhost/mydb
        PUBLIC_CORS_ORIGINS=https://a.com,https://b.com

        # app.py
        from ranbval_sdk import public
        db = public("PUBLIC_DATABASE_URL")          # -> plain str

    Safety rails:

    - If the key is ``SECRET_`` or ``PROXY_``, this raises — use ``decrypt_key`` / the proxy.
    - If the value looks like an encrypted ``ranbval.*`` token, this raises rather than
      handing back ciphertext (you almost certainly meant :func:`~ranbval_sdk.decrypt_key`).

    ``default`` is returned when the key is absent (otherwise :class:`MissingKeyError`).
    """
    _ensure_env_loaded(mode)
    return _lookup_public(name, default)


def public_config(*, mode: str | None = None) -> dict[str, str]:
    """Return every key declared under ``PUBLIC_`` as a ``{name: plaintext}`` dict.

    ::

        cfg = public_config()
        app.add_middleware(CORSMiddleware, allow_origins=cfg["CORS_ORIGINS"].split(","))
    """
    _ensure_env_loaded(mode)
    return _lookup_public_config()


def is_public(name: str) -> bool:
    """True when *name* carries the ``PUBLIC_`` prefix."""
    from ranbval_sdk.config import manifest

    return manifest.is_public(name)


def is_proxy(name: str) -> bool:
    """True when *name* carries the ``PROXY_`` prefix."""
    from ranbval_sdk.config import manifest

    return manifest.is_proxy(name)


def proxy_token(name: str, *, mode: str | None = None) -> str:
    """Return the raw encrypted ``ranbval.*`` token for a ``PROXY_`` secret.

    ``PROXY_`` secrets are never decrypted on the client — you pass this encrypted token to
    :func:`~ranbval_sdk.proxy_request`, and Ranbval injects the real key server-side::

        from ranbval_sdk import proxy_request, proxy_token
        proxy_request(
            token=proxy_token("PROXY_OPENAI_KEY"),
            target_url="https://api.openai.com/v1/chat/completions",
            inject_as="bearer",
            body={...},
        )

    The returned value is only the ciphertext token — useless without the project secret and
    an allowlisted repo, so it is safe to hold and pass around.

    Prefix-aware, to match ``public()`` / ``decrypt_key()``: a ``PUBLIC_`` or ``SECRET_`` key is
    **refused** (those are read with ``public()`` / ``decrypt_key().use()``). Only ``PROXY_``
    keys are accepted. Raises if the value is not an encrypted ``ranbval.*`` token.
    """
    from ranbval_sdk.config import manifest

    _ensure_env_loaded(mode)

    if manifest.is_public(name):
        raise RanbvalConfigError(
            f"{name!r} is a PUBLIC_ value; read it with public({name!r}). "
            "proxy_token() is only for PROXY_ vault tokens.",
            code="not_a_proxy_token",
        )
    if manifest.is_secret(name):
        raise RanbvalConfigError(
            f"{name!r} is a SECRET_ token — decrypt it locally with decrypt_key({name!r}). "
            "Rename it to PROXY_ if its plaintext should never reach the client.",
            code="not_a_proxy_token",
        )

    raw = os.environ.get(name)
    if raw is None:
        raise MissingKeyError(
            f"{name!r} is not set — did you create it in your .ranbval file?"
        )
    if not _is_token(raw):
        raise RanbvalConfigError(
            f"{name!r} is not an encrypted 'ranbval.*' token, so it cannot be used via the "
            "proxy. Put a vault token under PROXY_, or read it with public()/decrypt_key().",
            code="not_a_proxy_token",
        )
    return raw


# The declarative, class-based API (``Secret`` / ``SecretConfig``) lives in
# ``ranbval_sdk.config.declarative`` — a distinct access style from the imperative
# ``Vault`` / ``inject`` / ``secrets`` above. Both are re-exported from ``config``.
