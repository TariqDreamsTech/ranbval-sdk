"""Load configuration from layered ``.ranbval*`` files (dotenv-style, Ranbval-specific).

Plaintext keys stay readable in the file. ``ranbval.*`` tokens stay encoded on disk;
decryption still happens only inside the SDK at runtime (see ``crypto.safe_decrypt``).

Call ``load_ranbval()`` explicitly after importing the package (no import-time side effects).
"""

from __future__ import annotations

import contextlib
import functools
import inspect
import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol, runtime_checkable

from ranbval_sdk.secret_string import SecretString


def resolve_ranbval_mode(mode: str | None = None) -> str:
    """
    Which mode-specific file to merge: ``development`` | ``production`` | custom.

    Order: explicit ``mode`` arg → ``RANBVAL_ENV`` → ``ENVIRONMENT`` → ``ENV`` → ``development``.
    """
    if mode is not None and str(mode).strip():
        return str(mode).strip().lower()
    for key in ("RANBVAL_ENV", "ENVIRONMENT", "ENV"):
        v = os.environ.get(key)
        if v and str(v).strip():
            return str(v).strip().lower()
    return "development"


def _strip_inline_comment(value: str) -> str:
    v = value.strip()
    if "#" not in v:
        return v
    in_single = in_double = False
    for i, ch in enumerate(v):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return v[:i].strip().rstrip()
    return v


def _parse_ranbval_file(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    with open(path, encoding="utf-8-sig") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if not key:
                continue
            value = _strip_inline_comment(value)
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            out[key] = value
    return out


def _layer_paths(directory: Path, mode: str) -> list[Path]:
    """
    Merge order (later files override earlier for the same key):

    1. ``.ranbval`` — shared defaults
    2. ``.ranbval.{mode}`` — e.g. ``.ranbval.development`` or ``.ranbval.production``
    3. ``.ranbval.local`` — machine-specific (gitignore)
    4. ``.ranbval.{mode}.local`` — mode + local (highest priority among files)
    """
    m = (mode or "development").lower().strip() or "development"
    candidates = [
        directory / ".ranbval",
        directory / f".ranbval.{m}",
        directory / ".ranbval.local",
        directory / f".ranbval.{m}.local",
    ]
    return [p for p in candidates if p.is_file()]


def find_ranbval_directory(start: Path | str | None = None) -> Path | None:
    """
    Nearest directory (cwd → parents) that contains ``.ranbval`` or any ``.ranbval.*`` file.
    """
    cur = Path(start or os.getcwd()).resolve()
    for directory in [cur, *cur.parents]:
        if (directory / ".ranbval").is_file():
            return directory
        for p in directory.glob(".ranbval.*"):
            if p.is_file():
                return directory
    return None


def find_ranbval_file(start: Path | str | None = None) -> str | None:
    """Path to base ``.ranbval`` if present, else the first existing layer file in the config root."""
    root = find_ranbval_directory(start)
    if not root:
        return None
    base = root / ".ranbval"
    if base.is_file():
        return str(base)
    m = resolve_ranbval_mode(None)
    layers = _layer_paths(root, m)
    return str(layers[0]) if layers else None


def _normalize_project_name(name: str) -> str:
    """Convert project name to uppercase env prefix: 'my-app' → 'MY_APP'."""
    return re.sub(r"[^A-Z0-9]", "_", name.upper().strip()).strip("_")


def load_ranbval(
    path: str | None = None,
    *,
    mode: str | None = None,
    start: str | Path | None = None,
    override: bool = False,
    project_secret: str | None = None,
    project_name: str | None = None,
) -> bool:
    """
    Load ``KEY=value`` pairs into ``os.environ``.

    **Single file:** pass ``path`` to that file only.

    **Layered (default):** omit ``path``. Finds config root with ``find_ranbval_directory(start)``,
    resolves ``mode`` with ``resolve_ranbval_mode(mode)``, then merges (in order):

    ``.ranbval`` → ``.ranbval.{mode}`` → ``.ranbval.local`` → ``.ranbval.{mode}.local``

    Later files override earlier ones for duplicate keys. Then each key is applied with:

    - ``override=False`` (default): skip if the key is already set and non-empty in ``os.environ``.
    - ``override=True``: file-merged values always win over existing ``os.environ``.

    **Project context** (optional but recommended when using multiple projects):

    - ``project_secret``: the ``ranbval-proj-…`` key for this project. Stored as
      ``RANBVAL_PROJECT_SECRET`` so ``safe_decrypt`` and ``secure_client`` pick it up
      automatically without an extra env var.
    - ``project_name``: short name for this project (e.g. ``"myapp"``). Stored as
      ``RANBVAL_PROJECT_NAME`` and normalised to an uppercase env prefix
      (``"my-app"`` → ``"MY_APP_"``). Convention: name your vault tokens in ``.ranbval``
      with this prefix so origin is always clear::

          # .ranbval
          MYAPP_OPENAI_KEY=ranbval.xxxx.…ahsan
          MYAPP_STRIPE_KEY=ranbval.yyyy.…ahsan

          # app.py
          load_ranbval(project_secret="ranbval-proj-…", project_name="myapp")

      If a token's env-var prefix does not match the loaded project name, ``get_project_key``
      will raise ``ValueError`` so cross-project key mix-ups are caught at load time.

    Returns True if at least one file was read.
    """
    if path:
        p = Path(path)
        if not p.is_file():
            return False
        merged = _parse_ranbval_file(p)
    else:
        root = find_ranbval_directory(start)
        if not root:
            return False
        m = resolve_ranbval_mode(mode)
        layers = _layer_paths(root, m)
        if not layers:
            return False
        merged = {}
        for layer_path in layers:
            merged.update(_parse_ranbval_file(layer_path))

    for key, value in merged.items():
        if override or key not in os.environ or os.environ.get(key, "") == "":
            os.environ[key] = value

    # Inject project context into env so downstream helpers don't need extra args.
    if project_secret is not None:
        ps = project_secret.strip()
        if override or not os.environ.get("RANBVAL_PROJECT_SECRET"):
            os.environ["RANBVAL_PROJECT_SECRET"] = ps

    if project_name is not None:
        prefix = _normalize_project_name(project_name)
        if override or not os.environ.get("RANBVAL_PROJECT_NAME"):
            os.environ["RANBVAL_PROJECT_NAME"] = project_name
        if override or not os.environ.get("RANBVAL_PROJECT_PREFIX"):
            os.environ["RANBVAL_PROJECT_PREFIX"] = prefix

    # Move all *_PROJECT_SECRET keys from os.environ into the in-memory secret store.
    # This removes them from os.environ so they can't be read by os.environ inspection.
    from ranbval_sdk.crypto import _store_project_secret
    for key in list(os.environ.keys()):
        if key.endswith("_PROJECT_SECRET") and os.environ.get(key):
            _store_project_secret(key, os.environ[key])

    # Patch builtins.print and sys.stdout.write to raise if a protected secret
    # value is passed directly — prevents accidental plaintext output.
    from ranbval_sdk.secret_string import install_output_guards
    install_output_guards()

    return True


def get_project_key(env_var: str) -> str:
    """
    Return the value of ``env_var`` after verifying it belongs to the loaded project.

    If ``RANBVAL_PROJECT_PREFIX`` is set (via ``load_ranbval(project_name=…)``), the
    env var **must** start with that prefix — otherwise ``ValueError`` is raised so
    cross-project mix-ups are caught immediately.

    Example::

        load_ranbval(project_secret="ranbval-proj-…", project_name="myapp")
        token = get_project_key("MYAPP_OPENAI_KEY")   # OK
        token = get_project_key("OTHERAPP_STRIPE_KEY") # ValueError: wrong project prefix
    """
    prefix = os.environ.get("RANBVAL_PROJECT_PREFIX", "")
    if prefix and not env_var.upper().startswith(prefix + "_"):
        project_name = os.environ.get("RANBVAL_PROJECT_NAME", prefix)
        raise ValueError(
            f"Key {env_var!r} does not belong to project {project_name!r} "
            f"(expected prefix {prefix + '_'!r}). "
            "Pass the correct project_name to load_ranbval() or use the right .ranbval file."
        )
    value = os.environ.get(env_var, "")
    if not value:
        raise ValueError(
            f"Environment variable {env_var!r} is not set. "
            "Check your .ranbval file or load_ranbval() call."
        )
    return value


# ---------------------------------------------------------------------------
# High-level, ergonomic config access
#
# Thin, readable wrappers over ``load_ranbval`` + ``crypto.decrypt_key`` so apps
# consume their ``.ranbval`` surface with almost no boilerplate. Decryption still
# happens only in ``crypto.safe_decrypt`` — these are pure convenience.
# ---------------------------------------------------------------------------

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
        raise KeyError(f"{env_var!r} is not set — did you create it in your .ranbval file?")
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

    def __init__(self, *, mode: str | None = None, override: bool = False, autoload: bool = True):
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


def inject(*names: str, reveal: bool = False, mode: str | None = None, **aliases: str) -> Callable:
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


class Secret:
    """Descriptor for declaring a secret on a config class — decrypted lazily, cached.

    ::

        class Config(SecretConfig):
            openai = Secret("OPENAI_API_KEY")
            stripe = Secret("STRIPE_KEY", reveal=True)   # plaintext str

        Config.openai        # -> SecretString (cached on the class)
        Config.stripe        # -> plaintext str
    """

    __slots__ = ("env_var", "reveal", "attr")

    def __init__(self, env_var: str, *, reveal: bool = False):
        self.env_var = env_var
        self.reveal = reveal
        self.attr = env_var

    def __set_name__(self, owner: type, name: str) -> None:
        self.attr = name

    def __get__(self, obj: Any, owner: type | None = None) -> Any:
        holder = owner if owner is not None else type(obj)
        _ensure_env_loaded()
        store = holder._secret_cache
        if self.env_var not in store:
            store[self.env_var] = _resolve(self.env_var, reveal=False)
        value = store[self.env_var]
        if self.reveal and isinstance(value, SecretString):
            return value.use()
        return value


class SecretConfig:
    """Base for declarative secret config classes; each subclass gets its own cache."""

    _secret_cache: dict[str, Any] = {}
    _secret_fields: tuple[str, ...] = ()

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        cls._secret_cache = {}
        cls._secret_fields = tuple(
            name for name, value in vars(cls).items() if isinstance(value, Secret)
        )
