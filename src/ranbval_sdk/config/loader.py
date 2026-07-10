"""Load configuration from layered ``.ranbval*`` files (dotenv-style, Ranbval-specific).

Plaintext keys stay readable in the file. ``ranbval.*`` tokens stay encoded on disk;
decryption still happens only inside the SDK at runtime (see ``crypto.safe_decrypt``).

Call ``load_ranbval()`` explicitly after importing the package (no import-time side effects).
"""

from __future__ import annotations

import os
import re
import sys
import warnings
from pathlib import Path

from ranbval_sdk.config import manifest
from ranbval_sdk.exceptions import RanbvalConfigError

# Ranbval must be the *only* configuration/secret loader. These are the competing dotenv-style
# loaders we can actually detect once imported; ``os.getenv`` itself is plain Python and cannot
# be forbidden (the SDK uses it internally too).
_COMPETING_LOADERS = {
    "dotenv": "python-dotenv",
    "decouple": "python-decouple (from decouple import config)",
    "environs": "environs",
    "dynaconf": "dynaconf",
}


def _enforce_sole_loader(root: Path | None) -> None:
    """Refuse to run alongside another env loader: a competing ``.env*`` file, or a known
    env-loader library already imported. Keeps Ranbval the single source of secrets/config.

    Honest limit: a bare ``os.getenv("X")`` cannot be detected or forbidden — it is ordinary
    Python. This catches the two competing mechanisms that *can* be seen.
    """
    if root is not None:
        competing = sorted(
            p.name for p in root.glob(".env*") if p.is_file() and p.name != ".ranbval"
        )
        if competing:
            raise RanbvalConfigError(
                f"Competing env file(s) found next to your .ranbval: {', '.join(competing)}. "
                "Ranbval must be the only config source — move those values into .ranbval "
                "(with PUBLIC_/SECRET_/PROXY_ prefixes) and delete the .env file(s). "
                "Pass load_ranbval(sole_loader=False) only if you must keep them.",
                code="competing_env_file",
            )
    imported = sorted({pkg for mod, pkg in _COMPETING_LOADERS.items() if mod in sys.modules})
    if imported:
        raise RanbvalConfigError(
            f"A non-Ranbval env loader is imported: {', '.join(imported)}. Ranbval should be "
            "the sole secret loader — remove it and load everything via load_ranbval(). "
            "Pass load_ranbval(sole_loader=False) if a dependency pulls it in unavoidably.",
            code="competing_env_loader",
        )


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
            return v[:i].strip()
    return v


def _parse_ranbval_file(path: Path) -> dict[str, str]:
    """Parse one ``.ranbval`` file into ``{name: value}``.

    Classification comes from each key's **name prefix** (``PUBLIC_`` / ``SECRET_`` / ``PROXY_``),
    not from any ``[section]`` header — so there is no section state to track here.
    """
    out: dict[str, str] = {}
    with open(path, encoding="utf-8-sig") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                raise RanbvalConfigError(
                    f"{path.name}: '[section]' headers are no longer supported. Classify each "
                    "variable by a name prefix instead — PUBLIC_/SECRET_/PROXY_ "
                    "(e.g. SECRET_OPENAI_KEY=ranbval.…). See the README 'Variable classification'.",
                    code="section_not_supported",
                )
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


def _validate_classification(values: dict[str, str]) -> None:
    """Reject any ``.ranbval`` key that lacks a class prefix (and isn't exempt infrastructure).

    Every variable must start with ``PUBLIC_`` / ``SECRET_`` / ``PROXY_``. ``RANBVAL_*`` and
    ``*_PROJECT_SECRET`` are exempt. This is what guarantees every value's exposure class is
    declared in its own name — no unclassified, ambiguous keys reach the app.
    """
    unclassified = [name for name in values if not manifest.is_classified(name)]
    if unclassified:
        listed = ", ".join(sorted(unclassified))
        raise RanbvalConfigError(
            f"These .ranbval variables have no class prefix: {listed}. Every variable must start "
            "with PUBLIC_ (plaintext), SECRET_ (decrypt locally), or PROXY_ (server-side only) — "
            "e.g. rename FOO to PUBLIC_FOO / SECRET_FOO / PROXY_FOO. "
            "(RANBVAL_* and *_PROJECT_SECRET are exempt.)",
            code="unclassified_key",
        )


def _warn_value_mismatches(values: dict[str, str]) -> None:
    """Warn when a value contradicts its name prefix (helps catch copy/paste mistakes)."""
    for key, value in values.items():
        kind = manifest.kind_of(key)
        is_token = value.startswith("ranbval.")
        if kind == "public" and is_token:
            warnings.warn(
                f"{key!r} is PUBLIC_ but its value is an encrypted vault token. Public keys are "
                "meant to be plaintext — rename it to SECRET_ or PROXY_.",
                stacklevel=3,
            )
        elif kind == "secret" and value and not is_token:
            warnings.warn(
                f"{key!r} is SECRET_ but its value is plaintext (not a 'ranbval.*' token), so it "
                "will not be decrypted. Rename it to PUBLIC_ or replace it with a vault token.",
                stacklevel=3,
            )
        elif kind == "proxy" and value and not is_token:
            warnings.warn(
                f"{key!r} is PROXY_ but its value is plaintext (not a 'ranbval.*' token). A proxy "
                "secret must be an encrypted vault token — its plaintext is only injected "
                "server-side via the proxy.",
                stacklevel=3,
            )


def load_ranbval(
    path: str | None = None,
    *,
    mode: str | None = None,
    start: str | Path | None = None,
    override: bool = False,
    project_secret: str | None = None,
    project_name: str | None = None,
    guard_stdout: bool = False,
    sole_loader: bool = True,
    remote: bool = False,
    api_key: str | None = None,
    host: str | None = None,
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
      ``RANBVAL_PROJECT_SECRET`` so ``safe_decrypt`` / ``decrypt_key`` pick it up
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

    **Hardening** (optional):

    - ``guard_stdout=False`` (default): no global patching. Secrets still mask themselves
      via ``SecretString.__str__``/``__repr__``.
    - ``guard_stdout=True``: patch ``builtins.print`` / ``sys.stdout.write`` so passing a
      revealed secret straight to them raises ``PermissionError``. Opt-in because it mutates
      global builtins and can surprise other libraries / test capture.

    **Sole loader** (default on):

    - ``sole_loader=True`` (default): Ranbval must be the *only* config/secret loader. Raises
      ``RanbvalConfigError`` if a competing ``.env*`` file sits next to your ``.ranbval``, or if a
      dotenv-style library (``python-dotenv``/``decouple``/``environs``/``dynaconf``) is already
      imported. (A bare ``os.getenv`` is plain Python and cannot be detected — not covered.)
    - ``sole_loader=False``: skip that check (only if a dependency pulls one in unavoidably).

    **Variable classification:** every key in a ``.ranbval`` file must start with ``PUBLIC_``,
    ``SECRET_``, or ``PROXY_`` (``RANBVAL_*`` and ``*_PROJECT_SECRET`` are exempt). Any
    unclassified key — or a legacy ``[section]`` header — raises ``RanbvalConfigError``.

    **Remote config** (optional):

    - ``remote=True``: instead of reading local files, fetch the project's env-set from the
      Ranbval control plane and load it through the same pipeline. The owner authenticates with
      ``project_secret``; a developer with ``api_key`` (a ``ranbval-dev-…`` token). ``SECRET_``/
      ``PROXY_`` values arrive as encrypted ``ranbval.*`` tokens and are decrypted client-side
      exactly as from a file. ``host`` overrides the control-plane URL.

    Returns True if at least one file was read (always True for a successful ``remote=True`` load).
    """
    if remote:
        # Remote is just another SOURCE: fetch the env-set from the control plane, then run the
        # identical validation + crypto pipeline below. No local files are read.
        from ranbval_sdk.remote.client import fetch_env_set

        ps = (project_secret or os.environ.get("RANBVAL_PROJECT_SECRET") or "").strip()
        merged = fetch_env_set(project_secret=ps or None, api_key=api_key, host=host)
        config_root = None
    elif path:
        p = Path(path)
        if not p.is_file():
            return False
        config_root = p.parent
        merged = _parse_ranbval_file(p)
    else:
        root = find_ranbval_directory(start)
        if not root:
            return False
        config_root = root
        m = resolve_ranbval_mode(mode)
        layers = _layer_paths(root, m)
        if not layers:
            return False
        merged = {}
        for layer_path in layers:
            merged.update(_parse_ranbval_file(layer_path))

    # Ranbval must be the sole config/secret loader — refuse to run beside a competing .env file
    # or an imported dotenv-style library (see _enforce_sole_loader for the honest limits).
    if sole_loader:
        _enforce_sole_loader(config_root)

    # Every variable must declare its class via a name prefix (PUBLIC_/SECRET_/PROXY_); reject
    # anything unclassified, then warn on values that contradict their prefix.
    _validate_classification(merged)
    _warn_value_mismatches(merged)

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
    from ranbval_sdk.crypto.cipher import _store_project_secret

    for key in list(os.environ.keys()):
        if key.endswith("_PROJECT_SECRET") and os.environ.get(key):
            _store_project_secret(key, os.environ[key])

    # Optional, opt-in hardening: patch builtins.print / sys.stdout.write to raise if a
    # protected secret is passed directly. Off by default because patching global builtins
    # is invasive; SecretString already masks itself via __str__/__repr__ without it.
    if guard_stdout:
        from ranbval_sdk.crypto.output_guards import install_output_guards

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
        raise RanbvalConfigError(
            f"Key {env_var!r} does not belong to project {project_name!r} "
            f"(expected prefix {prefix + '_'!r}). "
            "Pass the correct project_name to load_ranbval() or use the right .ranbval file."
        )
    value = os.environ.get(env_var, "")
    if not value:
        raise RanbvalConfigError(
            f"Environment variable {env_var!r} is not set. "
            "Check your .ranbval file or load_ranbval() call."
        )
    return value
