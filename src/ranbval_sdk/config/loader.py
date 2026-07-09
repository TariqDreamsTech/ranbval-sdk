"""Load configuration from layered ``.ranbval*`` files (dotenv-style, Ranbval-specific).

Plaintext keys stay readable in the file. ``ranbval.*`` tokens stay encoded on disk;
decryption still happens only inside the SDK at runtime (see ``crypto.safe_decrypt``).

Call ``load_ranbval()`` explicitly after importing the package (no import-time side effects).
"""

from __future__ import annotations

import os
import re
import warnings
from pathlib import Path

from ranbval_sdk.config import manifest
from ranbval_sdk.exceptions import RanbvalConfigError


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


_SECTION_RE = re.compile(r"^\[\s*(?P<name>[A-Za-z0-9_-]+)\s*\]$")


def _section_kind(header: str) -> str | None:
    """Map a ``[section]`` header to ``"public"`` / ``"secret"`` / ``"proxy"``, or ``None``."""
    name = header.lower()
    if name in manifest.PUBLIC_SECTIONS:
        return "public"
    if name in manifest.SECRET_SECTIONS:
        return "secret"
    if name in manifest.PROXY_SECTIONS:
        return "proxy"
    return None  # unknown header — keys under it stay unlabelled (auto-detect)


def _parse_ranbval_file(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Parse one ``.ranbval`` file into ``(values, kinds)``.

    ``values`` is ``name -> value``; ``kinds`` is ``name -> "public"|"secret"`` for keys that
    appear under a recognised ``[public]`` / ``[secret]`` section. Keys before any section (or
    under an unknown header) are omitted from ``kinds`` so they keep the auto-detect behaviour.
    """
    out: dict[str, str] = {}
    kinds: dict[str, str] = {}
    section: str | None = None
    with open(path, encoding="utf-8-sig") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            header = _SECTION_RE.match(line)
            if header:
                section = _section_kind(header.group("name"))
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
            if section is not None:
                kinds[key] = section
    return out, kinds


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


def _warn_declaration_mismatches(values: dict[str, str], kinds: dict[str, str]) -> None:
    """Warn when a value contradicts its declared section (helps catch copy/paste mistakes)."""
    for key, kind in kinds.items():
        value = values.get(key, "")
        if kind == "public" and value.startswith("ranbval."):
            warnings.warn(
                f"{key!r} is declared under [public] but its value is an encrypted "
                "vault token. Public keys are meant to be plaintext — move it to [secrets].",
                stacklevel=3,
            )
        elif kind == "secret" and value and not value.startswith("ranbval."):
            warnings.warn(
                f"{key!r} is declared under [secrets] but its value is plaintext "
                "(not a 'ranbval.*' token), so it will not be decrypted. "
                "Move it to [public] or replace it with a vault token.",
                stacklevel=3,
            )
        elif kind == "proxy" and value and not value.startswith("ranbval."):
            warnings.warn(
                f"{key!r} is declared under [proxy] but its value is plaintext "
                "(not a 'ranbval.*' token). A [proxy] secret must be an encrypted vault "
                "token — its plaintext is only ever injected server-side via the proxy.",
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

    Returns True if at least one file was read.
    """
    if path:
        p = Path(path)
        if not p.is_file():
            return False
        merged, merged_kinds = _parse_ranbval_file(p)
    else:
        root = find_ranbval_directory(start)
        if not root:
            return False
        m = resolve_ranbval_mode(mode)
        layers = _layer_paths(root, m)
        if not layers:
            return False
        merged = {}
        merged_kinds = {}
        for layer_path in layers:
            values, kinds = _parse_ranbval_file(layer_path)
            merged.update(values)
            merged_kinds.update(kinds)

    # Record [public]/[secret] declarations and flag values that contradict them.
    manifest.record(merged_kinds)
    _warn_declaration_mismatches(merged, merged_kinds)

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
        from ranbval_sdk.crypto.secret_string import install_output_guards

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
