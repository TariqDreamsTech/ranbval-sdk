"""Load configuration from layered ``.ranbval*`` files (dotenv-style, Ranbval-specific).

Plaintext keys stay readable in the file. ``ranbval.*`` tokens stay encoded on disk;
decryption still happens only inside the SDK at runtime (see ``crypto.safe_decrypt``).

Call ``load_ranbval()`` explicitly after importing the package (no import-time side effects).
"""

from __future__ import annotations

import os
from pathlib import Path


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


def load_ranbval(
    path: str | None = None,
    *,
    mode: str | None = None,
    start: str | Path | None = None,
    override: bool = False,
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

    return True
