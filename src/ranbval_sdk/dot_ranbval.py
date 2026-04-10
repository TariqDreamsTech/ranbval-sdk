"""Load configuration from a ``.ranbval`` file (like dotenv, Ranbval-specific name).

Plaintext keys stay readable in the file. ``ranbval.*`` tokens stay encoded on disk;
decryption still happens only inside the SDK at runtime (see ``crypto.safe_decrypt``).
"""

from __future__ import annotations

import os
from pathlib import Path


def find_ranbval_file(start: Path | str | None = None) -> str | None:
    """Return path to the nearest ``.ranbval`` searching ``start`` then parents."""
    cur = Path(start or os.getcwd()).resolve()
    for directory in [cur, *cur.parents]:
        candidate = directory / ".ranbval"
        if candidate.is_file():
            return str(candidate)
    return None


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


def load_ranbval(
    path: str | None = None,
    *,
    override: bool = False,
) -> bool:
    """
    Parse ``KEY=value`` lines into ``os.environ``.

    - Skips blank lines and ``#`` comments.
    - Strips optional single/double quotes around values.
    - **override** ``False`` (default): do not replace keys already set in the environment.
    - **override** ``True``: file wins over existing environment.

    Returns True if a file was found and read (even if no lines applied).
    """
    resolved = path or find_ranbval_file()
    if not resolved:
        return False

    with open(resolved, encoding="utf-8-sig") as f:
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

            if override or key not in os.environ or os.environ.get(key, "") == "":
                os.environ[key] = value

    return True
