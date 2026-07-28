"""``ranbval init`` — scaffold a starter ``.ranbval`` and gitignore ``.ranbval.local``."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from ranbval_sdk.cli import _shared

_LOCAL_TEMPLATE = """\
# .ranbval.local — MACHINE-ONLY. Never commit this file.
#
# This is the root key that unseals every token in .ranbval. It is the one value that cannot
# be encrypted (the key that encrypts it would just take its place), so it is kept out of git
# instead — and out of reach of other users on this machine, which is why this file is 0600.

RANBVAL_PROJECT_SECRET=paste-your-ranbval-proj-…-key-here
"""


def _write_private(path: Path, text: str) -> None:
    """Create ``path`` readable only by its owner, without ever existing world-readable.

    ``open()`` then ``chmod()`` would leave a window where the default umask (usually 022, giving
    0644) applies to a file that already holds the project secret. Opening with mode 0o600 up
    front closes that window. On Windows the mode argument is ignored by the OS, which is why
    the loader's warning is POSIX-only.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


def handle(args: argparse.Namespace) -> int:
    root = Path.cwd()
    target = root / ".ranbval"
    if target.exists() and not args.force:
        print(f"{target} already exists — use --force to overwrite.")
        return 1
    target.write_text(_shared.TEMPLATE, encoding="utf-8")
    print(_shared.color(f"✓ wrote {target}", "green"))

    # Create the root-key file too, at 0600 from birth. Left to the user it is created by hand
    # under the default umask — 0644, readable by every account on the box — and the file holding
    # the key to the whole vault is the last one that should be.
    local = root / ".ranbval.local"
    if local.exists():
        print(_shared.color(f"• {local.name} already exists — left untouched", "dim"))
    else:
        _write_private(local, _LOCAL_TEMPLATE)
        print(_shared.color(f"✓ wrote {local} (0600 — owner only)", "green"))

    gitignore = root / ".gitignore"
    entries = [".ranbval.local", ".ranbval.*.local"]
    existing = gitignore.read_text(encoding="utf-8") if gitignore.exists() else ""
    missing = [e for e in entries if e not in existing.splitlines()]
    if missing:
        with open(gitignore, "a", encoding="utf-8") as f:
            if existing and not existing.endswith("\n"):
                f.write("\n")
            f.write("\n# Ranbval — never commit machine-local secrets\n")
            f.write("\n".join(missing) + "\n")
        print(_shared.color(f"✓ added {', '.join(missing)} to .gitignore", "green"))
    print(
        "\nNext: put your project secret in .ranbval.local, paste a token from the dashboard "
        "as SECRET_… / PROXY_…, then run `ranbval check`."
    )
    return 0
