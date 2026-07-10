"""``ranbval init`` — scaffold a starter ``.ranbval`` and gitignore ``.ranbval.local``."""

from __future__ import annotations

import argparse
from pathlib import Path

from ranbval_sdk.cli import _shared


def handle(args: argparse.Namespace) -> int:
    root = Path.cwd()
    target = root / ".ranbval"
    if target.exists() and not args.force:
        print(f"{target} already exists — use --force to overwrite.")
        return 1
    target.write_text(_shared.TEMPLATE, encoding="utf-8")
    print(_shared.color(f"✓ wrote {target}", "green"))

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
    print("\nNext: paste a token from the dashboard as SECRET_… / PROXY_…, then `ranbval check`.")
    return 0
