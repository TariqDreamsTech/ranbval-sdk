"""``ranbval check`` — lint ``.ranbval``: classification, competing loaders, value mismatches."""

from __future__ import annotations

import argparse
import sys

from ranbval_sdk.cli import _shared
from ranbval_sdk.config import manifest
from ranbval_sdk.config.loader import (
    _COMPETING_LOADERS,
    _parse_ranbval_file,
    find_ranbval_directory,
)


def handle(args: argparse.Namespace) -> int:
    root = find_ranbval_directory()
    if not root:
        print(_shared.color("✗ no .ranbval file found (run `ranbval init`).", "red"))
        return 1

    base = root / ".ranbval"
    try:
        values = _parse_ranbval_file(base) if base.is_file() else {}
    except Exception as e:  # section header etc.
        print(_shared.color(f"✗ {e}", "red"))
        return 1

    errors: list[str] = []
    warnings_: list[str] = []
    counts = {"public": 0, "secret": 0, "proxy": 0}

    for name, value in sorted(values.items()):
        kind = manifest.kind_of(name)
        if kind is None:
            if manifest.is_exempt(name):
                continue
            errors.append(f"{name}: no class prefix (PUBLIC_/SECRET_/PROXY_)")
            continue
        counts[kind] += 1
        is_token = value.startswith("ranbval.")
        if kind == "public" and is_token:
            warnings_.append(f"{name}: PUBLIC_ but value is an encrypted token — rename to SECRET_/PROXY_")
        elif kind in ("secret", "proxy") and value and not is_token:
            warnings_.append(f"{name}: {kind.upper()}_ but value is plaintext (not a ranbval.* token)")

    competing = sorted(p.name for p in root.glob(".env*") if p.is_file() and p.name != ".ranbval")
    if competing:
        errors.append(f"competing env file(s) next to .ranbval: {', '.join(competing)}")
    loaded = sorted({pkg for mod, pkg in _COMPETING_LOADERS.items() if mod in sys.modules})
    if loaded:
        warnings_.append(f"non-Ranbval env loader imported: {', '.join(loaded)}")

    print(
        f"{_shared.color('classified', 'dim')}: "
        f"{counts['public']} public, {counts['secret']} secret, {counts['proxy']} proxy"
    )
    for w in warnings_:
        print(_shared.color(f"⚠ {w}", "yellow"))
    for e in errors:
        print(_shared.color(f"✗ {e}", "red"))
    if errors:
        print(_shared.color(f"\n{len(errors)} error(s).", "red"))
        return 1
    print(_shared.color("\n✓ all variables classified.", "green"))
    return 0
