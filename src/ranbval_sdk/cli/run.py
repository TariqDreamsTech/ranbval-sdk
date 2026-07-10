"""``ranbval run -- CMD`` — load ``.ranbval`` into the environment, then exec ``CMD``.

Secrets live only in this process (and the child it spawns); nothing is written to disk and no
value is ever printed.
"""

from __future__ import annotations

import argparse
import subprocess

from ranbval_sdk.cli import _shared
from ranbval_sdk.config.loader import load_ranbval


def handle(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":  # argparse.REMAINDER keeps the separator
        command = command[1:]
    if not command:
        print("usage: ranbval run -- COMMAND [args...]")
        return 2
    try:
        load_ranbval(sole_loader=not args.allow_other_loaders)
    except Exception as e:
        print(_shared.color(f"✗ {e}", "red"))
        return 1
    return subprocess.call(command)
