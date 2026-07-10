"""``ranbval`` command-line tool — scaffold, lint, and run with your ``.ranbval`` config.

Commands (all offline — no network, no plaintext ever printed):

    ranbval init            # create a starter .ranbval and gitignore .ranbval.local
    ranbval check           # lint .ranbval: classification, competing loaders, value mismatches
    ranbval run -- CMD ...  # load .ranbval into the environment, then exec CMD

Each command lives in its own module (:mod:`~ranbval_sdk.cli.init`, :mod:`~ranbval_sdk.cli.check`,
:mod:`~ranbval_sdk.cli.run`); this module only wires them to the argument parser. Dependency-free
(argparse + stdlib).
"""

from __future__ import annotations

import argparse

from ranbval_sdk.cli import check, init, run


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ranbval", description="Ranbval config CLI.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="create a starter .ranbval and gitignore .ranbval.local")
    p_init.add_argument("--force", action="store_true", help="overwrite an existing .ranbval")
    p_init.set_defaults(func=init.handle)

    p_check = sub.add_parser("check", help="lint .ranbval (classification, clashes, mismatches)")
    p_check.set_defaults(func=check.handle)

    p_run = sub.add_parser("run", help="load .ranbval into the environment, then run a command")
    p_run.add_argument("--allow-other-loaders", action="store_true", help="skip the sole-loader check")
    p_run.add_argument("command", nargs=argparse.REMAINDER, help="command to run (after --)")
    p_run.set_defaults(func=run.handle)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
