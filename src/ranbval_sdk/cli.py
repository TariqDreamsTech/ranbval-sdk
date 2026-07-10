"""``ranbval`` command-line tool — scaffold, lint, and run with your ``.ranbval`` config.

Commands (all offline — no network, no plaintext ever printed):

    ranbval init            # create a starter .ranbval and gitignore .ranbval.local
    ranbval check           # lint .ranbval: classification, competing loaders, value mismatches
    ranbval run -- CMD ...  # load .ranbval into the environment, then exec CMD

Kept dependency-free (argparse + stdlib) so ``pip install ranbval-sdk`` is enough.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from ranbval_sdk.config import manifest
from ranbval_sdk.config.loader import (
    _COMPETING_LOADERS,
    _parse_ranbval_file,
    find_ranbval_directory,
    load_ranbval,
)

_TEMPLATE = """\
# .ranbval — Ranbval configuration. Every variable must start with a class prefix:
#   PUBLIC_  plaintext config (public() reads it)
#   SECRET_  encrypted; decrypt_key("SECRET_…").use() reveals it locally
#   PROXY_   encrypted; plaintext never on the client — proxy_token("PROXY_…") + proxy
# RANBVAL_* and *_PROJECT_SECRET are exempt (infrastructure).

# Keep the project secret in .ranbval.local (git-ignored), not here.
# RANBVAL_PROJECT_SECRET=ranbval-proj-xxxx

PUBLIC_APP_NAME=my-app
# SECRET_OPENAI_KEY=ranbval.xxxx.blob.ahsan     # paste a token from the Ranbval dashboard
# PROXY_STRIPE_KEY=ranbval.yyyy.blob.ahsan
"""

_GREEN, _RED, _YELLOW, _DIM, _RESET = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def _color(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if sys.stdout.isatty() else text


def cmd_init(args: argparse.Namespace) -> int:
    root = Path.cwd()
    target = root / ".ranbval"
    if target.exists() and not args.force:
        print(f"{target} already exists — use --force to overwrite.")
        return 1
    target.write_text(_TEMPLATE, encoding="utf-8")
    print(_color(f"✓ wrote {target}", _GREEN))

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
        print(_color(f"✓ added {', '.join(missing)} to .gitignore", _GREEN))
    print("\nNext: paste a token from the dashboard as SECRET_… / PROXY_…, then `ranbval check`.")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    root = find_ranbval_directory()
    if not root:
        print(_color("✗ no .ranbval file found (run `ranbval init`).", _RED))
        return 1

    base = root / ".ranbval"
    try:
        values = _parse_ranbval_file(base) if base.is_file() else {}
    except Exception as e:  # section header etc.
        print(_color(f"✗ {e}", _RED))
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
        f"{_color('classified', _DIM)}: "
        f"{counts['public']} public, {counts['secret']} secret, {counts['proxy']} proxy"
    )
    for w in warnings_:
        print(_color(f"⚠ {w}", _YELLOW))
    for e in errors:
        print(_color(f"✗ {e}", _RED))
    if errors:
        print(_color(f"\n{len(errors)} error(s).", _RED))
        return 1
    print(_color("\n✓ all variables classified.", _GREEN))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":  # argparse.REMAINDER keeps the separator
        command = command[1:]
    if not command:
        print("usage: ranbval run -- COMMAND [args...]")
        return 2
    try:
        load_ranbval(sole_loader=not args.allow_other_loaders)
    except Exception as e:
        print(_color(f"✗ {e}", _RED))
        return 1
    # Secrets are now in this process's environment; the child inherits them and nothing
    # touches disk. We never print any value.
    return subprocess.call(command)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ranbval", description="Ranbval config CLI.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="create a starter .ranbval and gitignore .ranbval.local")
    p_init.add_argument("--force", action="store_true", help="overwrite an existing .ranbval")
    p_init.set_defaults(func=cmd_init)

    p_check = sub.add_parser("check", help="lint .ranbval (classification, clashes, mismatches)")
    p_check.set_defaults(func=cmd_check)

    p_run = sub.add_parser("run", help="load .ranbval into the environment, then run a command")
    p_run.add_argument(
        "--allow-other-loaders", action="store_true", help="skip the sole-loader check"
    )
    p_run.add_argument("command", nargs=argparse.REMAINDER, help="command to run (after --)")
    p_run.set_defaults(func=cmd_run)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
