#!/usr/bin/env python3
"""Audit this package's declared dependencies for known vulnerabilities.

Deliberately audits `[project].dependencies` rather than the ambient environment. `pip-audit` with
no arguments reports every package installed in whatever virtualenv happens to be active — the
developer's editor plugins, an unrelated project's leftovers — none of which ship with this SDK.
Those findings are real for that machine and irrelevant to this package, and a hook that reports
things the author cannot fix is a hook that gets skipped.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    deps = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["dependencies"]
    if not deps:
        print("✓ no declared dependencies to audit")
        return 0

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(deps) + "\n")
        requirements = f.name

    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip_audit", "-r", requirements, "--progress-spinner", "off"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
    finally:
        Path(requirements).unlink(missing_ok=True)

    if result.returncode != 0:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        print(f"\n✗ vulnerable dependencies among: {', '.join(deps)}")
        return 1

    print(f"✓ no known vulnerabilities in: {', '.join(deps)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
