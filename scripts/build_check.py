#!/usr/bin/env python3
"""Build the distribution into a temporary directory and validate it with twine.

Deliberately does **not** build into ./dist. A stale wheel left there from an earlier version is
a live hazard: `twine upload dist/*` would publish every version sitting in that directory, and a
version published to PyPI can never be replaced. This project has already shipped two versions
that way. Building into a temp directory that is discarded means the hook can never contribute to
that failure mode.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(cmd: list[str]) -> int:
    result = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
    return result.returncode


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        if run([sys.executable, "-m", "build", "--outdir", tmp, "-q"]) != 0:
            print("✗ build failed")
            return 1

        artifacts = sorted(Path(tmp).iterdir())
        if run([sys.executable, "-m", "twine", "check", *map(str, artifacts)]) != 0:
            print("✗ twine check failed")
            return 1

        print(f"✓ built and validated: {', '.join(a.name for a in artifacts)}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
