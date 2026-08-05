#!/usr/bin/env python3
"""Fail if the version in pyproject.toml has no CHANGELOG entry.

The same gate CI applies, run before the push instead of after it. A release that reaches PyPI
without release notes cannot be corrected — the version number is spent either way — so this is
worth catching at the cheapest possible moment.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    changelog = (ROOT / "CHANGELOG.md").read_text()

    if re.search(rf"^## \[{re.escape(version)}\]", changelog, re.MULTILINE):
        print(f"OK: {version} has a CHANGELOG entry")
        return 0

    released = re.findall(r"^## \[([^\]]+)\]", changelog, re.MULTILINE)[:3]
    print(f"FAIL: pyproject version {version} has no '## [{version}]' entry in CHANGELOG.md")
    print(f"  most recent entries: {', '.join(released) or 'none'}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
