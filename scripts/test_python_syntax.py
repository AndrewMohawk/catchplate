#!/usr/bin/env python3
"""Parse every tracked Python source without importing or executing it.

Run only after the source freeze, alongside the no-build engineering checks.
This is a syntax check, not runtime or production verification.
"""
from __future__ import annotations

import ast
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    inventory = subprocess.check_output(
        ["git", "ls-files", "-z", "--", "*.py"], cwd=ROOT
    )
    names = [name.decode("utf-8") for name in inventory.split(b"\0") if name]
    if not names:
        raise RuntimeError("tracked Python source inventory is empty")
    failures = []
    for name in names:
        try:
            ast.parse((ROOT / name).read_bytes(), filename=name)
        except (SyntaxError, ValueError) as exc:
            failures.append(f"{name}: {exc}")
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f"Parsed {len(names)} tracked Python sources; {len(failures)} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
