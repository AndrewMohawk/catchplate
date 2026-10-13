#!/usr/bin/env python3
"""Run the standalone managed-client tests in the ordinary offline lane."""
from pathlib import Path
from importlib.metadata import PackageNotFoundError, version
import sys
import unittest

directory = Path(__file__).resolve().parents[1] / "examples" / "managed-client"
sys.path.insert(0, str(directory))

if __name__ == "__main__":
    # Dependency provisioning belongs to the networked setup phase, never this
    # offline test. Fail instead of skipping/mocking the real Requests check.
    try:
        for line in (directory / "requirements.txt").read_text().splitlines():
            if not line or line.startswith("#"):
                continue
            name, expected = line.split("==")
            if version(name) != expected:
                raise ValueError("managed-client dependency version mismatch")
    except (PackageNotFoundError, ValueError):
        raise SystemExit("Install both locked test dependency inputs before the offline managed-client suite") from None
    suite = unittest.defaultTestLoader.discover(str(directory), pattern="test_*.py")
    if not suite.countTestCases():
        raise SystemExit("managed-client tests missing")
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)
