#!/usr/bin/env python3
"""Explicit offline migration of a stopped ordinary Serverware copy."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-data", "target-data", "source-gate-data", "target-gate-data"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--public-url", required=True)
    parser.add_argument("--proxy-url", required=True)
    parser.add_argument("--acknowledge-offline-source", action="store_true")
    parser.add_argument("--ca-mode", choices=("preserve", "replace"), default="preserve")
    parser.add_argument("--replacement-ca", type=Path)
    args = parser.parse_args()
    from catchplate.rebrand_migration import MigrationError, migrate
    try:
        result = migrate(**vars(args))
    except MigrationError as error:
        print(json.dumps({"status": "refused", "error": str(error), "source_unchanged": True}), file=sys.stderr)
        return 1
    except Exception:
        print(json.dumps({"status": "failed", "error": "Migration did not complete; retain the partial target for diagnosis. No automatic retry is safe.",
            "source_unchanged": True}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
