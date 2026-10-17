#!/usr/bin/env python3
"""Copy one explicitly stopped synthetic Serverware sandbox into Catchplate."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-data", type=Path, required=True)
    parser.add_argument("--target-data", type=Path, required=True)
    parser.add_argument("--acknowledge-offline-source", action="store_true")
    args = parser.parse_args()
    from catchplate.rebrand_sandbox import MigrationError, migrate
    try:
        result = migrate(**vars(args))
    except MigrationError as error:
        print(json.dumps({"status": "refused", "error": str(error), "source_unchanged": True}), file=sys.stderr)
        return 1
    except Exception:
        print(json.dumps({"status": "failed", "error": "Sandbox migration did not complete; preserve the partial target. Do not retry or start it.",
            "source_unchanged": True}), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
