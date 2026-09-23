#!/usr/bin/env python3
"""Fixed no-build component job; not a controller receipt or release gate."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from serverware.native_postgres_runner import main

if __name__ == "__main__":
    raise SystemExit(main())
