"""Fixed isolated entry for the separately installed native pilot runtime.

This bootstrap supplies import paths, not privilege, credentials, provisioning
or launch authority. The existing conductor owns all admission and cleanup.
"""
from __future__ import annotations

import os
import runpy
import sys


def main():
    script = "/app/scripts/native_pilot_runtime_entrypoint.py"
    python = "/runtime/python/bin/python3"
    if not (
        sys.argv[0] == script
        and __file__ == script and os.path.realpath(__file__) == script
        and sys.executable == python and os.path.realpath(sys.executable) == python
        and sys.prefix == sys.base_prefix == "/runtime/python"
        and sys.version_info[:2] == (3, 11)
        and sys.flags.isolated == 1 and sys.flags.ignore_environment == 1
        and sys.flags.no_user_site == 1 and sys.flags.safe_path
        and sys.flags.dont_write_bytecode == 1
    ):
        raise SystemExit("native pilot runtime invocation refused")
    # -I intentionally ignores PYTHONPATH and the script directory. Only these
    # fixed, packaged roots are added; no caller module or path is accepted.
    sys.path[:0] = ["/vendor", "/app"]
    from catchplate.native_pilot_adopted_intake import invocation
    try:
        invocation(sys.argv[1:])  # Exact legacy flag or explicit fixed adopted intake.
    except (ValueError, TypeError):
        raise SystemExit("native pilot runtime invocation refused") from None
    runpy.run_path("/app/scripts/run_native_pilot.py", run_name="__main__")


if __name__ == "__main__":
    main()
