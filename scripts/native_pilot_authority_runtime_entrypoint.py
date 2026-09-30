"""Fixed isolated entry for the separately packaged pilot authority coordinator.

Argument syntax selects only already-protected inventory/key descriptors. The
real coordinator retains all approval, key ownership and cleanup checks. This
bootstrap creates no keys, approvals, inventories, configuration or services.
"""
from __future__ import annotations

import os
import re
import runpy
import sys


def main():
    script = "/authority/app/scripts/native_pilot_authority_runtime_entrypoint.py"
    python = "/runtime/python/bin/python3"
    arguments = sys.argv[1:]
    if not (
        sys.argv[0] == script and __file__ == script and os.path.realpath(__file__) == script
        and sys.executable == python and os.path.realpath(sys.executable) == python
        and sys.prefix == sys.base_prefix == "/runtime/python"
        and sys.version_info[:2] == (3, 11)
        and sys.flags.isolated == 1 and sys.flags.ignore_environment == 1
        and sys.flags.no_user_site == 1 and sys.flags.safe_path
        and sys.flags.dont_write_bytecode == 1
        and 7 <= len(arguments) <= 261 and len(arguments) % 2 == 1
        and arguments[0] == "--run-native-pilot"
        and arguments[1] == "--runtime-inventory-fd"
        and re.fullmatch(r"[1-9][0-9]{0,9}", arguments[2]) is not None
        and 3 <= int(arguments[2]) < (1 << 31)
        and arguments[3] == "--runtime-inventory-sha256"
        and re.fullmatch(r"sha256:[0-9a-f]{64}", arguments[4]) is not None
        and all(arguments[index] == "--authority-key"
                and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}=[1-9][0-9]{0,9}", arguments[index + 1]) is not None
                for index in range(5, len(arguments), 2))
    ):
        raise SystemExit("native pilot authority runtime invocation refused")
    # The separate namespace leaves the conductor's exact /app/scripts intact.
    # -I ignores caller paths/environment; only these packaged roots are added.
    sys.path[:0] = ["/authority/app", "/vendor", "/app"]
    runpy.run_path("/authority/app/scripts/run_native_pilot_authority_coordinator.py", run_name="__main__")


if __name__ == "__main__":
    main()
