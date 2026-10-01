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


def valid_arguments(arguments):
    """Keep the operational invocation closed; cold commissioning is explicit."""
    if type(arguments) is not list or not arguments or not all(type(v) is str for v in arguments):
        return False
    cold = arguments[0] in ("--run-native-genesis", "--run-native-genesis-handoff")
    if arguments[0] not in ("--run-native-pilot", "--run-native-genesis", "--run-native-genesis-handoff"):
        return False
    prefix = (("--supervisor-inventory-fd", "fd"), ("--supervisor-inventory-sha256", "sha"),
        ("--genesis-configuration-fd", "fd"), ("--genesis-configuration-sha256", "sha")) if cold else (
        ("--runtime-inventory-fd", "fd"), ("--runtime-inventory-sha256", "sha"))
    if arguments[0] == "--run-native-genesis-handoff":
        prefix += (("--core-handoff-fd", "fd"),)
    offset = 1 + 2 * len(prefix)
    if not offset + 2 <= len(arguments) <= offset + 256 or len(arguments) % 2 != 1:
        return False
    for index, (flag, kind) in enumerate(prefix):
        if arguments[1 + index * 2] != flag:
            return False
        value = arguments[2 + index * 2]
        if kind == "sha":
            if re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
                return False
        elif re.fullmatch(r"[1-9][0-9]{0,9}", value) is None or not 3 <= int(value) < (1 << 31):
            return False
    return all(arguments[index] == "--authority-key"
        and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}=[1-9][0-9]{0,9}", arguments[index + 1]) is not None
        for index in range(offset, len(arguments), 2))


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
        and valid_arguments(arguments)
    ):
        raise SystemExit("native pilot authority runtime invocation refused")
    # The separate namespace leaves the conductor's exact /app/scripts intact.
    # -I ignores caller paths/environment; only these packaged roots are added.
    sys.path[:0] = ["/authority/app", "/vendor", "/app"]
    runpy.run_path("/authority/app/scripts/run_native_pilot_authority_coordinator.py", run_name="__main__")


if __name__ == "__main__":
    main()
