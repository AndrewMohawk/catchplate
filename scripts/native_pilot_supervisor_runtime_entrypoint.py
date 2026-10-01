"""Fixed isolated entry for the separately packaged pilot supervisor.

Only protected descriptor and independently pinned original arguments are
forwarded. This supplies fixed import roots, not keys, policy, installation,
late decisions, approval-channel ownership or pilot acceptance.
"""
from __future__ import annotations

import os
import re
import runpy
import sys

SCRIPT = "/supervisor/app/scripts/native_pilot_supervisor_runtime_entrypoint.py"
CLI = "/supervisor/app/scripts/run_native_pilot_supervisor.py"
PYTHON = "/runtime/python/bin/python3"
IMPORT_ROOTS = ("/supervisor/app", "/authority/app", "/vendor", "/app")
INPUTS = ("supervisor-inventory", "policy", "recipe", "conductor-inventory", "authority-inventory")
MAX_KEYS = 128


def _number(value, minimum, maximum):
    return (type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,9}", value) is not None
            and minimum <= int(value) <= maximum)


def valid_arguments(arguments):
    """Closed invocation syntax only; actual originals/keys/peer stay CLI-owned."""
    if (type(arguments) is not list or not all(type(value) is str for value in arguments)
            or not 31 <= len(arguments) <= 29 + 2 * MAX_KEYS or len(arguments) % 2 != 1
            or arguments[0] != "--run-native-pilot"):
        return False
    descriptors = set()
    for index, name in enumerate(INPUTS):
        offset = 1 + 4 * index
        flag, number, pin_flag, pin = arguments[offset:offset + 4]
        if (flag != "--" + name + "-fd" or not _number(number, 3, (1 << 31) - 1)
                or pin_flag != "--" + name + "-sha256"
                or re.fullmatch(r"sha256:[0-9a-f]{64}", pin) is None
                or int(number) in descriptors):
            return False
        descriptors.add(int(number))
    for offset, name, minimum, maximum in (
            (21, "approval-fd", 3, (1 << 31) - 1),
            (23, "approval-peer-pid", 2, (1 << 31) - 1),
            (25, "approval-peer-uid", 0, (1 << 32) - 2),
            (27, "approval-peer-gid", 0, (1 << 32) - 2)):
        if arguments[offset] != "--" + name or not _number(arguments[offset + 1], minimum, maximum):
            return False
    channel = int(arguments[22])
    if channel in descriptors:
        return False
    descriptors.add(channel)
    purposes = set()
    for offset in range(29, len(arguments), 2):
        literal = arguments[offset + 1]
        if (arguments[offset] != "--authority-key"
                or re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}=[1-9][0-9]{0,9}", literal) is None):
            return False
        purpose, number = literal.split("=", 1)
        if (purpose in purposes or not _number(number, 3, (1 << 31) - 1)
                or int(number) in descriptors):
            return False
        purposes.add(purpose)
        # Distinct purposes may deliberately reuse one supplied key FD. The
        # real capability bindings decide whether that key is permitted.
    # The real CLI independently requires the exact source-selected purposes,
    # protected FD/key identities, policies, inventory pins and channel peer.
    return True


def main():
    if not (
        sys.argv[0] == SCRIPT and __file__ == SCRIPT and os.path.realpath(__file__) == SCRIPT
        and sys.executable == PYTHON and os.path.realpath(sys.executable) == PYTHON
        and sys.prefix == sys.base_prefix == "/runtime/python"
        and sys.version_info[:2] == (3, 11)
        and sys.flags.isolated == 1 and sys.flags.ignore_environment == 1
        and sys.flags.no_user_site == 1 and sys.flags.safe_path
        and sys.flags.dont_write_bytecode == 1
        and valid_arguments(sys.argv[1:])
    ):
        raise SystemExit("native pilot supervisor runtime invocation refused")
    # Namespace packages combine only the fixed source-selected script trees;
    # the unchanged shared serverware package remains under /app.
    sys.path[:0] = list(IMPORT_ROOTS)
    runpy.run_path(CLI, run_name="__main__")


if __name__ == "__main__":
    main()
