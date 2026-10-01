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
LIFECYCLE_CLI = "/supervisor/app/scripts/run_native_pilot_lifecycle.py"
LIFECYCLE_MODE = "--run-native-pilot-lifecycle"
LIFECYCLE_INPUTS = ("supervisor-inventory", "listener-configuration")
LIFECYCLE_KEYS = (("cold-authority-key", 36), ("adopted-authority-key", 123))
PROVIDER_CLI = "/supervisor/app/scripts/run_native_pilot_approval_provider.py"
PROVIDER_MODE = "approval-provider"
PROVIDER_INPUTS = ("policy", "supervisor-inventory", "recipe", "conductor-inventory", "authority-inventory")
DECISION_CLI = "/supervisor/app/scripts/run_native_pilot_current_head_decisions.py"
DECISION_MODE = "current-head-decision-service"
DECISION_INPUTS = ("supervisor-inventory", "configuration")
HEAD_WORKER_CLI = "/supervisor/app/scripts/run_native_pilot_current_head_worker.py"
HEAD_WORKER_MODE = "current-head-worker"
HEAD_UPDATE_MODE = "current-head-state-update"
HEAD_WORKER_INPUTS = ("supervisor-inventory", "policy")
HEAD_UPDATE_INPUTS = ("supervisor-inventory", "authorization")
STARTUP_CLI = "/supervisor/app/scripts/run_native_pilot_startup.py"
STARTUP_MODE = "commissioning-startup"
STARTUP_CHILD_CLI = "/supervisor/app/scripts/run_native_pilot_startup_child.py"
STARTUP_CHILD_MODE = "commissioning-startup-child"
STARTUP_INPUTS = ("configuration", "supervisor-inventory")
STARTUP_ROLES = ("lifecycle", "provider", "decisions")
PROVISIONING_CLI = "/supervisor/app/scripts/run_native_pilot_startup_provisioning.py"
PROVISIONING_MODE = "startup-provisioning"
PROVISIONING_INPUTS = ("supervisor-inventory", "delegation", "configuration", "recipe",
    "conductor-inventory", "authority-inventory")
PYTHON = "/runtime/python/bin/python3"
IMPORT_ROOTS = ("/supervisor/app", "/authority/app", "/vendor", "/app")
INPUTS = ("supervisor-inventory", "policy", "recipe", "conductor-inventory", "authority-inventory")
MAX_KEYS = 128


def _number(value, minimum, maximum):
    return (type(value) is str and re.fullmatch(r"0|[1-9][0-9]{0,9}", value) is not None
            and minimum <= int(value) <= maximum)


def _public_peer_arguments(arguments, inputs, sockets):
    """Fixed protected public pairs and distinct authenticated socket descriptors."""
    if len(arguments) != 1 + 4 * len(inputs) + 2 * len(sockets):
        return False
    descriptors = set()
    for index, name in enumerate(inputs):
        offset = 1 + 4 * index
        flag, number, pin_flag, pin = arguments[offset:offset + 4]
        if (flag != "--" + name + "-fd" or not _number(number, 3, (1 << 31) - 1)
                or pin_flag != "--" + name + "-sha256"
                or re.fullmatch(r"sha256:[0-9a-f]{64}", pin) is None
                or int(number) in descriptors):
            return False
        descriptors.add(int(number))
    for index, name in enumerate(sockets):
        offset = 1 + 4 * len(inputs) + 2 * index
        flag, number = arguments[offset:offset + 2]
        if (flag != "--" + name + "-fd" or not _number(number, 3, (1 << 31) - 1)
                or int(number) in descriptors):
            return False
        descriptors.add(int(number))
    return True


def _keyed_arguments(arguments, inputs, *, approval=False):
    """Fixed staged caller syntax; the real CLI checks exact key purposes."""
    keys_offset = 1 + 4 * len(inputs) + (8 if approval else 0)
    if len(arguments) != keys_offset + 2 * sum(count for _, count in LIFECYCLE_KEYS):
        return False
    descriptors = set()
    for index, name in enumerate(inputs):
        offset = 1 + 4 * index
        flag, number, pin_flag, pin = arguments[offset:offset + 4]
        if (flag != "--" + name + "-fd" or not _number(number, 3, (1 << 31) - 1)
                or pin_flag != "--" + name + "-sha256"
                or re.fullmatch(r"sha256:[0-9a-f]{64}", pin) is None
                or int(number) in descriptors):
            return False
        descriptors.add(int(number))
    if approval:
        approval_offset = 1 + 4 * len(inputs)
        for offset, name, minimum, maximum in (
                (approval_offset, "approval-fd", 3, (1 << 31) - 1),
                (approval_offset + 2, "approval-peer-pid", 2, (1 << 31) - 1),
                (approval_offset + 4, "approval-peer-uid", 0, (1 << 32) - 2),
                (approval_offset + 6, "approval-peer-gid", 0, (1 << 32) - 2)):
            if arguments[offset] != "--" + name or not _number(arguments[offset + 1], minimum, maximum):
                return False
        channel = int(arguments[approval_offset + 1])
        if channel in descriptors:
            return False
        descriptors.add(channel)
    offset = keys_offset
    for flag, count in LIFECYCLE_KEYS:
        purposes = set()
        for _ in range(count):
            literal = arguments[offset + 1]
            if (arguments[offset] != "--" + flag
                    or re.fullmatch(r"[A-Za-z][A-Za-z0-9-]{0,127}=[1-9][0-9]{0,9}", literal) is None):
                return False
            purpose, number = literal.split("=", 1)
            if (purpose in purposes or not _number(number, 3, (1 << 31) - 1)
                    or int(number) in descriptors):
                return False
            purposes.add(purpose)
            offset += 2
    return True


def _startup_child_arguments(arguments):
    return (len(arguments) == 14 and arguments[1] in STARTUP_ROLES
        and _public_peer_arguments([arguments[0], *arguments[2:10]], STARTUP_INPUTS, ())
        and arguments[10] == "--parent-pid" and _number(arguments[11], 2, (1 << 31) - 1)
        and arguments[12] == "--parent-start-time-ticks"
        and re.fullmatch(r"[1-9][0-9]{0,19}", arguments[13]) is not None
        and 1 <= int(arguments[13]) < (1 << 64))


def valid_arguments(arguments):
    """Closed invocation syntax only; actual originals/keys/peer stay CLI-owned."""
    if type(arguments) is not list or not arguments or not all(type(value) is str for value in arguments):
        return False
    if arguments[0] == LIFECYCLE_MODE:
        return _keyed_arguments(arguments, LIFECYCLE_INPUTS, approval=True)
    if arguments[0] == STARTUP_MODE:
        return _keyed_arguments(arguments, STARTUP_INPUTS)
    if arguments[0] == STARTUP_CHILD_MODE:
        return _startup_child_arguments(arguments)
    if arguments[0] == PROVIDER_MODE:
        return _public_peer_arguments(arguments, PROVIDER_INPUTS, ("approval-socket", "current-head-socket"))
    if arguments[0] == DECISION_MODE:
        return _public_peer_arguments(arguments, DECISION_INPUTS, ("approval-socket",))
    if arguments[0] == HEAD_WORKER_MODE:
        return _public_peer_arguments(arguments, HEAD_WORKER_INPUTS, ())
    if arguments[0] == HEAD_UPDATE_MODE:
        return _public_peer_arguments(arguments, HEAD_UPDATE_INPUTS, ())
    if arguments[0] == PROVISIONING_MODE:
        return _public_peer_arguments(arguments, PROVISIONING_INPUTS, ())
    adopted = arguments[0] == "--run-adopted-native-pilot"
    inputs = INPUTS + (("intake-configuration",) if adopted else ())
    keys_offset = 1 + 4 * len(inputs) + 8
    if (arguments[0] not in ("--run-native-pilot", "--run-adopted-native-pilot")
            or not keys_offset + 2 <= len(arguments) <= keys_offset + 2 * MAX_KEYS or len(arguments) % 2 != 1):
        return False
    descriptors = set()
    for index, name in enumerate(inputs):
        offset = 1 + 4 * index
        flag, number, pin_flag, pin = arguments[offset:offset + 4]
        if (flag != "--" + name + "-fd" or not _number(number, 3, (1 << 31) - 1)
                or pin_flag != "--" + name + "-sha256"
                or re.fullmatch(r"sha256:[0-9a-f]{64}", pin) is None
                or int(number) in descriptors):
            return False
        descriptors.add(int(number))
    approval_offset = 1 + 4 * len(inputs)
    for offset, name, minimum, maximum in (
            (approval_offset, "approval-fd", 3, (1 << 31) - 1),
            (approval_offset + 2, "approval-peer-pid", 2, (1 << 31) - 1),
            (approval_offset + 4, "approval-peer-uid", 0, (1 << 32) - 2),
            (approval_offset + 6, "approval-peer-gid", 0, (1 << 32) - 2)):
        if arguments[offset] != "--" + name or not _number(arguments[offset + 1], minimum, maximum):
            return False
    channel = int(arguments[approval_offset + 1])
    if channel in descriptors:
        return False
    descriptors.add(channel)
    purposes = set()
    for offset in range(keys_offset, len(arguments), 2):
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
    selected_cli = {LIFECYCLE_MODE: LIFECYCLE_CLI, PROVIDER_MODE: PROVIDER_CLI,
        DECISION_MODE: DECISION_CLI, STARTUP_MODE: STARTUP_CLI,
        HEAD_WORKER_MODE: HEAD_WORKER_CLI, HEAD_UPDATE_MODE: HEAD_WORKER_CLI,
        STARTUP_CHILD_MODE: STARTUP_CHILD_CLI, PROVISIONING_MODE: PROVISIONING_CLI}.get(sys.argv[1], CLI)
    runpy.run_path(selected_cli, run_name="__main__")


if __name__ == "__main__":
    main()
