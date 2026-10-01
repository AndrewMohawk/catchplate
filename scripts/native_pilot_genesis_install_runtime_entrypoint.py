"""Two fixed approved-pair installers inside the admitted supervisor runtime.

The parent withholds stdout until this process exits and is actually reaped.
No command, module, path, key, deadline or approval can be supplied implicitly.
"""
from __future__ import annotations

import os
import re
import signal
import sys

SCRIPT = "/supervisor/app/scripts/native_pilot_genesis_install_runtime_entrypoint.py"
PYTHON = "/runtime/python/bin/python3"
IMPORT_ROOTS = ("/supervisor/app", "/authority/app", "/vendor", "/app")


def arguments(values):
    if type(values) is not list or not values or not all(type(value) is str for value in values):
        raise ValueError("fixed installer invocation refused")
    if values[0] not in ("--install-rendezvous", "--install-job"):
        raise ValueError("unknown fixed installer")
    names = ("supervisor-inventory",) + (("configuration",) if values[0] == "--install-job" else ()) + (
        "request", "input", "approval")
    if len(values) != 1 + 4 * len(names):
        raise ValueError("fixed installer argument count refused")
    descriptors = set()
    for index, name in enumerate(names):
        flag, number, pin_flag, pin = values[1 + 4 * index:5 + 4 * index]
        if (flag != "--" + name + "-fd" or pin_flag != "--" + name + "-sha256"
                or re.fullmatch(r"[1-9][0-9]{0,9}", number) is None
                or not 3 <= int(number) < (1 << 31) or int(number) in descriptors
                or re.fullmatch(r"sha256:[0-9a-f]{64}", pin) is None):
            raise ValueError("fixed installer descriptor or pin refused")
        descriptors.add(int(number))
    return values[0], int(values[2]), values[4], values[5:]


def main():
    if not (sys.argv[0] == SCRIPT and __file__ == SCRIPT and os.path.realpath(__file__) == SCRIPT
            and sys.executable == PYTHON and os.path.realpath(sys.executable) == PYTHON
            and sys.prefix == sys.base_prefix == "/runtime/python" and sys.version_info[:2] == (3, 11)
            and sys.flags.isolated == sys.flags.ignore_environment == sys.flags.no_user_site == 1
            and sys.flags.safe_path and sys.flags.dont_write_bytecode == 1):
        raise SystemExit("fixed installer runtime refused")
    mode, inventory_fd, inventory_sha256, selected = arguments(sys.argv[1:])
    sys.path[:0] = list(IMPORT_ROOTS)
    from serverware.native_pilot_genesis_authority import _SelfRuntime
    from serverware import native_pilot_genesis_parent_control_io as io
    from scripts.authority import native_pilot_authority_io as output
    runtime = _SelfRuntime()
    result = 1
    def stop(_signum, _frame):
        raise KeyboardInterrupt
    for number in io.CANCELLATION:
        signal.signal(number, stop)
    try:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, io.CANCELLATION)
        runtime.admit(inventory_fd, inventory_sha256)
        if mode == "--install-rendezvous":
            from scripts import install_native_pilot_genesis_rendezvous as installer
            selected_script = "/supervisor/app/scripts/install_native_pilot_genesis_rendezvous.py"
        else:
            from scripts import install_native_pilot_genesis_job as installer
            selected_script = "/supervisor/app/scripts/install_native_pilot_genesis_job.py"
        sys.argv = [selected_script, *selected]
        # A CLI with unknown cleanup never returns; runtime stays held here.
        result = installer.main()
        if result == 0:
            runtime.check(installed=True)
    except BaseException:
        result = 1
    for number in io.CANCELLATION:
        signal.signal(number, signal.SIG_IGN)
    try:
        runtime.close()
    except BaseException:
        output.fail()
        while True:
            signal.pause()
    return result


if __name__ == "__main__":
    raise SystemExit(main())
