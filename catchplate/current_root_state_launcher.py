"""Fixed isolated runtime entry for separately enrolled current-root state.

The release installer must independently authenticate the full runtime closure.
These path checks are not native measurement or a hardware trust statement.
No checkout, ambient Python path or caller-selected module is admitted.
"""
from __future__ import annotations

import os
import stat
import sys


def _runtime_paths():
    if (sys.prefix != "/runtime/python" or sys.executable != "/runtime/python/bin/python3"
            or not sys.flags.isolated or not sys.flags.ignore_environment
            or len(sys.argv) != 2 or sys.argv[1] not in ("--root-delivery", "--run")):
        raise RuntimeError("current-root state requires its fixed isolated runtime")
    for path in ("/", "/runtime", "/runtime/authority-bootstrap", "/vendor", "/app"):
        value = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISDIR(value.st_mode) or value.st_uid != 0
                or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise RuntimeError("current-root runtime directory is not protected")
    sys.dont_write_bytecode = True
    sys.path[:0] = ["/vendor", "/app"]


def main() -> int:
    try:
        _runtime_paths()
        if sys.argv[1] == "--root-delivery":
            from catchplate.current_root_state_entrypoint import main as run
        else:
            from catchplate.current_root_state_runner import main as run
        return run()
    except BaseException:
        # No parser/native exception, signed input or secret reaches logs.
        try:
            os.write(2, b"current-root state launch failed\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
