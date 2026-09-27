"""Isolated activation planner entry, never a caller-selected checkout/module."""
from __future__ import annotations

import os
import stat
import sys


def main():
    try:
        if (sys.prefix != "/runtime/python" or sys.executable != "/runtime/python/bin/python3"
                or not sys.flags.isolated or not sys.flags.ignore_environment
                or len(sys.argv) != 2 or sys.argv[1] not in ("--root-delivery", "--run")):
            raise RuntimeError("activation planner requires its fixed isolated runtime")
        for path in ("/", "/runtime", "/runtime/authority-bootstrap", "/vendor", "/app"):
            value = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISDIR(value.st_mode) or value.st_uid != 0
                    or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise RuntimeError("activation planner runtime directory is not protected")
        sys.dont_write_bytecode = True
        sys.path[:0] = ["/vendor", "/app"]
        if sys.argv[1] == "--root-delivery":
            from serverware.oidc_session_activation_planner_entrypoint import main as run
        else:
            from serverware.oidc_session_activation_planner_runner import main as run
        return run()
    except BaseException:
        try:
            os.write(2, b"activation planner launch failed\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
