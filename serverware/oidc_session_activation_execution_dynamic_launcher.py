"""Isolated source-fixed raw-original execution delivery launcher."""
from __future__ import annotations

import os
import stat
import sys


def main():
    try:
        if (sys.prefix != "/runtime/python" or sys.executable != "/runtime/python/bin/python3"
                or not sys.flags.isolated or not sys.flags.ignore_environment
                or len(sys.argv) != 3 or sys.argv[1] != "--root-delivery"):
            raise RuntimeError("execution delivery requires its fixed isolated runtime")
        for path in ("/", "/runtime", "/runtime/authority-bootstrap", "/vendor", "/app"):
            value = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISDIR(value.st_mode) or value.st_uid != 0
                    or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise RuntimeError("execution delivery runtime directory is not protected")
        sys.dont_write_bytecode = True
        sys.path[:0] = ["/vendor", "/app"]
        from serverware.oidc_session_activation_execution_dynamic_entrypoint import main as run
        return run(sys.argv[2])
    except BaseException:
        try:
            os.write(2, b"execution dynamic launch failed\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
