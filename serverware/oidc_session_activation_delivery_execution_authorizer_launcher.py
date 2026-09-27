"""Isolated fixed consume-authorizer entry, not a caller-selected module."""
from __future__ import annotations

import os
import stat
import sys


def main():
    try:
        if (sys.prefix != "/runtime/python" or sys.executable != "/runtime/python/bin/python3"
                or not sys.flags.isolated or not sys.flags.ignore_environment
                or len(sys.argv) != 2 or sys.argv[1] not in ("--root-delivery", "--run")):
            raise RuntimeError("consume authorizer requires its fixed isolated runtime")
        for path in ("/", "/runtime", "/runtime/authority-bootstrap", "/vendor", "/app"):
            value = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISDIR(value.st_mode) or value.st_uid != 0
                    or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise RuntimeError("consume authorizer runtime directory is not protected")
        sys.dont_write_bytecode = True
        sys.path[:0] = ["/vendor", "/app"]
        if sys.argv[1] == "--root-delivery":
            from serverware.oidc_session_activation_delivery_execution_authorizer_entrypoint import main as run
        else:
            from serverware.oidc_session_activation_delivery_execution_authorizer_runner import main as run
        return run()
    except BaseException:
        try:
            os.write(2, b"consume authorizer launch failed\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
