"""Fixed isolated root launcher for the one-shot recovery grant issuer."""
from __future__ import annotations

import os
import stat
import sys


def main():
    try:
        if (sys.prefix != "/runtime/python" or sys.executable != "/runtime/python/bin/python3"
                or not sys.flags.isolated or not sys.flags.ignore_environment
                or len(sys.argv) != 2 or sys.argv[1] != "--root-delivery"):
            raise RuntimeError("recovery issuer requires its fixed isolated root launcher")
        for path in ("/", "/runtime", "/runtime/authority-bootstrap", "/vendor", "/app"):
            value = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISDIR(value.st_mode) or value.st_uid != 0
                    or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise RuntimeError("recovery issuer runtime directory is not protected")
        sys.dont_write_bytecode = True
        sys.path[:0] = ["/vendor", "/app"]
        from catchplate.oidc_session_activation_release_recovery_issuer_entrypoint import main as run
        return run()
    except BaseException:
        try:
            os.write(2, b"recovery issuer launch failed\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
