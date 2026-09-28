"""Fixed isolated proof staging and same-process private continuation."""
from __future__ import annotations

import os
import stat
import sys


def main():
    try:
        if (sys.prefix != "/runtime/python" or sys.executable != "/runtime/python/bin/python3"
                or not sys.flags.isolated or not sys.flags.ignore_environment
                or len(sys.argv) != 2 or sys.argv[1] != "--root-delivery"):
            raise RuntimeError("dynamic proof requires its fixed isolated root launcher")
        for path in ("/", "/runtime", "/runtime/authority-bootstrap", "/vendor", "/app"):
            value = os.stat(path, follow_symlinks=False)
            if (not stat.S_ISDIR(value.st_mode) or value.st_uid != 0
                    or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise RuntimeError("dynamic proof runtime directory is not protected")
        sys.dont_write_bytecode = True
        sys.path[:0] = ["/vendor", "/app"]
        from serverware.oidc_session_activation_release_proof_dynamic_entrypoint import main as run
        return run()
    except BaseException:
        try:
            os.write(2, b"dynamic release proof delivery failed; readiness is not established\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
