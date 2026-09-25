"""Fixed isolated launcher for the separately enrolled local signer runtime.

The release installer, not this path check, authenticates the complete runtime
closure. In particular this does not measure native dependencies or prove TEE
execution. No checkout, ambient Python path or arbitrary module is admitted.
"""
from __future__ import annotations

import os
import stat
import sys


def _runtime_paths():
    if (sys.prefix != "/runtime/python" or sys.executable != "/runtime/python/bin/python3"
            or not sys.flags.isolated or not sys.flags.ignore_environment
            or len(sys.argv) != 2 or sys.argv[1] not in ("--root-delivery", "--run")):
        raise RuntimeError("registration signer requires its fixed isolated runtime")
    for path in ("/", "/runtime", "/runtime/authority-bootstrap", "/vendor", "/app"):
        value = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISDIR(value.st_mode) or value.st_uid != 0
                or value.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise RuntimeError("registration signer runtime directory is not protected")
    # -I also ignores PYTHONDONTWRITEBYTECODE, so set this before package imports.
    sys.dont_write_bytecode = True
    sys.path[:0] = ["/vendor", "/app"]


def main() -> int:
    try:
        _runtime_paths()
        if sys.argv[1] == "--root-delivery":
            from serverware.registration_evidence_signer_entrypoint import main as run
        else:
            from serverware.registration_evidence_signer_runner import main as run
        return run()
    except BaseException:
        # Never expose native/parser exceptions, input bytes or key material.
        try:
            os.write(2, b"registration evidence signer launch failed\n")
        except OSError:
            pass
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
