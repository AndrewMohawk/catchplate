"""Single-PID bounded accept loop; no renewal, restart or request retry."""
from __future__ import annotations

import os
import signal


def main() -> int:
    from serverware import registration_evidence_signer_startup as startup

    stopping = False
    previous = {}
    status = 0

    def stop(_number, _frame):
        nonlocal stopping
        # Leave an in-flight bounded request to its actual owner. Interrupting
        # durable grant consumption cannot make the grant retryable.
        stopping = True

    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, stop)
        startup.initialize_from_environment()
        while not stopping:
            owner = startup.require_started()
            try:
                owner.serve_once()
            except startup.SignerRequestError:
                # No raw exception logging, same-connection retry or grant reset.
                # A failed lifecycle check is terminal, not another request.
                startup.require_started()
    except BaseException:
        status = 1
    finally:
        try:
            startup.close()
        except BaseException:
            status = 1
        for number, handler in previous.items():
            try:
                signal.signal(number, handler)
            except BaseException:
                status = 1
    if status:
        try:
            os.write(2, b"registration evidence signer stopped after lifecycle failure\n")
        except OSError:
            pass
    return status


if __name__ == "__main__":
    raise SystemExit(main())
