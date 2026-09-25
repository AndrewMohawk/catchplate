"""One cold state owner and finite serial serving, never automatic renewal."""
from __future__ import annotations

import os
import signal


def main() -> int:
    from serverware import current_root_state_startup as startup

    stopping = False
    previous = {}
    status = 0

    def stop(_number, _frame):
        nonlocal stopping
        # Let the actual bounded owner finish an in-flight durable action.
        # Signal delivery does not reset publication or authorize its retry.
        stopping = True

    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, stop)
        startup.initialize_from_environment()
        while not stopping:
            owner = startup.require_started()
            try:
                owner.serve_once()
            except startup.CurrentRootStateRequestError:
                # Request denial may continue only with a still-live owner.
                # Poison, expiry and every lifecycle error are terminal.
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
            os.write(2, b"current-root state stopped after lifecycle failure\n")
        except OSError:
            pass
    return status


if __name__ == "__main__":
    raise SystemExit(main())
