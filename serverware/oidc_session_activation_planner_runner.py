"""One accepted activation planner connection per launch; no automatic retry."""
from __future__ import annotations

import os
import signal


def main():
    from serverware import authority_oidc_session_activation_planner_service as startup

    stopping, status, previous = False, 0, {}

    def stop(_number, _frame):
        nonlocal stopping
        stopping = True

    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, stop)
        startup.initialize_from_environment()
        while not stopping:
            if startup.require_started().serve_once():
                break
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
            os.write(2, b"activation planner stopped; planning or retention outcome is not established\n")
        except OSError:
            pass
    return status


if __name__ == "__main__":
    raise SystemExit(main())
