"""Finite serial serving under one cold owner; no automatic renewal/retry."""
from __future__ import annotations

import os
import signal


def main():
    from serverware import registration_finalization_authorizer_startup as startup

    stopping, status, previous = False, 0, {}

    def stop(_number, _frame):
        nonlocal stopping
        stopping = True

    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, stop)
        startup.initialize_from_environment()
        while not stopping:
            try:
                startup.require_started().serve_once()
            except startup.AuthorizerRequestError:
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
            os.write(2, b"registration finalization stopped after lifecycle failure\n")
        except OSError:
            pass
    return status


if __name__ == "__main__":
    raise SystemExit(main())
