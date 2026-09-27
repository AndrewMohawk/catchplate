"""Finite same-process consume completion continuation; no automatic retry."""
from __future__ import annotations

import os
import signal


def _run_on_work(*, work, live_window, transport_deadline_ns):
    from serverware import oidc_session_activation_delivery_completion_startup as startup

    stopping, status, previous = False, 0, {}

    def stop(_number, _frame):
        nonlocal stopping
        stopping = True

    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, stop)
        startup.initialize_from_environment(work=work, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns)
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
            os.write(2, b"consume completion stopped; delivery is not established\n")
        except OSError:
            pass
    return status


def main():
    try:
        os.write(2, b"consume completion requires its original root-delivery continuation\n")
    except OSError:
        pass
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
