"""One accepted consume-planner connection per launch, without automatic retry."""
from __future__ import annotations

import os
import signal


def _run_on_work(*, work, live_window, transport_deadline_ns, delivery_current):
    """Dynamic same-PID prepare then exact export, never a fresh request scope."""
    from serverware import authority_oidc_session_activation_delivery_planner_service as startup

    status = 1
    try:
        delivery_current()
        startup._initialize_from_delivery_on_work(work=work, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, delivery_current=delivery_current)
        if startup.require_started().serve_sequence() is True:
            status = 0
    except BaseException:
        status = 1
    finally:
        try:
            startup.close()
        except BaseException:
            status = 1
    if status:
        try:
            os.write(2, b"dynamic consume planner stopped; planning or export is not established\n")
        except OSError:
            pass
    return status


def main():
    from serverware import authority_oidc_session_activation_delivery_planner_service as startup

    stopping, status, previous = False, 0, {}

    def stop(_number, _frame):
        nonlocal stopping
        stopping = True

    try:
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, stop)
        startup.initialize_from_environment()
        while not stopping:
            # False is only an idle accept under the actual service's retained
            # startup guard. Accepted failure/uncertainty is terminal, not False.
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
            os.write(2, b"consume planner stopped; planning or retention outcome is not established\n")
        except OSError:
            pass
    return status


if __name__ == "__main__":
    raise SystemExit(main())
