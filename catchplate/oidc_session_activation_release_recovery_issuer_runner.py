"""Continue one recovery issuance under the actual root-delivery allowance."""
from __future__ import annotations

import os


def _run_on_work(*, work, live_window, transport_deadline_ns, delivery_current):
    from catchplate import oidc_session_activation_release_recovery_issuer_startup as startup

    status = 1
    try:
        delivery_current()
        startup.initialize_from_environment(work=work, live_window=live_window,
            transport_deadline_ns=transport_deadline_ns, delivery_current=delivery_current)
        if startup.require_started().serve_once() is True:
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
            os.write(2, b"recovery issuer stopped; issuance is not established\n")
        except OSError:
            pass
    return status


def main():
    try:
        os.write(2, b"recovery issuer requires its original root-delivery continuation\n")
    except OSError:
        pass
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
