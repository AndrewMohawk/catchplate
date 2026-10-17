"""Finite same-process release continuation; standalone starts are rejected."""
from __future__ import annotations

import os
import signal

from catchplate import oidc_session_activation_release_resources as resources
from catchplate import oidc_session_activation_release_startup as startup
from catchplate import oidc_session_activation_release_service as service


def _diagnostic(message):
    try:
        os.write(2, message)
    except OSError:
        pass


def _run_with_resources(resource_owner):
    """Consume actual root intake, return status only, and close every owner."""
    started, status, previous = None, 1, {}

    def stop(_number, _frame):
        raise service.ReleaseServiceError("release runner was interrupted")

    try:
        if type(resource_owner) is not resources._Resources:
            raise service.ReleaseServiceError("release runner requires actual root resource intake")
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, stop)
        started = startup.start_from_resources(resource_owner)
        if service.serve_once(started) is not True:
            raise service.ReleaseServiceError("release service did not complete its sole exchange")
        status = 0
    except BaseException:
        status = 1
    finally:
        try:
            if type(started) is startup._StartedRelease:
                startup._StartedRelease.close(started)
            elif type(resource_owner) is resources._Resources:
                resources._Resources.close(resource_owner)
        except BaseException:
            status = 1
        for number, handler in previous.items():
            try:
                signal.signal(number, handler)
            except BaseException:
                status = 1
    if status:
        _diagnostic(b"token release stopped; response delivery is not established\n")
    return status


def main():
    _diagnostic(b"token release requires its original root-resource continuation\n")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
