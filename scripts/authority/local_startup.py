#!/usr/bin/env python3
"""Fixed actual parent for one independently admitted local authority role."""
from __future__ import annotations

from pathlib import Path
import re
import signal
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

USAGE = """Usage: python -I -B scripts/authority/local_startup.py --plan-fd N --plan-sha256 sha256:HEX --listener-fd 3

Run as root under actual one-listener systemd socket activation. The protected
canonical serverware.authorityTrustedHostLocalStartup/v1 plan pins the installed
/runtime Python/bootstrap files, static resource paths/digests, credential and
initially empty exchange directories, original clocks, and three generation
digests. No command, key, signature or database credentials are generated.

The parent atomically publishes observation.json in the pinned root0700 exchange
directory. Independent automation must atomically supply manifest.json and
certificate.json, plus evidence.json for verifier/planner/planner-writer/issuer/
executor, as root:root0400 canonical signed originals. Their exact bytes are
sealed for the existing child admission; signature verification remains there.
The <=300s original window never renews. After the actual child's post-admission
notice, the parent supervises its real PIDFD until exit; this is not readiness.
SIGTERM/SIGINT cancel and reap the child. Failure never removes or retries files.
Requires the genuinely installed /runtime layout, not the ordinary dev image.
"""


def arguments(argv):
    if len(argv) != 6 or argv[::2] != ["--plan-fd", "--plan-sha256", "--listener-fd"]:
        raise ValueError("fixed local startup arguments required")
    fd = int(argv[1])
    digest = argv[3]
    if str(fd) != argv[1] or not 4 <= fd < 2**31 or argv[5] != "3" or len(digest) != 71 or not digest.startswith("sha256:") or any(c not in "0123456789abcdef" for c in digest[7:]):
        raise ValueError("fixed local startup argument invalid")
    return dict(plan_fd=fd, plan_sha256=digest, listener_fd=3)


def _failure_line(value):
    try:
        print(value, file=sys.stderr, flush=True)
    except BaseException:
        pass  # Broken diagnostics must not prevent cleanup or failure return.


def _failure_name(value):
    return value if type(value) is str and re.fullmatch(r"[A-Za-z0-9_.<>-]{1,96}", value) else "unknown"


def _failure_diagnostics(error, owner):
    """Fixed metadata only: never format exceptions, source lines or locals."""
    admitted = getattr(owner, "admitted", "unknown")
    status = getattr(owner, "child_status", "unknown")
    _failure_line("LOCAL_STARTUP_FAILURE_ADMITTED=" + (str(int(admitted)) if type(admitted) is bool else "unknown"))
    _failure_line("LOCAL_STARTUP_FAILURE_CHILD_STATUS=" + ("none" if status is None else
        str(status) if type(status) is int and -255 <= status <= 255 else "unknown"))
    seen = set()
    current = error
    # The original exception plus at most four cause/context links.
    for index in range(5):
        if not isinstance(current, BaseException) or id(current) in seen:
            break
        seen.add(id(current))
        _failure_line(f"LOCAL_STARTUP_FAILURE_CAUSE={index}:{_failure_name(type(current).__name__)}")
        trace = current.__traceback__
        for _ in range(8):
            if trace is None:
                break
            code = trace.tb_frame.f_code
            filename = code.co_filename
            name = Path(filename).name if type(filename) is str and len(filename) <= 4096 else "unknown"
            line = trace.tb_lineno
            line = line if type(line) is int and 0 < line < 2**31 else 0
            _failure_line(f"LOCAL_STARTUP_FAILURE_FRAME={index}:{_failure_name(name)}:{_failure_name(code.co_name)}:{line}")
            trace = trace.tb_next
        current = current.__cause__ if current.__cause__ is not None else current.__context__


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--help"]:
        print(USAGE, end=""); return 0
    try:
        selected = arguments(argv)
    except (ValueError, TypeError):
        print("local startup refused: use --help", file=sys.stderr); return 2
    from serverware.authority_local_startup import LocalAuthorityStartup, encode
    owner = None
    def cancelled(signo, frame):
        raise KeyboardInterrupt()
    for signo in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(signo, cancelled)
    try:
        owner = LocalAuthorityStartup.open(**selected)
        result = owner.run()
        print(encode(result).decode("ascii")); return 0
    except BaseException as error:
        owner = getattr(error, "owner", None) or owner
        try:
            _failure_diagnostics(error, owner)
        except BaseException:
            pass
        try:
            if owner is not None:
                owner.close(cancel=True)
        except BaseException:
            _failure_line("local startup failed; child or descriptor cleanup is uncertain; no retry")
            return 1
        _failure_line("local startup failed; no readiness asserted; retained files were not removed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
