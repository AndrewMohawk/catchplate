"""Bounded private denial diagnostics shared by authority processes."""
from __future__ import annotations

import fcntl
import os
import stat


def report_denial(stage: str, error: BaseException) -> None:
    """Best-effort private source labels only; never serialize exception text.

    A blocking pipe can hold the denial path past its existing deadline. Do
    not change inherited flags or retry writes; skip unsupported stderr sinks.
    Root-owned private files are valid when inherited by an unprivileged role.
    """
    try:
        if stage not in {"runtime-relay", "authority-server", "replay-witness"}:
            return
        sink = os.fstat(2)
        if (sink.st_uid not in {0, os.geteuid()} or sink.st_nlink != 1
                or stat.S_IMODE(sink.st_mode) & 0o077):
            return
        if not stat.S_ISREG(sink.st_mode):
            if (not stat.S_ISFIFO(sink.st_mode)
                    or not fcntl.fcntl(2, fcntl.F_GETFL) & os.O_NONBLOCK):
                return

        def symbol(value: object) -> str:
            # Reject rather than truncate arbitrary or oversized labels.
            if (type(value) is str and 1 <= len(value) <= 96
                    and value.isascii() and value.isidentifier()):
                return value
            return "unavailable"

        lines = ["AUTHORITY_DENIAL_STAGE=" + stage]
        seen: set[int] = set()
        causes = []
        cause = error
        while isinstance(cause, BaseException) and len(seen) < 8:
            if id(cause) in seen:
                break
            seen.add(id(cause))
            frames = []
            trace = cause.__traceback__
            traversed = 0
            while trace is not None and traversed < 128:
                frames.append(trace)
                if len(frames) > 12:
                    del frames[0]
                traversed += 1
                trace = trace.tb_next
            # Never present a bounded outer prefix as the innermost callsite.
            if trace is not None:
                frames = [None]
            causes.append((symbol(type(cause).__name__), frames))
            cause = (cause.__cause__ if cause.__cause__ is not None
                     else None if cause.__suppress_context__ else cause.__context__)
        frame_count = 0
        for index, (name, frames) in enumerate(causes):
            lines.append(f"AUTHORITY_DENIAL_TYPE={index}:" + name)
            # Preserve at least one innermost site for each remaining cause.
            reserved = sum(bool(tail) for _name, tail in causes[index + 1:])
            count = min(len(frames), 12 - frame_count - reserved)
            for trace in frames[-count:] if count else ():
                frame_count += 1
                if trace is None:
                    lines.append(f"AUTHORITY_DENIAL_FRAME={index}:unavailable:unavailable:0")
                    continue
                code = trace.tb_frame.f_code
                filename = code.co_filename
                basename = "unavailable"
                if type(filename) is str and len(filename) <= 4096:
                    candidate = filename.rsplit("/", 1)[-1]
                    if (candidate.endswith(".py") and len(candidate) <= 96
                            and symbol(candidate[:-3]) != "unavailable"):
                        basename = candidate
                line = trace.tb_lineno
                if type(line) is not int or not 1 <= line <= 9999999:
                    line = 0
                lines.append(f"AUTHORITY_DENIAL_FRAME={index}:{basename}:"
                             + symbol(code.co_name) + f":{line}")
        encoded = ("\n".join(lines) + "\n").encode("ascii")
        if len(encoded) <= 4096:
            os.write(2, encoded)
    except Exception:
        # Diagnostics must not replace the original denial or cleanup path.
        pass
