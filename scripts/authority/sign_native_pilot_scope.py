"""Sign one approved native driver Scope/v4 from fixed protected FD inputs.

No generated key, live-owner reconstruction, path argument, installer, deadline
renewal or automatic retry. The independent supervisor must reject partial output.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import native_pilot_authority_io as io
from serverware import native_pilot_scope_authority as authority


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot scope invocation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--input-fd", required=True, type=int)
        parser.add_argument("--authority-key-fd", required=True, type=int)
        args = parser.parse_args()
        authority.p.require(args.input_fd >= 3 and args.authority_key_fd >= 3
            and args.input_fd != args.authority_key_fd)
        raw = io.read_public(args.input_fd, authority.MAX_INPUT)
        result = authority.sign(raw, io.signing_key(args.authority_key_fd))
        authority.p.require(io.read_public(args.input_fd, authority.MAX_INPUT) == raw)
        scope = authority.p.document(result, authority.MAX_SCOPE)["payload"]
        io.write_public(result, deadline_boottime_ns=authority.p.ns(scope["startupDeadlineBoottimeNs"]))
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
