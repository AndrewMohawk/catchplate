"""Install one independently approved fixed job pair; never issue approval."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "authority"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import native_pilot_authority_io as io
from serverware import native_pilot_approval_install as installation


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot approval installation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--request-fd", required=True, type=int)
        parser.add_argument("--approval-fd", required=True, type=int)
        parser.add_argument("--approval-sha256", required=True)
        parser.add_argument("--input-fd", required=True, type=int)
        parser.add_argument("--input-sha256", required=True)
        args = parser.parse_args()
        specifications = ((args.request_fd, installation.MAX_REQUEST),
            (args.approval_fd, installation.MAX_APPROVAL), (args.input_fd, installation.MAX_INPUT))
        installation.p.require(len({fd for fd, _ in specifications}) == 3)
        for fd, _ in specifications:
            installation.p.integer(fd, minimum=3, maximum=(1 << 31) - 1)
        raw = tuple(io.read_public(fd, maximum) for fd, maximum in specifications)
        installation.p.require(tuple(io.read_public(fd, maximum) for fd, maximum in specifications) == raw)
        result = installation.install(*raw, approval_sha256=args.approval_sha256,
            input_sha256=args.input_sha256)
        installation.p.require(tuple(io.read_public(fd, maximum) for fd, maximum in specifications) == raw)
        deadline = installation.p.ns(installation.p.document(raw[0], installation.MAX_REQUEST)["deadlineBoottimeNs"])
        io.write_public(installation.p.canonical(result), deadline_boottime_ns=deadline)
        return 0
    except BaseException:
        # Partial names/output are retained; failure never authorizes a retry.
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
