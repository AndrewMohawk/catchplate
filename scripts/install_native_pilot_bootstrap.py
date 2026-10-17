"""Install one independently approved fixed driver bootstrap bundle, control last."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "authority"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import native_pilot_authority_io as io
from catchplate import native_pilot_bootstrap_install as installation


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native pilot bootstrap installation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--input-fd", required=True, type=int)
        parser.add_argument("--input-sha256", required=True)
        args = parser.parse_args()
        installation.p.integer(args.input_fd, minimum=3, maximum=(1 << 31) - 1)
        raw = io.read_public(args.input_fd, installation.MAX_INPUT)
        installation.p.require(io.read_public(args.input_fd, installation.MAX_INPUT) == raw)
        result = installation.install(raw, expected_sha256=args.input_sha256)
        installation.p.require(io.read_public(args.input_fd, installation.MAX_INPUT) == raw)
        io.write_public(installation.p.canonical(result),
            deadline_boottime_ns=installation.p.ns(result["startupDeadlineBoottimeNs"]))
        return 0
    except BaseException:
        # Refusal, partial publication or uncertain output never enables retry.
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
