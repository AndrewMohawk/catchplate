#!/usr/bin/env python3
"""Sign one independently approved activation-receiver original, offline.

Use python3 -I -B as root with --operation delivery|service|installation,
--input-fd, its independently approved complete --input-sha256, and an
explicitly supplied existing sealed 32-byte --authority-key-fd. Delivery and
installation use the selected C9 authority; service uses the independently
selected supervisor authority. The issuer checks the supplied key's purpose.

Each invocation needs its own approved input. A service input already contains
the signed C9 and separately approved native admission/initial-state originals;
an installation input already contains the complete approved public file set.
This command does not construct or approve subsequent inputs automatically.

Stdout is only the exact canonical signed original, without framing or newline.
For installation this is Completion/v2; the receiver transport must add its
four-byte big-endian length and EOF. Require complete output AND exit zero.
Partial output or failure authorizes no retry. No key, file, nonce, guest clock,
deadline, approval, journal or native authority is generated here. Host
BOOTTIME is used only by the shared bounded pipe writer, never as guest time.
The real receiver still validates its actual original clock and admission.
An external supervisor must bound blocking filesystem and crypto work; Python
key copies provide neither hardware custody nor guaranteed erasure.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import sys

_SCRIPT = Path(__file__).resolve().parent
_PACKAGED_SCRIPT = "/authority/app/scripts/authority/issue_native_activation_receiver.py"
if str(_SCRIPT) == "/authority/app/scripts/authority":
    # This command is deliberately separate from the coordinator's closed
    # entrypoint. Under -I only these fixed packaged import roots are added.
    if not (
        sys.argv[0] == _PACKAGED_SCRIPT and __file__ == _PACKAGED_SCRIPT
        and os.path.realpath(__file__) == _PACKAGED_SCRIPT
        and sys.executable == "/runtime/python/bin/python3"
        and os.path.realpath(sys.executable) == "/runtime/python/bin/python3"
        and sys.prefix == sys.base_prefix == "/runtime/python"
        and sys.version_info[:2] == (3, 11)
        and sys.flags.isolated == 1 and sys.flags.ignore_environment == 1
        and sys.flags.no_user_site == 1 and sys.flags.safe_path
        and sys.flags.dont_write_bytecode == 1
    ):
        raise SystemExit("native activation receiver packaged invocation refused")
    sys.path[:0] = [str(_SCRIPT), "/authority/app", "/vendor", "/app"]
else:
    # Source invocation retains the explicit script-relative repository roots.
    sys.path[:0] = [str(_SCRIPT.parent.parent), str(_SCRIPT)]

import native_pilot_authority_io as io
from catchplate import native_activation_receiver_issuer as issuer


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native activation receiver issuance invocation refused")


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--operation", choices=issuer.OPERATIONS, required=True)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--input-sha256", required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        io._process()
        io._require(args.input_fd >= 3 and args.authority_key_fd >= 3
            and args.input_fd != args.authority_key_fd)
        input_identity = io._input(args.input_fd, issuer.MAX_INPUT)
        key_identity = io._input(args.authority_key_fd, 32, private=True)
        io._require(key_identity[6] == 32 and input_identity[:2] != key_identity[:2])
        raw = io.read_public(args.input_fd, issuer.MAX_INPUT)
        # The complete public input, not a caller-selected fragment, must have
        # been independently approved before any signing key bytes are read.
        io._require(args.input_sha256 == "sha256:" + hashlib.sha256(raw).hexdigest())
        process = os.getpid()

        def check():
            io._require(os.getpid() == process
                and io._input(args.input_fd, issuer.MAX_INPUT) == input_identity
                and io._input(args.authority_key_fd, 32, private=True) == key_identity
                and io.read_public(args.input_fd, issuer.MAX_INPUT) == raw)

        check()
        issuer.prepare_input(args.operation, raw)
        check()
        key = io.signing_key(args.authority_key_fd)
        check()
        signed = issuer.sign(args.operation, raw, key, check=check)
        check()
        # Never reinterpret a receiver BOOTTIME deadline in this host domain.
        # The existing pipe writer's local I/O ceiling is not startup authority.
        io.write_public(signed, check=check)
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
