#!/usr/bin/env python3
"""Sign one independently approved measured-audit policy original, offline.

Use python3 -I -B as root with --input-fd, its independently approved complete
--input-sha256, and a distinct preprovisioned sealed --authority-key-fd. Input
is the exact canonical serverware.measuredAuditAuthorityPolicy/v1 payload,
including its full configuration digest, native targets and original interval.
No field, timestamp, key, approval or assignment is generated or renewed here.

Output is the existing signedMeasuredAuditAuthorityPolicy/v1 original, no LF,
on the root supervisor pipe. Require complete output AND exit0; partial output
or failure permits no retry. A signature authorizes the approved assignment,
not the truth of a quote, measured execution, admission, or runtime readiness.
An independent supervisor must bound filesystem and cryptographic stalls.
Python/OpenSSL key copies are software custody, not guaranteed memory erasure.
"""
from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

import native_pilot_authority_io as io
from serverware import data_plane_audit_authority as authority
from serverware import native_shadow_nitro_originals as originals

MAX_INPUT = 2 * 1024 * 1024
MAX_OUTPUT = 3 * 1024 * 1024


class _Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("measured audit assignment invocation refused")


def _interval(value, now):
    authority.require(type(value) is dict and set(value) == {"schema", "sourceRevision",
        "configurationDigest", "deploymentId", "issuedAtEpochNs", "expiresAtEpochNs",
        "trustRoots", "assignments"} and value["schema"] == authority.POLICY_SCHEMA)
    issued, expires = value["issuedAtEpochNs"], value["expiresAtEpochNs"]
    authority.require(type(issued) is int and type(expires) is int
        and 0 < issued <= now < expires <= issued + 86_400_000_000_000)
    return expires


def _sign(value, raw, key, check):
    # sign_policy requires an actual Ed25519PrivateKey, not a callback wrapper.
    # Use its exact validator, domain, canonical payload and envelope, with the
    # live check placed AFTER potentially lengthy trust/CA validation and directly
    # before/after private signing. Never substitute a new issuance interval.
    authority.require(isinstance(key, authority.Ed25519PrivateKey))
    admitted = authority.policy(value, key.public_key())
    authority.require(authority.canonical(admitted) == raw)
    preimage = authority.POLICY_SCHEMA.encode("ascii") + b"\0" + raw
    check()
    signature = key.sign(preimage)
    check()
    result = authority.canonical({
        "schema": "serverware.signedMeasuredAuditAuthorityPolicy/v1",
        "payload": admitted,
        "signatureBase64Url": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    })
    authority.require(len(result) <= MAX_OUTPUT)
    check()
    return result


def main():
    try:
        parser = _Parser(description=__doc__, add_help=False, allow_abbrev=False)
        parser.add_argument("--input-fd", type=int, required=True)
        parser.add_argument("--input-sha256", required=True)
        parser.add_argument("--authority-key-fd", type=int, required=True)
        args = parser.parse_args()
        authority.require(args.input_fd >= 3 and args.authority_key_fd >= 3
            and args.input_fd != args.authority_key_fd)
        pin = authority.digest(args.input_sha256)
        input_identity = io._input(args.input_fd, MAX_INPUT)
        key_identity = io._input(args.authority_key_fd, 32, private=True)
        owner = os.getpid(), originals._start(), originals._boot()
        before_boot, before_wall = originals._clock(), time.time_ns()
        raw = io.read_public(args.input_fd, MAX_INPUT)
        authority.require(authority.sha256(raw) == pin)
        value = authority.document(raw, MAX_INPUT)
        # Exact canonical public original and its original interval precede key
        # byte access. Key-dependent trust/target validation remains unchanged.
        authority.require(authority.canonical(value) == raw)
        expires = _interval(value, before_wall)
        deadline = before_boot + expires - before_wall
        previous = [before_boot, before_wall]

        def check():
            authority.require(io._input(args.input_fd, MAX_INPUT) == input_identity
                and io._input(args.authority_key_fd, 32, private=True) == key_identity
                and io.read_public(args.input_fd, MAX_INPUT) == raw
                and owner == (os.getpid(), originals._start(), originals._boot()))
            now_boot, now_wall = originals._clock(), time.time_ns()
            authority.require(previous[0] <= now_boot < deadline and previous[1] <= now_wall)
            _interval(value, now_wall)
            previous[:] = now_boot, now_wall

        check()
        key = io.signing_key(args.authority_key_fd)
        check()
        result = _sign(value, raw, key, check)
        check()
        io.write_public(result, deadline_boottime_ns=deadline, check=check)
        check()
        return 0
    except BaseException:
        return io.fail()


if __name__ == "__main__":
    raise SystemExit(main())
