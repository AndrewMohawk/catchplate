#!/usr/bin/env python3
"""Assemble one unsigned native delivery from explicitly pinned public FDs.

Run python3 -I -B as root with --input-fd, its independently approved
--input-sha256, and a distinct --output-fd write pipe. The canonical descriptor
is serverware.nativeConfigurationDeliveryAssemblyInput/v1 with exactly:
apiVersion, challenge {fd,sha256}, issuedAtEpochNs, expiresAtEpochNs,
deadlineBoottimeNs, configurationSha256, launchSha256, and artifacts
[{label,fd,sha256}]. Challenge is the original unframed canonical receiver hello.
Every input is a read-only root:root0400 regular file or sealed memfd. Only
independently selected public/encrypted artifacts belong in this descriptor;
the command has no private-key or plaintext-credential input.

The separately selected AssemblyInput/v2 adds exactly startupProfile with the
fixed value static-credential-rotation-v25 and requires a matching v2 hello.
It produces the v2 payload; v1 fields and output remain unchanged.

Output is the existing canonical nativeConfigurationDelivery/v1 unsigned
payload, without framing or newline. A supervisor must retain complete output
AND exit0, then stage/hash it for independent approval by the existing signer.
The assembler does not approve inputs, verify authority, contact an enclave,
choose deadlines, regenerate N/launch, or claim closure/admission/readiness.
The receiver still checks the source-owned artifact/path/profile closure.
Failure or partial output is not permission to retry. The original interval
bounds work/output; an external supervisor must bound blocking filesystem I/O.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import os
from pathlib import Path
import re
import signal
import stat
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent))
import send_native_configuration as transport

INPUT_API = "serverware.nativeConfigurationDeliveryAssemblyInput/v1"
ROTATION_INPUT_API = "serverware.nativeConfigurationDeliveryAssemblyInput/v2"
MAX_INPUT = 64 * 1024
SEALS = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("native delivery assembly invocation refused")


def descriptor_number(value):
    transport.require(type(value) is int and 3 <= value < 2**31)
    return value


def public_identity(fd, maximum):
    descriptor_number(fd)
    flags, info = fcntl.fcntl(fd, fcntl.F_GETFL), os.fstat(fd)
    transport.require(not flags & os.O_PATH and flags & os.O_ACCMODE == os.O_RDONLY
        and stat.S_ISREG(info.st_mode) and (info.st_uid, info.st_gid) == (0, 0)
        and stat.S_IMODE(info.st_mode) == 0o400 and 0 < info.st_size <= maximum)
    if info.st_nlink == 0:
        transport.require(fcntl.fcntl(fd, fcntl.F_GET_SEALS) == SEALS)
    else:
        transport.require(info.st_nlink == 1)
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_public(fd, expected, pin, check):
    """Acquire one literal original without moving the inherited file offset."""
    result = bytearray()
    while len(result) < expected[6]:
        check()
        chunk = os.pread(fd, min(65536, expected[6] - len(result)), len(result))
        check()
        transport.require(bool(chunk))
        result.extend(chunk)
    transport.require(not os.pread(fd, 1, len(result)))
    check()
    raw = bytes(result)
    transport.require("sha256:" + hashlib.sha256(raw).hexdigest() == pin)
    check()
    return raw


def descriptor(raw):
    value = transport.document(raw, MAX_INPUT, canonical_required=True)
    rotation = value.get("apiVersion") == ROTATION_INPUT_API
    transport.require(set(value) == {"apiVersion", "challenge", "issuedAtEpochNs", "expiresAtEpochNs",
        "deadlineBoottimeNs", "configurationSha256", "launchSha256", "artifacts"}
        | ({"startupProfile"} if rotation else set())
        and value["apiVersion"] == (ROTATION_INPUT_API if rotation else INPUT_API))
    if rotation:
        transport.require(value["startupProfile"] == transport.ROTATION_PROFILE)
    challenge = value["challenge"]
    transport.require(type(challenge) is dict and set(challenge) == {"fd", "sha256"})
    descriptor_number(challenge["fd"]); transport.digest(challenge["sha256"])
    for name in ("issuedAtEpochNs", "expiresAtEpochNs", "deadlineBoottimeNs"):
        transport.u64(value[name])
    for name in ("configurationSha256", "launchSha256"):
        transport.digest(value[name])
    rows = value["artifacts"]
    transport.require(type(rows) is list and 2 <= len(rows) <= 128)
    pins = {}
    for row in rows:
        transport.require(type(row) is dict and set(row) == {"label", "fd", "sha256"}
            and type(row["label"]) is str and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", row["label"]) is not None
            and row["label"] not in pins)
        descriptor_number(row["fd"])
        pins[row["label"]] = transport.digest(row["sha256"])
    transport.require(pins.get("configuration") == value["configurationSha256"]
        and pins.get("launch") == value["launchSha256"])
    return value


class AdmittedBudget:
    """Reuse the sender's parser without restarting the original interval."""
    def __init__(self, budget):
        self.budget = budget

    def admit(self, issued, expires):
        transport.require(self.budget.interval is not None and (issued, expires) == self.budget.interval[:2])
        self.budget.remaining()

    def remaining(self):
        return self.budget.remaining()


def main():
    transport.require(sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1
        and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
        and threading.current_thread() is threading.main_thread())
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--input-fd", type=int, required=True)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--output-fd", type=int, required=True)
    args = parser.parse_args()
    descriptor_number(args.input_fd); descriptor_number(args.output_fd)
    transport.require(args.input_fd != args.output_fd)
    input_pin = transport.digest(args.input_sha256)
    output = transport.pipe_identity(args.output_fd, os.O_WRONLY)
    transport.require(output[3:] == (0, 0))
    held = {args.input_fd: (MAX_INPUT, public_identity(args.input_fd, MAX_INPUT))}
    pid, budget = os.getpid(), transport.Budget()

    def check():
        transport.require(os.getpid() == pid and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0)
            and transport.pipe_identity(args.output_fd, os.O_WRONLY) == output
            and fcntl.fcntl(args.output_fd, fcntl.F_GETFL) & os.O_NONBLOCK)
        for fd, (maximum, expected) in held.items():
            transport.require(public_identity(fd, maximum) == expected)
        return budget.remaining()

    try:
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(number, transport.cancelled)
        os.set_inheritable(args.output_fd, False)
        fcntl.fcntl(args.output_fd, fcntl.F_SETFL, fcntl.fcntl(args.output_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        os.set_inheritable(args.input_fd, False)
        check()
        value = descriptor(read_public(args.input_fd, held[args.input_fd][1], input_pin, check))
        profile = transport.ROTATION_PROFILE if value["apiVersion"] == ROTATION_INPUT_API else transport.STATIC_PROFILE
        budget.admit(value["issuedAtEpochNs"], value["expiresAtEpochNs"])
        challenge_fd = value["challenge"]["fd"]
        transport.require(challenge_fd not in {args.input_fd, args.output_fd})
        held[challenge_fd] = transport.MAX_HELLO, public_identity(challenge_fd, transport.MAX_HELLO)
        os.set_inheritable(challenge_fd, False)
        challenge = transport.hello(read_public(challenge_fd, held[challenge_fd][1], value["challenge"]["sha256"], check),
            profile=profile)
        transport.require(value["deadlineBoottimeNs"] > challenge["receiverStartedBoottimeNs"])
        total = 0
        for row in value["artifacts"]:
            fd = row["fd"]
            transport.require(fd not in {args.input_fd, args.output_fd, challenge_fd})
            current = public_identity(fd, transport.MAX_FILE)
            transport.require(fd not in held or held[fd] == (transport.MAX_FILE, current))
            held[fd] = transport.MAX_FILE, current
            os.set_inheritable(fd, False)
            total += current[6]
            transport.require(total <= transport.MAX_TOTAL)
        check()
        artifacts = []
        for row in value["artifacts"]:
            raw = read_public(row["fd"], held[row["fd"]][1], row["sha256"], check)
            artifacts.append({"label": row["label"], "sha256": row["sha256"],
                "contentBase64Url": base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")})
            del raw
            check()
        _, signed_api, payload_api = transport.profile_apis(profile)
        payload = {"apiVersion": payload_api, **{name: challenge[name] for name in transport.profile_scope(profile)},
            **{name: value[name] for name in ("issuedAtEpochNs", "expiresAtEpochNs", "deadlineBoottimeNs",
                "configurationSha256", "launchSha256")}, "artifacts": artifacts}
        result = transport.canonical(payload)
        # This non-authorizing signature slot exists only to call the unchanged
        # sender grammar/bounds. It is never signed, returned or transmitted.
        preflight = transport.canonical({"apiVersion": signed_api, "payload": payload,
            "signatureBase64Url": base64.urlsafe_b64encode(bytes(64)).rstrip(b"=").decode("ascii")})
        transport.manifest(preflight, challenge, AdmittedBudget(budget), profile=profile)
        del preflight, payload, artifacts
        check()
        transport.write_exact(args.output_fd, result, check)
        check()
    finally:
        os.close(args.output_fd)


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt):
        try:
            transport.report(2, b"Native configuration assembly refused or incomplete; no retry authorized.\n")
        except Exception:
            pass
        raise SystemExit(1) from None
