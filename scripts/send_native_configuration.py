#!/usr/bin/env python3
"""Transport one public native configuration delivery through explicit pipes.

Run python3 -I -B with an explicit enclave CID and distinct inherited PIPE FDs:
--challenge-output-fd (write end) and --manifest-input-fd (read end). Network
frames and the challenge output use a 4-byte big-endian length plus original
bytes. The manifest pipe receives the signer's raw original followed by EOF;
this command supplies its network length prefix without changing those bytes.
No files, keys, signatures, or configuration are created.

The default profile is postboot-static-v24 with the unchanged v1 wire. Explicit
--profile static-credential-rotation-v25 requires the closed v2 hello/manifest
and its signed startupProfile; neither profile accepts caller-selected argv.

The single connection uses fixed port 9100. Preauthorization waits are unbounded
until input, disconnect or cancellation. Once the manifest supplies its original
expiry, parsing/validation/transmission consume that interval without renewal.
The receiver alone verifies signature/authority/closure. Successful transport
does NOT establish native admission, attestation or readiness. Any failure can
leave delivery uncertain; this command never reconnects or retries a delivery.
"""
from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import hashlib
import json
import os
import re
import select
import signal
import socket
import stat
import sys
import time

PORT = 9100
MAX_HELLO = 4096
MAX_MANIFEST = 64 * 1024 * 1024
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_INTERVAL = 86_400_000_000_000
HELLO_API = "catchplate.nativeConfigurationDeliveryChallenge/v1"
SIGNED_API = "catchplate.signedNativeConfigurationDelivery/v1"
PAYLOAD_API = "catchplate.nativeConfigurationDelivery/v1"
SCOPE = {"challengeBase64Url", "bootId", "receiverStartedBoottimeNs", "deliveryKeySpkiSha256"}
STATIC_PROFILE = "postboot-static-v24"
ROTATION_PROFILE = "static-credential-rotation-v25"
ROTATION_HELLO_API = "catchplate.nativeConfigurationDeliveryChallenge/v2"
ROTATION_SIGNED_API = "catchplate.signedNativeConfigurationDelivery/v2"
ROTATION_PAYLOAD_API = "catchplate.nativeConfigurationDelivery/v2"


def require(value):
    if not value:
        raise ValueError("native configuration transport refused")


def profile_apis(profile):
    require(profile in (STATIC_PROFILE, ROTATION_PROFILE))
    return ((HELLO_API, SIGNED_API, PAYLOAD_API) if profile == STATIC_PROFILE else
        (ROTATION_HELLO_API, ROTATION_SIGNED_API, ROTATION_PAYLOAD_API))


def profile_scope(profile):
    profile_apis(profile)
    return SCOPE if profile == STATIC_PROFILE else SCOPE | {"startupProfile"}


def payload_profile(value):
    """Only a closed version selects signing grammar; no argv is accepted."""
    require(type(value) is dict)
    if value.get("apiVersion") == PAYLOAD_API:
        return STATIC_PROFILE
    require(value.get("apiVersion") == ROTATION_PAYLOAD_API
        and value.get("startupProfile") == ROTATION_PROFILE)
    return ROTATION_PROFILE


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("invalid native configuration transport arguments")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def document(raw, maximum, *, canonical_required=False):
    require(type(raw) is bytes and 0 < len(raw) <= maximum)

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result

    def invalid(_value):
        raise ValueError("noninteger or non-JSON number")

    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
                       parse_constant=invalid, parse_float=invalid)
    require(type(value) is dict and (not canonical_required or canonical(value) == raw))
    return value


def encoded(value, maximum, *, exact=None):
    require(type(value) is str and 0 < len(value) <= (maximum * 4 + 2) // 3
            and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None)
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    require(0 < len(raw) <= maximum and (exact is None or len(raw) == exact)
            and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def u64(value):
    require(type(value) is int and 0 <= value < 2**64)
    return value


def digest(value):
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None)
    return value


def hello(raw, *, profile=STATIC_PROFILE):
    value = document(raw, MAX_HELLO, canonical_required=True)
    require(set(value) == {"apiVersion", *profile_scope(profile)} and value["apiVersion"] == profile_apis(profile)[0])
    if profile == ROTATION_PROFILE:
        require(value["startupProfile"] == ROTATION_PROFILE)
    require(encoded(value["challengeBase64Url"], 32, exact=32) != bytes(32))
    require(type(value["bootId"]) is str and re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", value["bootId"]) is not None)
    u64(value["receiverStartedBoottimeNs"])
    digest(value["deliveryKeySpkiSha256"])
    return value


class Budget:
    """Conservative local conversion; never reinterpret enclave BOOTTIME."""
    def __init__(self):
        self.start_boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        self.start_wall = time.time_ns()
        self.previous = self.start_boot, self.start_wall
        self.interval = None

    def admit(self, issued, expires):
        require(self.interval is None and 0 < issued < expires and expires - issued <= MAX_INTERVAL)
        self.interval = issued, expires, self.start_boot + expires - self.start_wall
        self.remaining()

    def remaining(self):
        boot, wall = time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()
        require(self.previous[0] <= boot and self.previous[1] <= wall)
        self.previous = boot, wall
        if self.interval is None:
            return None
        issued, expires, deadline = self.interval
        require(issued <= wall < expires and boot < deadline)
        return (deadline - boot) / 1_000_000_000


def manifest(raw, challenge, budget, *, profile=STATIC_PROFILE):
    hello(canonical(challenge), profile=profile)
    scope = profile_scope(profile)
    _, signed_api, payload_api = profile_apis(profile)
    value = document(raw, MAX_MANIFEST)
    require(set(value) == {"apiVersion", "payload", "signatureBase64Url"} and value["apiVersion"] == signed_api)
    encoded(value["signatureBase64Url"], 64, exact=64)  # Encoding, NOT signature verification.
    payload = value["payload"]
    require(type(payload) is dict and set(payload) == {"apiVersion", *scope,
        "issuedAtEpochNs", "expiresAtEpochNs", "deadlineBoottimeNs", "configurationSha256", "launchSha256", "artifacts"}
        and payload["apiVersion"] == payload_api)
    require(all(type(payload[name]) is type(challenge[name]) and payload[name] == challenge[name] for name in scope))
    budget.admit(u64(payload["issuedAtEpochNs"]), u64(payload["expiresAtEpochNs"]))
    # Only native can compare its absolute BOOTTIME deadline to its current
    # clock. Preserve this original; the parent uses the original wall expiry.
    require(u64(payload["deadlineBoottimeNs"]) > challenge["receiverStartedBoottimeNs"])
    for name in ("configurationSha256", "launchSha256"):
        digest(payload[name])
    rows = payload["artifacts"]
    require(type(rows) is list and 2 <= len(rows) <= 128)
    pins, total = {}, 0
    for row in rows:
        budget.remaining()
        require(type(row) is dict and set(row) == {"label", "sha256", "contentBase64Url"}
                and type(row["label"]) is str and re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", row["label"]) is not None
                and row["label"] not in pins)
        content = encoded(row["contentBase64Url"], MAX_FILE)
        total += len(content)
        require(total <= MAX_TOTAL and "sha256:" + hashlib.sha256(content).hexdigest() == digest(row["sha256"]))
        pins[row["label"]] = row["sha256"]
        if profile == ROTATION_PROFILE and row["label"] == "configuration":
            configuration = document(content, MAX_FILE)
            require(configuration.get("apiVersion") == "catchplate.nativeStartupConfiguration/v25"
                and "measuredStaticCredential" not in configuration
                and type(configuration.get("measuredStaticCredentialRotation")) is dict
                and configuration["measuredStaticCredentialRotation"].get("apiVersion")
                == "catchplate.nativeStaticCredentialRotationConfiguration/v1")
        del content
        budget.remaining()
    require(pins.get("configuration") == payload["configurationSha256"]
            and pins.get("launch") == payload["launchSha256"])
    budget.remaining()


def pipe_identity(fd, access):
    require(type(fd) is int and 3 <= fd < 2**31)
    info, flags = os.fstat(fd), fcntl.fcntl(fd, fcntl.F_GETFL)
    require(stat.S_ISFIFO(info.st_mode) and not flags & os.O_PATH and flags & os.O_ACCMODE == access)
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def wait(fd, writing, check, peer=None):
    while True:
        remaining = check()
        readers = [] if writing else [fd]
        if peer is not None:
            readers.append(peer)
        readable, writable, exceptional = select.select(readers, [fd] if writing else [], [fd],
            0.1 if remaining is None else min(0.1, remaining))
        check()
        require(not exceptional)
        if peer is not None and peer in readable:
            # After the hello the peer sends no more data. EOF or unsolicited
            # bytes both refuse while the operator is composing the manifest.
            raise ValueError("native delivery peer closed or sent unexpected bytes")
        if fd in (writable if writing else readable):
            return


def read_once(fd, length, check, peer=None):
    while True:
        wait(fd, False, check, peer)
        try:
            result = os.read(fd, length)
        except BlockingIOError:
            continue
        check()
        return result


def read_exact(fd, length, check, peer=None):
    result = bytearray()
    while len(result) < length:
        chunk = read_once(fd, min(65536, length - len(result)), check, peer)
        require(bool(chunk))
        result.extend(chunk)
    return bytes(result)


def read_frame(fd, maximum, check, peer=None):
    prefix = read_exact(fd, 4, check, peer)
    length = int.from_bytes(prefix, "big")
    require(0 < length <= maximum)
    return prefix, read_exact(fd, length, check, peer)


def read_original(fd, maximum, check, peer=None):
    """Direct signer stdout, bounded and complete before any network send."""
    result = bytearray()
    while True:
        chunk = read_once(fd, min(65536, maximum + 1 - len(result)), check, peer)
        if not chunk:
            require(0 < len(result) <= maximum)
            return bytes(result)
        result.extend(chunk)
        require(len(result) <= maximum)


def write_exact(fd, raw, check, peer=None):
    remaining = memoryview(raw)
    while remaining:
        wait(fd, True, check, peer)
        try:
            count = os.write(fd, remaining[:65536])
        except BlockingIOError:
            continue
        check()
        require(count > 0)
        remaining = remaining[count:]


def cancelled(_number, _frame):
    raise KeyboardInterrupt


def report(fd, raw):
    fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
    require(os.write(fd, raw) == len(raw))


def main():
    require(sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1)
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--enclave-cid", type=int, required=True)
    parser.add_argument("--challenge-output-fd", type=int, required=True)
    parser.add_argument("--manifest-input-fd", type=int, required=True)
    parser.add_argument("--profile", choices=(STATIC_PROFILE, ROTATION_PROFILE), default=STATIC_PROFILE)
    args = parser.parse_args()
    require(4 <= args.enclave_cid < 2**32 - 1 and args.challenge_output_fd != args.manifest_input_fd)
    pipes = {args.challenge_output_fd: (os.O_WRONLY, pipe_identity(args.challenge_output_fd, os.O_WRONLY)),
             args.manifest_input_fd: (os.O_RDONLY, pipe_identity(args.manifest_input_fd, os.O_RDONLY))}
    require(pipes[args.challenge_output_fd][1][:2] != pipes[args.manifest_input_fd][1][:2])
    pid, budget = os.getpid(), None

    def check():
        require(os.getpid() == pid)
        for fd, (access, held) in pipes.items():
            require(pipe_identity(fd, access) == held and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NONBLOCK)
        return None if budget is None else budget.remaining()

    try:
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(number, cancelled)
        for fd in pipes:
            os.set_inheritable(fd, False)
            fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        check()
        with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM) as stream:
            stream.setblocking(False)
            result = stream.connect_ex((args.enclave_cid, PORT))  # Single attempt, no rediscovery.
            require(result in {0, errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK, errno.EINTR})
            if result != 0:
                wait(stream.fileno(), True, check)
                require(stream.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0)
            require(stream.getpeername() == (args.enclave_cid, PORT))
            prefix, raw = read_frame(stream.fileno(), MAX_HELLO, check)
            challenge = hello(raw, profile=args.profile)
            write_exact(args.challenge_output_fd, prefix, check, stream.fileno())
            write_exact(args.challenge_output_fd, raw, check, stream.fileno())
            os.close(args.challenge_output_fd)
            del pipes[args.challenge_output_fd]
            raw = read_original(args.manifest_input_fd, MAX_MANIFEST, check, stream.fileno())
            prefix = len(raw).to_bytes(4, "big")
            budget = Budget()  # Parsing and structural checks consume this same original expiry.
            manifest(raw, challenge, budget, profile=args.profile)
            check()
            write_exact(stream.fileno(), prefix, check)
            write_exact(stream.fileno(), raw, check)
            check()
            stream.shutdown(socket.SHUT_WR)
            check()
        check()
    finally:
        for fd in pipes:
            os.close(fd)
    report(1, b"bytes-delivered-unverified: local transport only; native admission/readiness unverified\n")


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt):
        try:
            report(2, b"Native configuration delivery refused or uncertain; no retry authorized.\n")
        except Exception:
            pass
        raise SystemExit(1) from None
