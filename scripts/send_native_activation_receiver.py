#!/usr/bin/env python3
"""Bridge one activation receiver's public control exchange, without authority.

Run python3 -I -B on the parent, which LISTENS at fixed CID3:9103. The guest
bootstrap connects once; --enclave-cid selects its route, not its identity or
attestation. Distinct inherited --observation-output-fd and --completion-input-fd
pipes belong to the independently operated authority workflow. The observation
output is its literal BE32 frame followed by EOF. The completion input is the
already signed canonical Completion/v2 original followed by EOF; this bridge
adds BE32 framing and shuts down its network write half exactly once.

The two cold SHA256 arguments only constrain the selected public projection.
They are not approvals. Invoke the separate delivery, service and installation
issuer operations explicitly with independently approved inputs; this command
does not invoke a signer, load keys, create inputs or verify signing authority.
The receiver verifies the whole installation signature and native admission.

--io-timeout-seconds is an explicit local transport budget, starting before
listen. It neither replaces nor renews the guest's original signed window;
guest BOOTTIME is never compared with the parent's clock. There is no retry,
reconnect, acknowledgment or readiness claim. Failure can leave delivery
uncertain. No cross-kernel pipe or inherited host descriptor is assumed.
"""
from __future__ import annotations

import argparse
import base64
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

PARENT_CID, PORT = 3, 9103
MAX_OBSERVATION, MAX_COMPLETION = 8192, 1024 * 1024
OBSERVATION_API = "serverware.nativeShadowActivationReceiverObservation/v1"
COMPLETION_API = "serverware.nativeShadowActivationReceiverCompletion/v2"
INSTALLATION_API = "serverware.nativeShadowActivationReceiverInstallation/v1"
OBSERVATION_FIELDS = {"apiVersion", "okForAction", "configurationSha256", "deliveryConfigurationSha256",
    "processId", "processStartTicks", "processPidfdInode", "bootIdBase64url", "timeNamespaceDevice",
    "timeNamespaceInode", "observedAtBoottimeNs", "localCid", "localPort", "peerCid", "peerPort", "activation"}
PAYLOAD_FIELDS = {"apiVersion", "purpose", "observationSha256", "configurationSha256",
    "deliveryConfigurationSha256", "launchSha256", "issuedAtBoottimeNs", "startupDeadlineBoottimeNs", "files"}


def require(value):
    if not value:
        raise ValueError("activation receiver control transport refused")


class Parser(argparse.ArgumentParser):
    def error(self, _message):
        raise ValueError("activation receiver control invocation refused")


def document(raw, maximum):
    require(type(raw) is bytes and 0 < len(raw) <= maximum)

    def pairs(items):
        value = {}
        for name, item in items:
            require(name not in value)
            value[name] = item
        return value

    def invalid(_value):
        raise ValueError("noninteger JSON number")

    value = json.loads(raw.decode("ascii"), object_pairs_hook=pairs,
        parse_float=invalid, parse_constant=invalid)
    require(type(value) is dict and json.dumps(value, ensure_ascii=True, allow_nan=False,
        sort_keys=True, separators=(",", ":")).encode("ascii") == raw)
    return value


def digest(value):
    require(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None
        and value != "sha256:" + "0" * 64)
    return value


def integer(value, minimum=1, maximum=2**64 - 1):
    require(type(value) is int and minimum <= value <= maximum)
    return value


def decimal(value):
    require(type(value) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None)
    return integer(int(value))


def encoded(value, size):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None
        and len(value) == (size * 4 + 2) // 3)
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    require(len(raw) == size and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") == value)
    return raw


def observation(raw, *, enclave_cid, configuration_sha256, delivery_configuration_sha256):
    value = document(raw, MAX_OBSERVATION)
    require(set(value) == OBSERVATION_FIELDS and value["apiVersion"] == OBSERVATION_API
        and value["okForAction"] is False
        and value["configurationSha256"] == configuration_sha256
        and value["deliveryConfigurationSha256"] == delivery_configuration_sha256
        and type(value["localCid"]) is int and value["localCid"] == enclave_cid
        and type(value["localPort"]) is int and value["localPort"] == 9102
        and type(value["peerCid"]) is int and value["peerCid"] == PARENT_CID)
    integer(value["peerPort"], 1024, 2**32 - 2)
    integer(value["processId"], maximum=2**31 - 1)
    for field in ("processStartTicks", "processPidfdInode", "timeNamespaceDevice", "timeNamespaceInode"):
        integer(value[field])
    require(encoded(value["bootIdBase64url"], 16) != bytes(16))
    decimal(value["observedAtBoottimeNs"])
    entries = value["activation"]
    require(type(entries) is list and len(entries) == 2)
    for index, (entry, name, kind) in enumerate(zip(entries,
            ("activation-channel", "activation-journal"), (stat.S_IFSOCK, stat.S_IFDIR)), 6):
        require(type(entry) is dict and set(entry) == {"name", "fd", "device", "inode", "mode", "uid", "gid"}
            and entry["name"] == name and type(entry["fd"]) is int and entry["fd"] == index)
        integer(entry["device"], 0); integer(entry["inode"])
        for field in ("mode", "uid", "gid"):
            integer(entry[field], 0, 2**32 - 1)
        require(stat.S_IFMT(entry["mode"]) == kind)
    return value


def completion(raw, observation_raw, observed):
    """Projection/encoding checks only; the receiver verifies the signature."""
    value = document(raw, MAX_COMPLETION)
    require(set(value) == {"apiVersion", "installation"} and value["apiVersion"] == COMPLETION_API)
    signed = value["installation"]
    require(type(signed) is dict and set(signed) == {"payload", "signature"})
    encoded(signed["signature"], 64)
    payload = signed["payload"]
    require(type(payload) is dict and set(payload) == PAYLOAD_FIELDS
        and payload["apiVersion"] == INSTALLATION_API
        and payload["purpose"] == "install-activation-public-originals"
        and payload["observationSha256"] == "sha256:" + hashlib.sha256(observation_raw).hexdigest()
        and all(payload[field] == observed[field] for field in
            ("configurationSha256", "deliveryConfigurationSha256"))
        and payload["issuedAtBoottimeNs"] == observed["observedAtBoottimeNs"])
    issued, expires = decimal(payload["issuedAtBoottimeNs"]), decimal(payload["startupDeadlineBoottimeNs"])
    require(issued < expires <= issued + 30_000_000_000)
    digest(payload["launchSha256"])
    # Full file roster/content/signature admission belongs to the native
    # installer; this transport neither repairs nor reserializes any original.
    require(type(payload["files"]) is list and len(payload["files"]) == 13)


class Budget:
    def __init__(self, seconds):
        integer(seconds, 1, 86400)
        self.previous = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        self.deadline = self.previous + seconds * 1_000_000_000

    def remaining(self):
        now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        require(self.previous <= now < self.deadline)
        self.previous = now
        return (self.deadline - now) / 1_000_000_000


def identity(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def pipe_identity(fd, access):
    integer(fd, 3, 2**31 - 1)
    result, flags = identity(fd), fcntl.fcntl(fd, fcntl.F_GETFL)
    require(stat.S_ISFIFO(result[2]) and not flags & os.O_PATH and flags & os.O_ACCMODE == access)
    return result


def wait(fd, writing, check):
    while True:
        remaining = check()
        try:
            readable, writable, exceptional = select.select([] if writing else [fd],
                [fd] if writing else [], [fd], min(0.1, remaining))
        except InterruptedError:
            continue
        check(); require(not exceptional)
        if fd in (writable if writing else readable):
            return


def read_once(fd, count, check):
    while True:
        wait(fd, False, check)
        try:
            value = os.read(fd, count)
        except (InterruptedError, BlockingIOError):
            continue
        check()
        return value


def read_exact(fd, count, check):
    result = bytearray()
    while len(result) < count:
        part = read_once(fd, min(65536, count - len(result)), check)
        require(bool(part)); result.extend(part)
    return bytes(result)


def read_original(fd, maximum, check):
    result = bytearray()
    while True:
        part = read_once(fd, min(65536, maximum + 1 - len(result)), check)
        if not part:
            require(0 < len(result) <= maximum)
            return bytes(result)
        result.extend(part); require(len(result) <= maximum)


def write_exact(fd, raw, check):
    view = memoryview(raw)
    while view:
        wait(fd, True, check)
        try:
            count = os.write(fd, view[:65536])
        except (InterruptedError, BlockingIOError):
            continue
        check(); require(count > 0)
        view = view[count:]


def cancelled(_number, _frame):
    raise KeyboardInterrupt


def report(fd, raw):
    fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
    require(os.write(fd, raw) == len(raw))


def main():
    require(sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1)
    parser = Parser(description=__doc__, add_help=False, allow_abbrev=False)
    parser.add_argument("--enclave-cid", type=int, required=True)
    parser.add_argument("--observation-output-fd", type=int, required=True)
    parser.add_argument("--completion-input-fd", type=int, required=True)
    parser.add_argument("--receiver-configuration-sha256", required=True)
    parser.add_argument("--delivery-configuration-sha256", required=True)
    parser.add_argument("--io-timeout-seconds", type=int, required=True)
    args = parser.parse_args()
    integer(args.enclave_cid, 4, 2**32 - 2)
    digest(args.receiver_configuration_sha256); digest(args.delivery_configuration_sha256)
    require(args.observation_output_fd != args.completion_input_fd)
    pipes = {args.observation_output_fd: (os.O_WRONLY, pipe_identity(args.observation_output_fd, os.O_WRONLY)),
        args.completion_input_fd: (os.O_RDONLY, pipe_identity(args.completion_input_fd, os.O_RDONLY))}
    require(pipes[args.observation_output_fd][1][:2] != pipes[args.completion_input_fd][1][:2])
    pid, budget, sockets = os.getpid(), Budget(args.io_timeout_seconds), {}

    def check():
        require(os.getpid() == pid)
        for fd, (access, held) in pipes.items():
            require(pipe_identity(fd, access) == held and fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_NONBLOCK
                and fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
        for stream, (held, peer) in sockets.items():
            require(identity(stream.fileno()) == held and stream.getsockname() == (PARENT_CID, PORT)
                and stream.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
                and stream.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == socket.AF_VSOCK
                and stream.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == int(peer is None)
                and fcntl.fcntl(stream.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK
                and fcntl.fcntl(stream.fileno(), fcntl.F_GETFD) & fcntl.FD_CLOEXEC)
            if peer is not None:
                require(stream.getpeername() == peer)
        return budget.remaining()

    try:
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(number, cancelled)
        for fd in pipes:
            os.set_inheritable(fd, False)
            fcntl.fcntl(fd, fcntl.F_SETFL, fcntl.fcntl(fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        check()
        with socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM | socket.SOCK_CLOEXEC | socket.SOCK_NONBLOCK) as listener:
            listener.bind((PARENT_CID, PORT)); listener.listen(1)
            sockets[listener] = identity(listener.fileno()), None
            check()
            while True:
                wait(listener.fileno(), False, check)
                try:
                    stream, peer = listener.accept()
                    break
                except (InterruptedError, BlockingIOError):
                    continue  # The same pending accept, never another connection.
            with stream:
                # Close the listener after the sole accepted connection, even
                # if the selected route is wrong. There is no second attempt.
                del sockets[listener]; listener.close()
                require(type(peer) is tuple and len(peer) == 2 and peer[0] == args.enclave_cid)
                integer(peer[1], 1024, 2**32 - 2)
                stream.setblocking(False); stream.set_inheritable(False)
                sockets[stream] = identity(stream.fileno()), peer
                check()
                prefix = read_exact(stream.fileno(), 4, check)
                length = int.from_bytes(prefix, "big")
                require(0 < length <= MAX_OBSERVATION)
                raw = read_exact(stream.fileno(), length, check)
                require(read_once(stream.fileno(), 1, check) == b"")  # Guest's write-half EOF.
                observed = observation(raw, enclave_cid=args.enclave_cid,
                    configuration_sha256=args.receiver_configuration_sha256,
                    delivery_configuration_sha256=args.delivery_configuration_sha256)
                write_exact(args.observation_output_fd, prefix + raw, check)
                os.close(args.observation_output_fd); del pipes[args.observation_output_fd]
                signed = read_original(args.completion_input_fd, MAX_COMPLETION, check)
                completion(signed, raw, observed)
                check()
                write_exact(stream.fileno(), len(signed).to_bytes(4, "big") + signed, check)
                check(); stream.shutdown(socket.SHUT_WR); check()
                del sockets[stream]
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
            report(2, b"Activation receiver control refused or uncertain; no retry authorized.\n")
        except Exception:
            pass
        raise SystemExit(1) from None
