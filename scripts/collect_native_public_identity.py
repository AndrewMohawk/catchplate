#!/usr/bin/env python3
"""Collect one unverified public role-4 original from an explicit enclave.

Run as root with python3 -I -B, --enclave-cid and an inherited --output-fd
that is a root-owned write pipe. Port 9101 is fixed. Before any connection is
accepted, definitive ECONNREFUSED permits waiting and another connect to that
same endpoint. All other errors are terminal. After connection there is exactly
one empty request and one response: no reconnect, replay or retry of that action.

Waits have no local setup timeout; input, disconnect or cancellation ends them.
The native service alone owns its original deadline. Framing and document
syntax are checked, not signature, hardware identity, authority or readiness.
The complete original, including its single final LF, is written unchanged to
the pipe only after server EOF. A failed output can leave partial public bytes;
consumers must retain the complete original AND this process's successful exit.
No keys, data files, challenges, deadlines or configuration are created or read.
"""
from __future__ import annotations

import errno
import fcntl
import os
from pathlib import Path
import select
import signal
import socket
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import send_native_configuration as transport

PORT = 9101
MAX_ORIGINAL = 64 * 1024
API = "serverware.nativeResponseProofPublicIdentity/v1"
FIELDS = {"apiVersion", "purpose", "evidenceScope", "okForAction", "bootId",
          "keyId", "publicKeyPem", "controlPlaneResponseSigningKeyId", "scope",
          "caCertificateDerBase64url", "nativeKeyEvidence", "quoteNonceBase64url",
          "quoteUserDataBase64url"}
SCOPE = {"releaseRecordSha256", "policyHash", "configurationSha256",
         "caCertificateSha256", "caPublicKeySpkiSha256"}


def require(value):
    if not value:
        raise ValueError("native public identity collection refused")


def public_original(raw):
    """Closed syntax only. Return the SAME bytes, never an admission verdict."""
    require(type(raw) is bytes and 1 < len(raw) <= MAX_ORIGINAL
            and raw[-1:] == b"\n" and b"\n" not in raw[:-1])
    value = transport.document(raw[:-1], MAX_ORIGINAL - 1)
    require(set(value) == FIELDS and value["apiVersion"] == API
            and value["purpose"] == "postboot-static-assignment-inputs"
            and value["evidenceScope"] == "unverified-startup-role4-public-material"
            and value["okForAction"] is False)
    transport.encoded(value["bootId"], 32, exact=32)
    for name in ("keyId", "controlPlaneResponseSigningKeyId"):
        transport.digest(value[name])
    pem = value["publicKeyPem"]
    require(type(pem) is str and pem.startswith("-----BEGIN PUBLIC KEY-----\n")
            and pem.endswith("\n-----END PUBLIC KEY-----\n"))
    scope = value["scope"]
    require(type(scope) is dict and set(scope) == SCOPE)
    for item in scope.values():
        transport.digest(item)
    transport.encoded(value["caCertificateDerBase64url"], 16 * 1024)
    evidence = value["nativeKeyEvidence"]
    require(type(evidence) is dict and set(evidence) == {
        "apiVersion", "responseProofPublicKey", "attestationDocumentB64"}
        and evidence["apiVersion"] == "serverware.nativeResponseProofKeyEvidence/v1")
    transport.encoded(evidence["responseProofPublicKey"], 32, exact=32)
    transport.encoded(evidence["attestationDocumentB64"], 12 * 1024)
    transport.encoded(value["quoteNonceBase64url"], 32, exact=32)
    transport.encoded(value["quoteUserDataBase64url"], 1024)
    return raw


def socket_identity(stream):
    info = os.fstat(stream.fileno())
    require(stat.S_ISSOCK(info.st_mode) and stream.family == socket.AF_VSOCK
            and stream.type == socket.SOCK_STREAM
            and fcntl.fcntl(stream.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK)
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def main():
    require(sys.flags.isolated == 1 and sys.flags.dont_write_bytecode == 1
            and os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0))
    parser = transport.Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--enclave-cid", type=int, required=True)
    parser.add_argument("--output-fd", type=int, required=True)
    args = parser.parse_args()
    require(4 <= args.enclave_cid < 2**32 - 1)
    output = transport.pipe_identity(args.output_fd, os.O_WRONLY)
    require(output[3:] == (0, 0))
    pid, stream, held_socket, connected = os.getpid(), None, None, False

    def check():
        require(os.getpid() == pid and os.getresuid() == (0, 0, 0)
                and os.getresgid() == (0, 0, 0)
                and transport.pipe_identity(args.output_fd, os.O_WRONLY) == output
                and fcntl.fcntl(args.output_fd, fcntl.F_GETFL) & os.O_NONBLOCK)
        if stream is not None:
            require(socket_identity(stream) == held_socket)
            if connected:
                require(stream.getpeername() == (args.enclave_cid, PORT))
        return None  # No caller-created preauthorization or setup deadline.

    try:
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(number, transport.cancelled)
        os.set_inheritable(args.output_fd, False)
        fcntl.fcntl(args.output_fd, fcntl.F_SETFL,
                    fcntl.fcntl(args.output_fd, fcntl.F_GETFL) | os.O_NONBLOCK)
        check()
        while True:
            stream = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            stream.setblocking(False)
            held_socket = socket_identity(stream)
            check()
            result = stream.connect_ex((args.enclave_cid, PORT))
            if result in {errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK, errno.EINTR}:
                transport.wait(stream.fileno(), True, check)
                result = stream.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            check()
            if result == errno.ECONNREFUSED:
                # No accepted stream/action exists. Never enter this branch
                # after successful connection, request dispatch or any output.
                stream.close()
                stream, held_socket = None, None
                check()
                select.select([], [], [], 0.25)
                check()
                continue
            require(result == 0)
            connected = True
            check()
            stream.shutdown(socket.SHUT_WR)  # The entire request is empty EOF.
            check()
            break
        _prefix, raw = transport.read_frame(stream.fileno(), MAX_ORIGINAL, check)
        require(transport.read_once(stream.fileno(), 1, check) == b"")
        raw = public_original(raw)
        check()
        transport.write_exact(args.output_fd, raw, check)
        check()
    finally:
        if stream is not None:
            stream.close()
        os.close(args.output_fd)


if __name__ == "__main__":
    try:
        main()
    except (Exception, KeyboardInterrupt):
        try:
            transport.report(2, b"Native public identity collection failed or partial; no connected action retry authorized.\n")
        except Exception:
            pass
        raise SystemExit(1) from None
