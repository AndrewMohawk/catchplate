"""Authorize one exact native workload trust configuration and launch offline.

Requires independently approved pinned originals and an existing private key
on a protected read-only FD. No key generation, policy acquisition, installation
or runtime readiness is provided. An external watchdog must bound blocking I/O
and crypto; Python/OpenSSL key copies are not hardware custody or erased memory.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import fcntl
import hashlib
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from catchplate import authority_successor_execution_window as windows
from catchplate import native_workload_identity_trust_authorization as authorization
from catchplate import workload_identity_issuer_bootstrap as shared
from catchplate.authority_query_read_work import QueryReadValidationLimits, _ValidationWork
from catchplate_agent_trust import _workload_tls as tls


def _require(value):
    if not value:
        raise ValueError("native workload trust authorization refused")


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        # Do not echo supplied originals, paths or parser detail on failure.
        raise ValueError("invalid authorization arguments")


def _arguments():
    parser = _Parser(description=__doc__, allow_abbrev=False)
    for name in ("configuration", "launch", "policy", "policy-signing-public-key"):
        parser.add_argument("--" + name, required=True, help="absolute protected original file")
        parser.add_argument("--" + name + "-sha256", required=True, help="independently approved sha256: original-byte pin")
    parser.add_argument("--authorizer-private-key-fd", type=int, required=True,
        help="inherited read-only FD >=3 for protected existing Ed25519 PKCS#8 PEM")
    parser.add_argument("--issued-at-epoch-ns", type=int, required=True)
    parser.add_argument("--expires-at-epoch-ns", type=int, required=True)
    parser.add_argument("--timeout-ms", type=int, required=True, help="original processing budget, 1..30000 milliseconds")
    parser.add_argument("--output", required=True, help="new file in an existing owner-only 0700 directory; never overwritten")
    return parser.parse_args()


def _key_identity(fd, budget):
    budget.check()
    _require(fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY)
    info = os.fstat(fd)
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) in {0o400, 0o600} and info.st_nlink == 1
        and 0 < info.st_size <= authorization.MAX_KEY_BYTES)
    budget.check()
    return tls._metadata(info)


def _key_bytes(fd, budget):
    budget.check()
    raw = os.pread(fd, authorization.MAX_KEY_BYTES + 1, 0)
    _require(0 < len(raw) <= authorization.MAX_KEY_BYTES)
    budget.check()
    return raw


def _output_parts(path):
    _require(type(path) is str and 1 <= len(path.encode("utf-8")) <= 4096
        and path.startswith("/") and "\x00" not in path and str(Path(path)) == path
        and all(part not in {"", ".", ".."} for part in path.split("/")[1:]))
    return path.split("/")[1:]


def _open_parent(parts, budget):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    budget.check()
    descriptor = os.open("/", flags)
    try:
        for part in parts[:-1]:
            budget.check()
            child = os.open(part, flags, dir_fd=descriptor)
            previous, descriptor = descriptor, child
            os.close(previous)
        budget.check()
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _directory_identity(fd):
    info = os.fstat(fd)
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700)
    # Directory timestamps change when our exclusive output is created.
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_nlink


def main():
    try:
        args = _arguments()
        _require(sys.platform == "linux" and 1 <= args.timeout_ms <= 30000
            and args.authorizer_private_key_fd >= 3
            and 0 < args.issued_at_epoch_ns < args.expires_at_epoch_ns <= (1 << 63) - 1)
        work = _ValidationWork(QueryReadValidationLimits())
        window, bound = shared._construction_on_work(work)
        window = windows._narrow(window, deadline_epoch_ns=window[0] + args.timeout_ms * 1_000_000,
            maximum_lifetime_ns=args.timeout_ms * 1_000_000, maximum_clock_skew_ns=0)
        budget = shared._Budget(work, window, min(bound, window[4]), None)
        budget.interval(args.issued_at_epoch_ns, args.expires_at_epoch_ns)
        parts = _output_parts(args.output)
        with ExitStack() as owners:
            key_identity = _key_identity(args.authorizer_private_key_fd, budget)
            key_fd = fcntl.fcntl(args.authorizer_private_key_fd, fcntl.F_DUPFD_CLOEXEC, 3)
            owners.callback(os.close, key_fd)
            _require(_key_identity(key_fd, budget) == key_identity)
            key_raw = _key_bytes(key_fd, budget)
            _require(len(key_raw) == key_identity[6] and _key_identity(key_fd, budget) == key_identity)
            key_digest = hashlib.sha256(key_raw).digest()
            private = serialization.load_pem_private_key(key_raw, password=None)
            _require(isinstance(private, Ed25519PrivateKey)
                and private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()) == key_raw)
            budget.check()
            specs = ((args.configuration, args.configuration_sha256, authorization.MAX_CONFIGURATION_BYTES, True),
                (args.launch, args.launch_sha256, authorization.MAX_LAUNCH_BYTES, False),
                (args.policy, args.policy_sha256, authorization.MAX_POLICY_BYTES, False),
                (args.policy_signing_public_key, args.policy_signing_public_key_sha256, authorization.MAX_KEY_BYTES, False))
            originals = tuple(tls._load_original(tls.PinnedFile(path, pin), maximum, private_file, budget, owners)
                for path, pin, maximum, private_file in specs)
            directory = _open_parent(parts, budget)
            owners.callback(os.close, directory)
            directory_identity = _directory_identity(directory)

            def recheck():
                budget.check()
                for original in originals:
                    original.recheck(budget)
                    info = os.fstat(original.descriptor)
                    _require(info.st_uid == os.geteuid() and not info.st_mode & 0o022 and info.st_nlink == 1)
                _require(_key_identity(args.authorizer_private_key_fd, budget) == key_identity
                    and _key_identity(key_fd, budget) == key_identity)
                current_key = _key_bytes(key_fd, budget)
                _require(current_key == key_raw and hashlib.sha256(current_key).digest() == key_digest
                    and _key_identity(key_fd, budget) == key_identity)
                _require(_directory_identity(directory) == directory_identity)
                named = _open_parent(parts, budget)
                try:
                    _require(_directory_identity(named) == directory_identity)
                finally:
                    os.close(named)
                budget.check()

            recheck()
            try:
                os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise ValueError("output exists")
            raw = authorization.produce_on_work(configuration_bytes=originals[0].raw,
                launch_bytes=originals[1].raw, policy_bytes=originals[2].raw, policy_public_key_bytes=originals[3].raw,
                expected_configuration_sha256=args.configuration_sha256, expected_launch_sha256=args.launch_sha256,
                expected_policy_public_key_sha256=args.policy_signing_public_key_sha256, authorizer_private_key=private,
                issued_at_epoch_ns=args.issued_at_epoch_ns, expires_at_epoch_ns=args.expires_at_epoch_ns,
                work=work, live_window=budget.window, transport_deadline_ns=budget.bound, _current=budget.current)
            _require(type(raw) is bytes and 0 < len(raw) <= authorization.MAX_BYTES and raw.isascii() and not raw.endswith(b"\n"))
            recheck()
            output = os.open(parts[-1], os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=directory)
            owners.callback(os.close, output)
            os.fchmod(output, 0o600)
            offset = 0
            while offset < len(raw):
                budget.check()
                count = os.write(output, raw[offset:offset + 16384])
                _require(0 < count <= min(16384, len(raw) - offset))
                offset += count
            budget.check()
            os.fsync(output)
            budget.check()
            _require(os.pread(output, authorization.MAX_BYTES + 1, 0) == raw)
            os.fsync(directory)
            recheck()
            info = os.fstat(output)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size == len(raw)
                and tls._metadata(info) == tls._metadata(os.stat(parts[-1], dir_fd=directory, follow_symlinks=False)))
            budget.check()
        sys.stderr.write("Native workload trust authorization written. Installation and native runtime admission remain separate.\n")
        return 0
    except Exception:
        sys.stderr.write("Native workload trust authorization refused. Any partial output remains; do not retry, overwrite or treat it as installed trust.\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
