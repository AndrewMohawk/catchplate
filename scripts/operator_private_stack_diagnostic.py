#!/usr/bin/env python3
"""One launch-only stack observation for the isolated synthetic npm fixture.

This is not a production entrypoint. The real custody owner must opt out before
any diagnostic file is opened or watchdog started. A dedicated 2 MiB tmpfs is
the output ceiling; ENOSPC may truncate the observation, never authorize a retry
or change the checker's verdict. Only faulthandler writes frames, without locals
or source lines. A fixed-time snapshot need not coincide with a stall.
"""
from __future__ import annotations

import faulthandler
import json
import os
import re
import runpy
import stat
import sys


ENTRYPOINT = "serverware.operator_demo_runner"
DUMP_AFTER_SECONDS = 50
OUTPUT_DIRECTORY = "/run/serverware-private-diagnostic"
OUTPUT_NAME = "frames.txt"
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MARKER_PATH = "/private-audit-fixture.json"
MARKER = {"schema": "serverware.privateOperatorAuditFixture/v1", "syntheticOnly": True}
_REQUIRED_ENV = {
    "SERVERWARE_OPERATOR_DEMO": "1",
    "SERVERWARE_RELEASE_CHANNEL": "dev",
    "SERVERWARE_DATA_DIR": "/data",
    "SERVERWARE_PUBLIC_URL": "https://serverware-demo.example.com",
    "SERVERWARE_OPERATOR_DEMO_UPSTREAMS": '["https://registry.npmjs.org"]',
    "SERVERWARE_OPERATOR_DEMO_PROXY_URL": "https://serverware-proxy.example.com",
    "SERVERWARE_DIRECT_CA_DOWNLOAD_ENABLED": "1",
    "SERVERWARE_ADMIN_USER": "user:operator-demo-operator",
    "SERVERWARE_DATA_PLANE_INSTANCE_ID": "spiffe://operator-demo.serverware/decision-gate/local",
    "SERVERWARE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED": "0",
    "SERVERWARE_DECISION_GATE_BASE": "http://127.0.0.1:9091",
    **{"SERVERWARE_" + prefix + "_TOKEN_FILE": "/run/secrets/serverware/" + role + ".token"
       for role, prefix in (
           ("admin", "ADMIN"), ("credential-lease", "DATA_PLANE_CREDENTIAL_LEASE"),
           ("audit", "DATA_PLANE_AUDIT"), ("grant-consume", "DATA_PLANE_GRANT_CONSUME"),
           ("rate-limit-consume", "DATA_PLANE_RATE_LIMIT_CONSUME"),
           ("release-authorization", "DATA_PLANE_RELEASE_AUTHORIZATION"),
           ("management", "DATA_PLANE_MANAGEMENT"))},
}
_OPTIONAL_ENV = {
    "SERVERWARE_PROCESS_MODE": "serverware-control-plane",
    "SERVERWARE_METADATA_STORE_BACKEND": "sqlite",
    "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite",
    "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
    "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
    "SERVERWARE_KEY_RELEASE_REQUIRED": "0",
    "SERVERWARE_DEV_AUTHENTICATOR": "0",
    "SERVERWARE_DEV_DEMO_SEED": "0",
    "SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED": "0",
    "SERVERWARE_DEVELOPMENT_SANDBOX": "0",
    "SERVERWARE_PRODUCTION_IMAGE": "0",
}
_BINARY_ENV = "SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST"


class DiagnosticRefused(RuntimeError):
    pass


def _require(value):
    if not value:
        raise DiagnosticRefused("private stack diagnostic refused")


def _admit_configuration():
    """No files, application configuration, authority admission or threads."""
    _require(os.getuid() == os.geteuid() == os.getgid() == os.getegid() == 10001)
    _require(sys.argv == ["/diagnostic/operator_private_stack_diagnostic.py"])
    environment = {key: value for key, value in os.environ.items() if key.startswith("SERVERWARE_")}
    _require(set(environment) <= set(_REQUIRED_ENV) | set(_OPTIONAL_ENV) | {_BINARY_ENV})
    _require(all(environment.get(key) == value for key, value in _REQUIRED_ENV.items()))
    _require(all(environment.get(key, value) == value for key, value in _OPTIONAL_ENV.items()))
    _require(re.fullmatch(r"sha256:[0-9a-f]{64}", environment.get(_BINARY_ENV, "")) is not None)


def _read_bounded(path, maximum):
    with open(path, "rb") as source:
        raw = source.read(maximum + 1)
    _require(len(raw) <= maximum)
    return raw


def _admit_fixture():
    descriptor = os.open(MARKER_PATH, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        _require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o400
                 and info.st_uid == info.st_gid == 10001 and info.st_nlink == 1
                 and 0 < info.st_size <= 1024)
        raw = os.read(descriptor, 1025)
        pairs = json.loads(raw, object_pairs_hook=tuple)
        _require(len(raw) == info.st_size and type(pairs) is tuple and len(pairs) == 2
                 and {key for key, _value in pairs} == set(MARKER))
        document = dict(pairs)
        _require(document["schema"] == MARKER["schema"] and document["syntheticOnly"] is True)
    finally:
        os.close(descriptor)
    status = dict(line.split(":", 1) for line in _read_bounded("/proc/self/status", 32768).decode("ascii").splitlines()
                  if ":" in line)
    _require(status["NoNewPrivs"].strip() == "1" and all(int(status[key].strip(), 16) == 0
             for key in ("CapEff", "CapPrm", "CapInh", "CapAmb", "CapBnd")))
    # This existing fixture guard checks exact hosts/resolver bytes, lo-only
    # routes and the locally assigned synthetic address. Its sockets are
    # temporary, after genuine custody opt-out; no provider request is made.
    from scripts.operator_npm_metadata_fixture_network import assert_isolated_network
    assert_isolated_network()


def _open_frames():
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    directory = os.open("/", flags)
    try:
        for part in OUTPUT_DIRECTORY.split("/")[1:]:
            child = os.open(part, flags, dir_fd=directory)
            os.close(directory)
            directory = child
        info = os.fstat(directory)
        _require(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
                 and info.st_uid == info.st_gid == 10001 and not os.listdir(directory))
        rows = []
        for line in _read_bounded("/proc/self/mountinfo", 256 * 1024).decode("ascii").splitlines():
            before, separator, after = line.partition(" - ")
            fields, filesystem = before.split(), after.split()
            _require(separator and len(fields) >= 6 and len(filesystem) == 3)
            _require(not fields[4].startswith(OUTPUT_DIRECTORY + "/"))
            if fields[4] == OUTPUT_DIRECTORY:
                rows.append((fields, filesystem))
        _require(len(rows) == 1)
        fields, filesystem = rows[0]
        _require(fields[3] == "/" and fields[2] == f"{os.major(info.st_dev)}:{os.minor(info.st_dev)}"
                 and {"rw", "nosuid", "nodev", "noexec"} <= set(fields[5].split(","))
                 and filesystem[0] == "tmpfs" and "rw" in filesystem[2].split(","))
        capacity = os.fstatvfs(directory)
        _require(capacity.f_frsize > 0 and capacity.f_blocks * capacity.f_frsize == MAX_OUTPUT_BYTES)
        descriptor = os.open(OUTPUT_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=directory)
        try:
            created = os.fstat(descriptor)
            _require(stat.S_ISREG(created.st_mode) and stat.S_IMODE(created.st_mode) == 0o600
                     and created.st_uid == created.st_gid == 10001 and created.st_nlink == 1
                     and created.st_size == 0 and created.st_dev == info.st_dev)
            return os.fdopen(descriptor, "wb", buffering=0)
        except BaseException:
            os.close(descriptor)
            raise
    finally:
        os.close(directory)


def _run_runner(frames):
    try:
        faulthandler.dump_traceback_later(DUMP_AFTER_SECONDS, repeat=False, file=frames, exit=False)
    except Exception:
        raise DiagnosticRefused("private stack diagnostic refused") from None
    try:
        return runpy.run_module(ENTRYPOINT, run_name="__main__")
    finally:
        # Never replace the original application's exception with a diagnostic
        # cleanup error. No new timer, external signal or retry is scheduled.
        try:
            faulthandler.cancel_dump_traceback_later()
        except Exception:
            pass


def main():
    try:
        _admit_configuration()
        from serverware import control_plane_custody_startup as custody
        _require(custody.initialize_from_environment() is None)
        # The unchanged runner repeats this real initializer, which checks its
        # already pinned disabled namespace, not a fabricated descriptor list.
        _admit_fixture()
        frames = _open_frames()
    except Exception:
        raise DiagnosticRefused("private stack diagnostic refused") from None
    try:
        return _run_runner(frames)
    finally:
        try:
            frames.close()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        main()
    except DiagnosticRefused:
        raise SystemExit(78) from None
