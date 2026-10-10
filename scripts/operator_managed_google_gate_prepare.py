#!/usr/bin/env python3
"""One internal synthetic Prepare; stopped app/gate and network-none required.

The UUID claim is durable before Prepare and is never removed or replayed.
--status-only is an original-lock SH metadata lookup, not cold startup: recovery
cannot activate the pending selection. Root owns all container lifecycle steps.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import stat
import sys
import uuid

CLIENT_ID = "123-managed-gate-fixture.apps.googleusercontent.com"
SYNTHETIC_SECRET = "synthetic-managed-gate-application-secret-no-real-provider"
ACTOR = "operator-managed-google-gate-fixture"
WORK = Path("/managed-work")
CLAIM = WORK / ".managed-google-prepare.claim"
RESULT = WORK / "prepare-result.json"
MARKER = {"schema": "serverware.privateOperatorAuditFixture/v1", "syntheticOnly": True}
_network_attempts = []


def require(value):
    if not value:
        raise RuntimeError("managed fixture operation refused")


def _network(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        _network_attempts.append(event)
        raise RuntimeError("managed fixture network contact refused")


def _read(path, *, mode, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == info.st_gid == 10001 and stat.S_IMODE(info.st_mode) == mode
            and 0 < info.st_size <= maximum)
        raw = os.read(descriptor, maximum + 1)
        require(len(raw) == info.st_size)
        return json.loads(raw)
    finally:
        os.close(descriptor)


def _write(path, value):
    encoded = (json.dumps(value, sort_keys=True) + "\n").encode("ascii")
    require(len(encoded) <= 32768 and SYNTHETIC_SECRET.encode("ascii") not in encoded)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(encoded)
        stream.flush()
        os.fsync(stream.fileno())
    parent = os.open(WORK, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _admit():
    require(os.geteuid() == os.getegid() == 10001 and {name for _, name in socket.if_nameindex()} == {"lo"})
    require(_read(Path("/private-audit-fixture.json"), mode=0o400, maximum=1024) == MARKER)
    info = WORK.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == info.st_gid == 10001 and stat.S_IMODE(info.st_mode) == 0o700)
    require(os.getenv("SERVERWARE_DATA_DIR") == "/data"
        and os.getenv("SERVERWARE_OPERATOR_PROVIDER_CUSTODY_DIR") == "/provider-custody")
    from serverware import operator_catalog_oauth_profile as profiles
    require(profiles._raw_development_directory(managed=True) == Path("/data"))


def _claim():
    value = _read(CLAIM, mode=0o600, maximum=1024)
    require(type(value) is dict and set(value) == {"schema", "operation_id", "actor_id", "syntheticOnly"}
        and value["schema"] == "serverware.managedGoogleFixtureClaim/v1"
        and value["actor_id"] == ACTOR and value["syntheticOnly"] is True
        and type(value["operation_id"]) is str and str(uuid.UUID(value["operation_id"])) == value["operation_id"])
    return value


def status_only():
    claim = _claim()
    from serverware import operator_publication as publication, operator_google_setup as setup
    admission = publication.admit_bootstrap_reader(Path("/data"), operator_development=True,
        release_channel="dev", production_image=False, native_or_enrolled=False)
    with publication.bootstrap_read(admission) as conn:
        result = setup._public(setup._get(conn, claim["operation_id"], ACTOR))
    require(not _network_attempts)
    return {"ok": True, "schema": "serverware.managedGoogleFixturePrepare/v1", "syntheticOnly": True,
        "readOnlyRecovery": True, "operation": result, "providerCalls": 0}


def prepare():
    require(set(os.listdir(WORK)) == set())
    operation_id = str(uuid.uuid4())
    _write(CLAIM, {"schema": "serverware.managedGoogleFixtureClaim/v1", "operation_id": operation_id,
        "actor_id": ACTOR, "syntheticOnly": True})
    from serverware import operator_google_managed_config as managed
    managed.bootstrap()
    from serverware import operator_demo
    operator_demo.activate()
    from serverware.control_plane_startup import validate_control_plane_startup
    validate_control_plane_startup()
    from serverware import operator_google_setup as setup, operator_catalog_oauth_profile as profiles
    require(not profiles.selected())
    review = setup.review_configuration(ACTOR)
    require(review["eligible"] is True and review["expected_revision"] == 1
        and review["old_settings"]["allowed_upstreams"] == ["https://demo-upstream:8443"]
        and review["target_settings"]["allowed_upstreams"] == ["https://demo-upstream:8443", "https://gmail.googleapis.com"])
    result = setup.prepare_configuration({**{key: review[key] for key in (
        "expected_revision", "expected_policy_hash", "expected_settings_digest")}, "operation_id": operation_id,
        "client_id": CLIENT_ID, "client_secret": SYNTHETIC_SECRET}, ACTOR)
    require(result["status"] == "pending" and result["operation_id"] == operation_id
        and result["revision"] == 2 and result["activation_receipt"] is None
        and setup.status(operation_id, ACTOR) == result and not profiles.selected() and not _network_attempts)
    receipt = {"ok": True, "schema": "serverware.managedGoogleFixturePrepare/v1", "syntheticOnly": True,
        "readOnlyRecovery": False, "operation": result, "providerCalls": 0}
    _write(RESULT, receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--status-only", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    def expired(*_):
        raise TimeoutError("bounded managed fixture phase")
    signal.signal(signal.SIGALRM, expired)
    signal.alarm(60)
    sys.addaudithook(_network)
    try:
        _admit()
        result = status_only() if args.status_only else prepare()
        encoded = json.dumps(result, sort_keys=True)
        require(SYNTHETIC_SECRET not in encoded)
        print(encoded)
        return 0
    except Exception:
        # A commit may have happened. Preserve the claim and all storage; never
        # retry Prepare or infer rollback from this deliberately generic result.
        print(json.dumps({"ok": False, "syntheticOnly": True, "outcome": "unknown",
            "error": "managed fixture phase refused", "recovery": "exact claim status-only; never repeat Prepare"}))
        return 1
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    raise SystemExit(main())
