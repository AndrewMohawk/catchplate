#!/usr/bin/env python3
"""One-shot offline seed for the private connected workload-renewal fixture.

This constructs explicitly synthetic retained state, not a historical issuance
receipt: its modeled original token lifetime is one hour, with 150 seconds left.
The clock, product limits, policy signer and database owners are unchanged.
Run before app/gate startup in the reviewed network-none UID/GID 10001 phase.
Any failure retains its claim and partial state; this script never retries.
"""
from __future__ import annotations

from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import sys
import time
import uuid

DATA = Path("/data")
OUTPUT = Path("/seed-output")
MARKER = Path("/private-fixture.json")
OWNER = (10001, 10001)
SCHEMA = "catchplate.privateWorkloadRenewalSeed/v1"
EVENT = "operator_fixture.workload_renewal_retained_client_seeded"
DEFAULTS = {
    "CATCHPLATE_RELEASE_CHANNEL": "dev",
    "CATCHPLATE_PROCESS_MODE": "catchplate-control-plane",
    "CATCHPLATE_METADATA_STORE_BACKEND": "sqlite",
    "CATCHPLATE_AUDIT_STORE_BACKEND": "sqlite",
    "CATCHPLATE_GRANT_STORE_BACKEND": "sqlite",
    "CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
    "CATCHPLATE_KEY_RELEASE_REQUIRED": "0",
    "CATCHPLATE_DEV_AUTHENTICATOR": "0",
    "CATCHPLATE_DEV_DEMO_SEED": "0",
}


def require(condition):
    if not condition:
        raise ValueError("private workload renewal seed refused")


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def identity(info):
    require(stat.S_ISDIR(info.st_mode) and (info.st_uid, info.st_gid) == OWNER
        and stat.S_IMODE(info.st_mode) == 0o700)
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)


def directory(path):
    require(path.resolve() == path)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        identity(os.fstat(descriptor))
        require(not os.listdir(descriptor))
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def write_exclusive(directory_fd, name, value):
    body = canonical(value)
    require(len(body) <= 4096)
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        | os.O_CLOEXEC, 0o400, dir_fd=directory_fd)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(body)
        stream.flush()
        os.fchmod(stream.fileno(), 0o400)
        os.fsync(stream.fileno())
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and (info.st_uid, info.st_gid) == OWNER and stat.S_IMODE(info.st_mode) == 0o400
            and info.st_size == len(body))
    os.fsync(directory_fd)
    return hashlib.sha256(body).hexdigest()


def fixture_marker():
    def unique(pairs):
        value = dict(pairs)
        require(len(value) == len(pairs))
        return value

    descriptor = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and (info.st_uid, info.st_gid) == OWNER and stat.S_IMODE(info.st_mode) == 0o400
            and 0 < info.st_size <= 1024)
        raw = stream.read(1025)
        require(len(raw) == info.st_size)
    value = json.loads(raw, object_pairs_hook=unique)
    require(type(value) is dict and set(value) == {"schema", "syntheticOnly"}
        and value["schema"] == "catchplate.privateOperatorAuditFixture/v1"
        and value["syntheticOnly"] is True)
    return hashlib.sha256(raw).hexdigest()


def seed():
    require(__debug__ and len(sys.argv) == 1 and sys.dont_write_bytecode
        and os.getuid() == os.geteuid() == OWNER[0]
        and os.getgid() == os.getegid() == OWNER[1]
        and Path(__file__).resolve() == Path("/app/scripts/seed_operator_workload_renewal_connected.py"))
    require({name for _, name in socket.if_nameindex()} == {"lo"})
    require(os.environ.get("CATCHPLATE_OPERATOR_DEMO") == "1"
        and os.environ.get("CATCHPLATE_DATA_DIR") == str(DATA)
        and os.environ.get("CATCHPLATE_OPERATOR_MANAGED_GOOGLE_ENABLED", "0") == "0")
    for name, value in DEFAULTS.items():
        os.environ.setdefault(name, value)
        require(os.environ[name] == value)
    os.umask(0o077)
    marker_sha = fixture_marker()
    data_fd = directory(DATA)
    try:
        output_fd = directory(OUTPUT)
        try:
            data_identity, output_identity = identity(os.fstat(data_fd)), identity(os.fstat(output_fd))
            require(data_identity[:2] != output_identity[:2])
            write_exclusive(output_fd, "seed-claim.json", {"schema": SCHEMA,
                "synthetic_retained_state": True, "fixture_marker_sha256": marker_sha,
                "claimed_at_epoch_ms": time.time_ns() // 1_000_000})

            # Same real bootstrap order as the focused operator backend.
            sys.path.insert(0, "/app")
            from catchplate import operator_demo
            operator_demo.activate()
            from catchplate import config, db, operator_demo_store as store
            from catchplate import operator_catalog_policy as policy
            from catchplate import operator_catalog_schema as schema
            from catchplate import operator_publication, policy_bundle
            require(operator_demo.active() and config.DATA_DIR == DATA
                and config.DB_PATH == DATA / "catchplate.sqlite3")
            db.init_db()
            store.initialize()

            with operator_publication.exclusive(), closing(db.connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                before = schema.read_catalog(conn)
                require(before == {"revision": 1, "credentials": [], "applications": [], "access_rules": []})
                require(conn.execute("SELECT COUNT(*) FROM credentials").fetchone()[0] == 0
                    and conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 0)
                previous_policy = dict(conn.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone())
                require(previous_policy["sequence"] == 1)
                seeded_at = time.time_ns() // 1_000_000
                expiry = seeded_at + 150_000
                created_ms = expiry - 3_600_000
                created_at = (datetime(1970, 1, 1, tzinfo=timezone.utc)
                    + timedelta(milliseconds=created_ms)).isoformat()
                token, identifier = secrets.token_urlsafe(32), str(uuid.uuid4())
                require(re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is not None)
                digest = "sha256:" + hashlib.sha256(token.encode("ascii")).hexdigest()
                record = schema.save_resource(conn, "applications", {
                    "id": identifier, "name": "Connected renewal retained-client fixture",
                    "principal_id": "agent:operator-demo:" + identifier,
                    "token_sha256": digest, "token_expires_at_epoch_ms": expiry,
                    "token_version": 1, "created_at": created_at, "status": "active",
                    "proxy_authentication": "basic_and_bearer_v1",
                }, create=True)
                schema.validate_bindings(conn)
                published = policy.publish(conn)
                require(published == {"policy_hash": previous_policy["policy_hash"],
                    "sequence": 1, "changed": False})
                revision = schema.advance_revision(conn, 1)
                event = {"schema": SCHEMA, "application_id": identifier,
                    "synthetic_retained_state": True, "seeded_at_epoch_ms": seeded_at,
                    "created_at_epoch_ms": created_ms, "original_expiry_epoch_ms": expiry,
                    "original_lifetime_seconds": 3600, "modeled_retained_age_seconds": 3450,
                    "token_generation": 1, "revision": revision,
                    "policy_hash": published["policy_hash"], "policy_sequence": 1,
                    "policy_activation_claimed": False}
                db.append_audit_event(conn, event_type=EVENT, actor_type="system",
                    actor_id="private-workload-renewal-fixture", event=event)
                after = schema.read_catalog(conn)
                require(after == {"revision": 2, "credentials": [],
                    "applications": [record], "access_rules": []})
                require(dict(conn.execute("SELECT * FROM operator_demo_policy WHERE singleton=1").fetchone()) == previous_policy)
                conn.commit()
                store.materialize()

            signed = json.loads(previous_policy["signed_bundle_json"])
            compiled = policy_bundle.compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
            require(compiled.hash == published["policy_hash"]
                and config.POLICY_BUNDLE_PATH.read_bytes() == previous_policy["signed_bundle_json"].encode("utf-8")
                and signed["credentials"] == [] and len(signed["principals"]) == 1
                and signed["principals"][0]["id"] == "agent:operator-demo:empty"
                and [row["id"] for row in signed["routes"]] == ["operator.empty"])
            audit = db.verify_audit_chain()
            require(audit["ok"] is True and audit["complete"] is True and audit["count"] == 1)
            require(identity(os.fstat(data_fd)) == identity(DATA.stat()) == data_identity
                and identity(os.fstat(output_fd)) == identity(OUTPUT.stat()) == output_identity
                and {name for _, name in socket.if_nameindex()} == {"lo"})
            secret = {"schema": SCHEMA, "application_id": identifier,
                "client_token": token, "token_sha256": digest, "original_expiry_epoch_ms": expiry,
                "created_at": created_at, "created_at_epoch_ms": created_ms,
                "seeded_at_epoch_ms": seeded_at, "original_lifetime_seconds": 3600,
                "modeled_retained_age_seconds": 3450, "synthetic_retained_state": True,
                "token_generation": 1, "proxy_authentication": "basic_and_bearer_v1"}
            secret_sha = write_exclusive(output_fd, "client.json", secret)
            public = {**event, "ok": True, "fixture_marker_sha256": marker_sha,
                "seed_file_sha256": secret_sha, "real_clock_unmodified": True,
                "credentials": 0, "access_rules": 0, "audit_events": 1}
            print(canonical(public).decode("ascii"), end="", flush=True)
        finally:
            os.close(output_fd)
    finally:
        os.close(data_fd)


if __name__ == "__main__":
    try:
        seed()
    except Exception:
        print('{"ok":false,"error":"private workload renewal seed refused"}', flush=True)
        raise SystemExit(1) from None
