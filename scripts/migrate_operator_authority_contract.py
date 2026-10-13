#!/usr/bin/env python3
"""Explicit offline, empty-authority ordinary-SQLite contract transition.

This is NOT a native/PostgreSQL migration, startup compatibility switch, or
authority grant. Plan is read-only. Apply requires a stopped copied store, its
byte-identical backup, and an exact reviewed plan. It changes one digest cell;
all schema definitions and every other row must remain identical. The sole
immutable UPDATE trigger is removed and restored in the same exclusive SQLite
transaction. A crash after commit but before the external receipt is an unknown
outcome: inspect the backup/plan/database, never blindly replay.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import ExitStack, closing, contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
PIN_FILE = ROOT / "scripts/operator_authority_contract_migration_pins.json"
PIN_SHA256 = "sha256:4199bfe9362e1f7990a612e5b1cae9b7603dc2908c953ea8ea6201f602dd8e5f"
X_QUOTA_PIN_FILE = ROOT / "scripts/operator_authority_contract_migration_x_quota_pins.json"
# Independently derived fixed transition; never a caller-selected pin artifact.
X_QUOTA_PIN_SHA256 = "sha256:ea376f5dce618b3888f5418a48bd160de8d01b83779e525db48ac6529bb46582"
TRANSITIONS = ("historical", "jit-denial-quota-v1")
SCHEMA = "serverware.operatorAuthorityContractMigrationPlan/v1"
RECEIPT_SCHEMA = "serverware.operatorAuthorityContractMigrationReceipt/v1"
MARKER = ".serverware-operator-demo.json"
MARKER_BYTES = b'{"schema": "serverware.operatorDemo/v1", "syntheticOnly": false}\n'
DATABASE = "serverware.sqlite3"
WITNESS = "webauthn-recovery-witness.sqlite3"
CONTRACT_TABLE = "policy_authority_schema_contracts"
PUBLIC_FILES = {"policy-signing-ed25519.pub.pem": {0o644},
    "decision-gate-ca-cert.pem": {0o444}, "mitmproxy/mitmproxy-ca-cert.pem": {0o644}}
EMPTY_MOUNTPOINTS = frozenset({"gate-runtime/.operator-publication.lock", "gate-runtime/.serverware-operator-demo.json",
    "gate-runtime/mitmproxy/mitmproxy-ca-cert.pem", "gate-runtime/mitmproxy/mitmproxy-ca.pem"})
MAX_FILE = 256 * 1024 * 1024
MAX_PLAN = 16 * 1024 * 1024
MAX_ROWS = 1_000_000
ENVIRONMENT = {"SERVERWARE_OPERATOR_DEMO": "1", "SERVERWARE_RELEASE_CHANNEL": "dev",
    "SERVERWARE_PROCESS_MODE": "serverware-control-plane", "SERVERWARE_METADATA_STORE_BACKEND": "sqlite",
    "SERVERWARE_AUDIT_STORE_BACKEND": "sqlite", "SERVERWARE_GRANT_STORE_BACKEND": "sqlite",
    "SERVERWARE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0", "SERVERWARE_KEY_RELEASE_REQUIRED": "0",
    "SERVERWARE_DEV_AUTHENTICATOR": "0", "SERVERWARE_DEV_DEMO_SEED": "0",
    "SERVERWARE_OPERATOR_DEMO_UPSTREAMS": '["https://api.example.com"]',
    "SERVERWARE_OPERATOR_DEMO_PROXY_URL": "https://proxy.example.com"}


class Refused(ValueError):
    def __init__(self):
        super().__init__("offline ordinary authority migration refused")


def require(value):
    if not value:
        raise Refused()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _value: (_ for _ in ()).throw(Refused()))


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode),
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def held_file(path, maximum=MAX_FILE, *, private=True, allow_change=False):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        original = identity(os.fstat(fd))
        require(stat.S_ISREG(os.fstat(fd).st_mode) and original[5] == 1
            and original[2] == os.geteuid() and 0 <= original[6] <= maximum
            and (not private or original[4] & 0o077 == 0)
            and identity(os.stat(path, follow_symlinks=False)) == original)
        raw = os.pread(fd, maximum + 1, 0)
        require(len(raw) == original[6] and identity(os.fstat(fd)) == original)
        yield fd, original, raw
        current = identity(os.stat(path, follow_symlinks=False))
        require(current[:6] == original[:6] if allow_change else current == original)
    finally:
        os.close(fd)


def transition_profile(transition):
    require(type(transition) is str and transition in TRANSITIONS)
    if transition == "historical":
        return PIN_FILE, PIN_SHA256
    require(type(X_QUOTA_PIN_SHA256) is str
        and re.fullmatch(r"sha256:[0-9a-f]{64}", X_QUOTA_PIN_SHA256) is not None)
    return X_QUOTA_PIN_FILE, X_QUOTA_PIN_SHA256


def transition_binding(pinned, transition):
    _path, digest = transition_profile(transition)
    if transition == "historical":
        require("transitionId" not in pinned)
        return digest, {}
    require(pinned.get("transitionId") == transition)
    return digest, {"transitionId": transition}


def pins(transition="historical"):
    path, expected = transition_profile(transition)
    raw = path.read_bytes()
    require(sha(raw) == expected)
    value = strict_json(raw)
    require(value["schema"] == "serverware.operatorAuthorityContractMigrationPins/v1")
    transition_binding(value, transition)
    return value


def source(pinned, directory):
    expected = {**ENVIRONMENT, "SERVERWARE_DATA_DIR": str(directory)}
    require(all(name in expected and value == expected[name]
        for name, value in os.environ.items() if name.startswith("SERVERWARE_")))
    for name, value in expected.items():
        os.environ[name] = value
    for relative, digest in pinned["target"]["sourceFiles"].items():
        path = ROOT / relative
        require(not path.is_symlink() and path.is_file() and path.resolve().is_relative_to(ROOT)
            and sha(path.read_bytes()) == digest)
    require(pinned["old"]["sourceDdlSha256"] == pinned["target"]["sourceDdlSha256"])
    require(not any(name == "serverware" or name.startswith("serverware.") for name in sys.modules))
    sys.path.insert(0, str(ROOT))
    from serverware import db, operator_catalog_schema
    from serverware.authority_store import metadata_schema_source
    require(db._policy_candidate_authority_source_contract_digest() == pinned["target"]["sourceContractDigest"])
    return db, operator_catalog_schema, metadata_schema_source.metadata_schema_source()


def objects(conn):
    return [list(row) for row in conn.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")]


def typed(value):
    if isinstance(value, bytes):
        return ["blob", base64.b64encode(value).decode("ascii")]
    if value is None:
        return ["null"]
    require(type(value) in (int, float, str))
    return [type(value).__name__, value]


def row_commitments(conn, tables, *, normalize_contract=False):
    result = {}
    for name in tables:
        require(re.fullmatch(r"[a-z_][a-z0-9_]*", name) is not None)
        cursor = conn.execute('SELECT * FROM "' + name + '"')
        columns = [field[0] for field in cursor.description]
        rows = []
        for row in cursor:
            require(len(rows) < MAX_ROWS)
            values = list(row)
            if normalize_contract and name == CONTRACT_TABLE:
                values[columns.index("source_contract_digest")] = "contract-transition-only"
            rows.append(sha(canonical([typed(value) for value in values])))
        result[name] = {"columns": columns, "count": len(rows), "sha256": sha(canonical(sorted(rows)))}
    return result


def sidecars_absent(directory):
    for name in (DATABASE, WITNESS):
        for suffix in ("-wal", "-shm", "-journal"):
            require(not os.path.lexists(directory / (name + suffix)))


def tree(directory):
    result = {}
    total = 0
    for ordinal, path in enumerate(directory.rglob("*")):
        require(ordinal < 512 and not path.is_symlink())
        info = path.stat(follow_symlinks=False)
        require(info.st_uid == os.geteuid())
        relative = str(path.relative_to(directory))
        if path.is_dir():
            require(stat.S_IMODE(info.st_mode) & 0o077 == 0)
            result[relative] = {"kind": "directory", "mode": stat.S_IMODE(info.st_mode)}
            continue
        require(path.name not in (DATABASE + "-wal", DATABASE + "-shm", DATABASE + "-journal",
            WITNESS + "-wal", WITNESS + "-shm", WITNESS + "-journal"))
        if path == directory / DATABASE:
            continue
        if relative in EMPTY_MOUNTPOINTS:
            fd = os.open(path, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                pinned = identity(os.fstat(fd))
                require(stat.S_ISREG(os.fstat(fd).st_mode) and pinned[2] == os.geteuid()
                    and pinned[4:7] == (0, 1, 0) and identity(path.stat(follow_symlinks=False)) == pinned)
                result[relative] = {"sha256": sha(b""), "mode": 0, "bytes": 0}
            finally:
                os.close(fd)
            continue
        public = relative in PUBLIC_FILES
        with held_file(path, private=not public) as (_fd, original, raw):
            require(original[4] in (PUBLIC_FILES[relative] if public else {0o600, 0o400}))
            total += len(raw)
            require(total <= 512 * 1024 * 1024)
            result[relative] = {"sha256": sha(raw), "mode": original[4], "bytes": len(raw)}
    return result


@contextmanager
def admitted_directory(path, *, write=False):
    directory = Path(path)
    require(directory.is_absolute() and directory != Path("/") and ".." not in directory.parts
        and not directory.is_symlink() and directory.resolve() == directory)
    info = directory.stat(follow_symlinks=False)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700)
    with held_file(directory / MARKER, 1024) as (_fd, marker_identity, raw):
        require(raw == MARKER_BYTES and marker_identity[4] == 0o600)
        with ExitStack() as locks:
            for name in (".operator-publication.lock", DATABASE + ".migration.lock"):
                lock_fd, _lock_identity, _raw = locks.enter_context(held_file(directory / name, 1024))
                fcntl.flock(lock_fd, (fcntl.LOCK_EX if write else fcntl.LOCK_SH) | fcntl.LOCK_NB)
                locks.callback(fcntl.flock, lock_fd, fcntl.LOCK_UN)
            sidecars_absent(directory)
            yield directory
            require(identity(directory.stat(follow_symlinks=False))[:6] == identity(info)[:6])


def witness(directory, pinned):
    with held_file(directory / WITNESS) as (_fd, original, raw):
        require(raw.startswith(b"SQLite format 3\x00"))
        with closing(sqlite3.connect((directory / WITNESS).as_uri() + "?mode=ro&immutable=1", uri=True, timeout=0)) as conn:
            conn.execute("PRAGMA query_only=ON")
            conn.execute("BEGIN")
            require(sha(canonical(objects(conn))) == pinned["target"]["witnessObjectsSha256"])
            for name in ("recovery_authorization_claims", "recovery_witness_heads"):
                require(conn.execute('SELECT 1 FROM "' + name + '" LIMIT 1').fetchone() is None)
            conn.rollback()
        require(identity(os.stat(directory / WITNESS, follow_symlinks=False)) == original)


def inspect(conn, pinned, helpers, *, expected_digest):
    db, catalog, ddl = helpers
    from serverware.authority_store.metadata_schema import configure_sqlite_metadata_connection
    configure_sqlite_metadata_connection(conn)
    schema = objects(conn)
    tables = sorted(row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'"))
    optional = tables == pinned["target"]["optionalTables"]
    require(optional or tables == pinned["target"]["tables"])
    require(sha(canonical(schema)) == pinned["target"]["optionalSqliteObjectsSha256" if optional else "sqliteObjectsSha256"])
    require(conn.execute("PRAGMA quick_check").fetchall()[0][0] == "ok"
        and not conn.execute("PRAGMA foreign_key_check").fetchall())
    manifest, digest = db._validate_policy_candidate_authority_structure(conn,
        require_recorded_contract=False, source_schema_program=ddl)
    require(digest == pinned["target"]["structuralManifestDigest"]
        and sha(manifest.encode()) == pinned["target"]["structuralManifestJsonSha256"])
    rows = conn.execute("SELECT * FROM policy_authority_schema_contracts").fetchall()
    require(len(rows) == 1)
    contract = dict(rows[0])
    require(contract["schema_version"] == 9 and contract["source_revision"] == pinned["target"]["sourceRevision"]
        and contract["contract_id"] == "serverware.policyCandidateAuthoritySchema/v9"
        and contract["source_contract_digest"] == expected_digest
        and contract["structural_manifest_json"] == manifest
        and contract["structural_manifest_digest"] == digest and contract["offline_migration_receipt_digest"] is None)
    require(conn.execute("SELECT version FROM serverware_store_migrations WHERE migration='policy_candidate_authority'").fetchall()[0][0] == 9)
    for name in pinned["target"]["emptyTables"]:
        require(conn.execute('SELECT 1 FROM "' + name + '" LIMIT 1').fetchone() is None)
    require(catalog.active(conn))
    catalog.read_catalog(conn)
    if optional:
        from serverware import operator_upstream_setup
        operator_upstream_setup._rows(conn)
    return {"contract": contract, "rows": row_commitments(conn, tables, normalize_contract=True),
        "sqliteObjectsSha256": sha(canonical(schema))}


def plan(directory, pinned, helpers, *, transition="historical"):
    pin_digest, binding = transition_binding(pinned, transition)
    with admitted_directory(directory) as directory:
        before_files = tree(directory)
        witness(directory, pinned)
        with held_file(directory / DATABASE) as (_fd, original, raw):
            require(raw.startswith(b"SQLite format 3\x00"))
            conn = sqlite3.connect((directory / DATABASE).as_uri() + "?mode=ro&immutable=1", uri=True, timeout=0)
            try:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA query_only=ON")
                conn.execute("BEGIN")
                value = inspect(conn, pinned, helpers, expected_digest=pinned["old"]["sourceContractDigest"])
                conn.rollback()
            finally:
                conn.close()
            require(identity(os.stat(directory / DATABASE, follow_symlinks=False)) == original)
        sidecars_absent(directory)
        require(tree(directory) == before_files)
        return {"schema": SCHEMA, "pinsSha256": pin_digest, **binding, "databaseSha256": sha(raw),
            "targetContractDigest": pinned["target"]["sourceContractDigest"],
            "databaseIdentity": list(original), "files": before_files, **value}


def apply(directory, pinned, helpers, reviewed, expected_plan_sha256, backup, *, checkpoint=lambda _stage: None,
        transition="historical"):
    pin_digest, binding = transition_binding(pinned, transition)
    require(reviewed.get("schema") == SCHEMA and sha(canonical(reviewed)) == expected_plan_sha256
        and reviewed["pinsSha256"] == pin_digest
        and (reviewed.get("transitionId") == transition if binding else "transitionId" not in reviewed))
    backup = Path(backup)
    require(backup.is_absolute() and backup.resolve() == backup and not backup.is_relative_to(directory))
    with held_file(backup) as (_backup_fd, backup_identity, backup_raw):
        require(sha(backup_raw) == reviewed["databaseSha256"])
        with admitted_directory(directory, write=True) as directory:
            require(tree(directory) == reviewed["files"])
            witness(directory, pinned)
            with held_file(directory / DATABASE, allow_change=True) as (_fd, original, raw):
                require(list(original) == reviewed["databaseIdentity"] and raw == backup_raw
                    and original[:2] != backup_identity[:2])
                conn = sqlite3.connect((directory / DATABASE).as_uri() + "?mode=rw", uri=True, timeout=0)
                try:
                    conn.row_factory = sqlite3.Row
                    conn.execute("PRAGMA foreign_keys=ON")
                    conn.execute("BEGIN EXCLUSIVE")
                    before = inspect(conn, pinned, helpers, expected_digest=pinned["old"]["sourceContractDigest"])
                    require(all(before[key] == reviewed[key] for key in before))
                    db = helpers[0]
                    trigger = db._policy_candidate_authority_object_name("serverware", CONTRACT_TABLE, "immutable", "update")
                    trigger_rows = conn.execute("SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=? AND tbl_name=?",
                        (trigger, CONTRACT_TABLE)).fetchall()
                    require(len(trigger_rows) == 1)
                    trigger_sql = trigger_rows[0][0]
                    checkpoint("before_guard")
                    conn.execute('DROP TRIGGER "' + trigger + '"')
                    checkpoint("after_guard")
                    changed = conn.execute("UPDATE policy_authority_schema_contracts SET source_contract_digest=? "
                        "WHERE schema_version=9 AND source_contract_digest=?", (reviewed["targetContractDigest"],
                            pinned["old"]["sourceContractDigest"]))
                    require(changed.rowcount == 1)
                    checkpoint("after_update")
                    conn.execute(trigger_sql)
                    checkpoint("after_restore")
                    after = inspect(conn, pinned, helpers, expected_digest=pinned["target"]["sourceContractDigest"])
                    require(after["rows"] == before["rows"] and after["sqliteObjectsSha256"] == before["sqliteObjectsSha256"])
                    require({**after["contract"], "source_contract_digest": before["contract"]["source_contract_digest"]}
                        == before["contract"])
                    require(identity(os.stat(backup, follow_symlinks=False)) == backup_identity)
                    checkpoint("before_commit")
                    conn.commit()
                except BaseException:
                    conn.rollback()
                    raise
                finally:
                    conn.close()
            sidecars_absent(directory)
            require(tree(directory) == reviewed["files"])
            receipt_binding = {**binding, "pinsSha256": pin_digest} if binding else {}
            return {"schema": RECEIPT_SCHEMA, **receipt_binding, "planSha256": expected_plan_sha256,
                "backupSha256": sha(backup_raw), "beforeContract": before["contract"],
                "afterContract": after["contract"], "unchangedRowsSha256": sha(canonical(after["rows"])),
                "unchangedSqliteObjectsSha256": after["sqliteObjectsSha256"],
                "unchangedFilesSha256": sha(canonical(reviewed["files"])), "status": "committed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transition", choices=TRANSITIONS, default="historical",
        help="fixed reviewed transition; historical remains the default")
    parser.add_argument("--data-directory", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--acknowledge-stopped-copied-store", action="store_true")
    args = parser.parse_args()
    pinned = pins(args.transition)
    require(args.data_directory.exists())
    helpers = source(pinned, args.data_directory)
    if args.apply:
        require(args.acknowledge_stopped_copied_store and args.plan and args.backup and args.expected_plan_sha256)
        with held_file(args.plan, MAX_PLAN) as (_fd, _identity, raw):
            result = apply(args.data_directory, pinned, helpers, strict_json(raw), args.expected_plan_sha256, args.backup,
                transition=args.transition)
    else:
        require(not (args.plan or args.backup or args.expected_plan_sha256 or args.acknowledge_stopped_copied_store))
        result = plan(args.data_directory, pinned, helpers, transition=args.transition)
    print(canonical(result).decode())


if __name__ == "__main__":
    try:
        signal.alarm(60)
        def deny_network(event, _arguments):
            if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
                raise Refused()
        sys.addaudithook(deny_network)
        main()
    except Exception:
        print('{"error":"offline ordinary authority migration refused"}', file=sys.stderr)
        raise SystemExit(1) from None
