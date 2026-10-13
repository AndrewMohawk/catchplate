#!/usr/bin/env python3
"""Explicit empty-authority ordinary-SQLite additive schema transition.

This is not native/PostgreSQL admission or a startup compatibility fallback.
Plan is read-only. Apply requires a stopped copied store, an exact reviewed
plan and a separate byte-identical backup. One exclusive transaction creates
only the source-defined empty native-pair table and updates three contract
metadata cells. Existing rows, guards, ordered audit and files are preserved.
Loss after COMMIT but before the external receipt is an unknown outcome: keep
the plan/backup/store and inspect them; never automatically replay or restore.
The historical identical-DDL migration engine remains unchanged.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import signal
import sqlite3
import sys

import migrate_operator_authority_contract as shared

ROOT = shared.ROOT
PIN_FILE = ROOT / "scripts/operator_native_jit_schema_migration_pins.json"
# Replaced only by the reviewed output of genuine old/target initialization.
# Missing or provisional pins refuse before any Serverware import or DB open.
PIN_SHA256 = "sha256:9bc74904575a444124ec487a5da3da488dd168a9abe672210efa81943670770a"
TRANSITION = "native-jit-pair-v1"
PIN_SCHEMA = "serverware.operatorNativeJitSchemaMigrationPins/v1"
SCHEMA = "serverware.operatorNativeJitSchemaMigrationPlan/v1"
RECEIPT_SCHEMA = "serverware.operatorNativeJitSchemaMigrationReceipt/v1"
OLD_COMMIT = "35817cf50b0dc87cf06a07c0c9ce273f13af323f"
TARGET_COMMIT = "aca8e74ed8cb2c790342fb3265ba12606ba88005"
TABLE = "policy_authority_native_jit_review_pairs"
CONTRACT_FIELDS = frozenset({"source_contract_digest", "structural_manifest_json", "structural_manifest_digest"})
PLAN_FIELDS = frozenset({"schema", "transitionId", "pinsSha256", "databaseSha256", "databaseIdentity",
    "files", "targetContractDigest", "contract", "rows", "orderedAudit", "sqliteObjectsSha256", "variant"})

# Reuse the existing strict filesystem and ordinary-store utilities, not its
# intentionally incompatible single-cell inspection/mutation implementation.
Refused = shared.Refused
require, canonical, sha, strict_json = shared.require, shared.canonical, shared.sha, shared.strict_json
held_file, identity, tree = shared.held_file, shared.identity, shared.tree
admitted_directory, sidecars_absent = shared.admitted_directory, shared.sidecars_absent
objects, row_commitments = shared.objects, shared.row_commitments
DATABASE, WITNESS, CONTRACT_TABLE = shared.DATABASE, shared.WITNESS, shared.CONTRACT_TABLE
MARKER, MARKER_BYTES = shared.MARKER, shared.MARKER_BYTES
PUBLIC_FILES, EMPTY_MOUNTPOINTS = shared.PUBLIC_FILES, shared.EMPTY_MOUNTPOINTS
MAX_PLAN = shared.MAX_PLAN


def pins():
    require(PIN_SHA256 != "sha256:" + "0" * 64)
    raw = PIN_FILE.read_bytes()
    require(sha(raw) == PIN_SHA256)
    pinned = strict_json(raw)
    require(type(pinned) is dict and pinned.get("schema") == PIN_SCHEMA
        and pinned.get("transitionId") == TRANSITION and pinned.get("oldCommit") == OLD_COMMIT
        and pinned.get("targetBaseCommit") == TARGET_COMMIT)
    old, target = pinned["old"], pinned["target"]
    require(old["schemaVersion"] == target["schemaVersion"] == 9
        and old["sourceRevision"] == target["sourceRevision"]
        and old["sourceContractDigest"] != target["sourceContractDigest"]
        and old["witnessObjectsSha256"] == target["witnessObjectsSha256"])
    for field in ("tables", "optionalTables", "emptyTables"):
        require(old[field] == sorted(set(old[field])) and TABLE not in old[field]
            and target[field] == sorted(old[field] + [TABLE]))
    require(len(old["emptyTables"]) == 185
        and set(old["optionalTables"]) - set(old["tables"]) == {"operator_upstream_setups"})
    return pinned


def require_pins(pinned):
    require(pinned == pins())  # No caller-selected pin object, source or profile.


def source(pinned, directory):
    require_pins(pinned)
    expected = {**shared.ENVIRONMENT, "SERVERWARE_DATA_DIR": str(directory)}
    require(all(name in expected and value == expected[name]
        for name, value in os.environ.items() if name.startswith("SERVERWARE_")))
    os.environ.update(expected)
    for relative, digest in pinned["target"]["sourceFiles"].items():
        path = ROOT / relative
        require(not path.is_symlink() and path.is_file() and path.resolve().is_relative_to(ROOT)
            and sha(path.read_bytes()) == digest)
    require(not any(name == "serverware" or name.startswith("serverware.") for name in sys.modules))
    sys.path.insert(0, str(ROOT))
    from serverware import db, operator_catalog_schema, authority_native_jit_retention_schema
    from serverware.authority_store.metadata_schema_source import metadata_schema_source
    ddl, addition = metadata_schema_source(), authority_native_jit_retention_schema.source()
    require(db._policy_candidate_authority_source_contract_digest() == pinned["target"]["sourceContractDigest"]
        and sha(ddl.encode()) == pinned["target"]["emittedDdlSha256"]
        and sha(addition.encode()) == pinned["additionDdlSha256"]
        and ddl.count(addition) == 1
        and sha(ddl.replace(addition, "", 1).encode()) == pinned["old"]["emittedDdlSha256"])
    return db, operator_catalog_schema, ddl, addition


def ordered_audit(conn):
    cursor = conn.execute("SELECT rowid,* FROM audit_events ORDER BY rowid")
    rows = []
    for row in cursor:
        require(len(rows) < shared.MAX_ROWS)
        rows.append(sha(canonical([shared.typed(cell) for cell in row])))
    return {"columns": [field[0] for field in cursor.description], "count": len(rows),
        "sha256": sha(canonical(rows))}


def inspect(conn, pinned, helpers, *, target=False):
    """Old exact independent pins; after creation, actual target validation too."""
    db, catalog, ddl, _addition = helpers
    from serverware.authority_store.metadata_schema import configure_sqlite_metadata_connection
    configure_sqlite_metadata_connection(conn)
    selected = pinned["target" if target else "old"]
    schema = objects(conn)
    tables = sorted(row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'"))
    optional = tables == selected["optionalTables"]
    require(optional or tables == selected["tables"])
    require(sha(canonical(schema)) == selected["optionalSqliteObjectsSha256" if optional else "sqliteObjectsSha256"])
    require([row[0] for row in conn.execute("PRAGMA quick_check")] == ["ok"]
        and not conn.execute("PRAGMA foreign_key_check").fetchall())
    rows = conn.execute("SELECT * FROM policy_authority_schema_contracts").fetchall()
    require(len(rows) == 1)
    contract = dict(rows[0])
    require(set(contract) == {"schema_version", "contract_id", "source_revision", "source_contract_digest",
        "structural_manifest_json", "structural_manifest_digest", "offline_migration_receipt_digest", "installed_at"})
    require(contract["schema_version"] == 9 and contract["source_revision"] == selected["sourceRevision"]
        and contract["contract_id"] == "serverware.policyCandidateAuthoritySchema/v9"
        and contract["source_contract_digest"] == selected["sourceContractDigest"]
        and sha(contract["structural_manifest_json"].encode()) == selected["structuralManifestJsonSha256"]
        and contract["structural_manifest_digest"] == selected["structuralManifestDigest"]
        and contract["offline_migration_receipt_digest"] is None)
    if target:
        manifest, digest = db._validate_policy_candidate_authority_structure(conn,
            require_recorded_contract=True, source_schema_program=ddl)
        require(contract["structural_manifest_json"] == manifest and contract["structural_manifest_digest"] == digest)
    versions = conn.execute("SELECT version FROM serverware_store_migrations "
        "WHERE migration='policy_candidate_authority'").fetchall()
    require(len(versions) == 1 and versions[0][0] == 9)
    for name in selected["emptyTables"]:
        require(re.fullmatch(r"[a-z_][a-z0-9_]*", name) is not None
            and conn.execute('SELECT 1 FROM "' + name + '" LIMIT 1').fetchone() is None)
    require(catalog.active(conn))
    catalog.read_catalog(conn)
    if optional:
        from serverware import operator_upstream_setup
        operator_upstream_setup._rows(conn)
    return {"contract": contract, "rows": row_commitments(conn, tables), "orderedAudit": ordered_audit(conn),
        "sqliteObjectsSha256": sha(canonical(schema)), "variant": "optional" if optional else "base"}


def plan(directory, pinned, helpers):
    require_pins(pinned)
    with admitted_directory(directory) as directory:
        before_files = tree(directory)
        shared.witness(directory, pinned)
        with held_file(directory / DATABASE) as (_fd, original, raw):
            require(raw.startswith(b"SQLite format 3\x00"))
            conn = sqlite3.connect((directory / DATABASE).as_uri() + "?mode=ro&immutable=1", uri=True, timeout=0)
            try:
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA query_only=ON")
                conn.execute("BEGIN")
                value = inspect(conn, pinned, helpers)
                conn.rollback()
            finally:
                conn.close()
            require(identity(os.stat(directory / DATABASE, follow_symlinks=False)) == original)
        sidecars_absent(directory)
        require(tree(directory) == before_files)
        return {"schema": SCHEMA, "transitionId": TRANSITION, "pinsSha256": PIN_SHA256,
            "databaseSha256": sha(raw), "databaseIdentity": list(original), "files": before_files,
            "targetContractDigest": pinned["target"]["sourceContractDigest"], **value}


def require_addition(before, after):
    expected = {("table", TABLE), *(('index', 'sqlite_autoindex_' + TABLE + '_' + str(number))
        for number in (1, 2, 3))}
    added = [row for row in after if row[2] == TABLE]
    require({tuple(row[:2]) for row in added} == expected and len(added) == 4
        and all(row[3] is None for row in added if row[0] == "index")
        and [row for row in after if row[2] != TABLE] == before)


def apply(directory, pinned, helpers, reviewed, expected_plan_sha256, backup, *, checkpoint=lambda _stage: None):
    require_pins(pinned)
    require(type(reviewed) is dict and set(reviewed) == PLAN_FIELDS and reviewed["schema"] == SCHEMA
        and reviewed["transitionId"] == TRANSITION and reviewed["pinsSha256"] == PIN_SHA256
        and sha(canonical(reviewed)) == expected_plan_sha256
        and reviewed["targetContractDigest"] == pinned["target"]["sourceContractDigest"])
    directory, backup = Path(directory), Path(backup)
    require(backup.is_absolute() and backup.resolve() == backup and not backup.is_relative_to(directory))
    with held_file(backup) as (_backup_fd, backup_identity, backup_raw):
        require(sha(backup_raw) == reviewed["databaseSha256"])
        with admitted_directory(directory, write=True) as directory:
            require(tree(directory) == reviewed["files"])
            shared.witness(directory, pinned)
            with held_file(directory / DATABASE, allow_change=True) as (_fd, original, raw):
                require(list(original) == reviewed["databaseIdentity"] and raw == backup_raw
                    and original[:2] != backup_identity[:2])
                conn = sqlite3.connect((directory / DATABASE).as_uri() + "?mode=rw", uri=True, timeout=0)
                try:
                    conn.row_factory = sqlite3.Row
                    conn.execute("PRAGMA foreign_keys=ON")
                    conn.execute("BEGIN EXCLUSIVE")
                    before = inspect(conn, pinned, helpers)
                    require(all(before[key] == reviewed[key] for key in before))
                    before_schema = objects(conn)
                    db, _catalog, ddl, addition = helpers
                    checkpoint("before_create")
                    db._execute_metadata_schema_statements(conn, addition)
                    checkpoint("after_create")
                    require_addition(before_schema, objects(conn))
                    require(conn.execute('SELECT 1 FROM "' + TABLE + '" LIMIT 1').fetchone() is None)
                    manifest, digest = db._validate_policy_candidate_authority_structure(conn,
                        require_recorded_contract=False, source_schema_program=ddl)
                    require(sha(manifest.encode()) == pinned["target"]["structuralManifestJsonSha256"]
                        and digest == pinned["target"]["structuralManifestDigest"])
                    trigger = db._policy_candidate_authority_object_name("serverware", CONTRACT_TABLE, "immutable", "update")
                    triggers = conn.execute("SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=? AND tbl_name=?",
                        (trigger, CONTRACT_TABLE)).fetchall()
                    require(len(triggers) == 1)
                    trigger_sql = triggers[0][0]
                    checkpoint("before_guard")
                    conn.execute('DROP TRIGGER "' + trigger + '"')
                    checkpoint("after_guard")
                    old = before["contract"]
                    changed = conn.execute("UPDATE policy_authority_schema_contracts SET source_contract_digest=?, "
                        "structural_manifest_json=?, structural_manifest_digest=? WHERE schema_version=9 "
                        "AND source_contract_digest=? AND structural_manifest_json=? AND structural_manifest_digest=?",
                        (reviewed["targetContractDigest"], manifest, digest, old["source_contract_digest"],
                            old["structural_manifest_json"], old["structural_manifest_digest"]))
                    require(changed.rowcount == 1)
                    checkpoint("after_update")
                    conn.execute(trigger_sql)
                    checkpoint("after_restore")
                    after = inspect(conn, pinned, helpers, target=True)
                    require_addition(before_schema, objects(conn))
                    require(after["variant"] == before["variant"] and after["orderedAudit"] == before["orderedAudit"]
                        and all(after["rows"][name] == row for name, row in before["rows"].items() if name != CONTRACT_TABLE)
                        and after["rows"][TABLE]["count"] == 0
                        and {key: value for key, value in after["contract"].items() if key not in CONTRACT_FIELDS}
                            == {key: value for key, value in old.items() if key not in CONTRACT_FIELDS})
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
            # No compensating mutation or successful-replay shortcut after COMMIT.
            checkpoint("after_commit")
            return {"schema": RECEIPT_SCHEMA, "transitionId": TRANSITION, "pinsSha256": PIN_SHA256,
                "planSha256": expected_plan_sha256, "backupSha256": sha(backup_raw),
                "beforeContract": before["contract"], "afterContract": after["contract"],
                "preservedOldRowsSha256": sha(canonical({name: row for name, row in before["rows"].items()
                    if name != CONTRACT_TABLE})), "orderedAudit": after["orderedAudit"],
                "beforeSqliteObjectsSha256": before["sqliteObjectsSha256"],
                "afterSqliteObjectsSha256": after["sqliteObjectsSha256"],
                "unchangedFilesSha256": sha(canonical(reviewed["files"])), "newTableRows": 0, "status": "committed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-directory", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--acknowledge-stopped-copied-store", action="store_true")
    args = parser.parse_args()
    pinned = pins()
    require(args.data_directory.exists())
    helpers = source(pinned, args.data_directory)
    if args.apply:
        require(args.acknowledge_stopped_copied_store and args.plan and args.backup and args.expected_plan_sha256)
        with held_file(args.plan, MAX_PLAN) as (_fd, _identity, raw):
            result = apply(args.data_directory, pinned, helpers, strict_json(raw), args.expected_plan_sha256, args.backup)
    else:
        require(not (args.plan or args.backup or args.expected_plan_sha256 or args.acknowledge_stopped_copied_store))
        result = plan(args.data_directory, pinned, helpers)
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
        print('{"error":"offline ordinary native-pair schema migration refused"}', file=sys.stderr)
        raise SystemExit(1) from None
