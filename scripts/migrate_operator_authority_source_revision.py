#!/usr/bin/env python3
"""Fixed ordinary SQLite source-349 to source-350 transition on a stopped copy.

Only independently derived pins and their reviewed exact digest are admitted.
No caller-selected source/revision, live-store derivation, startup repair, native
or PostgreSQL migration. Populated authority/history is refused unchanged.
A lost COMMIT acknowledgement or external receipt is unknown: never auto-replay.
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
PIN_FILE = Path(__file__).with_name("operator_authority_source_revision_migration_pins.json")
# Hosted derivation 38516997815; independently joined to both fixed Git sources.
# This enables stopped-copy tests, not automatic migration or live promotion.
PIN_SHA256 = "sha256:72ce5ebdb7f422e881987749310493451f6d19fa397bb39157313bb85b7472e4"
OLD_COMMIT = "c11e75982ceeec516887c3db65a9d88eabf819a9"
TARGET_COMMIT = "1052d0e8ae565956ca8d39df0859f2017f8c107b"
OLD_REVISION = "catchplate.policyCandidateAuthoritySource/2026-07-30.349"
TARGET_REVISION = "catchplate.policyCandidateAuthoritySource/2026-07-30.350"
TRANSITION = "ordinary-source-349-to-350-v1"
PIN_SCHEMA = "catchplate.operatorAuthoritySourceRevisionPins/v1"
SCHEMA = "catchplate.operatorAuthoritySourceRevisionPlan/v1"
RECEIPT_SCHEMA = "catchplate.operatorAuthoritySourceRevisionReceipt/v1"
IMAGE = "python@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea"
CHANGED_TABLES = (
    "policy_activation_export_authorizations",
    "policy_activation_export_issuances",
    "policy_activation_finalized_exports",
    "policy_authority_activation_evidence_bindings",
    "policy_authority_authorization_dependency_manifests",
    "policy_authority_authorization_projections",
    "policy_authority_bounded_aggregate_states",
    "policy_authority_continuations",
    "policy_authority_current_root_commit_markers",
    "policy_authority_exact_pages",
    "policy_authority_execution_envelopes",
    "policy_authority_external_evidence_receipts",
    "policy_authority_native_jit_review_pairs",
    "policy_authority_opaque_values",
    "policy_authority_operation_mutation_templates",
    "policy_authority_owner_contracts",
    "policy_authority_owner_decisions",
    "policy_authority_owner_operations",
    "policy_authority_planner_transactions",
    "policy_authority_query_dependency_manifests",
    "policy_authority_revocation_retained_capabilities",
    "policy_authority_revocation_retained_plans",
    "policy_authority_revocation_writer_acknowledgments",
    "policy_authority_revocation_writer_requests",
    "policy_authority_schema_contracts",
    "policy_authority_sealed_values",
    "policy_authority_secondary_index_heads",
    "policy_authority_tombstones",
    "policy_authority_v9_offline_migration_receipts",
    "policy_authority_webauthn_assertion_evidence",
    "policy_authority_webauthn_evidence_retained_plans",
    "policy_authority_webauthn_transition_retained_plans",
    "policy_authority_work_pages",
    "policy_authority_writer_receipts",
)
CONTRACT_FIELDS = frozenset({"source_revision", "source_contract_digest",
    "structural_manifest_json", "structural_manifest_digest"})
PLAN_FIELDS = frozenset({"schema", "transitionId", "pinsSha256", "databaseSha256", "databaseIdentity",
    "files", "targetContractDigest", "contract", "contractRowid", "rows", "orderedAudit",
    "sqliteObjectsSha256", "variant"})
Refused = shared.Refused
require, canonical, sha, strict_json = shared.require, shared.canonical, shared.sha, shared.strict_json
held_file, identity, tree = shared.held_file, shared.identity, shared.tree
admitted_directory, sidecars_absent = shared.admitted_directory, shared.sidecars_absent
objects, row_commitments = shared.objects, shared.row_commitments
DATABASE, WITNESS, CONTRACT_TABLE = shared.DATABASE, shared.WITNESS, shared.CONTRACT_TABLE
MARKER, MARKER_BYTES, EMPTY_MOUNTPOINTS = shared.MARKER, shared.MARKER_BYTES, shared.EMPTY_MOUNTPOINTS
MAX_PLAN = shared.MAX_PLAN


def validate_pins(pinned):
    """Pure derivation check; only pins() can admit these as migration authority."""
    require(type(pinned) is dict and set(pinned) == {"schema", "transitionId", "oldCommit",
        "targetBaseCommit", "derivationImage", "old", "target", "rebuildTables"}
        and pinned["schema"] == PIN_SCHEMA and pinned["transitionId"] == TRANSITION
        and pinned["oldCommit"] == OLD_COMMIT and pinned["targetBaseCommit"] == TARGET_COMMIT
        and pinned["derivationImage"] == IMAGE)
    old, target = pinned["old"], pinned["target"]
    require(old["sourceRevision"] == OLD_REVISION and target["sourceRevision"] == TARGET_REVISION
        and old["schemaVersion"] == target["schemaVersion"] == 9
        and old["sourceContractDigest"] != target["sourceContractDigest"]
        and old["witnessObjectsSha256"] == target["witnessObjectsSha256"])
    for field in ("tables", "optionalTables", "emptyTables"):
        require(old[field] == target[field] == sorted(set(old[field])))
    require(len(old["tables"]) == 217 and len(old["optionalTables"]) == 218
        and len(old["emptyTables"]) == 186
        and set(old["optionalTables"]) - set(old["tables"]) == {"operator_upstream_setups"}
        and set(CHANGED_TABLES) - set(old["emptyTables"]) == {CONTRACT_TABLE})
    require(set(pinned["rebuildTables"]) == set(CHANGED_TABLES))
    for name, pair in pinned["rebuildTables"].items():
        require(type(pair) is dict and set(pair) == {"old", "target"})
        left, right = pair["old"], pair["target"]
        require(type(left) is str and type(right) is str and left.count(OLD_REVISION) == 1
            and TARGET_REVISION not in left and OLD_REVISION not in right
            and right == left.replace(OLD_REVISION, TARGET_REVISION, 1)
            and re.match(r"CREATE TABLE\s+" + name + r"\s*\(", left) is not None)
    return pinned


def pins():
    # No pin-generation command, environment override or caller-supplied artifact
    # is an alternative to this independently reviewed immutable file digest.
    require(type(PIN_SHA256) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", PIN_SHA256) is not None
        and PIN_SHA256 != "sha256:" + "0" * 64)
    raw = PIN_FILE.read_bytes()
    require(len(raw) <= MAX_PLAN and sha(raw) == PIN_SHA256)
    return validate_pins(strict_json(raw))


def require_pins(pinned):
    require(pinned == pins())


def source(pinned, directory):
    require_pins(pinned)
    expected = {**shared.ENVIRONMENT, "CATCHPLATE_DATA_DIR": str(directory)}
    require(all(name in expected and value == expected[name]
        for name, value in os.environ.items() if name.startswith("CATCHPLATE_")))
    os.environ.update(expected)
    for relative, digest in pinned["target"]["sourceFiles"].items():
        path = ROOT / relative
        require(not path.is_symlink() and path.is_file() and path.resolve().is_relative_to(ROOT)
            and sha(path.read_bytes()) == digest)
    require(not any(name == "catchplate" or name.startswith("catchplate.") for name in sys.modules))
    sys.path.insert(0, str(ROOT))
    from catchplate import db, operator_catalog_schema
    from catchplate.authority_store.metadata_schema_source import metadata_schema_source
    ddl = metadata_schema_source()
    require(db._policy_candidate_authority_source_contract_digest() == pinned["target"]["sourceContractDigest"]
        and sha(ddl.encode()) == pinned["target"]["emittedDdlSha256"]
        and ddl.count(TARGET_REVISION) == len(CHANGED_TABLES) and OLD_REVISION not in ddl
        and sha(ddl.replace(TARGET_REVISION, OLD_REVISION).encode()) == pinned["old"]["emittedDdlSha256"])
    return db, operator_catalog_schema, ddl


def ordered_audit(conn):
    cursor = conn.execute("SELECT rowid,* FROM audit_events ORDER BY rowid")
    rows = []
    for row in cursor:
        require(len(rows) < shared.MAX_ROWS)
        rows.append(sha(canonical([shared.typed(cell) for cell in row])))
    return {"columns": [field[0] for field in cursor.description], "count": len(rows),
        "sha256": sha(canonical(rows))}


def inspect(conn, pinned, helpers, *, target=False):
    db, catalog, ddl = helpers
    from catchplate.authority_store.metadata_schema import configure_sqlite_metadata_connection
    configure_sqlite_metadata_connection(conn)
    selected = pinned["target" if target else "old"]
    schema = objects(conn)
    tables = sorted(row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'"))
    optional = tables == selected["optionalTables"]
    require(optional or tables == selected["tables"])
    require(sha(canonical(schema)) == selected["optionalSqliteObjectsSha256" if optional else "sqliteObjectsSha256"])
    require([row[0] for row in conn.execute("PRAGMA quick_check")] == ["ok"]
        and not conn.execute("PRAGMA foreign_key_check").fetchall())
    rows = conn.execute("SELECT rowid AS retained_rowid,* FROM policy_authority_schema_contracts").fetchall()
    require(len(rows) == 1)
    contract = dict(rows[0])
    rowid = contract.pop("retained_rowid")
    require(type(rowid) is int and set(contract) == {"schema_version", "contract_id", "source_revision",
        "source_contract_digest", "structural_manifest_json", "structural_manifest_digest",
        "offline_migration_receipt_digest", "installed_at"})
    require(contract["schema_version"] == 9 and contract["source_revision"] == selected["sourceRevision"]
        and contract["contract_id"] == "catchplate.policyCandidateAuthoritySchema/v9"
        and contract["source_contract_digest"] == selected["sourceContractDigest"]
        and sha(contract["structural_manifest_json"].encode()) == selected["structuralManifestJsonSha256"]
        and contract["structural_manifest_digest"] == selected["structuralManifestDigest"]
        and contract["offline_migration_receipt_digest"] is None)
    if target:
        manifest, digest = db._validate_policy_candidate_authority_structure(conn,
            require_recorded_contract=True, source_schema_program=ddl)
        require(contract["structural_manifest_json"] == manifest and contract["structural_manifest_digest"] == digest)
    versions = conn.execute("SELECT version FROM catchplate_store_migrations "
        "WHERE migration='policy_candidate_authority'").fetchall()
    require(len(versions) == 1 and versions[0][0] == 9)
    # This includes all retained roots/trees/leaves/history, not just the 33
    # tables rebuilt below. Ordinary credential_generations is not erased.
    for name in selected["emptyTables"]:
        require(re.fullmatch(r"[a-z_][a-z0-9_]*", name) is not None
            and conn.execute('SELECT 1 FROM "' + name + '" LIMIT 1').fetchone() is None)
    require(catalog.active(conn))
    catalog.read_catalog(conn)
    if optional:
        from catchplate import operator_upstream_setup
        operator_upstream_setup._rows(conn)
    return {"contract": contract, "contractRowid": rowid, "rows": row_commitments(conn, tables),
        "orderedAudit": ordered_audit(conn), "sqliteObjectsSha256": sha(canonical(schema)),
        "variant": "optional" if optional else "base"}


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


def require_delta(before, after, pinned):
    expected = []
    seen = set()
    for kind, name, owner, sql in before:
        if kind == "table" and name in CHANGED_TABLES:
            require(sql == pinned["rebuildTables"][name]["old"])
            sql = pinned["rebuildTables"][name]["target"]
            seen.add(name)
        expected.append([kind, name, owner, sql])
    require(seen == set(CHANGED_TABLES) and after == expected)


def rebuild(conn, pinned, helpers, before, checkpoint):
    """Only invoked after exact admission repeated under BEGIN EXCLUSIVE."""
    require_pins(pinned)
    require(conn.in_transaction and conn.execute("PRAGMA foreign_keys").fetchone()[0] == 0)
    db, _catalog, ddl = helpers
    schema = objects(conn)
    # DROP TABLE drops its own indexes/triggers. No renaming: dependent SQL
    # must remain byte-identical. Foreign keys are OFF before BEGIN, so no
    # implicit delete cascade may rewrite ordinary or historical rows.
    attached = [row for row in schema if row[2] in CHANGED_TABLES and row[0] in {"index", "trigger"}
        and row[3] is not None]
    require(all(row[0] in {"table", "index", "trigger"} for row in schema if row[2] in CHANGED_TABLES))
    for name in CHANGED_TABLES:
        require(conn.execute('SELECT sql FROM sqlite_schema WHERE type=\'table\' AND name=?', (name,)).fetchone()[0]
            == pinned["rebuildTables"][name]["old"])
        if name != CONTRACT_TABLE:
            require(conn.execute('SELECT 1 FROM "' + name + '" LIMIT 1').fetchone() is None)
    checkpoint("before_drop")
    for name in CHANGED_TABLES:
        conn.execute('DROP TABLE "' + name + '"')
        checkpoint("after_drop:" + name)
    for name in CHANGED_TABLES:
        conn.execute(pinned["rebuildTables"][name]["target"])
        checkpoint("after_create:" + name)
    # Recreate exact attached indexes/guards, including guards on the contract.
    # Fresh contract INSERT is permitted; immutable UPDATE/DELETE stay refused.
    for kind, _name, owner, sql in attached:
        if owner != CONTRACT_TABLE:
            conn.execute(sql)
    # Validation requires every guard, including those on the empty contract
    # table. Restore them first; INSERT is the normal fresh-contract operation.
    for _kind, _name, owner, sql in attached:
        if owner == CONTRACT_TABLE:
            conn.execute(sql)
    manifest, digest = db._validate_policy_candidate_authority_structure(conn,
        require_recorded_contract=False, source_schema_program=ddl)
    require(sha(manifest.encode()) == pinned["target"]["structuralManifestJsonSha256"]
        and digest == pinned["target"]["structuralManifestDigest"])
    value = {**before["contract"], "source_revision": TARGET_REVISION,
        "source_contract_digest": pinned["target"]["sourceContractDigest"],
        "structural_manifest_json": manifest, "structural_manifest_digest": digest}
    columns = tuple(before["contract"])
    conn.execute('INSERT INTO "' + CONTRACT_TABLE + '" (rowid,' + ",".join(columns) + ") VALUES("
        + ",".join("?" for _ in range(len(columns) + 1)) + ")",
        (before["contractRowid"], *(value[column] for column in columns)))
    checkpoint("after_contract")
    require_delta(schema, objects(conn), pinned)
    require(not conn.execute("PRAGMA foreign_key_check").fetchall())


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
                    # This is a new migration-owned connection. Never toggle
                    # foreign_keys inside BEGIN (where SQLite ignores it).
                    conn.execute("PRAGMA foreign_keys=OFF")
                    require(conn.execute("PRAGMA foreign_keys").fetchone()[0] == 0 and not conn.in_transaction)
                    conn.execute("BEGIN EXCLUSIVE")
                    before = inspect(conn, pinned, helpers)
                    require(all(before[key] == reviewed[key] for key in before))
                    rebuild(conn, pinned, helpers, before, checkpoint)
                    after = inspect(conn, pinned, helpers, target=True)
                    require(after["variant"] == before["variant"] and after["orderedAudit"] == before["orderedAudit"]
                        and after["contractRowid"] == before["contractRowid"]
                        and all(after["rows"][name] == row for name, row in before["rows"].items()
                            if name != CONTRACT_TABLE)
                        and {k: v for k, v in after["contract"].items() if k not in CONTRACT_FIELDS}
                            == {k: v for k, v in before["contract"].items() if k not in CONTRACT_FIELDS})
                    require(identity(os.stat(backup, follow_symlinks=False)) == backup_identity)
                    checkpoint("before_commit")
                    conn.commit()
                    conn.execute("PRAGMA foreign_keys=ON")
                    require(conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
                        and not conn.execute("PRAGMA foreign_key_check").fetchall())
                except BaseException:
                    conn.rollback()
                    raise
                finally:
                    conn.close()
            sidecars_absent(directory)
            require(tree(directory) == reviewed["files"])
            checkpoint("after_commit")  # No compensation or successful-replay shortcut.
            return {"schema": RECEIPT_SCHEMA, "transitionId": TRANSITION, "pinsSha256": PIN_SHA256,
                "planSha256": expected_plan_sha256, "backupSha256": sha(backup_raw),
                "beforeContract": before["contract"], "afterContract": after["contract"],
                "preservedOldRowsSha256": sha(canonical({n: row for n, row in before["rows"].items()
                    if n != CONTRACT_TABLE})), "orderedAudit": after["orderedAudit"],
                "beforeSqliteObjectsSha256": before["sqliteObjectsSha256"],
                "afterSqliteObjectsSha256": after["sqliteObjectsSha256"],
                "unchangedFilesSha256": sha(canonical(reviewed["files"])),
                "rebuiltTables": list(CHANGED_TABLES), "status": "committed"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-directory", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--plan", type=Path)
    parser.add_argument("--expected-plan-sha256")
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--acknowledge-stopped-copied-store", action="store_true")
    args = parser.parse_args()
    pinned = pins()  # Refuses unavailable pin artifact before imports/DB/files.
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
            if event.startswith("socket."):
                raise Refused()
        sys.addaudithook(deny_network)
        main()
    except Exception:
        print('{"error":"offline ordinary source-revision migration refused; inspect retained outcome before retry"}',
            file=sys.stderr)
        raise SystemExit(1) from None
