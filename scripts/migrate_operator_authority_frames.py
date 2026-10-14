#!/usr/bin/env python3
"""Fixed ordinary SQLite .350 -> .351 stopped-copy transition.

Reuse the source-revision transaction driver without changing its historical
transition. This adapter admits only the 34 revision-literal rebuilds, one empty
custody-table composite key, and the new empty frame table with its guards.
No native/PostgreSQL migration, startup fallback, live retry or rollback.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import re
import signal
import sys

import migrate_operator_authority_source_revision as historical

# A private module instance keeps the historical driver's globals untouched.
_spec = importlib.util.spec_from_file_location("_ordinary_frames_engine", historical.__file__)
engine = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(engine)
engine.PIN_FILE = Path(__file__).with_name("operator_authority_frames_migration_pins.json")
# Independently reviewed genuine d745/ca912 derivation, ordinary SQLite only.
engine.PIN_SHA256 = "sha256:82db49f312c6d8da46efb37cf4cb11dc2b25abafb9b23a9f822e5d6c824613e5"
engine.OLD_COMMIT = "d7459af70b60f8c52d5e6ce6acfa794986aa32e3"
engine.TARGET_COMMIT = "ca91224ba2b4f1500b03b73641b90624ed0b1d49"
engine.OLD_REVISION = "serverware.policyCandidateAuthoritySource/2026-07-30.350"
engine.TARGET_REVISION = "serverware.policyCandidateAuthoritySource/2026-07-30.351"
engine.TRANSITION = "ordinary-source-350-to-351-v1"
engine.PIN_SCHEMA = "serverware.operatorAuthorityFramesPins/v1"
engine.SCHEMA = "serverware.operatorAuthorityFramesPlan/v1"
engine.RECEIPT_SCHEMA = "serverware.operatorAuthorityFramesReceipt/v1"
engine.IMAGE = "sha256:ec14a558a42e483a834860521e399b461a2df880fcba495e7127b0d8d2a51e01"
FRAME = "policy_authority_successor_execution_frames"
CUSTODY = "policy_authority_successor_execution_custody"
engine.CHANGED_TABLES = (*historical.CHANGED_TABLES, CUSTODY)
require, sha, canonical = engine.require, engine.sha, engine.canonical


def validate_pins(pinned):
    require(type(pinned) is dict and set(pinned) == {"schema", "transitionId", "oldCommit",
        "targetBaseCommit", "derivationImage", "old", "target", "rebuildTables", "addedObjects"}
        and pinned["schema"] == engine.PIN_SCHEMA and pinned["transitionId"] == engine.TRANSITION
        and pinned["oldCommit"] == engine.OLD_COMMIT and pinned["targetBaseCommit"] == engine.TARGET_COMMIT
        and pinned["derivationImage"] == engine.IMAGE)
    old, target = pinned["old"], pinned["target"]
    require(old["sourceRevision"] == engine.OLD_REVISION and target["sourceRevision"] == engine.TARGET_REVISION
        and old["schemaVersion"] == target["schemaVersion"] == 9
        and old["sourceContractDigest"] != target["sourceContractDigest"]
        and old["witnessObjectsSha256"] == target["witnessObjectsSha256"])
    for field, count in (("tables", 217), ("optionalTables", 218), ("emptyTables", 186)):
        require(old[field] == sorted(set(old[field])) and len(old[field]) == count
            and FRAME not in old[field] and target[field] == sorted([*old[field], FRAME]))
    require(set(old["optionalTables"]) - set(old["tables"]) == {"operator_upstream_setups"}
        and set(engine.CHANGED_TABLES) - set(old["emptyTables"]) == {engine.CONTRACT_TABLE}
        and set(pinned["rebuildTables"]) == set(engine.CHANGED_TABLES))
    for name, pair in pinned["rebuildTables"].items():
        require(type(pair) is dict and set(pair) == {"old", "target"})
        left, right = pair["old"], pair["target"]
        require(type(left) is str and type(right) is str
            and re.match(r"CREATE TABLE\s+" + name + r"\s*\(", left) is not None)
        if name == CUSTODY:
            addition = "            UNIQUE (pending_decision_digest, packet_digest),\n"
            require(engine.OLD_REVISION not in left and engine.TARGET_REVISION not in right
                and right.count(addition) == 1 and right.replace(addition, "", 1) == left)
        else:
            require(left.count(engine.OLD_REVISION) == 1 and engine.TARGET_REVISION not in left
                and engine.OLD_REVISION not in right
                and right == left.replace(engine.OLD_REVISION, engine.TARGET_REVISION, 1))
    added = pinned["addedObjects"]
    require(type(added) is list and added == sorted(added)
        and all(type(row) is list and len(row) == 4 for row in added)
        and len({(row[0], row[1]) for row in added}) == len(added))
    # Names are closed here; exact SQL is additionally bound by the reviewed
    # artifact hash and the actual source-owned structural manifest.
    expected = {("table", FRAME), ("index", "sqlite_autoindex_" + FRAME + "_1"),
        ("index", "sqlite_autoindex_" + CUSTODY + "_6"),
        ("trigger", "serverware_successor_frames_sqlite_insert_guard")}
    require({(row[0], row[1]) for row in added} == expected
        and all(row[2] == (CUSTODY if row[1] == "sqlite_autoindex_" + CUSTODY + "_6" else FRAME)
            and ((row[3] is None) == (row[0] == "index")) for row in added))
    return pinned


def source(pinned, directory):
    engine.require_pins(pinned)
    expected = {**engine.shared.ENVIRONMENT, "SERVERWARE_DATA_DIR": str(directory)}
    require(all(name in expected and value == expected[name]
        for name, value in os.environ.items() if name.startswith("SERVERWARE_")))
    os.environ.update(expected)
    for relative, digest in pinned["target"]["sourceFiles"].items():
        path = engine.ROOT / relative
        require(not path.is_symlink() and path.is_file() and path.resolve().is_relative_to(engine.ROOT)
            and sha(path.read_bytes()) == digest)
    require(not any(name == "serverware" or name.startswith("serverware.") for name in sys.modules))
    sys.path.insert(0, str(engine.ROOT))
    from serverware import db, operator_catalog_schema
    from serverware.authority_store.metadata_schema_source import metadata_schema_source
    ddl = metadata_schema_source()
    require(db._policy_candidate_authority_source_contract_digest() == pinned["target"]["sourceContractDigest"]
        and sha(ddl.encode()) == pinned["target"]["emittedDdlSha256"]
        and ddl.count(engine.TARGET_REVISION) == len(historical.CHANGED_TABLES)
        and engine.OLD_REVISION not in ddl)
    return db, operator_catalog_schema, ddl


def require_delta(before, after, pinned):
    expected = []
    seen = set()
    for kind, name, owner, sql in before:
        if kind == "table" and name in engine.CHANGED_TABLES:
            require(sql == pinned["rebuildTables"][name]["old"])
            sql = pinned["rebuildTables"][name]["target"]
            seen.add(name)
        expected.append([kind, name, owner, sql])
    require(seen == set(engine.CHANGED_TABLES) and after == sorted([*expected, *pinned["addedObjects"]]))


def rebuild(conn, pinned, helpers, before, checkpoint):
    engine.require_pins(pinned)
    require(conn.in_transaction and conn.execute("PRAGMA foreign_keys").fetchone()[0] == 0)
    db, _catalog, ddl = helpers
    schema = engine.objects(conn)
    attached = [row for row in schema if row[2] in engine.CHANGED_TABLES
        and row[0] in {"index", "trigger"} and row[3] is not None]
    require(all(row[0] in {"table", "index", "trigger"} for row in schema if row[2] in engine.CHANGED_TABLES))
    for name in engine.CHANGED_TABLES:
        require(conn.execute("SELECT sql FROM sqlite_schema WHERE type='table' AND name=?", (name,)).fetchone()[0]
            == pinned["rebuildTables"][name]["old"])
        if name != engine.CONTRACT_TABLE:
            require(conn.execute('SELECT 1 FROM "' + name + '" LIMIT 1').fetchone() is None)
    checkpoint("before_drop")
    for name in engine.CHANGED_TABLES:
        conn.execute('DROP TABLE "' + name + '"')
        checkpoint("after_drop:" + name)
    for name in engine.CHANGED_TABLES:
        conn.execute(pinned["rebuildTables"][name]["target"])
        checkpoint("after_create:" + name)
    for kind, _name, _owner, sql in pinned["addedObjects"]:
        if kind == "table":
            conn.execute(sql)
    for _kind, _name, _owner, sql in attached:
        conn.execute(sql)
    for kind, _name, _owner, sql in pinned["addedObjects"]:
        if kind == "trigger":
            conn.execute(sql)
    checkpoint("after_additions")
    manifest, digest = db._validate_policy_candidate_authority_structure(conn,
        require_recorded_contract=False, source_schema_program=ddl)
    require(sha(manifest.encode()) == pinned["target"]["structuralManifestJsonSha256"]
        and digest == pinned["target"]["structuralManifestDigest"])
    value = {**before["contract"], "source_revision": engine.TARGET_REVISION,
        "source_contract_digest": pinned["target"]["sourceContractDigest"],
        "structural_manifest_json": manifest, "structural_manifest_digest": digest}
    columns = tuple(before["contract"])
    conn.execute('INSERT INTO "' + engine.CONTRACT_TABLE + '" (rowid,' + ",".join(columns) + ") VALUES("
        + ",".join("?" for _ in range(len(columns) + 1)) + ")",
        (before["contractRowid"], *(value[column] for column in columns)))
    checkpoint("after_contract")
    require_delta(schema, engine.objects(conn), pinned)
    require(not conn.execute("PRAGMA foreign_key_check").fetchall())


engine.validate_pins = validate_pins
engine.source = source
engine.require_delta = require_delta
engine.rebuild = rebuild
pins, plan, apply = engine.pins, engine.plan, engine.apply


if __name__ == "__main__":
    try:
        signal.alarm(60)
        def deny_network(event, _arguments):
            if event.startswith("socket."):
                raise engine.Refused()
        sys.addaudithook(deny_network)
        engine.main()
    except Exception:
        print('{"error":"offline ordinary frames migration refused; inspect retained outcome before retry"}',
            file=sys.stderr)
        raise SystemExit(1) from None
