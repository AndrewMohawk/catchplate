#!/usr/bin/env python3
"""Secret-silent stopped-rollout observer; no app imports or live SQLite opens.

Root owns service stops, archives and extraction. Inventory reads only files;
compare accepts private extracted trees and recovers further disposable SQLite
copies. It neither stops services nor proves they stopped. Output contains
metadata/counts/digests only. No output or archive files are created here.
"""
from collections import Counter
from contextlib import ExitStack
import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import stat
import sys
import tempfile

SCHEMA = "serverware.operatorRolloutInventory/v1"
DB_MAIN = "app-data/serverware.sqlite3"
DB_FILES = frozenset(DB_MAIN + suffix for suffix in ("", "-wal", "-shm", "-journal"))
DERIVED = frozenset("app-data/decision-gate-ca-" + kind + ".pem" for kind in ("cert", "key"))
NOTIFICATIONS = frozenset("operator_notification_" + suffix for suffix in ("meta", "config", "operations", "deliveries", "attempts"))
MAX_OBJECTS, MAX_MEMBERS, MAX_ROWS = 4096, 2048, 65536
MAX_FILE, MAX_DB, MAX_TOTAL = 32 * 1024**2, 256 * 1024**2, 1024**3


class SnapshotError(RuntimeError):
    def __init__(self, code, table=None):
        self.code, self.table = code, table
        super().__init__("operator rollout observation refused")


def require(condition, code="invalid_observation", table=None):
    if not condition:
        raise SnapshotError(code, table)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode("ascii")).hexdigest()


def path(value):
    value = Path(value)
    require(value.is_absolute() and value != Path("/") and ".." not in value.parts and value.resolve(strict=True) == value)
    return value


def metadata(value):
    info = value.lstat()
    require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode), "special_file_refused")
    result = {"kind": "directory" if stat.S_ISDIR(info.st_mode) else "file",
        "dev": info.st_dev, "ino": info.st_ino, "uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}
    if result["kind"] == "file":
        require(info.st_nlink == 1, "hardlink_refused")
        result["size"] = info.st_size
    return result, (info.st_mtime_ns, info.st_ctime_ns)


def tree(root):
    root = path(root)
    initial, _ = metadata(root)
    require(initial["kind"] == "directory")
    result, total = {".": initial}, 0
    def walk_error(_error):
        raise SnapshotError("inventory_unavailable")
    for directory, directories, filenames in os.walk(root, followlinks=False, onerror=walk_error):
        require(len(result) + len(directories) + len(filenames) <= MAX_MEMBERS, "inventory_bound")
        for name in sorted(directories + filenames):
            current = Path(directory) / name
            relative = str(current.relative_to(root))
            info, stamps = metadata(current)
            if info["kind"] == "file":
                maximum = MAX_DB if relative in DB_FILES else MAX_FILE
                total += info["size"]
                require(info["size"] <= maximum and total <= MAX_TOTAL, "file_bound")
                with os.fdopen(os.open(current, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), "rb") as source:
                    opened = os.fstat(source.fileno())
                    require((opened.st_dev, opened.st_ino) == (info["dev"], info["ino"]))
                    hashed = hashlib.file_digest(source, "sha256").hexdigest()
                    finished = os.fstat(source.fileno())
                    require((finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns, finished.st_ctime_ns)
                        == (info["dev"], info["ino"], info["size"], *stamps), "file_changed_during_read")
                require(metadata(current) == (info, stamps), "file_changed_during_read")
                info["sha256"] = hashed
            result[relative] = info
    require(metadata(root)[0] == initial)
    return result


def inventory(persistent_root, custody_root):
    persistent_root, custody_root = path(persistent_root), path(custody_root)
    require(not persistent_root.is_relative_to(custody_root) and not custody_root.is_relative_to(persistent_root))
    persistent, custody = tree(persistent_root), tree(custody_root)
    require(DB_MAIN in persistent, "database_missing")
    owner = tuple(persistent[DB_MAIN][key] for key in ("uid", "gid"))
    for name in DB_FILES & persistent.keys():
        info = persistent[name]
        require(info["kind"] == "file" and info["mode"] == 0o600
            and tuple(info[key] for key in ("uid", "gid")) == owner, "sqlite_file_identity")
    require(set(custody) <= {".", "notification-key.json"} and custody["."]["mode"] == 0o700, "custody_inventory")
    if "notification-key.json" in custody:
        key = custody["notification-key.json"]
        require(key["kind"] == "file" and key["mode"] == 0o600 and 1 <= key["size"] <= 512
            and (key["uid"], key["gid"]) == (custody["."]["uid"], custody["."]["gid"]), "custody_inventory")
    return {"schema": SCHEMA, "persistent": persistent, "custody": custody, "live_sqlite_opened": False}


def content(info):
    return {key: value for key, value in info.items() if key not in {"dev", "ino"}}


def compare_files(before, after, *, identities):
    require(before["schema"] == after["schema"] == SCHEMA)
    require(set(before["persistent"]) - DB_FILES == set(after["persistent"]) - DB_FILES, "file_inventory_changed")
    require(set(before["custody"]) == set(after["custody"]), "custody_inventory_changed")
    recreated = []
    for namespace in ("persistent", "custody"):
        for name, old in before[namespace].items():
            if namespace == "persistent" and name in DB_FILES:
                continue
            new = after[namespace][name]
            if not identities:
                require(content(old) == content(new), "file_content_or_ownership_changed")
            elif namespace == "persistent" and name in DERIVED:
                require({key: value for key, value in old.items() if key != "ino"}
                    == {key: value for key, value in new.items() if key != "ino"}, "derived_ca_changed")
                if old["ino"] != new["ino"]:
                    recreated.append(name)
            else:
                require(old == new, "custody_identity_changed" if namespace == "custody" else "file_identity_changed")
    if identities:
        require(all(before["persistent"][DB_MAIN][key] == after["persistent"][DB_MAIN][key]
            for key in ("kind", "dev", "ino", "uid", "gid", "mode")), "database_identity_changed")
    return recreated


def _cell(value):
    if value is None:
        return ("null", "")
    if type(value) is bytes:
        return ("blob", value.hex())
    if type(value) is float:
        return ("real", value.hex())
    require(type(value) in {str, int}, "sqlite_value_type")
    return ("text" if type(value) is str else "integer", str(value))


def rows(connection, table, *, audit=False):
    require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", table) is not None, "table_name")
    cursor = connection.execute('SELECT ' + ('rowid,*' if audit else '*') + ' FROM "' + table + '"'
        + (' ORDER BY rowid' if audit else '') + ' LIMIT ?', (MAX_ROWS + 1,))
    result = cursor.fetchall()
    require(len(result) <= MAX_ROWS, "row_bound", table)
    require(sum(sum(len(str(value)) if value is not None else 0 for value in row) for row in result) <= MAX_DB, "row_byte_bound", table)
    return [item[0] for item in cursor.description], [tuple(_cell(value) for value in row) for row in result]


def row_digest(columns, values):
    # Counter retains duplicate multiplicity; typed values distinguish 1/1.0.
    return digest([columns, sorted((canonical(row), count) for row, count in Counter(values).items())])


def compare_databases(before, after):
    schemas = []
    for connection in (before, after):
        connection.create_function("regexp", 2, lambda pattern, value: None if value is None else
            int(isinstance(value, str) and isinstance(pattern, str) and re.fullmatch(pattern, value) is not None), deterministic=True)
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        require(connection.execute("PRAGMA integrity_check").fetchall() == [("ok",)], "sqlite_integrity")
        schema = connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name LIMIT ?", (MAX_OBJECTS + 1,)).fetchall()
        require(0 < len(schema) <= MAX_OBJECTS, "schema_bound")
        schemas.append(schema)
    require(schemas[0] == schemas[1], "database_schema_changed")
    tables = sorted(row[1] for row in schemas[0] if row[0] == "table")
    require({"audit_events", "metadata_audit_outbox"} <= set(tables), "required_tables_missing")
    present = NOTIFICATIONS & set(tables)
    require(not present or present == NOTIFICATIONS, "partial_notification_schema")
    authority, migrations = {}, None
    for table in tables:
        if table == "audit_events":
            continue
        old_columns, old = rows(before, table)
        new_columns, new = rows(after, table)
        require(old_columns == new_columns, "table_columns_changed", table)
        old_hash, new_hash = row_digest(old_columns, old), row_digest(new_columns, new)
        if table == "serverware_store_migrations":
            require(old_columns == ["migration", "version", "applied_at"], "migration_columns_changed")
            require(Counter(row[:2] for row in old) == Counter(row[:2] for row in new), "migration_authority_changed")
            for row in old + new:
                require(row[2][0] == "text" and datetime.fromisoformat(row[2][1]).tzinfo is not None, "migration_timestamp_invalid")
            migrations = {"count": len(old), "timestamp_only_change": old_hash != new_hash,
                "before_sha256": old_hash, "after_sha256": new_hash}
        else:
            require(Counter(old) == Counter(new), "authority_table_changed", table)
            if table == "metadata_audit_outbox":
                require(not old, "audit_outbox_not_empty")
            authority[table] = {"count": len(old), "sha256": old_hash}
    columns, old_audit = rows(before, "audit_events", audit=True)
    after_columns, new_audit = rows(after, "audit_events", audit=True)
    require(columns == after_columns and new_audit[:len(old_audit)] == old_audit, "audit_prefix_changed")
    return {"schema_object_count": len(schemas[0]), "complete_schema_sha256": digest(schemas[0]),
        "all_non_audit_tables": authority, "notification_tables": sorted(present), "migration_timestamps": migrations,
        "prior_audit_count": len(old_audit), "current_audit_count": len(new_audit),
        "prior_audit_prefix_sha256": digest([columns, old_audit]), "database_schema_equal": True}


def private_database(root, expected, scratch):
    for name in sorted(DB_FILES & expected["persistent"].keys()):
        source, target = root / name, scratch / Path(name).name
        with os.fdopen(os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC), "rb") as incoming, target.open("xb") as outgoing:
            hashed = hashlib.sha256()
            size = 0
            while chunk := incoming.read(1024**2):
                size += len(chunk)
                require(size <= MAX_DB, "database_copy_bound")
                hashed.update(chunk)
                outgoing.write(chunk)
        require(size == expected["persistent"][name]["size"] and hashed.hexdigest() == expected["persistent"][name]["sha256"], "database_copy_changed")
    # Only scratch is writable. Private recovery precedes query_only snapshots.
    connection = sqlite3.connect(scratch / "serverware.sqlite3", timeout=2)
    connection.execute("SELECT count(*) FROM sqlite_master").fetchone()
    return connection


def load_receipt(filename):
    filename = path(filename)
    require(filename.is_file() and filename.stat().st_size <= 2 * 1024**2, "receipt_bound")
    value = json.loads(filename.read_text())
    require(isinstance(value, dict) and set(value) == {"schema", "persistent", "custody", "live_sqlite_opened"}
        and value["schema"] == SCHEMA and value["live_sqlite_opened"] is False, "receipt_contract")
    return value


def compare(before_root, after_root, before_custody, after_custody, before_inventory, after_inventory):
    roots = [path(value) for value in (before_root, after_root, before_custody, after_custody)]
    require(len(set(roots)) == 4 and all(not left.is_relative_to(right) for left in roots for right in roots if left != right))
    before, after = inventory(roots[0], roots[2]), inventory(roots[1], roots[3])
    for copied, recorded in ((before, before_inventory), (after, after_inventory)):
        require(all({name: content(info) for name, info in copied[area].items()}
            == {name: content(info) for name, info in recorded[area].items()} for area in ("persistent", "custody")), "copy_not_bound_to_inventory")
    compare_files(before, after, identities=False)
    recreated = compare_files(before_inventory, after_inventory, identities=True)
    with tempfile.TemporaryDirectory(prefix="operator-rollout-sqlite-") as temporary, ExitStack() as stack:
        scratch = Path(temporary)
        connections = []
        for index, (root, snapshot) in enumerate(((roots[0], before), (roots[1], after))):
            directory = scratch / str(index)
            directory.mkdir(mode=0o700)
            connection = private_database(root, snapshot, directory)
            stack.callback(connection.close)
            connections.append(connection)
        database = compare_databases(*connections)
    require(inventory(roots[0], roots[2]) == before and inventory(roots[1], roots[3]) == after, "source_copy_changed")
    return {"schema": "serverware.operatorRolloutComparison/v1", "ok": True, **database,
        "non_sqlite_files_and_custody_preserved": True, "custody_live_identity_preserved": True,
        "derived_ca_publication_inode_changes": recreated, "live_sqlite_opened": False,
        "whole_database_byte_equality_claimed": False, "services_stopped_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("inventory")
    capture.add_argument("--persistent-root", required=True)
    capture.add_argument("--custody-root", required=True)
    comparison = commands.add_parser("compare")
    for name in ("before-root", "after-root", "before-custody", "after-custody", "before-inventory", "after-inventory"):
        comparison.add_argument("--" + name, required=True)
    comparison.add_argument("--private-copies-acknowledged", action="store_true", required=True)
    args = parser.parse_args()
    signal.alarm(120)
    os.umask(0o077)
    if args.command == "inventory":
        result = inventory(args.persistent_root, args.custody_root)
    else:
        result = compare(args.before_root, args.after_root, args.before_custody, args.after_custody,
            load_receipt(args.before_inventory), load_receipt(args.after_inventory))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        result = {"ok": False, "error": "operator rollout observation refused"}
        if isinstance(error, SnapshotError):
            result.update(code=error.code, **({"table": error.table} if error.table else {}))
        print(json.dumps(result, sort_keys=True))
        sys.exit(1)
