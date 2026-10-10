#!/usr/bin/env python3
"""Secret-silent stopped-rollout observer; no app imports or live SQLite opens.

Root owns service stops, archives and extraction. Inventory reads only files;
compare accepts private extracted trees and recovers further disposable SQLite
copies. It neither stops services nor proves they stopped. Output contains
metadata/counts/digests only. No output or archive files are created here.

The explicit managed-unconfigured mode adds only a closed derived gate tree;
it never authorizes setup, custody creation, settings changes or schema repair.
Inventory requires an explicit private-copy or stopped-files acknowledgement.
The latter records the caller's prerequisite, not proof from this tool: root
must separately verify that the relevant services are stopped before capturing
original file identities. Inventory never opens SQLite; comparison still accepts
only acknowledged private copies and opens further disposable copies.
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
MANAGED_SCHEMA = "serverware.operatorRolloutInventory/v2"
GATE_ROOT = "app-data/gate-runtime"
POLICY = "app-data/policy-bundle.json"
GATE_POLICY = GATE_ROOT + "/policy-bundle.json"
GATE_GOOGLE = GATE_ROOT + "/operator-google-configuration.json"
GATE_DIRECTORIES = frozenset((GATE_ROOT, GATE_ROOT + "/mitmproxy"))
GATE_PLACEHOLDERS = frozenset(GATE_ROOT + "/" + name for name in (
    ".operator-publication.lock", ".serverware-operator-demo.json",
    "mitmproxy/mitmproxy-ca-cert.pem", "mitmproxy/mitmproxy-ca.pem"))
GATE_MEMBERS = GATE_DIRECTORIES | GATE_PLACEHOLDERS | {GATE_POLICY, GATE_GOOGLE}
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
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


def tree(root, *, empty_placeholders=frozenset()):
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
                if relative in empty_placeholders:
                    # A regular, single-link file of size zero has no bytes to
                    # read. Do not chmod/open the deliberately inaccessible 000
                    # mountpoints. This exception is opt-in and exact-path only.
                    require(info["mode"] == 0 and info["size"] == 0, "gate_placeholder")
                    require(metadata(current) == (info, stamps), "file_changed_during_read")
                    info["sha256"] = EMPTY_SHA256
                    result[relative] = info
                    continue
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


def inventory(persistent_root, custody_root, *, managed_unconfigured=False, provider_custody_root=None):
    require(managed_unconfigured == (provider_custody_root is not None), "managed_options")
    persistent_root, custody_root = path(persistent_root), path(custody_root)
    require(not persistent_root.is_relative_to(custody_root) and not custody_root.is_relative_to(persistent_root))
    persistent = tree(persistent_root, empty_placeholders=GATE_PLACEHOLDERS if managed_unconfigured else frozenset())
    custody = tree(custody_root)
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
    result = {"schema": SCHEMA, "persistent": persistent, "custody": custody, "live_sqlite_opened": False}
    if managed_unconfigured:
        provider_root = path(provider_custody_root)
        require(all(not provider_root.is_relative_to(other) and not other.is_relative_to(provider_root)
            for other in (persistent_root, custody_root)), "provider_custody_overlap")
        provider = tree(provider_root)
        require(set(provider) == {"."} and provider["."]["mode"] == 0o700
            and (provider["."]["uid"], provider["."]["gid"]) == owner, "provider_custody_not_empty_private")
        provider_identity = tuple(provider["."][key] for key in ("dev", "ino"))
        require(all(provider_identity != tuple(info[key] for key in ("dev", "ino"))
            for area in (persistent, custody) for info in area.values() if info["kind"] == "directory"),
            "provider_custody_alias")
        require(persistent["."]["mode"] == custody["."]["mode"] == 0o700
            and persistent.get("app-data", {}).get("mode") == 0o700, "private_copies_required")
        result.update(schema=MANAGED_SCHEMA, provider_custody=provider, managed_unconfigured=True)
        managed_gate_inventory(result)
    return result


def gate_members(snapshot):
    return {name for name in snapshot["persistent"] if name == GATE_ROOT or name.startswith(GATE_ROOT + "/")}


def managed_gate_inventory(snapshot):
    """Closed derived inventory, never a prefix exclusion from preservation."""
    persistent = snapshot["persistent"]
    owner = tuple(persistent[DB_MAIN][key] for key in ("uid", "gid"))
    names = gate_members(snapshot)
    require(not names or names == GATE_MEMBERS, "gate_inventory")
    for name in {POLICY} | names:
        info = persistent.get(name, {})
        directory, placeholder = name in GATE_DIRECTORIES, name in GATE_PLACEHOLDERS
        require(info.get("kind") == ("directory" if directory else "file")
            and info.get("mode") == (0o700 if directory else 0 if placeholder else 0o600)
            and (info.get("uid"), info.get("gid")) == owner, "gate_file_identity")
        if placeholder:
            require(info.get("size") == 0 and info.get("sha256") == EMPTY_SHA256, "gate_placeholder")
    if names:
        require(all(persistent[GATE_POLICY][key] == persistent[POLICY][key] for key in ("size", "sha256")), "gate_policy_changed")


def content(info):
    return {key: value for key, value in info.items() if key not in {"dev", "ino"}}


def compare_files(before, after, *, identities, managed_transition=None):
    require(managed_transition in {None, "first", "retained"}, "managed_options")
    require(before["schema"] == after["schema"] == (MANAGED_SCHEMA if managed_transition else SCHEMA))
    added = set()
    if managed_transition:
        for snapshot in (before, after):
            require(snapshot.get("managed_unconfigured") is True, "receipt_contract")
            managed_gate_inventory(snapshot)
        require(gate_members(before) == (set() if managed_transition == "first" else GATE_MEMBERS)
            and gate_members(after) == GATE_MEMBERS, "gate_transition")
        added = GATE_MEMBERS if managed_transition == "first" else set()
    require(((set(before["persistent"]) - DB_FILES) | added) == set(after["persistent"]) - DB_FILES, "file_inventory_changed")
    require(set(before["custody"]) == set(after["custody"]), "custody_inventory_changed")
    recreated = []
    for namespace in (("persistent", "custody", "provider_custody") if managed_transition else ("persistent", "custody")):
        if namespace == "provider_custody":
            require(set(before[namespace]) == set(after[namespace]) == {"."}, "provider_custody_not_empty_private")
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


def managed_database_identity(connection, snapshot):
    """Join public file bytes to preserved SQL, not to caller-supplied settings.

    This is a preservation check on a further disposable SQLite copy, not an
    alternate startup/profile validator. No product modules or secrets load.
    Provider custody must be empty, so even cancelled setup history is outside
    this deliberately first-configuration-only transition.
    """
    objects = connection.execute("SELECT name,tbl_name FROM sqlite_master").fetchall()
    forbidden = ("operator_google_", "operator_provider_custody", "operator_catalog_oauth_")
    require(not any(value.lower().startswith(forbidden) for row in objects for value in row), "managed_state_present")
    tables = {row[0] for row in objects}
    for table, column in (("operator_catalog_credentials", "data_json"), ("operator_demo_connections", "metadata_json")):
        if table in tables:
            for (raw,) in connection.execute('SELECT "' + column + '" FROM "' + table + '" LIMIT ?', (MAX_ROWS + 1,)):
                require(type(raw) is str and len(raw.encode("utf-8")) <= MAX_FILE, "credential_metadata")
                value = json.loads(raw)
                require(type(value) is dict and value.get("auth_type") != "google_oauth", "managed_state_present")
    settings_rows = connection.execute("SELECT singleton,settings_json FROM operator_demo_settings LIMIT 2").fetchall()
    require(len(settings_rows) == 1 and type(settings_rows[0][0]) is int and settings_rows[0][0] == 1, "managed_settings")
    raw = settings_rows[0][1]
    require(type(raw) is str and len(raw.encode("utf-8")) <= 16384, "managed_settings")
    settings = json.loads(raw)
    require(type(settings) is dict and set(settings) == {"allowed_upstreams", "fixture_cidrs"}
        and type(settings["allowed_upstreams"]) is list and 1 <= len(settings["allowed_upstreams"]) <= 16
        and all(type(item) is str and 1 <= len(item) <= 2048 for item in settings["allowed_upstreams"])
        and len(set(settings["allowed_upstreams"])) == len(settings["allowed_upstreams"])
        and type(settings["fixture_cidrs"]) is list and len(settings["fixture_cidrs"]) <= 16
        and all(type(item) is str and 1 <= len(item) <= 128 for item in settings["fixture_cidrs"])
        and raw == json.dumps(settings, sort_keys=True), "managed_settings")
    policy = connection.execute("SELECT singleton,signed_bundle_json FROM operator_demo_policy LIMIT 2").fetchall()
    require(len(policy) == 1 and type(policy[0][0]) is int and policy[0][0] == 1
        and type(policy[0][1]) is str and 0 < len(policy[0][1].encode("utf-8")) <= MAX_FILE, "managed_policy")
    policy_bytes = policy[0][1].encode("utf-8")
    policy_sha = hashlib.sha256(policy_bytes).hexdigest()
    require(snapshot["persistent"][POLICY]["size"] == len(policy_bytes)
        and snapshot["persistent"][POLICY]["sha256"] == policy_sha, "policy_not_authoritative")
    expected = {"schema": "serverware.operatorGoogleGateConfiguration/v1", "operation": None,
        "profile_binding": None, "profile_binding_digest": None, "effective_settings": settings,
        "effective_settings_digest": "sha256:" + digest(settings)}
    public_bytes = canonical(expected).encode("ascii")
    require(len(public_bytes) <= 32768, "managed_public_bound")
    public_sha = hashlib.sha256(public_bytes).hexdigest()
    if gate_members(snapshot):
        # Exact canonical bytes also reject extra/duplicate fields and any
        # non-null operation/profile, without echoing or parsing file contents.
        public = snapshot["persistent"][GATE_GOOGLE]
        require(public["size"] == len(public_bytes) and public["sha256"] == public_sha, "managed_public_not_authoritative")
    return {"effective_settings_digest": expected["effective_settings_digest"],
        "policy_file_sha256": policy_sha, "google_public_sha256": public_sha}


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


def load_receipt(filename, *, managed_unconfigured=False):
    filename = path(filename)
    require(filename.is_file() and filename.stat().st_size <= 2 * 1024**2, "receipt_bound")
    value = json.loads(filename.read_text())
    fields = {"schema", "persistent", "custody", "live_sqlite_opened"}
    if managed_unconfigured:
        fields |= {"provider_custody", "managed_unconfigured"}
    require(isinstance(value, dict) and set(value) == fields
        and value["schema"] == (MANAGED_SCHEMA if managed_unconfigured else SCHEMA)
        and value["live_sqlite_opened"] is False
        and (not managed_unconfigured or value["managed_unconfigured"] is True), "receipt_contract")
    return value


def compare(before_root, after_root, before_custody, after_custody, before_inventory, after_inventory,
        *, managed_transition=None, before_provider_custody=None, after_provider_custody=None):
    require(managed_transition in {None, "first", "retained"}, "managed_options")
    require((before_provider_custody is not None) == (after_provider_custody is not None) == bool(managed_transition), "managed_options")
    roots = [path(value) for value in (before_root, after_root, before_custody, after_custody)]
    if managed_transition:
        roots += [path(before_provider_custody), path(after_provider_custody)]
    require(len(set(roots)) == len(roots) and all(not left.is_relative_to(right) for left in roots for right in roots if left != right))
    options = [{"managed_unconfigured": True, "provider_custody_root": roots[index + 4]} if managed_transition else {}
        for index in range(2)]
    before, after = inventory(roots[0], roots[2], **options[0]), inventory(roots[1], roots[3], **options[1])
    areas = ("persistent", "custody", "provider_custody") if managed_transition else ("persistent", "custody")
    for copied, recorded in ((before, before_inventory), (after, after_inventory)):
        require(all({name: content(info) for name, info in copied[area].items()}
            == {name: content(info) for name, info in recorded[area].items()} for area in areas), "copy_not_bound_to_inventory")
    compare_files(before, after, identities=False, managed_transition=managed_transition)
    recreated = compare_files(before_inventory, after_inventory, identities=True, managed_transition=managed_transition)
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
        managed = None
        if managed_transition:
            managed = managed_database_identity(connections[0], before)
            require(managed_database_identity(connections[1], after) == managed, "managed_identity_changed")
    require(inventory(roots[0], roots[2], **options[0]) == before
        and inventory(roots[1], roots[3], **options[1]) == after, "source_copy_changed")
    result = {"schema": "serverware.operatorRolloutComparison/v1", "ok": True, **database,
        "non_sqlite_files_and_custody_preserved": True, "custody_live_identity_preserved": True,
        "derived_ca_publication_inode_changes": recreated, "live_sqlite_opened": False,
        "whole_database_byte_equality_claimed": False, "services_stopped_verified": False}
    if managed_transition:
        result.update(schema="serverware.operatorRolloutComparison/v2", managed_transition=managed_transition,
            managed_unconfigured=managed, derived_gate_files_added=sorted(GATE_MEMBERS) if managed_transition == "first" else [],
            provider_custody_empty=True, provider_custody_live_identity_preserved=True)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("inventory")
    capture.add_argument("--persistent-root", required=True)
    capture.add_argument("--custody-root", required=True)
    capture.add_argument("--managed-unconfigured", action="store_true")
    capture.add_argument("--provider-custody-root")
    capture_source = capture.add_mutually_exclusive_group()
    capture_source.add_argument("--private-copies-acknowledged", action="store_true",
        help="Inventory private copies; files are read without opening SQLite.")
    capture_source.add_argument("--stopped-files-acknowledged", action="store_true",
        help="Inventory original files after root separately confirms services stopped; "
            "this tool does not prove termination and never opens SQLite during inventory.")
    comparison = commands.add_parser("compare")
    for name in ("before-root", "after-root", "before-custody", "after-custody", "before-inventory", "after-inventory"):
        comparison.add_argument("--" + name, required=True)
    comparison.add_argument("--private-copies-acknowledged", action="store_true", required=True)
    comparison.add_argument("--managed-unconfigured", action="store_true")
    comparison.add_argument("--managed-transition", choices=("first", "retained"))
    comparison.add_argument("--before-provider-custody")
    comparison.add_argument("--after-provider-custody")
    args = parser.parse_args()
    signal.alarm(120)
    os.umask(0o077)
    if args.command == "inventory":
        require(not args.managed_unconfigured or args.private_copies_acknowledged
            or args.stopped_files_acknowledged, "private_copies_required")
        result = inventory(args.persistent_root, args.custody_root, managed_unconfigured=args.managed_unconfigured,
            provider_custody_root=args.provider_custody_root)
    else:
        require(args.managed_unconfigured == (args.managed_transition is not None), "managed_options")
        result = compare(args.before_root, args.after_root, args.before_custody, args.after_custody,
            load_receipt(args.before_inventory, managed_unconfigured=args.managed_unconfigured),
            load_receipt(args.after_inventory, managed_unconfigured=args.managed_unconfigured),
            managed_transition=args.managed_transition, before_provider_custody=args.before_provider_custody,
            after_provider_custody=args.after_provider_custody)
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
