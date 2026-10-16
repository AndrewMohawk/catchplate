#!/usr/bin/env python3
"""Secret-silent stopped-rollout observer; no app imports or live SQLite opens.

Root owns service stops, archives and extraction. Inventory reads only files;
compare accepts private extracted trees and recovers further disposable SQLite
copies. It neither stops services nor proves they stopped. Output contains
metadata/counts/digests only. No output or archive files are created here.

The explicit managed-unconfigured mode adds only a closed derived gate tree;
it never authorizes setup, custody creation, settings changes or schema repair.
The separate managed-X-unconfigured profile starts with that retained Google
tree and admits only its one unconfigured X manifest plus observation of an
already-created empty X custody directory. It does not initialize that directory.
Within retained managed-X-unconfigured files, --x-quota-transition separately
checks the exact additive quota initialization or its unchanged empty state.
It performs no initialization and preserves all preexisting comparison rules.
--ecr-initialization separately admits only the exact first ECR schema, one
process-owner row, empty publication/child tables and a new empty private
app-data/ecr-artifacts directory. It requires no audit append and preserves the
existing migration-timestamp-only exception; it never starts or stages a job.
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
MANAGED_X_SCHEMA = "serverware.operatorRolloutInventory/v3"
GATE_ROOT = "app-data/gate-runtime"
POLICY = "app-data/policy-bundle.json"
GATE_POLICY = GATE_ROOT + "/policy-bundle.json"
GATE_GOOGLE = GATE_ROOT + "/operator-google-configuration.json"
GATE_X = GATE_ROOT + "/operator-x-configuration.json"
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
ECR_DIRECTORY = "app-data/ecr-artifacts"
ECR_TABLES = frozenset("operator_ecr_" + name for name in ("owner", "publications", "child_ids"))
ECR_OBJECTS = ECR_TABLES | {"operator_ecr_publications_" + name for name in ("active", "page", "client_page")} | {
    "sqlite_autoindex_operator_ecr_publications_1", "sqlite_autoindex_operator_ecr_publications_2",
    "sqlite_autoindex_operator_ecr_child_ids_1"}
# Actual SQLite SQL, including retirement columns, partial/pagination indexes and
# automatic indexes. The focused test independently rejoins the owner initializer.
ECR_SCHEMA_SHA256 = "822e4c88b66dca18493a015cfcb42453c37ec66de334d7c54d6f95d4b11b8932"
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


def inventory(persistent_root, custody_root, *, managed_unconfigured=False, provider_custody_root=None,
        managed_x_unconfigured=False, x_custody_root=None):
    require(managed_unconfigured == (provider_custody_root is not None), "managed_options")
    require(managed_x_unconfigured == (x_custody_root is not None)
        and (not managed_x_unconfigured or managed_unconfigured), "managed_x_options")
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
        if managed_x_unconfigured:
            x_root = path(x_custody_root)
            require(all(not x_root.is_relative_to(other) and not other.is_relative_to(x_root)
                for other in (persistent_root, custody_root, provider_root)), "x_custody_overlap")
            x_custody = tree(x_root)
            require(set(x_custody) == {"."} and x_custody["."]["mode"] == 0o700
                and (x_custody["."]["uid"], x_custody["."]["gid"]) == owner, "x_custody_not_empty_private")
            x_identity = tuple(x_custody["."][key] for key in ("dev", "ino"))
            require(all(x_identity != tuple(info[key] for key in ("dev", "ino"))
                for area in (persistent, custody, provider) for info in area.values() if info["kind"] == "directory"),
                "x_custody_alias")
            result.update(schema=MANAGED_X_SCHEMA, x_custody=x_custody, managed_x_unconfigured=True)
        managed_gate_inventory(result, managed_x_unconfigured=managed_x_unconfigured)
    return result


def gate_members(snapshot):
    return {name for name in snapshot["persistent"] if name == GATE_ROOT or name.startswith(GATE_ROOT + "/")}


def managed_gate_inventory(snapshot, *, managed_x_unconfigured=False):
    """Closed derived inventory, never a prefix exclusion from preservation."""
    persistent = snapshot["persistent"]
    owner = tuple(persistent[DB_MAIN][key] for key in ("uid", "gid"))
    names = gate_members(snapshot)
    require(names in (GATE_MEMBERS, GATE_MEMBERS | {GATE_X}) if managed_x_unconfigured
        else not names or names == GATE_MEMBERS, "gate_inventory")
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


def _ecr_directory_addition(before, after):
    names = lambda snapshot: {name for name in snapshot["persistent"]
        if name == ECR_DIRECTORY or name.startswith(ECR_DIRECTORY + "/")}
    require(not names(before) and names(after) == {ECR_DIRECTORY}, "ecr_artifact_directory_not_fresh_empty")
    directory, database = after["persistent"][ECR_DIRECTORY], after["persistent"][DB_MAIN]
    require(directory.get("kind") == "directory" and directory.get("mode") == 0o700
        and all(directory.get(key) == database[key] for key in ("dev", "uid", "gid")), "ecr_artifact_directory_identity")
    identity = directory.get("dev"), directory.get("ino")
    require(all(identity != (info["dev"], info["ino"])
        for area in ("persistent", "custody", "provider_custody", "x_custody") if area in before
        for info in before[area].values() if info["kind"] == "directory"), "ecr_artifact_directory_alias")
    return {ECR_DIRECTORY}


def compare_files(before, after, *, identities, managed_transition=None, managed_x_unconfigured=False,
        ecr_initialization=False):
    require(managed_transition in {None, "first", "retained"}, "managed_options")
    require(not managed_x_unconfigured or managed_transition is not None, "managed_x_options")
    require(type(ecr_initialization) is bool and (not ecr_initialization
        or managed_transition != "first"), "ecr_initialization_options")
    require(before["schema"] == after["schema"] == (MANAGED_X_SCHEMA if managed_x_unconfigured
        else MANAGED_SCHEMA if managed_transition else SCHEMA))
    added = set()
    if managed_transition:
        for snapshot in (before, after):
            require(snapshot.get("managed_unconfigured") is True, "receipt_contract")
            if managed_x_unconfigured:
                require(snapshot.get("managed_x_unconfigured") is True, "receipt_contract")
            managed_gate_inventory(snapshot, managed_x_unconfigured=managed_x_unconfigured)
        retained = GATE_MEMBERS | ({GATE_X} if managed_x_unconfigured else set())
        initial = GATE_MEMBERS if managed_x_unconfigured else set()
        require(gate_members(before) == (initial if managed_transition == "first" else retained)
            and gate_members(after) == retained, "gate_transition")
        added = retained - initial if managed_transition == "first" else set()
    if ecr_initialization:
        added |= _ecr_directory_addition(before, after)
    require(((set(before["persistent"]) - DB_FILES) | added) == set(after["persistent"]) - DB_FILES, "file_inventory_changed")
    require(set(before["custody"]) == set(after["custody"]), "custody_inventory_changed")
    recreated = []
    areas = ("persistent", "custody") + (("provider_custody",) if managed_transition else ())
    for namespace in areas + (("x_custody",) if managed_x_unconfigured else ()):
        if namespace in {"provider_custody", "x_custody"}:
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


def _ecr_schema_addition(before, after):
    require(not any(value.lower().startswith("operator_ecr_") for row in before for value in row[1:3]),
        "ecr_schema_not_fresh")
    added = [row for row in after if row[1] in ECR_OBJECTS]
    require(len(added) == len(ECR_OBJECTS) and {row[1] for row in added} == ECR_OBJECTS
        and digest(added) == ECR_SCHEMA_SHA256, "ecr_initialization_schema")
    require(not any(row[1] not in ECR_OBJECTS and any(value.lower().startswith("operator_ecr_")
        for value in row[1:3]) for row in after), "ecr_initialization_schema")
    return [row for row in after if row[1] not in ECR_OBJECTS]


def _ecr_initial_state(after, prior_audit_count, current_audit_count):
    owners = after.execute("SELECT singleton,schema_version,owner_process,boot_id FROM operator_ecr_owner LIMIT 2").fetchall()
    uuid4 = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
    require(len(owners) == 1 and all(type(value) is int and value == 1 for value in owners[0][:2])
        and all(type(value) is str and re.fullmatch(uuid4, value) for value in owners[0][2:]), "ecr_initialization_owner")
    for table in sorted(ECR_TABLES - {"operator_ecr_owner"}):
        require(after.execute('SELECT 1 FROM "' + table + '" LIMIT 1').fetchone() is None,
            "ecr_initialization_not_empty", table)
    require(prior_audit_count == current_audit_count, "ecr_initialization_audit_delta")
    return {"schema_sha256": ECR_SCHEMA_SHA256, "added_schema_objects": sorted(ECR_OBJECTS),
        "owner_row_count": 1, "owner_row_sha256": digest(owners[0]),
        "empty_usage_tables": sorted(ECR_TABLES - {"operator_ecr_owner"}), "audit_append_count": 0}


def compare_databases(before, after, *, x_quota_transition=None, ecr_initialization=False):
    require(type(ecr_initialization) is bool and (not ecr_initialization
        or x_quota_transition in {None, "retained"}), "ecr_initialization_options")
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
    require(x_quota_transition in {None, "first", "retained"}, "x_quota_options")
    compared_schemas = [schemas[0], _ecr_schema_addition(*schemas) if ecr_initialization else schemas[1]]
    added_tables = ECR_TABLES if ecr_initialization else frozenset()
    if x_quota_transition:
        import operator_rollout_x_quota as quota
        added_tables |= quota.schema_transition(*compared_schemas, x_quota_transition, require)
    else:
        require(compared_schemas[0] == compared_schemas[1], "database_schema_changed")
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
    quota_result = None
    if x_quota_transition:
        quota_result = quota.initialization(before, after, x_quota_transition,
            len(old_audit), len(new_audit), require)
    ecr_result = _ecr_initial_state(after, len(old_audit), len(new_audit)) if ecr_initialization else None
    for table in sorted(added_tables):
        columns_added, values_added = rows(after, table)
        authority[table] = {"count": len(values_added), "sha256": row_digest(columns_added, values_added)}
    return {"schema_object_count": len(schemas[1]), "complete_schema_sha256": digest(schemas[1]),
        "all_non_audit_tables": authority, "notification_tables": sorted(present), "migration_timestamps": migrations,
        "prior_audit_count": len(old_audit), "current_audit_count": len(new_audit),
        "prior_audit_prefix_sha256": digest([columns, old_audit]), "database_schema_equal": schemas[0] == schemas[1],
        **({"x_quota_initialization": quota_result, "prior_complete_schema_sha256": digest(schemas[0]),
            "prior_schema_object_count": len(schemas[0]), "preexisting_schema_preserved": True}
            if quota_result is not None else {}),
        **({"ecr_initialization": ecr_result, "prior_complete_schema_sha256": digest(schemas[0]),
            "prior_schema_object_count": len(schemas[0]), "preexisting_schema_preserved": True}
            if ecr_result is not None else {})}


def managed_database_identity(connection, snapshot, *, managed_x_unconfigured=False):
    """Join public file bytes to preserved SQL, not to caller-supplied settings.

    This is a preservation check on a further disposable SQLite copy, not an
    alternate startup/profile validator. No product modules or secrets load.
    Provider custody must be empty, so even cancelled setup history is outside
    this deliberately first-configuration-only transition.
    """
    objects = connection.execute("SELECT name,tbl_name FROM sqlite_master").fetchall()
    forbidden = ("operator_google_", "operator_provider_custody", "operator_catalog_oauth_")
    if managed_x_unconfigured:
        forbidden += ("operator_x_configuration", "operator_x_provider_custody", "operator_x_account_")
    require(not any(value.lower().startswith(forbidden) for row in objects for value in row), "managed_state_present")
    tables = {row[0] for row in objects}
    if managed_x_unconfigured:
        require(connection.execute("SELECT 1 FROM audit_events WHERE lower(event_type) GLOB 'operator_catalog.x_oauth.*' "
            "OR lower(id) GLOB 'operator-x-configuration:*' LIMIT 1").fetchone() is None, "managed_x_history_present")
        for table, column in (("credentials", "metadata"), ("operator_catalog_credentials", "data_json"),
                ("operator_demo_connections", "metadata_json")):
            if table not in tables:
                continue
            records = connection.execute('SELECT "' + column + '" FROM "' + table + '" LIMIT ?', (MAX_ROWS + 1,)).fetchall()
            require(len(records) <= MAX_ROWS, "row_bound", table)
            for (raw,) in records:
                require(type(raw) is str and len(raw.encode("utf-8")) <= MAX_FILE, "credential_metadata")
                value = json.loads(raw)
                require(type(value) is dict and value.get("auth_type") != "x_oauth"
                    and value.get("connection_type") != "x_user_oauth_v1" and "operator_x_account" not in value,
                    "managed_x_history_present")
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
        and type(settings["allowed_upstreams"]) is list and 1 <= len(settings["allowed_upstreams"]) <= 32
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
    result = {"effective_settings_digest": expected["effective_settings_digest"],
        "policy_file_sha256": policy_sha, "google_public_sha256": public_sha}
    if managed_x_unconfigured:
        x_bytes = canonical({**expected, "schema": "serverware.operatorXGateConfiguration/v1"}).encode("ascii")
        x_sha = hashlib.sha256(x_bytes).hexdigest()
        if GATE_X in gate_members(snapshot):
            public = snapshot["persistent"][GATE_X]
            require(public["size"] == len(x_bytes) and public["sha256"] == x_sha, "managed_x_public_not_authoritative")
        result["x_public_sha256"] = x_sha
    return result


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


def load_receipt(filename, *, managed_unconfigured=False, managed_x_unconfigured=False):
    require(not managed_x_unconfigured or managed_unconfigured, "managed_x_options")
    filename = path(filename)
    require(filename.is_file() and filename.stat().st_size <= 2 * 1024**2, "receipt_bound")
    value = json.loads(filename.read_text())
    fields = {"schema", "persistent", "custody", "live_sqlite_opened"}
    if managed_unconfigured:
        fields |= {"provider_custody", "managed_unconfigured"}
    if managed_x_unconfigured:
        fields |= {"x_custody", "managed_x_unconfigured"}
    require(isinstance(value, dict) and set(value) == fields
        and value["schema"] == (MANAGED_X_SCHEMA if managed_x_unconfigured else MANAGED_SCHEMA if managed_unconfigured else SCHEMA)
        and value["live_sqlite_opened"] is False
        and (not managed_unconfigured or value["managed_unconfigured"] is True)
        and (not managed_x_unconfigured or value["managed_x_unconfigured"] is True), "receipt_contract")
    return value


def compare(before_root, after_root, before_custody, after_custody, before_inventory, after_inventory,
        *, managed_transition=None, before_provider_custody=None, after_provider_custody=None,
        managed_x_unconfigured=False, before_x_custody=None, after_x_custody=None,
        x_quota_transition=None, ecr_initialization=False):
    require(type(ecr_initialization) is bool and (not ecr_initialization
        or managed_transition != "first" and x_quota_transition in {None, "retained"}), "ecr_initialization_options")
    require(x_quota_transition in {None, "first", "retained"}
        and (x_quota_transition is None or (managed_x_unconfigured and managed_transition == "retained")),
        "x_quota_options")
    require(managed_transition in {None, "first", "retained"}, "managed_options")
    require((before_provider_custody is not None) == (after_provider_custody is not None) == bool(managed_transition), "managed_options")
    require((before_x_custody is not None) == (after_x_custody is not None) == managed_x_unconfigured
        and (not managed_x_unconfigured or managed_transition is not None), "managed_x_options")
    roots = [path(value) for value in (before_root, after_root, before_custody, after_custody)]
    if managed_transition:
        roots += [path(before_provider_custody), path(after_provider_custody)]
    if managed_x_unconfigured:
        roots += [path(before_x_custody), path(after_x_custody)]
    require(len(set(roots)) == len(roots) and all(not left.is_relative_to(right) for left in roots for right in roots if left != right))
    options = [{"managed_unconfigured": True, "provider_custody_root": roots[index + 4]} if managed_transition else {}
        for index in range(2)]
    if managed_x_unconfigured:
        for index in range(2):
            options[index].update(managed_x_unconfigured=True, x_custody_root=roots[index + 6])
    before, after = inventory(roots[0], roots[2], **options[0]), inventory(roots[1], roots[3], **options[1])
    areas = ("persistent", "custody", "provider_custody") if managed_transition else ("persistent", "custody")
    if managed_x_unconfigured:
        areas += ("x_custody",)
    for copied, recorded in ((before, before_inventory), (after, after_inventory)):
        require(all({name: content(info) for name, info in copied[area].items()}
            == {name: content(info) for name, info in recorded[area].items()} for area in areas), "copy_not_bound_to_inventory")
    compare_files(before, after, identities=False, managed_transition=managed_transition,
        managed_x_unconfigured=managed_x_unconfigured, ecr_initialization=ecr_initialization)
    recreated = compare_files(before_inventory, after_inventory, identities=True, managed_transition=managed_transition,
        managed_x_unconfigured=managed_x_unconfigured, ecr_initialization=ecr_initialization)
    with tempfile.TemporaryDirectory(prefix="operator-rollout-sqlite-") as temporary, ExitStack() as stack:
        scratch = Path(temporary)
        connections = []
        for index, (root, snapshot) in enumerate(((roots[0], before), (roots[1], after))):
            directory = scratch / str(index)
            directory.mkdir(mode=0o700)
            connection = private_database(root, snapshot, directory)
            stack.callback(connection.close)
            connections.append(connection)
        database = compare_databases(*connections, x_quota_transition=x_quota_transition,
            ecr_initialization=ecr_initialization)
        managed = None
        if managed_transition:
            managed = managed_database_identity(connections[0], before, managed_x_unconfigured=managed_x_unconfigured)
            require(managed_database_identity(connections[1], after, managed_x_unconfigured=managed_x_unconfigured)
                == managed, "managed_identity_changed")
    require(inventory(roots[0], roots[2], **options[0]) == before
        and inventory(roots[1], roots[3], **options[1]) == after, "source_copy_changed")
    result = {"schema": "serverware.operatorRolloutComparison/v1", "ok": True, **database,
        "non_sqlite_files_and_custody_preserved": True, "custody_live_identity_preserved": True,
        "derived_ca_publication_inode_changes": recreated, "live_sqlite_opened": False,
        "whole_database_byte_equality_claimed": False, "services_stopped_verified": False}
    if managed_transition:
        result.update(schema="serverware.operatorRolloutComparison/v2", managed_transition=managed_transition,
            managed_unconfigured=managed, derived_gate_files_added=sorted({GATE_X} if managed_x_unconfigured else GATE_MEMBERS)
                if managed_transition == "first" else [],
            provider_custody_empty=True, provider_custody_live_identity_preserved=True)
    if managed_x_unconfigured:
        result.update(schema="serverware.operatorRolloutComparison/v3", managed_x_unconfigured=True,
            x_custody_empty=True, x_custody_live_identity_preserved=True)
    if x_quota_transition:
        result["schema"] = "serverware.operatorRolloutComparison/v4"
    if ecr_initialization:
        result.update(schema="serverware.operatorRolloutComparison/v5", ecr_artifact_directory_added=ECR_DIRECTORY)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    capture = commands.add_parser("inventory")
    capture.add_argument("--persistent-root", required=True)
    capture.add_argument("--custody-root", required=True)
    capture.add_argument("--managed-unconfigured", action="store_true")
    capture.add_argument("--provider-custody-root")
    capture.add_argument("--managed-x-unconfigured", action="store_true")
    capture.add_argument("--x-custody-root")
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
    comparison.add_argument("--managed-x-unconfigured", action="store_true")
    comparison.add_argument("--before-x-custody")
    comparison.add_argument("--after-x-custody")
    comparison.add_argument("--x-quota-transition", choices=("first", "retained"),
        help="Exact quota initialization only with retained managed-X-unconfigured files. "
            "Existing migration timestamp exception still needs the caller's separately bounded check.")
    comparison.add_argument("--ecr-initialization", action="store_true",
        help="Exact first ECR schema and empty private artifact directory only; no audit append or staged publication.")
    args = parser.parse_args()
    signal.alarm(120)
    os.umask(0o077)
    if args.command == "inventory":
        require(not args.managed_unconfigured or args.private_copies_acknowledged
            or args.stopped_files_acknowledged, "private_copies_required")
        result = inventory(args.persistent_root, args.custody_root, managed_unconfigured=args.managed_unconfigured,
            provider_custody_root=args.provider_custody_root, managed_x_unconfigured=args.managed_x_unconfigured,
            x_custody_root=args.x_custody_root)
    else:
        require(args.managed_unconfigured == (args.managed_transition is not None), "managed_options")
        result = compare(args.before_root, args.after_root, args.before_custody, args.after_custody,
            load_receipt(args.before_inventory, managed_unconfigured=args.managed_unconfigured,
                managed_x_unconfigured=args.managed_x_unconfigured),
            load_receipt(args.after_inventory, managed_unconfigured=args.managed_unconfigured,
                managed_x_unconfigured=args.managed_x_unconfigured),
            managed_transition=args.managed_transition, before_provider_custody=args.before_provider_custody,
            after_provider_custody=args.after_provider_custody, managed_x_unconfigured=args.managed_x_unconfigured,
            before_x_custody=args.before_x_custody, after_x_custody=args.after_x_custody,
            x_quota_transition=args.x_quota_transition, ecr_initialization=args.ecr_initialization)
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
