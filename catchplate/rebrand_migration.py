"""Offline, copy-only migration of the bounded ordinary Serverware store.

This is not a runtime compatibility layer. The source is never initialized or
modified; only an empty destination is admitted. Historical audit/operation bytes
stay historical, while current ciphertext and signed policy become Catchplate.
No provider transport is used. Run in a fresh process, on a stopped private copy.
"""
from __future__ import annotations

import base64
from contextlib import closing, contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
import uuid

SCHEMA = "catchplate.ordinaryRebrandMigration/v1"
OLD_MARKER = b'{"schema": "serverware.operatorDemo/v1", "syntheticOnly": false}\n'
NEW_MARKER = b'{"schema": "catchplate.operatorDemo/v1", "syntheticOnly": false}\n'
MAX_TABLES = 256
MAX_ROWS = 100_000
MAX_DATABASE_BYTES = 256 * 1024 * 1024
TABLES = (
    "audit_events", "credential_generations", "credentials", "credential_lease_replay_state",
    "operator_demo_settings", "operator_demo_connections", "operator_demo_revocations",
    "operator_demo_nonces", "operator_demo_policy", "operator_catalog_state",
    "operator_catalog_credentials", "operator_catalog_applications", "operator_catalog_rules",
    "operator_upstream_setups", "operator_ecr_owner", "operator_x_quota_state",
)
PROVENANCE = ("policy_authority_schema_contracts", "serverware_store_migrations")
KEY_FILES = (
    "master.key", "policy-signing-ed25519.pem", "policy-signing-ed25519.pub.pem",
    "response-signing-ed25519.pem", "dev-tee-quote-ed25519.pem",
    "decision-gate-ca-cert.pem", "decision-gate-ca-key.pem",
)
CA_FILES = ("mitmproxy-ca.pem", "mitmproxy-ca-cert.pem", "mitmproxy-ca-cert.cer",
    "mitmproxy-ca-cert.p12", "mitmproxy-ca.p12", "mitmproxy-dhparam.pem")


class MigrationError(RuntimeError):
    """Fixed public diagnostic; never include row values or crypto exceptions."""


def _need(condition, message="Ordinary migration validation failed; source was not changed."):
    if not condition:
        raise MigrationError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value: bytes):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _path(value: Path):
    value = Path(value)
    _need(value.is_absolute() and value != Path("/") and ".." not in value.parts)
    current = Path("/")
    for part in value.parts[1:]:
        current /= part
        info = current.lstat()
        _need(not stat.S_ISLNK(info.st_mode))
    return value


def _directory(value: Path, *, empty=False):
    value = _path(value)
    info = value.stat()
    _need(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "Migration directories must be owned private directories without symlinks.")
    if empty:
        _need(next(value.iterdir(), None) is None, "Migration destination must be empty; existing state was not changed.")
    return value


def _read(path: Path, *, limit=1024 * 1024, private=True):
    _path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        _need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid()
            and 0 <= before.st_size <= limit and not before.st_mode & (0o077 if private else 0o022))
        value = os.read(fd, limit + 1)
        after = os.fstat(fd)
        _need(len(value) == before.st_size and (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns))
        return value
    finally:
        os.close(fd)


def _write(path: Path, value: bytes, *, mode=0o600):
    _need(mode in {0o600, 0o644})
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(value)
            stream.flush()
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def _table(name):
    _need(type(name) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name))
    return '"' + name + '"'


def inventory(conn):
    _need(conn.in_transaction and conn.execute("PRAGMA query_only").fetchone()[0] == 1)
    names = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT ?",
        (MAX_TABLES + 1,))]
    _need(len(names) <= MAX_TABLES)
    counts = {name: conn.execute("SELECT COUNT(*) FROM " + _table(name)).fetchone()[0] for name in names}
    _need(sum(counts.values()) <= MAX_ROWS)
    _need(all(not count or name in TABLES or name in PROVENANCE for name, count in counts.items()),
        "Unsupported populated state exists; provider, approval, notification and native history are not migrated by this command.")
    _need(all(counts.get(name) == 1 for name in ("operator_demo_policy", "operator_demo_settings", "operator_catalog_state")))
    if counts.get("operator_upstream_setups"):
        _need(conn.execute("SELECT 1 FROM operator_upstream_setups WHERE status!='activated' LIMIT 1").fetchone() is None,
            "Only completed destination history is supported; pending or cancelled operations require separate review.")
    for row in conn.execute("SELECT kind,lifecycle_status,encrypted_secret,metadata FROM credentials"):
        metadata = json.loads(row[3])
        _need(row[0] in {"bearer", "header"} and tuple(row[1:3]) == ("active", "envelope:v2"))
        _need(type(metadata) is dict and not any(key in metadata for key in
            ("oauth", "github_app", "operator_x_account", "connection_type")),
            "This migration supports ordinary static envelopes only; dedicated provider credentials require their own migration.")
    return counts


def verify_audit(conn):
    from .db_common import audit_hash
    previous = None
    total = 0
    for row in conn.execute("SELECT * FROM audit_events ORDER BY rowid"):
        item = dict(row)
        _need(item["prev_event_hash"] == previous)
        actual = audit_hash(event_id=item["id"], **{key: item[key] for key in
            ("event_type", "actor_type", "actor_id", "event_json", "prev_event_hash", "created_at")})
        _need(actual == item["event_hash"], "Historical audit chain verification failed; migration refused.")
        # Ordinary clear audit storage only; encrypted/native formats are separate.
        _need(not item.get("encrypted_canonical_event_json"))
        previous = actual
        total += 1
    return {"count": total, "head": previous}


def rewrap_credential(row, master_key: bytes):
    """Authenticate old exact AAD; emit new ciphertext with unchanged semantics."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from . import crypto
    value = dict(row)
    _need(len(master_key) == 32 and value["encrypted_secret"] == "envelope:v2")
    try:
        dek_version, dek_nonce, dek_cipher = value["encrypted_dek"].split(":")
        nonce_version, nonce = value["secret_nonce"].split(":")
        cipher_version, cipher = value["secret_ciphertext"].split(":")
        _need(dek_version == nonce_version == cipher_version == "v1")
        decode = lambda item: base64.urlsafe_b64decode(item + "=" * (-len(item) % 4))
        binding = f'{value["id"]}:v{value["credential_version"]}'
        dek = AESGCM(master_key).decrypt(decode(dek_nonce), decode(dek_cipher), ("serverware:dek:" + binding).encode())
        plaintext = AESGCM(dek).decrypt(decode(nonce), decode(cipher), ("serverware:secret:" + binding).encode()).decode("utf-8")
        encrypted = crypto.encrypt_secret_envelope(plaintext, credential_id=value["id"], credential_version=value["credential_version"])
        value.update(encrypted)
        _need(crypto.decrypt_secret_envelope(value) == plaintext)
        return value
    except Exception:
        raise MigrationError("A retained credential could not be authenticated and rewrapped; migration refused.") from None


def migrate_rule(record):
    """Only typed generated placeholders are protocol; user strings are opaque."""
    result = dict(record)
    data = json.loads(result["data_json"])
    if "app_preset" in data or "operation_bundle" in data:
        from . import operator_common_apps
        from . import operator_catalog_github, operator_catalog_npm, operator_catalog_x, operator_catalog_alchemy
        values = {app["placeholder"] for app in operator_common_apps.presets()}
        values.update(module.PLACEHOLDER for module in
            (operator_catalog_github, operator_catalog_npm, operator_catalog_x, operator_catalog_alchemy))
        values.update(("Bearer catchplate-gmail-placeholder-v1", "Bearer catchplate-x-post-placeholder-v1"))
        replacements = {value.replace("catchplate-", "serverware-", 1): value for value in values}
        if data.get("placeholder") in replacements:
            data["placeholder"] = replacements[data["placeholder"]]
            result["data_json"] = canonical(data)
    return result


def _copy_rows(source, target, table, *, master_key):
    columns = [row[1] for row in source.execute("PRAGMA table_info(" + _table(table) + ")")]
    _need(columns == [row[1] for row in target.execute("PRAGMA table_info(" + _table(table) + ")")],
        "A supported table changed shape; migration refused.")
    without_rowid = "WITHOUT ROWID" in source.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()[0].upper()
    selected = columns if without_rowid else ["rowid", *columns]
    rows = source.execute("SELECT " + ",".join(_table(name) for name in selected) + " FROM " + _table(table)
        + ("" if without_rowid else " ORDER BY rowid"))
    for original in rows:
        value = dict(zip(selected, original))
        if table == "credentials":
            value = rewrap_credential(value, master_key)
        elif table == "operator_catalog_rules":
            value = migrate_rule(value)
        target.execute("INSERT INTO " + _table(table) + " (" + ",".join(_table(name) for name in selected)
            + ") VALUES(" + ",".join("?" for _ in selected) + ")", [value[name] for name in selected])


def _configure(target: Path, settings, public_url, proxy_url):
    _need("catchplate.config" not in sys.modules, "Migration requires a fresh process before application configuration is imported.")
    _need(not any(name.startswith(("CATCHPLATE_", "SERVERWARE_")) for name in os.environ),
        "Run migration without inherited application configuration; use explicit public origin arguments.")
    from .operator_demo import origin
    _need(origin(public_url)[0] == public_url and origin(proxy_url)[0] == proxy_url and public_url != proxy_url)
    os.environ.update({"CATCHPLATE_OPERATOR_DEMO": "1", "CATCHPLATE_RELEASE_CHANNEL": "dev",
        "CATCHPLATE_PROCESS_MODE": "catchplate-control-plane", "CATCHPLATE_DATA_DIR": str(target),
        "CATCHPLATE_METADATA_STORE_BACKEND": "sqlite", "CATCHPLATE_AUDIT_STORE_BACKEND": "sqlite",
        "CATCHPLATE_GRANT_STORE_BACKEND": "sqlite", "CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
        "CATCHPLATE_KEY_RELEASE_REQUIRED": "0", "CATCHPLATE_DEV_AUTHENTICATOR": "0", "CATCHPLATE_DEV_DEMO_SEED": "0",
        "CATCHPLATE_PUBLIC_URL": public_url, "CATCHPLATE_OPERATOR_DEMO_PROXY_URL": proxy_url,
        "CATCHPLATE_OPERATOR_DEMO_UPSTREAMS": json.dumps(settings["allowed_upstreams"]),
        "CATCHPLATE_OPERATOR_DEMO_FIXTURE_CIDRS": json.dumps(settings["fixture_cidrs"])})


def _prepare_files(source, target, *, ca_mode, replacement_ca):
    copied = {}
    for name in KEY_FILES:
        path = source / name
        if path.exists():
            public = name.endswith((".pub.pem", "-cert.pem"))
            raw = _read(path, private=not public)
            _write(target / name, raw, mode=0o644 if public else 0o600)
            copied[name] = digest(raw)
    _need(all(name in copied for name in ("master.key", "policy-signing-ed25519.pem", "policy-signing-ed25519.pub.pem")))
    ca_source = source / "mitmproxy" if ca_mode == "preserve" else _directory(replacement_ca)
    (target / "mitmproxy").mkdir(mode=0o700)
    _need(ca_source.is_dir())
    for name in CA_FILES:
        if (ca_source / name).exists():
            public = name in {"mitmproxy-ca-cert.pem", "mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.p12", "mitmproxy-dhparam.pem"}
            raw = _read(ca_source / name, private=not public)
            _write(target / "mitmproxy" / name, raw, mode=0o644 if public else 0o600)
            copied["mitmproxy/" + name] = digest(raw)
    _need(all("mitmproxy/" + name in copied for name in ("mitmproxy-ca.pem", "mitmproxy-ca-cert.pem")),
        "The selected CA pair is incomplete; migration refused.")
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_private_key((target / "mitmproxy/mitmproxy-ca.pem").read_bytes(), password=None)
    cert = x509.load_pem_x509_certificate((target / "mitmproxy/mitmproxy-ca-cert.pem").read_bytes())
    spki = lambda value: value.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    _need(spki(key.public_key()) == spki(cert.public_key()))
    _write(target / ".catchplate-operator-demo.json", NEW_MARKER)
    return copied


@contextmanager
def source_snapshot(source: Path):
    _need(_read(source / ".serverware-operator-demo.json") == OLD_MARKER,
        "Only the ordinary Serverware operator marker is supported.")
    dbpath = source / "serverware.sqlite3"
    _path(dbpath)
    info = dbpath.stat()
    _need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
        and not info.st_mode & 0o077 and info.st_size <= MAX_DATABASE_BYTES)
    for suffix in ("-wal", "-shm", "-journal"):
        path = Path(str(dbpath) + suffix)
        _need(not path.exists() or _read(path, limit=MAX_DATABASE_BYTES) == b"",
            "Source must be a checkpointed stopped copy, without retained SQLite sidecars.")
    _need(_read(source / ".operator-publication.lock") == b"")
    descriptor = os.open(source / ".operator-publication.lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        # immutable is safe only for the explicitly acknowledged stopped copy,
        # after refusing sidecars. It prevents even incidental source writes.
        connection = sqlite3.connect(dbpath.as_uri() + "?mode=ro&immutable=1", uri=True)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        try:
            yield connection
        finally:
            connection.rollback()
            connection.close()
    finally:
        os.close(descriptor)


def migrate(source_data: Path, target_data: Path, source_gate_data: Path, target_gate_data: Path,
        *, public_url: str, proxy_url: str, acknowledge_offline_source: bool = False,
        ca_mode: str = "preserve", replacement_ca: Path | None = None):
    """Create one private migrated copy; interrupted targets are never adopted."""
    _need(acknowledge_offline_source is True, "An explicit stopped-copy acknowledgement is required.")
    _need(ca_mode in {"preserve", "replace"} and (replacement_ca is not None) == (ca_mode == "replace"))
    # This is a fresh, single-use offline process; SQLite and existing key
    # initializers inherit the same private file creation policy as deployment.
    os.umask(0o077)
    source, source_gate = _directory(source_data), _directory(source_gate_data)
    target, target_gate = _directory(target_data, empty=True), _directory(target_gate_data, empty=True)
    roots = (source, source_gate, target, target_gate)
    _need(all(a != b and not a.is_relative_to(b) and not b.is_relative_to(a)
        for index, a in enumerate(roots) for b in roots[index + 1:]))
    with source_snapshot(source) as old:
        counts = inventory(old)
        old_audit = verify_audit(old)
        settings = json.loads(old.execute("SELECT settings_json FROM operator_demo_settings WHERE singleton=1").fetchone()[0])
        _configure(target, settings, public_url, proxy_url)
        migration_id = str(uuid.uuid4())
        _write(target / "rebrand-incomplete.json", canonical({"schema": SCHEMA, "migration_id": migration_id}).encode())
        _write(target_gate / "rebrand-incomplete.json", canonical({"schema": SCHEMA, "migration_id": migration_id}).encode())
        copied = _prepare_files(source, target, ca_mode=ca_mode, replacement_ca=replacement_ca)
        from . import operator_demo, db, operator_demo_store as store, operator_publication as publication
        operator_demo.activate()
        db.init_db()
        store.initialize()
        from . import operator_upstream_setup as upstream, operator_x_quota as quota
        from . import operator_catalog_schema as catalog, operator_catalog_policy as policy
        from .rebrand_policy import prepare_policy_migration
        master = _read(source / "master.key", limit=32)
        with publication.exclusive(), closing(db.connect()) as new:
            new.execute("BEGIN IMMEDIATE")
            if "operator_upstream_setups" in counts:
                for _, _, sql in upstream._DEFINITIONS:
                    new.execute(sql)
            if "operator_x_quota_state" in counts:
                for sql in quota._DDL.values():
                    new.execute(sql)
            # Only fresh initializer placeholders may be removed. Never an existing destination.
            for table in reversed(TABLES):
                if new.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone():
                    _need(new.execute("SELECT COUNT(*) FROM " + _table(table)).fetchone()[0] <= (1 if table in {
                        "operator_demo_settings", "operator_demo_policy", "operator_catalog_state", "operator_ecr_owner",
                        "credential_lease_replay_state"} else 0),
                        "Fresh initializer produced unexpected rows in " + table + "; migration refused.")
                    if table != "operator_x_quota_state":
                        new.execute("DELETE FROM " + _table(table))
            for table in TABLES:
                if table in counts:
                    _copy_rows(old, new, table, master_key=master)
            _need(verify_audit(new) == old_audit)
            catalog.validate_bindings(new)
            if counts.get("operator_upstream_setups"):
                upstream._rows(new)
            if counts.get("operator_x_quota_state"):
                quota._retained_state(new)
            lineage = prepare_policy_migration(old, new, source, target, source_gate, target_gate)
            policy.verify_retained_policy(new, catalog.read_catalog(new))
            receipt = {"schema": SCHEMA, "migration_id": migration_id,
                "source_tables": counts, "rewrapped_credentials": counts.get("credentials", 0),
                "historical_audit": old_audit, "policy_lineage": lineage,
                "ca_mode": ca_mode, "retained_file_digests": copied,
                "source_contract_provenance": {table: [dict(row) for row in old.execute("SELECT * FROM " + _table(table))]
                    for table in PROVENANCE if table in counts}}
            event = db.append_audit_event(new, event_type="catchplate.rebrand.completed", actor_type="system",
                actor_id="catchplate-offline-migration", event={"schema": SCHEMA, "migration_id": migration_id,
                    "receipt_digest": digest(canonical(receipt).encode()), "historical_audit": old_audit})
            new.commit()
        store.materialize()
        receipt["migration_audit"] = {key: event[key] for key in ("id", "event_hash")}
        _write(target / "rebrand-receipt.json", canonical(receipt).encode() + b"\n")
        # Completion is separate from the retained start marker: no automatic retry.
        (target / "rebrand-incomplete.json").unlink()
        (target_gate / "rebrand-incomplete.json").unlink()
        return {"schema": SCHEMA, "migration_id": migration_id, "status": "complete",
            "receipt": str(target / "rebrand-receipt.json"), "rewrapped_credentials": counts.get("credentials", 0),
            "historical_audit_count": old_audit["count"], "ca_mode": ca_mode}
