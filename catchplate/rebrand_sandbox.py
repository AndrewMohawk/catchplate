"""Offline copy of the fixed synthetic sandbox, never ordinary/provider state.

Run once in a fresh process against an explicitly stopped, checkpointed copy.
The old signed bytes and audit/nonce history remain immutable originals. Only
static envelope AAD and the exact fixed policy protocol labels are migrated.
"""
from __future__ import annotations

import base64
from contextlib import ExitStack, closing, contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import uuid

from . import rebrand_migration as shared

SCHEMA = "catchplate.sandboxRebrandMigration/v1"
LINEAGE = "catchplate.sandboxRebrandPolicyLineage/v1"
OLD_MARKER = b'{"schema": "serverware.developmentSandbox/v1", "syntheticOnly": true}\n'
NEW_MARKER = b'{"schema": "catchplate.developmentSandbox/v1", "syntheticOnly": true}\n'
TABLES = ("credentials", "credential_generations", "credential_lease_replay_state", "routes", "audit_events")
PROVENANCE = ("policy_authority_schema_contracts", "serverware_store_migrations")
WITNESS = "webauthn-recovery-witness.sqlite3"
SANDBOX = "development-sandbox.sqlite3"
DATABASES = ("serverware.sqlite3", SANDBOX, WITNESS)
EPHEMERAL_LOCKS = ("policy-signing-ed25519.pem.lock", "serverware.sqlite3.migration.lock",
    "webauthn-trust-bundle.json.lock")
MigrationError = shared.MigrationError


def need(condition, message="Sandbox migration validation failed; source was not changed."):
    shared._need(condition, message)


def admit_root(source):
    """Only known state is copied; empty historical locks are explicit ephemera."""
    allowed = {".serverware-development-sandbox.json", "policy-bundle.json", "mitmproxy",
        *shared.KEY_FILES, *DATABASES, *EPHEMERAL_LOCKS,
        *(name + suffix for name in DATABASES for suffix in ("-wal", "-shm", "-journal"))}
    locks = []
    for path in source.iterdir():
        need(path.name in allowed and not path.is_symlink(),
            "Unknown auxiliary sandbox state or a symlink exists; migration refused before copying.")
        if path.name == "mitmproxy":
            shared._directory(path)
            for child in path.iterdir():
                need(child.name in shared.CA_FILES and not child.is_symlink() and child.is_file(),
                    "Unknown CA auxiliary state or a symlink exists; migration refused before copying.")
        else:
            need(path.is_file(), "Sandbox state must use regular files; migration refused before copying.")
        if path.name in EPHEMERAL_LOCKS:
            need(stat.S_IMODE(path.stat().st_mode) == 0o600 and shared._read(path) == b"",
                "Only empty private historical lock files may be omitted; migration refused before copying.")
            locks.append(path.name)
    return sorted(locks)


@contextmanager
def snapshot(path):
    # No journal adoption or checkpoint writes against the source are allowed.
    shared._read(path, limit=shared.MAX_DATABASE_BYTES)
    for suffix in ("-wal", "-shm", "-journal"):
        sidecar = Path(str(path) + suffix)
        need(not os.path.lexists(sidecar) or shared._read(sidecar, limit=shared.MAX_DATABASE_BYTES) == b"",
            "Source must be a stopped checkpointed copy without SQLite sidecars.")
    conn = sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    conn.execute("BEGIN")
    try:
        need(conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok")
        yield conn
    finally:
        conn.rollback()
        conn.close()


def counts(conn):
    names = [row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name LIMIT ?", (shared.MAX_TABLES + 1,))]
    need(len(names) <= shared.MAX_TABLES)
    result = {name: conn.execute("SELECT COUNT(*) FROM " + shared._table(name)).fetchone()[0] for name in names}
    need(sum(result.values()) <= shared.MAX_ROWS)
    return result


def configure(target):
    need("catchplate.config" not in sys.modules,
        "Sandbox migration requires a fresh process before application configuration is imported.")
    need(not any(key.startswith(("CATCHPLATE_", "SERVERWARE_")) for key in os.environ),
        "Run sandbox migration without inherited application configuration.")
    from .development_sandbox import _EXPECTED
    os.environ.update(_EXPECTED, CATCHPLATE_DATA_DIR=str(target),
        CATCHPLATE_DEV_AUTHENTICATOR="1", CATCHPLATE_DEV_DEMO_SEED="1")


def copy_files(source, target):
    copied = {}
    for name in shared.KEY_FILES:
        if os.path.lexists(source / name):
            public = name.endswith((".pub.pem", "-cert.pem"))
            raw = shared._read(source / name, private=not public)
            shared._write(target / name, raw, mode=0o644 if public else 0o600)
            copied[name] = shared.digest(raw)
    need(all(name in copied for name in ("master.key", "policy-signing-ed25519.pem",
        "policy-signing-ed25519.pub.pem", "response-signing-ed25519.pem")))
    # Preserve optional existing MITM CA files, never create or rotate trust.
    if os.path.lexists(source / "mitmproxy"):
        directory = shared._directory(source / "mitmproxy")
        need({path.name for path in directory.iterdir()} <= set(shared.CA_FILES))
        (target / "mitmproxy").mkdir(mode=0o700)
        for name in shared.CA_FILES:
            if os.path.lexists(directory / name):
                public = name in {"mitmproxy-ca-cert.pem", "mitmproxy-ca-cert.cer", "mitmproxy-ca-cert.p12", "mitmproxy-dhparam.pem"}
                raw = shared._read(directory / name, private=not public)
                shared._write(target / "mitmproxy" / name, raw, mode=0o644 if public else 0o600)
                copied["mitmproxy/" + name] = shared.digest(raw)
    return copied


def policy_lineage(source, target, old_store):
    from . import policy_bundle as bundles
    from .rebrand_policy import _json
    rows = old_store.execute("SELECT * FROM sandbox_policy").fetchall()
    need(len(rows) == 1 and rows[0]["singleton"] == 1)
    row = dict(rows[0])
    raw = row["signed_bundle_json"].encode()
    need(0 < len(raw) <= bundles.MAX_POLICY_BUNDLE_BYTES)
    old = _json(raw)
    metadata = old["metadata"]
    sequence, epoch = metadata["sequence"], metadata["rollbackEpoch"]
    need(type(sequence) is int and 1 <= sequence < 9_007_199_254_740_991
        and type(epoch) is int and 1 <= epoch <= 9_007_199_254_740_991)
    # Exact fixed template comparison, not a recursive replacement of user data.
    expected = bundles.demo_policy_bundle()
    expected["apiVersion"] = "serverware.policy/v1"
    expected["metadata"].update(id="serverware-demo", sequence=sequence, rollbackEpoch=epoch,
        signingKeyId=metadata["signingKeyId"], signature=metadata["signature"])
    for principal in expected["principals"]:
        principal["requiredHeaders"]["X-Serverware-Agent"] = principal["requiredHeaders"].pop("X-Catchplate-Agent")
    need(bundles.canonical_json(expected) == bundles.canonical_json(old)
        and bundles.canonical_json(old).encode() == raw
        and shared._read(source / "policy-bundle.json", limit=bundles.MAX_POLICY_BUNDLE_BYTES) == raw)
    bundles.verify_policy_signature(old)
    unsigned = deepcopy(old)
    unsigned["metadata"].pop("signature")
    old_hash = shared.digest(bundles.canonical_json(unsigned).encode())
    need((row["policy_id"], row["sequence"], row["rollback_epoch"], row["policy_hash"])
        == ("serverware-demo", sequence, epoch, old_hash))
    current = bundles.demo_policy_bundle()
    current["metadata"].update(sequence=sequence + 1, rollbackEpoch=epoch)
    signed = bundles.sign_policy_bundle(current)
    compiled = bundles.compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
    current_raw = bundles.canonical_json(signed).encode()
    need(signed["metadata"]["signingKeyId"] == metadata["signingKeyId"])
    receipt = {"schema": LINEAGE, "syntheticOnly": True,
        "source": {"policyId": row["policy_id"], "sequence": sequence, "rollbackEpoch": epoch,
            "policyHash": old_hash, "bundleDigest": shared.digest(raw)},
        "target": {"policyId": "catchplate-demo", "sequence": sequence + 1, "rollbackEpoch": epoch,
            "policyHash": compiled.hash, "bundleDigest": shared.digest(current_raw)},
        "signingKeyId": metadata["signingKeyId"], "gatePersistentHighWater": False}
    private = bundles._load_policy_private_key()
    receipt["signature"] = "ed25519:" + base64.urlsafe_b64encode(private.sign(
        LINEAGE.encode() + b"\0" + shared.canonical(receipt).encode())).decode().rstrip("=")
    archive = target / "rebrand-originals"
    archive.mkdir(mode=0o700)
    shared._write(archive / "policy-bundle.json", raw)
    shared._write(archive / "sandbox-policy.json", shared.canonical(row).encode())
    shared._write(archive / "lineage.json", shared.canonical(receipt).encode())
    shared._write(target / "policy-bundle.json", current_raw)
    return signed, row, receipt


def migrate(source_data: Path, target_data: Path, *, acknowledge_offline_source=False):
    """One stopped-copy migration; refusal never retries or adopts a target."""
    need(acknowledge_offline_source is True, "An explicit stopped-copy acknowledgement is required.")
    os.umask(0o077)
    source, target = shared._directory(source_data), shared._directory(target_data, empty=True)
    need(source != target and not source.is_relative_to(target) and not target.is_relative_to(source))
    ephemeral_locks = admit_root(source)
    need(shared._read(source / ".serverware-development-sandbox.json") == OLD_MARKER,
        "Only the exact synthetic Serverware sandbox marker is supported.")
    need(not os.path.lexists(source / "rebrand-incomplete.json")
        and not os.path.lexists(source / "policy-high-water.json"))
    with ExitStack() as stack:
        old = stack.enter_context(snapshot(source / "serverware.sqlite3"))
        old_store = stack.enter_context(snapshot(source / SANDBOX))
        old_witness = stack.enter_context(snapshot(source / WITNESS))
        inventory = counts(old)
        need(all(not count or name in TABLES or name in PROVENANCE for name, count in inventory.items()),
            "Unsupported populated sandbox state exists; migration refused.")
        need(inventory.get("credentials") == inventory.get("credential_generations") == 1
            and inventory.get("credential_lease_replay_state") == 1 and inventory.get("routes") == 12)
        credential = dict(old.execute("SELECT * FROM credentials").fetchone())
        need(credential["id"] == "cred-demo-bearer" and credential["kind"] == "bearer"
            and credential["encrypted_secret"] == "envelope:v2" and credential["lifecycle_status"] == "active")
        metadata = json.loads(credential["metadata"])
        need(type(metadata) is dict and metadata.get("provider_id") == "demo"
            and not any(key in metadata for key in ("oauth", "github_app", "operator_x_account", "connection_type")))
        need(counts(old_store).keys() == {"sandbox_policy", "sandbox_credential_nonces"}
            and counts(old_store)["sandbox_policy"] == 1)
        witness_counts = counts(old_witness)
        need(witness_counts == {"recovery_authorization_claims": 0, "recovery_witness_heads": 0})
        audit = shared.verify_audit(old)
        configure(target)
        migration_id = str(uuid.uuid4())
        shared._write(target / "rebrand-incomplete.json", shared.canonical({"schema": SCHEMA, "migration_id": migration_id}).encode())
        copied = copy_files(source, target)
        shared._write(target / ".catchplate-development-sandbox.json", NEW_MARKER)
        from . import development_sandbox as profile, development_sandbox_store as store, db
        profile.activate()
        db.init_db()
        signed, old_policy, lineage = policy_lineage(source, target, old_store)
        store.commission_policy(signed)
        master = shared._read(source / "master.key", limit=32)
        with closing(db.connect()) as new, store._connect() as new_store:
            new.execute("BEGIN IMMEDIATE")
            new_store.execute("BEGIN IMMEDIATE")
            for table in TABLES:
                need(new.execute("SELECT COUNT(*) FROM " + shared._table(table)).fetchone()[0]
                    == (1 if table == "credential_lease_replay_state" else 0))
                new.execute("DELETE FROM " + shared._table(table))
                shared._copy_rows(old, new, table, master_key=master)
            shared._copy_rows(old_store, new_store, "sandbox_credential_nonces", master_key=master)
            # The authority changes once, while the historical timestamp stays original.
            new_store.execute("UPDATE sandbox_policy SET updated_at=? WHERE singleton=1", (old_policy["updated_at"],))
            need(shared.verify_audit(new) == audit)
            receipt = {"schema": SCHEMA, "migration_id": migration_id, "syntheticOnly": True,
                "source_tables": inventory, "sandbox_tables": counts(old_store),
                "historical_audit": audit, "policy_lineage": lineage, "rewrapped_credentials": 1,
                "source_ephemeral_locks": ephemeral_locks,
                "retained_file_digests": copied, "gatePersistentHighWater": False,
                "source_contract_provenance": {table: [dict(row) for row in old.execute("SELECT * FROM " + shared._table(table))]
                    for table in PROVENANCE if table in inventory}}
            new_store.commit()
            new.commit()
        shared._write(target / "rebrand-receipt.json", shared.canonical(receipt).encode() + b"\n")
        (target / "rebrand-incomplete.json").unlink()
        return {"schema": SCHEMA, "status": "complete", "syntheticOnly": True,
            "migration_id": migration_id, "receipt": str(target / "rebrand-receipt.json"),
            "historical_audit_count": audit["count"], "retained_nonces": receipt["sandbox_tables"]["sandbox_credential_nonces"],
            "policy_sequence": lineage["target"]["sequence"]}
