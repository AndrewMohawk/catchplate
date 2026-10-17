#!/usr/bin/env python3
"""Real isolated SQLite staging bootstrap, not native or PostgreSQL admission.

The explicit development sandbox initializes the complete application schema
twice. Synthetic native-pair-shaped rows exercise only installed SQL grammar;
they are always rolled back, never admitted as proofs or retained as custody.
No app server, provider, authority execution or external database is used.
"""
from __future__ import annotations

from contextlib import closing
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True
_SCRATCH = tempfile.TemporaryDirectory(prefix="native-jit-sqlite-bootstrap-")
_DATA = Path(_SCRATCH.name) / "data"
# The real profile validates these settings before config can read any files.
for _name in tuple(os.environ):
    if _name.startswith("CATCHPLATE_"):
        del os.environ[_name]
os.environ.update({
    "CATCHPLATE_DATA_DIR": str(_DATA),
    "CATCHPLATE_DEVELOPMENT_SANDBOX": "1",
    "CATCHPLATE_RELEASE_CHANNEL": "dev",
    "CATCHPLATE_PROCESS_MODE": "catchplate-control-plane",
    "CATCHPLATE_METADATA_STORE_BACKEND": "sqlite",
    "CATCHPLATE_AUDIT_STORE_BACKEND": "sqlite",
    "CATCHPLATE_GRANT_STORE_BACKEND": "sqlite",
    "CATCHPLATE_ATOMIC_RELEASE_AUTHORIZATION_ENABLED": "0",
    "CATCHPLATE_KEY_RELEASE_REQUIRED": "0",
})


def _local_io_only(event, arguments):
    if event.startswith("socket.") or event in {
        "subprocess.Popen", "os.system", "os.exec", "os.posix_spawn",
    }:
        raise AssertionError("SQLite bootstrap test attempted external I/O")
    if event == "sqlite3.connect":
        if arguments[0] == ":memory:":
            return  # Real startup derives its expected schema in a private memory DB.
        path = Path(arguments[0])
        if not path.is_absolute() or not path.resolve().is_relative_to(_DATA.resolve()):
            raise AssertionError("SQLite bootstrap test opened an unowned database")


sys.addaudithook(_local_io_only)
from catchplate import development_sandbox

development_sandbox.activate()
from catchplate import authority_contract, authority_primary_contract, config, db
from catchplate import authority_native_jit_retention_contract as retention
from catchplate import authority_native_jit_retention_schema
from catchplate.authority_store import metadata_schema_source


TABLE = "policy_authority_native_jit_review_pairs"
COLUMNS = (
    "approval_request_id", "parent_request_digest", "parent_operation_id",
    "child_request_digest", "child_operation_id", "parent_request_original",
    "child_request_original", "pair_original", "proof_original", "pair_sha256",
    "proof_sha256", "source_contract_digest", "control_plane_configuration_digest",
    "owner_scope_digest", "secret_kek_id", "issued_at_epoch_ns",
    "seal_expires_at_epoch_ns", "document_expires_at_epoch_ns",
    "recorded_at_epoch_ns", "source_revision",
)
ORIGINAL_LIMITS = {
    "parent_request_original": 524288, "child_request_original": 524288,
    "pair_original": 1048576, "proof_original": 131072,
}
DIGEST_COLUMNS = (
    "parent_request_digest", "parent_operation_id", "child_request_digest",
    "child_operation_id", "pair_sha256", "proof_sha256", "source_contract_digest",
    "control_plane_configuration_digest", "owner_scope_digest",
)
EPOCH_COLUMNS = (
    "issued_at_epoch_ns", "seal_expires_at_epoch_ns",
    "document_expires_at_epoch_ns", "recorded_at_epoch_ns",
)
INSERT = f"INSERT INTO {TABLE} ({','.join(COLUMNS)}) VALUES ({','.join('?' for _ in COLUMNS)})"


def grammar_row(**updates):
    # Deliberately not a valid native pair/proof. SQL cannot admit those joins.
    value = {
        "approval_request_id": "11111111-1111-4111-8111-111111111111",
        **{name: "sha256:" + format(index, "064x")
           for index, name in enumerate(DIGEST_COLUMNS, 1)},
        **{name: "{}" for name in ORIGINAL_LIMITS},
        "secret_kek_id": "attested-memory-kek:" + "a" * 24,
        "issued_at_epoch_ns": 100, "recorded_at_epoch_ns": 101,
        "seal_expires_at_epoch_ns": 200, "document_expires_at_epoch_ns": 300,
        "source_revision": authority_contract.SOURCE_REVISION,
    }
    value.update(updates)
    return tuple(value[name] for name in COLUMNS)


class NativeJitSqliteBootstrapTests(unittest.TestCase):
    def test_actual_fresh_init_constraints_and_second_init_leave_no_native_rows(self):
        self.assertEqual(config.DB_PATH, _DATA / "catchplate.sqlite3")
        self.assertEqual((db.metadata_store_backend_name(), db.audit_store_backend_name(),
                          db.grants.backend_name()), ("sqlite", "sqlite", "sqlite"))
        self.assertEqual(config.WEBAUTHN_RECOVERY_WITNESS_BACKEND, "sqlite")
        self.assertFalse(config.DB_PATH.exists())
        db.init_db()
        with closing(db.connect()) as connection:
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone()[0], 1)
            columns = connection.execute(f"PRAGMA table_info({TABLE})").fetchall()
            self.assertEqual(tuple(row["name"] for row in columns), COLUMNS)
            self.assertTrue(all(row["notnull"] == 1 for row in columns))
            self.assertEqual(tuple(row["name"] for row in columns if row["pk"]),
                             ("approval_request_id",))
            self.assertEqual({row["name"]: row["type"] for row in columns},
                             {name: "BIGINT" if name in EPOCH_COLUMNS else "TEXT" for name in COLUMNS})
            installed = connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)
            ).fetchone()[0]
            self.assertIn("REGEXP", installed)
            self.assertIn("'^[ -~]+$'", installed)  # Literal tilde survives dialect translation.
            self.assertIn("DEFERRABLE INITIALLY DEFERRED", installed)
            foreign_keys = connection.execute(f"PRAGMA foreign_key_list({TABLE})").fetchall()
            self.assertEqual([(row["table"], row["from"], row["to"], row["on_update"], row["on_delete"])
                              for row in foreign_keys],
                             [("approval_requests", "approval_request_id", "id", "NO ACTION", "NO ACTION")])
            self.assertEqual(connection.execute("SELECT ? REGEXP ?", ("abc", "^[a-z]+$")).fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT ? REGEXP ?", ("abc\n", "^[a-z]+$")).fetchone()[0], 0)
            self.assertEqual(connection.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0], 0)

            # Real CHECK/NOT NULL failures, not a copied DDL or mocked validator.
            bad_values = [(name, None) for name in COLUMNS]
            bad_values += [("approval_request_id", "not-a-uuid"),
                           ("secret_kek_id", "attested-memory-kek:" + "A" * 24),
                           ("source_revision", "unrecognized-source")]
            bad_values += [(name, value) for name in DIGEST_COLUMNS
                           for value in ("sha256:" + "0" * 64, "sha256:" + "A" * 64)]
            bad_values += [(name, value) for name, maximum in ORIGINAL_LIMITS.items()
                           for value in ("x", "x" * (maximum + 1), "{\né}")]
            bad_values += [(name, 0) for name in EPOCH_COLUMNS]
            bad_values += [("recorded_at_epoch_ns", 99), ("recorded_at_epoch_ns", 200),
                           ("document_expires_at_epoch_ns", 199)]
            for name, value in bad_values:
                with self.subTest(rejected_column=name, kind=type(value).__name__,
                                  size=len(value) if isinstance(value, str) else None):
                    try:
                        with self.assertRaises(sqlite3.IntegrityError):
                            connection.execute(INSERT, grammar_row(**{name: value}))
                    finally:
                        connection.rollback()
            try:
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute(INSERT, grammar_row(
                        seal_expires_at_epoch_ns=30000000101,
                        document_expires_at_epoch_ns=30000000102))
            finally:
                connection.rollback()

            # SQL accepts exact byte caps; the missing parent prevents commit.
            for name, maximum in ORIGINAL_LIMITS.items():
                with self.subTest(exact_original_cap=name):
                    try:
                        connection.execute(INSERT, grammar_row(**{name: "~" * maximum}))
                        with self.assertRaises(sqlite3.IntegrityError):
                            connection.commit()
                    finally:
                        connection.rollback()

            # Primary/unique keys are actually enforced, still rollback-only.
            try:
                connection.execute(INSERT, grammar_row())
                for updates in (
                    {"parent_request_digest": "sha256:" + "d" * 64,
                     "child_request_digest": "sha256:" + "e" * 64},
                    {"approval_request_id": "22222222-2222-4222-8222-222222222222",
                     "child_request_digest": "sha256:" + "b" * 64},
                    {"approval_request_id": "33333333-3333-4333-8333-333333333333",
                     "parent_request_digest": "sha256:" + "c" * 64}):
                    with self.subTest(unique_fields=tuple(updates)), self.assertRaises(sqlite3.IntegrityError):
                        connection.execute(INSERT, grammar_row(**updates))
            finally:
                connection.rollback()
            self.assertEqual(connection.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM approval_requests").fetchone()[0], 0)

        db.init_db()
        with closing(db.connect()) as connection:
            self.assertEqual(connection.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)
            ).fetchone()[0], installed)
            for table in (TABLE, "approval_requests", "rbac_authority_state"):
                self.assertEqual(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 0)
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_source_inventory_keeps_native_table_protected_primary_keyed_and_insert_only(self):
        self.assertEqual(retention.TABLE, TABLE)
        self.assertEqual(retention.COLUMNS, COLUMNS)
        self.assertEqual(dict(retention.ORIGINAL_LIMITS), ORIGINAL_LIMITS)
        self.assertEqual(retention.PRIMARY_KEY, ("approval_request_id",))
        self.assertEqual(retention.UNIQUE_KEYS, (("parent_request_digest",), ("child_request_digest",)))
        self.assertEqual(retention.MUTATION_KINDS, ("INSERT",))
        self.assertEqual(authority_primary_contract.PRIMARY_KEY_COLUMNS[TABLE], ("approval_request_id",))
        self.assertIn(TABLE, authority_contract.V9_ADDITIONAL_PROTECTED_TABLES)
        self.assertIn(TABLE, authority_contract.POSTGRES_IMMUTABLE_CUSTODY_TABLES)
        self.assertIn(authority_native_jit_retention_schema.source(), metadata_schema_source.metadata_schema_source())
        writers = [name for name, spec in authority_contract.OPERATIONS.items() if TABLE in spec["businessWrites"]]
        self.assertEqual(writers, ["release.reserve"])
        spec = authority_contract.operation_spec("release.reserve")
        self.assertIn(TABLE, spec["businessReadBeforeWrite"])
        self.assertNotIn(TABLE, spec["businessReads"])
        templates = [item for item in spec["mutationTemplates"] if item["table"] == TABLE]
        self.assertEqual([(item["mutation"], item["before"], item["after"], item["cardinality"])
                          for item in templates], [("INSERT", "absent", "present", 1)])


if __name__ == "__main__":
    try:
        unittest.main()
    finally:
        _SCRATCH.cleanup()
