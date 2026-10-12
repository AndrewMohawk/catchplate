#!/usr/bin/env python3
"""Disposable ordinary-SQLite migration controls; never live-state admission.

Derivation runs with one immutable application tree mounted at /app in the
reviewed network-none dependency image. It initializes ONLY a fresh temporary
ordinary-development store and emits public source/schema pins, not row data.
"""
from __future__ import annotations

import hashlib
import fcntl
from contextlib import closing, contextmanager
from datetime import datetime
import json
import os
from pathlib import Path
import signal
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def upstream_fixture():
    from serverware import operator_upstream_setup as setup
    actor = "operator-contract-migration-synthetic"
    review = setup.review(actor)
    operation = str(uuid.uuid4())
    setup.prepare(setup.PrepareInput(operation_id=operation,
        expected_revision=review["expected_revision"], expected_policy_hash=review["expected_policy_hash"],
        expected_settings_digest=review["expected_settings_digest"],
        allowed_upstreams=["https://api.example.com", "https://other.example.com"]), actor)
    review = setup.review(actor)
    setup.cancel(setup.CancelInput(operation_id=operation, expected_revision=review["expected_revision"],
        expected_policy_hash=review["expected_policy_hash"]), actor)


def seed(source, directory):
    os.umask(0o077)
    require = lambda value: None if value else (_ for _ in ()).throw(ValueError("synthetic seed refused"))
    source, directory = Path(source), Path(directory)
    require(str(source) == "/previous-app" and directory.is_relative_to("/tmp")
        and not directory.exists() and directory.parent.is_dir())
    sys.path[:0] = [str(source / "scripts"), str(source)]
    import test_operator_workspace_store as fixture
    os.environ.update(fixture.common._ENVIRONMENT)
    os.environ["SERVERWARE_DATA_DIR"] = str(directory)
    config, db, store, bundles, schema, inputs, mutations = fixture.workspace()
    credential = fixture.create_credential(db, store, schema, inputs, mutations)["credential"]
    application = fixture.create_application(db, store, schema, inputs, mutations)["application"]
    fixture.create_rule(db, store, schema, inputs, mutations, application["id"], credential["id"])
    fixture.verify_signed(config, db, store, bundles)
    upstream_fixture()
    require(all(Path(module.__file__).resolve().is_relative_to(source) for name, module in tuple(sys.modules.items())
        if name == "serverware" or name.startswith("serverware.")))
    print('{"syntheticOldSourceInitialized":true,"resources":3}')


def cold_start(directory):
    os.umask(0o077)
    directory = Path(directory)
    if not directory.is_relative_to("/tmp") or not directory.is_dir():
        raise ValueError("synthetic cold-start path refused")
    for name in tuple(os.environ):
        if name.startswith("SERVERWARE_"):
            del os.environ[name]
    sys.path[:0] = ["/app/scripts", "/app"]
    import test_operator_workspace_store as fixture
    os.environ.update(fixture.common._ENVIRONMENT)
    os.environ["SERVERWARE_DATA_DIR"] = str(directory)
    config, db, store, bundles, _schema, _inputs, _mutations = fixture.workspace()
    fixture.verify_signed(config, db, store, bundles)
    print('{"syntheticMainColdStart":true}')


def derive(source):
    os.umask(0o077)
    for name in tuple(os.environ):
        if name.startswith("SERVERWARE_"):
            del os.environ[name]
    source = Path(source).resolve(strict=True)
    if str(source) != "/app" or any(name == "serverware" or name.startswith("serverware.") for name in sys.modules):
        raise ValueError("isolated source selection refused")
    sys.path[:0] = [str(source / "scripts"), str(source)]
    import test_operator_demo_persistence as fixture
    with tempfile.TemporaryDirectory(prefix="operator-contract-fixture-") as temporary:
        os.environ.update(fixture._ENVIRONMENT)
        os.environ["SERVERWARE_DATA_DIR"] = str(Path(temporary) / "data")
        config, db, store, _bundles = fixture.backend()
        from serverware import authority_contract
        from serverware.authority_store import metadata_schema_source
        with closing(sqlite3.connect(config.DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row
            tables = sorted(row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'"))
            prefixes = ("policy_authority_", "policy_activation_", "policy_candidate_", "policy_canar",
                "policy_compiler_", "policy_runtime_", "policy_native_", "policy_shadow_", "policy_control_plane_",
                "setup_", "webauthn_", "oidc_", "jit_", "approval_", "recovery_", "rbac_", "control_plane_",
                "release_authorization_")
            additional = set(authority_contract.V9_ADDITIONAL_PROTECTED_TABLES) - {"credential_generations"}
            additional |= {"policy_high_water", "policy_publications", "policy_state_bundles"}
            empty = sorted(name for name in tables if name != "policy_authority_schema_contracts"
                and (name.startswith(prefixes) or name in additional))
            nonempty = [name for name in empty if conn.execute('SELECT 1 FROM "' + name + '" LIMIT 1').fetchone()]
            if nonempty:
                raise ValueError("synthetic ordinary initializer has nonempty guarded tables")
            manifest, manifest_digest = db._validate_policy_candidate_authority_structure(conn,
                require_recorded_contract=True, source_schema_program=metadata_schema_source.metadata_schema_source())
            contract = dict(conn.execute("SELECT * FROM policy_authority_schema_contracts").fetchone())
            objects = [list(row) for row in conn.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")]
            if contract["source_contract_digest"] != db._policy_candidate_authority_source_contract_digest():
                raise ValueError("actual source producer disagrees with initialized contract")
        upstream_fixture()
        with closing(sqlite3.connect(config.DB_PATH)) as conn:
            optional_objects = [list(row) for row in conn.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")]
            optional_tables = sorted(row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'"))
            if set(optional_tables) - set(tables) != {"operator_upstream_setups"}:
                raise ValueError("actual optional setup schema differs")
        witness = Path(temporary) / "data" / "webauthn-recovery-witness.sqlite3"
        with closing(sqlite3.connect(witness)) as conn:
            witness_objects = [list(row) for row in conn.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_schema ORDER BY type,name")]
            witness_tables = sorted(row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'"))
            if witness_tables != ["recovery_authorization_claims", "recovery_witness_heads"] or any(
                    conn.execute('SELECT 1 FROM "' + name + '" LIMIT 1').fetchone() for name in witness_tables):
                raise ValueError("synthetic recovery witness is not empty")
        closure = {}
        for name, module in tuple(sys.modules.items()):
            if name == "serverware" or name.startswith("serverware."):
                path = Path(module.__file__).resolve(strict=True)
                relative = str(path.relative_to(source))
                closure[relative] = digest(path.read_bytes())
        return {"sourceContractDigest": contract["source_contract_digest"],
            "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
            "sourceRevision": authority_contract.SOURCE_REVISION, "schemaVersion": authority_contract.SCHEMA_VERSION,
            "sourceDdlSha256": digest((source / "serverware/authority_store/metadata_schema_source.py").read_bytes()),
            "structuralManifestDigest": manifest_digest, "structuralManifestJsonSha256": digest(manifest.encode()),
            "sqliteObjectsSha256": digest(canonical(objects)), "tables": tables, "emptyTables": empty,
            "optionalSqliteObjectsSha256": digest(canonical(optional_objects)), "optionalTables": optional_tables,
            "witnessObjectsSha256": digest(canonical(witness_objects)), "sourceFiles": dict(sorted(closure.items()))}


class MigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.umask(0o077)
        for name in tuple(os.environ):
            if name.startswith("SERVERWARE_"):
                del os.environ[name]
        cls.temporary = tempfile.TemporaryDirectory(prefix="operator-migration-tests-")
        cls.base = Path(cls.temporary.name)
        cls.seed_path = cls.base / "seed"
        result = subprocess.run([sys.executable, "-B", __file__, "--seed", "/previous-app", str(cls.seed_path)],
            env={name: value for name, value in os.environ.items() if not name.startswith("SERVERWARE_")},
            capture_output=True, timeout=50)
        if result.returncode != 0:
            raise AssertionError("old synthetic seed failed: " + result.stderr.decode()[-3000:])
        cls.migration = __import__("migrate_operator_authority_contract")
        cls.pinned = cls.migration.pins()
        cls.helpers = cls.migration.source(cls.pinned, cls.seed_path)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def setUp(self):
        self.directory = self.base / self._testMethodName
        shutil.copytree(self.seed_path, self.directory)
        self.backup = self.base / (self._testMethodName + ".backup")
        shutil.copyfile(self.directory / "serverware.sqlite3", self.backup)
        self.backup.chmod(0o600)
        self.m = self.migration

    def plan(self):
        return self.m.plan(self.directory, self.pinned, self.helpers)

    def apply(self, reviewed, **changes):
        return self.m.apply(self.directory, self.pinned, self.helpers, reviewed,
            self.m.sha(self.m.canonical(reviewed)), self.backup, **changes)

    @contextmanager
    def db(self):
        with closing(sqlite3.connect(self.directory / "serverware.sqlite3")) as conn, conn:
            yield conn

    def snapshot(self):
        return {str(path.relative_to(self.directory)): path.read_bytes()
            for path in self.directory.rglob("*") if path.is_file()}

    def test_plan_read_only_then_exact_single_cell_transition(self):
        before = self.snapshot()
        reviewed = self.plan()
        self.assertEqual(self.snapshot(), before)
        self.assertGreater(reviewed["rows"]["credentials"]["count"], 0)
        self.assertGreater(reviewed["rows"]["audit_events"]["count"], 0)
        self.assertEqual(reviewed["rows"]["operator_upstream_setups"]["count"], 1)
        receipt = self.apply(reviewed)
        self.assertEqual(receipt["status"], "committed")
        self.assertEqual(receipt["beforeContract"]["source_contract_digest"], self.pinned["old"]["sourceContractDigest"])
        self.assertEqual(receipt["afterContract"]["source_contract_digest"], self.pinned["target"]["sourceContractDigest"])
        after = self.snapshot()
        self.assertEqual({key: value for key, value in before.items() if key != "serverware.sqlite3"},
            {key: value for key, value in after.items() if key != "serverware.sqlite3"})
        self.assertEqual(self.backup.read_bytes(), before["serverware.sqlite3"])
        with self.db() as conn:
            conn.row_factory = sqlite3.Row
            actual = self.m.inspect(conn, self.pinned, self.helpers,
                expected_digest=self.pinned["target"]["sourceContractDigest"])
            self.assertEqual(actual["rows"], reviewed["rows"])
            with self.assertRaises(sqlite3.IntegrityError):
                conn.execute("UPDATE policy_authority_schema_contracts SET installed_at='changed'")
        with self.assertRaises(self.m.Refused):
            self.plan()
        with self.assertRaises(self.m.Refused):
            self.apply(reviewed)
        for _ in range(2):
            with self.db() as conn:
                conn.row_factory = sqlite3.Row
                prior_migrations = {row["migration"]: dict(row) for row in conn.execute(
                    "SELECT rowid,* FROM serverware_store_migrations ORDER BY migration")}
            child = subprocess.run([sys.executable, "-B", __file__, "--cold-start", str(self.directory)],
                env={name: value for name, value in os.environ.items() if not name.startswith("SERVERWARE_")},
                capture_output=True, timeout=40)
            self.assertEqual(child.returncode, 0, "fresh main-source synthetic initialization refused")
            self.assertEqual(child.stdout, b'{"syntheticMainColdStart":true}\n')
            with self.db() as conn:
                conn.row_factory = sqlite3.Row
                current = self.m.inspect(conn, self.pinned, self.helpers,
                    expected_digest=self.pinned["target"]["sourceContractDigest"])
                current_migrations = {row["migration"]: dict(row) for row in conn.execute(
                    "SELECT rowid,* FROM serverware_store_migrations ORDER BY migration")}
                name = "policy_candidate_authority"
                prior_time = datetime.fromisoformat(prior_migrations[name]["applied_at"])
                current_time = datetime.fromisoformat(current_migrations[name]["applied_at"])
                self.assertIsNotNone(prior_time.utcoffset())
                self.assertIsNotNone(current_time.utcoffset())
                self.assertGreater(current_time, prior_time)
                current_migrations[name]["applied_at"] = prior_migrations[name]["applied_at"]
                self.assertEqual(current_migrations, prior_migrations)
                self.assertEqual([name for name in current["rows"] if current["rows"][name] != reviewed["rows"][name]],
                    ["serverware_store_migrations"], "only the existing startup timestamp may refresh")
            self.assertEqual(self.m.tree(self.directory), reviewed["files"])

    def test_every_transaction_failure_restores_exact_guard_rows_and_file(self):
        for stage in ("before_guard", "after_guard", "after_update", "after_restore", "before_commit"):
            with self.subTest(stage=stage):
                reviewed = self.plan()
                before = self.snapshot()
                sentinel = RuntimeError("synthetic rollback")
                def fail(actual):
                    if actual == stage:
                        raise sentinel
                with self.assertRaises(RuntimeError) as raised:
                    self.apply(reviewed, checkpoint=fail)
                self.assertIs(raised.exception, sentinel)
                self.assertEqual(self.snapshot(), before)
                self.assertEqual(self.plan(), reviewed)

    def test_unknown_digest_and_changed_native_schema_refused(self):
        reviewed = self.plan()
        trigger = self.helpers[0]._policy_candidate_authority_object_name("serverware", self.m.CONTRACT_TABLE,
            "immutable", "update")
        with self.db() as conn:
            sql = conn.execute("SELECT sql FROM sqlite_schema WHERE name=?", (trigger,)).fetchone()[0]
            conn.execute('DROP TRIGGER "' + trigger + '"')
            conn.execute("UPDATE policy_authority_schema_contracts SET source_contract_digest=?", ("sha256:" + "f" * 64,))
            conn.execute(sql)
        before = self.snapshot()
        with self.assertRaises(self.m.Refused):
            self.plan()
        self.assertEqual(self.snapshot(), before)
        shutil.copyfile(self.backup, self.directory / "serverware.sqlite3")
        with self.db() as conn:
            conn.execute("ALTER TABLE approval_requests ADD COLUMN unreviewed TEXT")
        with self.assertRaises(self.m.Refused):
            self.plan()
        with self.assertRaises(self.m.Refused):
            self.apply(reviewed)

    def test_nonempty_authority_and_recovery_refused(self):
        with self.db() as conn:
            conn.execute("INSERT INTO rbac_authority_state (authority_id,generation,state_digest,updated_at) "
                "VALUES(1,0,?,'2026-10-12T00:00:00+00:00')", ("sha256:" + "1" * 64,))
        before = self.snapshot()
        with self.assertRaises(self.m.Refused):
            self.plan()
        self.assertEqual(self.snapshot(), before)
        shutil.copyfile(self.backup, self.directory / "serverware.sqlite3")
        reviewed = self.plan()
        self.assertTrue(all(reviewed["rows"][name]["count"] == 0 for name in self.pinned["target"]["emptyTables"]))
        witness = self.directory / "webauthn-recovery-witness.sqlite3"
        with closing(sqlite3.connect(witness)) as conn, conn:
            conn.execute("INSERT INTO recovery_witness_heads (root_key_id,user_id,last_sequence,updated_at) "
                "VALUES('synthetic-root','synthetic-user',1,'2026-10-12T00:00:00+00:00')")
        with self.assertRaises(self.m.Refused):
            self.plan()

    def test_stale_plan_backup_file_and_unknown_table_refused(self):
        reviewed = self.plan()
        with self.db() as conn:
            conn.execute("UPDATE operator_catalog_state SET revision=revision+1")
        with self.assertRaises(self.m.Refused):
            self.apply(reviewed)
        shutil.copyfile(self.backup, self.directory / "serverware.sqlite3")
        with self.db() as conn:
            conn.execute("CREATE TABLE unreviewed_table(value TEXT)")
        with self.assertRaises(self.m.Refused):
            self.plan()

    def test_corrupt_hardlinked_and_parent_symlink_backups_refused(self):
        reviewed = self.plan()
        before = self.snapshot()
        raw = self.backup.read_bytes()
        self.backup.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        with self.assertRaises(self.m.Refused):
            self.apply(reviewed)
        self.backup.write_bytes(raw)
        self.backup.unlink()
        os.link(self.directory / self.m.DATABASE, self.backup)
        with self.assertRaises(self.m.Refused):
            self.apply(reviewed)
        self.backup.unlink()
        self.backup.write_bytes(raw)
        inside = self.directory / "inside.backup"
        inside.write_bytes(raw)
        reviewed = self.plan()
        alias = self.base / "backup-directory-alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaises(self.m.Refused):
            self.m.apply(self.directory, self.pinned, self.helpers, reviewed,
                self.m.sha(self.m.canonical(reviewed)), alias / inside.name)
        inside.unlink()
        alias.unlink()
        with self.assertRaises(self.m.Refused):
            self.m.apply(self.directory, self.pinned, self.helpers, reviewed, "sha256:" + "0" * 64, self.backup)
        self.assertEqual(self.snapshot(), before)

    def test_closed_public_files_and_empty_mountpoints_preserved(self):
        for name, modes in self.m.PUBLIC_FILES.items():
            path = self.directory / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not path.exists():
                path.write_bytes(b"synthetic public certificate\n")
            path.chmod(next(iter(modes)))
        for name in self.m.EMPTY_MOUNTPOINTS:
            path = self.directory / name
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.touch(mode=0)
        reviewed = self.plan()
        self.apply(reviewed)
        self.assertEqual(self.m.tree(self.directory), reviewed["files"])
        public = self.directory / "decision-gate-ca-cert.pem"
        public.chmod(0o666)
        with self.assertRaises(self.m.Refused):
            self.m.tree(self.directory)
        public.chmod(0o444)
        placeholder = self.directory / sorted(self.m.EMPTY_MOUNTPOINTS)[0]
        placeholder.chmod(0o600)
        with self.assertRaises(self.m.Refused):
            self.m.tree(self.directory)
        placeholder.write_bytes(b"not empty")
        placeholder.chmod(0)
        with self.assertRaises(self.m.Refused):
            self.m.tree(self.directory)
        placeholder.chmod(0o600)

    def test_missing_marker_sidecar_and_held_writer_refused(self):
        marker = self.directory / self.m.MARKER
        raw = marker.read_bytes()
        marker.unlink()
        with self.assertRaises((OSError, self.m.Refused)):
            self.plan()
        marker.write_bytes(raw)
        marker.chmod(0o600)
        sidecar = self.directory / "serverware.sqlite3-wal"
        sidecar.write_bytes(b"synthetic stale WAL")
        with self.assertRaises(self.m.Refused):
            self.plan()
        sidecar.unlink()
        with (self.directory / (self.m.DATABASE + ".migration.lock")).open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises((OSError, self.m.Refused)):
                self.plan()
        reviewed = self.plan()
        conn = sqlite3.connect(self.directory / "serverware.sqlite3")
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("UPDATE operator_catalog_state SET revision=revision+1")
            with self.assertRaises((OSError, sqlite3.Error, self.m.Refused)):
                self.apply(reviewed)
        finally:
            conn.rollback()
            conn.close()


if __name__ == "__main__":
    signal.alarm(180)
    def deny_network(event, _arguments):
        if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
            raise RuntimeError("migration fixture network refused")
    sys.addaudithook(deny_network)
    if sys.argv[1:] == ["--derive", "/app"]:
        print(json.dumps(derive("/app"), sort_keys=True))
    elif len(sys.argv) == 4 and sys.argv[1] == "--seed":
        seed(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "--cold-start":
        cold_start(sys.argv[2])
    elif len(sys.argv) == 1:
        unittest.main(verbosity=2)
    else:
        raise SystemExit("migration test invocation refused")
