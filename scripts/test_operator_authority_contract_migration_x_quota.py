#!/usr/bin/env python3
"""Fixed ordinary SQLite transition with genuinely old-source initialized state.

Requires immutable /previous-app and /app trees plus the actual reviewed pin
file; never substitutes test pins or rewrites a database's original contract.
Catalog creation, encryption, policy signing, quota initialization and audit
appending use the old application's real owners. The three explicitly synthetic
quota history rows are preservation sentinels, NOT admitted OAuth claims,
provider effects, measured authority or native/PostgreSQL migration evidence.
Only fresh private /tmp stores are opened. No live services or network are used.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from copy import deepcopy
from datetime import datetime, timezone
from functools import partial
import json
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import migrate_operator_authority_contract as migration
import test_operator_authority_contract_migration as historical

TRANSITION = "jit-denial-quota-v1"
QUOTA = tuple("operator_x_quota_" + name for name in ("state", "accounts", "buckets", "attempts"))
HISTORICAL_PIN = "sha256:4199bfe9362e1f7990a612e5b1cae9b7603dc2908c953ea8ea6201f602dd8e5f"


def require(value):
    if not value:
        raise AssertionError("disposable quota migration fixture refused")


def child_environment():
    return {key: value for key, value in os.environ.items() if not key.startswith("CATCHPLATE_")}


def selected_environment(source, directory, *, create):
    """Select real development admission before importing any catchplate code."""
    source, directory = Path(source), Path(directory)
    require(str(source) in {"/app", "/previous-app"} and source.is_dir()
        and directory.is_absolute() and directory.is_relative_to("/tmp")
        and directory.parent.is_dir() and directory.exists() != create)
    require(not any(name == "catchplate" or name.startswith("catchplate.") for name in sys.modules))
    custody = directory.with_name(directory.name + ".x-custody")
    if create:
        custody.mkdir(mode=0o700)
    require(custody.is_dir() and not custody.is_symlink()
        and stat.S_IMODE(custody.stat().st_mode) == 0o700 and not list(custody.iterdir()))
    for key in tuple(os.environ):
        if key.startswith("CATCHPLATE_"):
            del os.environ[key]
    sys.path[:0] = [str(source / "scripts"), str(source)]
    import test_operator_workspace_store as workspace
    require(Path(workspace.__file__).resolve().is_relative_to(source))
    os.environ.update(workspace.common._ENVIRONMENT)
    os.environ.update(CATCHPLATE_DATA_DIR=str(directory), CATCHPLATE_OPERATOR_MANAGED_X_ENABLED="1",
        CATCHPLATE_OPERATOR_X_POST_ATTEMPT_QUOTA_ENABLED="1", CATCHPLATE_OPERATOR_GATE_PUBLICATION_ENABLED="1",
        CATCHPLATE_PUBLIC_URL="https://console.example.com", CATCHPLATE_OPERATOR_X_CUSTODY_DIR=str(custody))
    return workspace, custody


def require_source(source, custody):
    require(not list(custody.iterdir()))
    require(all(Path(module.__file__).resolve().is_relative_to(source)
        for name, module in tuple(sys.modules.items()) if name == "catchplate" or name.startswith("catchplate.")))


def backend():
    from catchplate import operator_demo
    operator_demo.activate()
    from catchplate.control_plane_startup import validate_control_plane_startup
    validate_control_plane_startup()
    from catchplate import config, db, operator_demo_store, policy_bundle
    from catchplate import operator_catalog_schema, operator_catalog_inputs, operator_catalog_mutations
    return config, db, operator_demo_store, policy_bundle, operator_catalog_schema, operator_catalog_inputs, operator_catalog_mutations


def seed(directory):
    workspace, custody = selected_environment("/previous-app", directory, create=True)
    config, db, store, bundles, schema, inputs, mutations = backend()
    credential = workspace.create_credential(db, store, schema, inputs, mutations)["credential"]
    application = workspace.create_application(db, store, schema, inputs, mutations)["application"]
    rule = workspace.create_rule(db, store, schema, inputs, mutations,
        application["id"], credential["id"])["access_rule"]
    historical.upstream_fixture()
    from catchplate import operator_x_quota as quota, operator_publication as publication
    with publication.exclusive(), closing(db.connect()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        quota.require_ready(conn)  # Real admitted, initialized old-source store.
        initialized = dict(conn.execute("SELECT * FROM " + quota.STATE).fetchone())
        day = initialized["initialized_at_epoch_ms"] // quota.DAY_MS
        created = day * quota.DAY_MS + 12_000
        subject = "18446744073709551001"
        bucket = quota._bucket_key(subject, day)
        policy = conn.execute("SELECT policy_hash FROM operator_demo_policy").fetchone()[0]
        conn.execute("INSERT INTO " + quota.ACCOUNTS + " VALUES(?,?,?)", (subject, day, created))
        conn.execute("INSERT INTO " + quota.BUCKETS + " VALUES(?,?,?,1,1)", (bucket, subject, day))
        for index, state in enumerate(("claimed", "reserved", "expired"), 1):
            binding = {"principal_id": application["principal_id"], "route_id": rule["route_id"],
                "credential_id": credential["id"], "credential_version": 1,
                "credential_metadata_digest": "sha256:" + "1" * 64, "policy_hash": policy,
                "request_digest": "sha256:" + str(index) * 64, "operation_digest": "sha256:" + "4" * 64,
                "attempt_nonce": "sha256:" + str(index + 4) * 64,
                "recipient_digest": "sha256:" + "8" * 64, "request_binding_digest": "sha256:" + "9" * 64,
                "expires_at_epoch_ms": created + 4000}
            conn.execute("INSERT INTO " + quota.ATTEMPTS + " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.UUID(int=index)), binding["attempt_nonce"], bucket, subject, day,
                 quota._json(binding), quota._digest(binding), state, created, created + 4000,
                 created + 1 if state == "claimed" else None))
        # Validate actual row constraints/digests without pretending that a
        # static credential is an authenticated X account or admitting a claim.
        for row in conn.execute("SELECT * FROM " + quota.ATTEMPTS):
            quota._attempt(row)
        quota._account(conn, subject)
        quota._bucket(conn, subject, day)
        db.append_audit_event(conn, event_type="operator_migration.synthetic_quota_history",
            actor_type="system", actor_id="migration-preservation-fixture",
            event={"syntheticOnly": True, "claimed": 1, "reserved": 1, "expired": 1})
    workspace.verify_signed(config, db, store, bundles)
    require_source(Path("/previous-app"), custody)
    print('{"oldSourceInitialized":true,"catalogResources":3,"syntheticQuotaRows":3}')


def cold_start(directory):
    workspace, custody = selected_environment("/app", directory, create=False)
    config, db, store, bundles, _schema, _inputs, _mutations = backend()
    workspace.verify_signed(config, db, store, bundles)
    require_source(Path("/app"), custody)
    print('{"candidateColdStart":true,"xCustodyEmpty":true}')


def source_refusal(directory):
    pinned = migration.pins(TRANSITION)
    changed = deepcopy(pinned)
    relative = next(iter(changed["target"]["sourceFiles"]))
    changed["target"]["sourceFiles"][relative] = "sha256:" + "0" * 64
    require(not any(name == "catchplate" or name.startswith("catchplate.") for name in sys.modules))
    try:
        migration.source(changed, Path(directory))
    except migration.Refused:
        pass
    else:
        raise AssertionError("changed source accepted")
    require(not any(name == "catchplate" or name.startswith("catchplate.") for name in sys.modules))
    print('{"changedSourceRefusedBeforeImport":true}')


class QuotaMigrationTests(historical.MigrationTests):
    # Retain the historical real transaction/rollback/backup/lock/schema controls.
    # Only their explicit profile seam changes; the actual engine still runs.
    @classmethod
    def setUpClass(cls):
        os.umask(0o077)
        for key in tuple(os.environ):
            if key.startswith("CATCHPLATE_"):
                del os.environ[key]
        cls.pinned = migration.pins(TRANSITION)  # Missing/unreviewed pins fail; never skip or replace them.
        require(cls.pinned["oldCommit"].startswith("a3899a95")
            and cls.pinned["targetBaseCommit"].startswith("6c6d6511"))
        cls.temporary = tempfile.TemporaryDirectory(prefix="operator-quota-migration-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = Path(cls.temporary.name)
        cls.seed_path = cls.base / "seed"
        cls.child("--seed", cls.seed_path, expected=b'{"oldSourceInitialized":true,"catalogResources":3,"syntheticQuotaRows":3}\n')
        cls.helpers = migration.source(cls.pinned, cls.seed_path)
        cls.migration = SimpleNamespace(**{**vars(migration),
            "apply": partial(migration.apply, transition=TRANSITION)})

    @classmethod
    def child(cls, operation, directory, *, expected):
        result = subprocess.run([sys.executable, "-B", __file__, operation, str(directory)],
            env=child_environment(), capture_output=True, timeout=50)
        if result.returncode != 0:
            # All state is disposable synthetic data; retain bounded failure
            # location rather than turn an unsuccessful initialization green.
            raise AssertionError("migration child failed: " + result.stderr.decode(errors="replace")[-3000:])
        require(result.stdout == expected)

    def setUp(self):
        self.directory = self.base / self._testMethodName
        def copy(source, destination):
            info = Path(source).stat()
            if stat.S_IMODE(info.st_mode) == 0:
                require(str(Path(source).relative_to(self.seed_path)) in migration.EMPTY_MOUNTPOINTS
                    and stat.S_ISREG(info.st_mode) and info.st_size == 0 and info.st_nlink == 1)
                Path(destination).touch(mode=0, exist_ok=False)
                return destination
            return shutil.copy2(source, destination)
        shutil.copytree(self.seed_path, self.directory, copy_function=copy)
        self.backup = self.base / (self._testMethodName + ".backup")
        shutil.copyfile(self.directory / migration.DATABASE, self.backup)
        self.backup.chmod(0o600)
        self.m = self.migration
        self.custody = self.directory.with_name(self.directory.name + ".x-custody")
        self.custody.mkdir(mode=0o700)

    @contextmanager
    def db(self):
        with closing(sqlite3.connect(self.directory / migration.DATABASE)) as conn, conn:
            conn.row_factory = sqlite3.Row
            from catchplate.authority_store.metadata_schema import configure_sqlite_metadata_connection
            configure_sqlite_metadata_connection(conn)
            yield conn

    def plan(self):
        return migration.plan(self.directory, self.pinned, self.helpers, transition=TRANSITION)

    def apply(self, reviewed, **changes):
        return migration.apply(self.directory, self.pinned, self.helpers, reviewed,
            migration.sha(migration.canonical(reviewed)), self.backup, transition=TRANSITION, **changes)

    def files(self):
        result = {}
        for path in self.directory.rglob("*"):
            if path.is_file():
                relative, info = str(path.relative_to(self.directory)), path.stat()
                mode = stat.S_IMODE(info.st_mode)
                if mode == 0:
                    require(relative in migration.EMPTY_MOUNTPOINTS and info.st_size == 0 and info.st_nlink == 1)
                result[relative] = (mode, migration.sha(b"" if mode == 0 else path.read_bytes()))
        return result

    def snapshot(self):
        return self.files()  # Historical rollback guards also cover the unreadable empty mountpoints.

    def logical(self):
        with self.db() as conn:
            tables = sorted(row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'"))
            rows = {}
            for table in tables:
                cursor = conn.execute('SELECT * FROM "' + table + '"')
                rows[table] = {"columns": [field[0] for field in cursor.description],
                    "values": sorted(([migration.typed(cell) for cell in row] for row in cursor), key=migration.canonical)}
            audit = [[migration.typed(cell) for cell in row]
                for row in conn.execute("SELECT rowid,* FROM audit_events ORDER BY rowid")]
            return {"schema": migration.objects(conn), "rows": rows, "orderedAudit": audit,
                "journalMode": conn.execute("PRAGMA journal_mode").fetchone()[0]}

    def assert_logical_equal(self, left, right):
        self.assertEqual(migration.sha(migration.canonical(left)), migration.sha(migration.canonical(right)))

    def restore_database(self):
        migration.sidecars_absent(self.directory)
        shutil.copyfile(self.backup, self.directory / migration.DATABASE)

    def test_fixed_selector_and_actual_pins_cannot_cross_or_default(self):
        self.assertEqual(migration.PIN_SHA256, HISTORICAL_PIN)
        self.assertEqual(migration.pins(), migration.pins("historical"))
        self.assertNotIn("transitionId", migration.pins())
        self.assertEqual(self.pinned["transitionId"], TRANSITION)
        for table in QUOTA:
            self.assertIn(table, self.pinned["target"]["tables"])
            self.assertNotIn(table, self.pinned["target"]["emptyTables"])
        self.assertEqual(len(self.pinned["target"]["optionalTables"]), 217)
        before = self.files()
        with patch.object(migration, "admitted_directory", side_effect=AssertionError("unexpected database admission")):
            for selected, pinned in (("unknown", self.pinned), ("historical", self.pinned),
                    (TRANSITION, migration.pins())):
                with self.subTest(selected=selected), self.assertRaises(migration.Refused):
                    migration.plan(self.directory, pinned, self.helpers, transition=selected)
            with patch.object(migration, "X_QUOTA_PIN_SHA256", None), \
                    patch.object(Path, "read_bytes", side_effect=AssertionError("unreviewed pin file opened")):
                with self.assertRaises(migration.Refused):
                    migration.pins(TRANSITION)
        self.assertEqual(self.files(), before)

    def test_plan_read_only_then_exact_single_cell_transition(self):
        before_files, before = self.files(), self.logical()
        reviewed = self.plan()
        self.assertEqual(self.files(), before_files)
        self.assertEqual(reviewed["transitionId"], TRANSITION)
        self.assertEqual(reviewed["pinsSha256"], migration.X_QUOTA_PIN_SHA256)
        for table in ("credentials", "credential_generations", "operator_catalog_credentials",
                "operator_catalog_applications", "operator_catalog_rules", "audit_events", *QUOTA):
            self.assertGreater(reviewed["rows"][table]["count"], 0, table)
        self.assertEqual(reviewed["rows"][QUOTA[3]]["count"], 3)
        self.assertIn("mitmproxy/mitmproxy-ca.pem", before_files)
        self.assertIn("mitmproxy/mitmproxy-ca-cert.pem", before_files)
        self.assertIn("master.key", before_files)
        receipt = self.apply(reviewed)
        self.assertEqual(receipt["status"], "committed")
        self.assertEqual(receipt["transitionId"], TRANSITION)
        self.assertEqual(receipt["pinsSha256"], migration.X_QUOTA_PIN_SHA256)
        expected = deepcopy(before)
        contract = expected["rows"][migration.CONTRACT_TABLE]
        self.assertEqual(len(contract["values"]), 1)
        position = contract["columns"].index("source_contract_digest")
        self.assertEqual(contract["values"][0][position], ["str", self.pinned["old"]["sourceContractDigest"]])
        contract["values"][0][position] = ["str", self.pinned["target"]["sourceContractDigest"]]
        self.assert_logical_equal(self.logical(), expected)
        self.assertEqual({k: v for k, v in self.files().items() if k != migration.DATABASE},
            {k: v for k, v in before_files.items() if k != migration.DATABASE})
        self.assertEqual(migration.sha(self.backup.read_bytes()), before_files[migration.DATABASE][1])
        self.assertEqual(list(self.custody.iterdir()), [])
        with self.db() as conn, self.assertRaises(sqlite3.IntegrityError):
            conn.execute("UPDATE policy_authority_schema_contracts SET installed_at='changed'")
        terminal = self.files()
        for call in (self.plan, lambda: self.apply(reviewed)):
            with self.assertRaises(migration.Refused):
                call()
            self.assertEqual(self.files(), terminal)

    def test_two_candidate_starts_preserve_quota_audit_and_all_but_one_timestamp(self):
        self.apply(self.plan())
        for _ in range(2):
            before, files = self.logical(), self.files()
            started = datetime.now(timezone.utc)
            self.child("--cold-start", self.directory, expected=b'{"candidateColdStart":true,"xCustodyEmpty":true}\n')
            finished = datetime.now(timezone.utc)
            after = self.logical()
            rows = after["rows"]["catchplate_store_migrations"]
            name_index, time_index = rows["columns"].index("migration"), rows["columns"].index("applied_at")
            selected = [row for row in rows["values"] if row[name_index] == ["str", "policy_candidate_authority"]]
            prior = [row for row in before["rows"]["catchplate_store_migrations"]["values"]
                if row[name_index] == ["str", "policy_candidate_authority"]]
            self.assertEqual((len(selected), len(prior)), (1, 1))
            observed = datetime.fromisoformat(selected[0][time_index][1])
            self.assertIsNotNone(observed.utcoffset())
            self.assertGreaterEqual(observed, started)
            self.assertLessEqual(observed, finished)
            selected[0][time_index] = prior[0][time_index]
            rows["values"].sort(key=migration.canonical)
            self.assert_logical_equal(after, before)
            self.assertEqual({k: v for k, v in self.files().items() if k != migration.DATABASE},
                {k: v for k, v in files.items() if k != migration.DATABASE})
            self.assertEqual(list(self.custody.iterdir()), [])

    def test_nonempty_denial_challenge_and_raw_history_refuse_without_changes(self):
        # Constraint-valid hostile sentinels, not accepted assertions/authority.
        cases = (
            ("webauthn_challenges", "INSERT INTO webauthn_challenges "
             "(id,challenge,challenge_type,user_id,payload_json,expires_at,created_at) VALUES(?,?,?,?,?,?,?)",
             (str(uuid.UUID(int=91)), "synthetic-challenge", "jit.deny", "synthetic-user", "{}",
              "2030-01-01T00:01:00+00:00", "2030-01-01T00:00:00+00:00")),
            ("policy_authority_webauthn_assertion_receipts", "INSERT INTO policy_authority_webauthn_assertion_receipts "
             "(assertion_receipt_digest,capability_id,operation_id,operation,request_digest,challenge_id,"
             "credential_record_id,credential_id,credential_policy_digest,trust_high_water_digest,"
             "client_data_json_digest,authenticator_data_digest,signature_digest,flags,prior_counter,counter,"
             "receipt_json,verified_at_epoch_ns) VALUES(" + ",".join("?" for _ in range(18)) + ")",
             ("sha256:" + "1" * 64, "synthetic-capability", "synthetic-operation", "jit.deny",
              "sha256:" + "2" * 64, str(uuid.UUID(int=92)), "synthetic-record", "synthetic-credential",
              *("sha256:" + character * 64 for character in "34567"), 5, 0, 1, "{}", 1)),
        )
        for table, sql, arguments in cases:
            with self.subTest(table=table):
                self.assertIn(table, self.pinned["target"]["emptyTables"])
                with self.db() as conn:
                    conn.execute(sql, arguments)
                before = self.files()
                with self.assertRaises(migration.Refused):
                    self.plan()
                self.assertEqual(self.files(), before)
                self.restore_database()

    def test_partial_quota_schema_and_opposite_plan_selector_refuse(self):
        reviewed = self.plan()
        with self.assertRaises(migration.Refused):
            migration.apply(self.directory, self.pinned, self.helpers, reviewed,
                migration.sha(migration.canonical(reviewed)), self.backup)
        for key, value in (("transitionId", "historical"), ("pinsSha256", HISTORICAL_PIN)):
            with self.assertRaises(migration.Refused):
                self.apply({**reviewed, key: value})
        with self.db() as conn:
            conn.execute("DROP INDEX operator_x_quota_expiry")
        before = self.files()
        with self.assertRaises(migration.Refused):
            self.plan()
        self.assertEqual(self.files(), before)

    def test_changed_actual_source_is_refused_before_application_import(self):
        self.child("--source-refusal", self.directory, expected=b'{"changedSourceRefusedBeforeImport":true}\n')


if __name__ == "__main__":
    os.umask(0o077)
    signal.alarm(240)
    def deny_network(event, _arguments):
        if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
            raise RuntimeError("migration fixture network refused")
    sys.addaudithook(deny_network)
    if len(sys.argv) == 3 and sys.argv[1] in {"--seed", "--cold-start", "--source-refusal"}:
        {"--seed": seed, "--cold-start": cold_start, "--source-refusal": source_refusal}[sys.argv[1]](sys.argv[2])
    elif len(sys.argv) == 1:
        unittest.main(verbosity=2)
    else:
        raise SystemExit("migration test invocation refused")
