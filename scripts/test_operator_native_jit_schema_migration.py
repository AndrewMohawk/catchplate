#!/usr/bin/env python3
"""Real old358 ordinary SQLite state through the fixed additive aca transition.

Requires immutable /previous-app and /app sources and the independently derived
fixed pins. Real owners initialize encrypted credentials, a client, permission,
signed policy, ordered audit and quota state. Three synthetic quota history rows
are preservation sentinels, not OAuth claims or provider effects. No contract,
signature, startup admission or migration validator is mocked or substituted.

Only disposable /tmp stores are opened in the approved network-none test lane.
This is ordinary SQLite migration evidence, never native/PostgreSQL admission.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from copy import deepcopy
from datetime import datetime, timezone
import fcntl
import os
from pathlib import Path
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import unquote, urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.dont_write_bytecode = True
import migrate_operator_native_jit_schema as migration
import test_operator_authority_contract_migration as historical
import test_operator_authority_contract_migration_x_quota as ordinary

OLD_COMMIT = "35817cf50b0dc87cf06a07c0c9ce273f13af323f"
TARGET_COMMIT = "aca8e74ed8cb2c790342fb3265ba12606ba88005"
TABLE = "policy_authority_native_jit_review_pairs"
CHANGED_FIELDS = {"source_contract_digest", "structural_manifest_json", "structural_manifest_digest"}
STAGES = ("before_create", "after_create", "before_guard", "after_guard", "after_update",
    "after_restore", "before_commit")
SEED_OUTPUT = b'{"oldSourceInitialized":true,"catalogResources":3,"syntheticQuotaRows":3}\n'
START_OUTPUT = b'{"candidateColdStart":true,"xCustodyEmpty":true,"providerCustodyEmpty":true}\n'
_OWNED_ROOT = None


def require(value):
    if not value:
        raise AssertionError("disposable native-pair migration fixture refused")


def source_matches(source, selected):
    """Check actual fixed source bytes before the child imports any app code."""
    pinned = migration.pins()
    require(pinned["oldCommit"] == OLD_COMMIT and pinned["targetBaseCommit"] == TARGET_COMMIT)
    require(not any(name == "serverware" or name.startswith("serverware.")
        or name == "serverware_agent_trust" or name.startswith("serverware_agent_trust.")
        for name in sys.modules))
    for relative, expected in pinned[selected]["sourceFiles"].items():
        path = Path(source) / relative
        require(not path.is_symlink() and path.is_file() and path.resolve().is_relative_to(source)
            and migration.sha(path.read_bytes()) == expected)


def selected_backend(source, directory, *, create):
    source_matches(source, "old" if source == "/previous-app" else "target")
    workspace, custody = ordinary.selected_environment(source, directory, create=create)
    directory = Path(directory)
    provider = directory.with_name(directory.name + ".provider-custody")
    if create:
        directory.mkdir(mode=0o700)
        provider.mkdir(mode=0o700)
    require(provider.is_dir() and not provider.is_symlink()
        and stat.S_IMODE(provider.stat().st_mode) == 0o700 and not list(provider.iterdir()))
    os.environ.update(SERVERWARE_OPERATOR_MANAGED_GOOGLE_ENABLED="1",
        SERVERWARE_OPERATOR_PROVIDER_CUSTODY_DIR=str(provider), SERVERWARE_DECISION_GATE_BASE="")
    from serverware import operator_google_managed_config
    operator_google_managed_config.bootstrap()  # Real cold bootstrap, before configured imports.
    backend = ordinary.backend()
    require(os.environ.get("SERVERWARE_CONTROL_PLANE_STARTUP_VALIDATED_PID") == str(os.getpid())
        and not operator_google_managed_config.selected())
    return workspace, custody, provider, backend


def require_owned_source(source, custody, provider):
    ordinary.require_source(Path(source), custody)
    require(not list(provider.iterdir()))
    require(all(Path(module.__file__).resolve().is_relative_to(source)
        for name, module in tuple(sys.modules.items())
        if name == "serverware_agent_trust" or name.startswith("serverware_agent_trust.")))


def seed(directory):
    workspace, custody, provider, backend = selected_backend("/previous-app", directory, create=True)
    config, db, store, bundles, schema, inputs, mutations = backend
    credential = workspace.create_credential(db, store, schema, inputs, mutations)["credential"]
    application = workspace.create_application(db, store, schema, inputs, mutations)["application"]
    rule = workspace.create_rule(db, store, schema, inputs, mutations,
        application["id"], credential["id"])["access_rule"]
    historical.upstream_fixture()
    # Reproduce the existing genuine-old quota preservation fixture using its
    # actual initialized owners. These rows do not claim authenticated X use.
    from serverware import operator_x_quota as quota, operator_publication as publication
    with publication.exclusive(), closing(db.connect()) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        quota.require_ready(conn)
        initialized = dict(conn.execute("SELECT * FROM " + quota.STATE).fetchone())
        day = initialized["initialized_at_epoch_ms"] // quota.DAY_MS
        created, subject = day * quota.DAY_MS + 12_000, "18446744073709551001"
        bucket = quota._bucket_key(subject, day)
        policy = conn.execute("SELECT policy_hash FROM operator_demo_policy").fetchone()[0]
        conn.execute("INSERT INTO " + quota.ACCOUNTS + " VALUES(?,?,?)", (subject, day, created))
        conn.execute("INSERT INTO " + quota.BUCKETS + " VALUES(?,?,?,1,1)", (bucket, subject, day))
        for index, state in enumerate(("claimed", "reserved", "expired"), 1):
            binding = {"principal_id": application["principal_id"], "route_id": rule["route_id"],
                "credential_id": credential["id"], "credential_version": 1,
                "credential_metadata_digest": "sha256:" + "1" * 64, "policy_hash": policy,
                "request_digest": "sha256:" + str(index) * 64, "operation_digest": "sha256:" + "4" * 64,
                "attempt_nonce": "sha256:" + str(index + 4) * 64, "recipient_digest": "sha256:" + "8" * 64,
                "request_binding_digest": "sha256:" + "9" * 64, "expires_at_epoch_ms": created + 4000}
            conn.execute("INSERT INTO " + quota.ATTEMPTS + " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.UUID(int=index)), binding["attempt_nonce"], bucket, subject, day,
                 quota._json(binding), quota._digest(binding), state, created, created + 4000,
                 created + 1 if state == "claimed" else None))
        for row in conn.execute("SELECT * FROM " + quota.ATTEMPTS):
            quota._attempt(row)
        quota._account(conn, subject)
        quota._bucket(conn, subject, day)
        db.append_audit_event(conn, event_type="operator_migration.synthetic_quota_history",
            actor_type="system", actor_id="migration-preservation-fixture",
            event={"syntheticOnly": True, "claimed": 1, "reserved": 1, "expired": 1})
    workspace.verify_signed(config, db, store, bundles)
    require_owned_source("/previous-app", custody, provider)
    sys.stdout.buffer.write(SEED_OUTPUT)


def cold_start(directory):
    workspace, custody, provider, backend = selected_backend("/app", directory, create=False)
    config, db, store, bundles, _schema, _inputs, _mutations = backend
    workspace.verify_signed(config, db, store, bundles)
    require_owned_source("/app", custody, provider)
    sys.stdout.buffer.write(START_OUTPUT)


def source_refusal(directory):
    changed = deepcopy(migration.pins())
    relative = next(iter(changed["target"]["sourceFiles"]))
    changed["target"]["sourceFiles"][relative] = "sha256:" + "0" * 64
    try:
        migration.source(changed, Path(directory))
    except migration.Refused:
        pass
    else:
        raise AssertionError("caller-authored source pins accepted")
    require(not any(name == "serverware" or name.startswith("serverware.")
        or name == "serverware_agent_trust" or name.startswith("serverware_agent_trust.")
        for name in sys.modules))
    print('{"changedSourceRefusedBeforeImport":true}')


class NativeJitSchemaMigrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        global _OWNED_ROOT
        os.umask(0o077)
        for key in tuple(os.environ):
            if key.startswith("SERVERWARE_"):
                del os.environ[key]
        cls.pinned = migration.pins()  # Absent or unreviewed pins fail, never skip.
        require(cls.pinned["oldCommit"] == OLD_COMMIT and cls.pinned["targetBaseCommit"] == TARGET_COMMIT)
        cls.temporary = tempfile.TemporaryDirectory(prefix="native-pair-migration-", dir="/tmp")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = _OWNED_ROOT = Path(cls.temporary.name)
        cls.seed_path = cls.base / "seed"
        cls.child("--seed", cls.seed_path, expected=SEED_OUTPUT)
        cls.helpers = migration.source(cls.pinned, cls.seed_path)

    @classmethod
    def child(cls, operation, directory, *, expected):
        result = subprocess.run([sys.executable, "-B", __file__, operation, str(directory)],
            env=ordinary.child_environment(), capture_output=True, timeout=55)
        if result.returncode != 0:
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
        self.custody = self.directory.with_name(self.directory.name + ".x-custody")
        self.provider = self.directory.with_name(self.directory.name + ".provider-custody")
        self.custody.mkdir(mode=0o700)
        self.provider.mkdir(mode=0o700)

    @contextmanager
    def db(self):
        with closing(sqlite3.connect(self.directory / migration.DATABASE)) as conn, conn:
            conn.row_factory = sqlite3.Row
            from serverware.authority_store.metadata_schema import configure_sqlite_metadata_connection
            configure_sqlite_metadata_connection(conn)
            yield conn

    def plan(self):
        return migration.plan(self.directory, self.pinned, self.helpers)

    def apply(self, reviewed, **changes):
        return migration.apply(self.directory, self.pinned, self.helpers, reviewed,
            migration.sha(migration.canonical(reviewed)), self.backup, **changes)

    def files(self):
        result = {}
        for path in self.directory.rglob("*"):
            info = path.stat(follow_symlinks=False)
            require(not path.is_symlink())
            relative, mode = str(path.relative_to(self.directory)), stat.S_IMODE(info.st_mode)
            if path.is_dir():
                result[relative] = ("directory", mode)
            else:
                if mode == 0:
                    require(relative in migration.EMPTY_MOUNTPOINTS and info.st_size == 0 and info.st_nlink == 1)
                result[relative] = ("file", mode, migration.sha(b"" if mode == 0 else path.read_bytes()))
        return result

    def logical(self):
        with self.db() as conn:
            tables = sorted(row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type='table'"))
            rows = {}
            for table in tables:
                cursor = conn.execute('SELECT * FROM "' + table + '"')
                rows[table] = {"columns": [field[0] for field in cursor.description],
                    "values": sorted(([migration.shared.typed(cell) for cell in row] for row in cursor),
                        key=migration.canonical)}
            audit = [[migration.shared.typed(cell) for cell in row]
                for row in conn.execute("SELECT rowid,* FROM audit_events ORDER BY rowid")]
            return {"schema": migration.objects(conn), "rows": rows, "orderedAudit": audit,
                "journalMode": conn.execute("PRAGMA journal_mode").fetchone()[0]}

    def assert_preserved_except_addition(self, before, before_files):
        after = self.logical()
        self.assertEqual(set(after["rows"]) - set(before["rows"]), {TABLE})
        self.assertEqual(after["rows"][TABLE]["values"], [])
        additions = [row for row in after["schema"] if row[2] == TABLE]
        self.assertEqual({tuple(row[:2]) for row in additions}, {("table", TABLE),
            *(("index", "sqlite_autoindex_" + TABLE + "_" + str(number)) for number in (1, 2, 3))})
        self.assertEqual(len(additions), 4)
        self.assertTrue(all(row[3] is None for row in additions if row[0] == "index"))
        self.assertEqual([row for row in after["schema"] if row[2] != TABLE], before["schema"])
        old_contract, new_contract = (value["rows"][migration.CONTRACT_TABLE] for value in (before, after))
        self.assertEqual(old_contract["columns"], new_contract["columns"])
        self.assertEqual((len(old_contract["values"]), len(new_contract["values"])), (1, 1))
        changed = {name for name, old, new in zip(old_contract["columns"], old_contract["values"][0],
            new_contract["values"][0]) if old != new}
        self.assertEqual(changed, CHANGED_FIELDS)
        with self.db() as conn:
            admitted = migration.inspect(conn, self.pinned, self.helpers, target=True)
        self.assertEqual(admitted["contract"]["source_contract_digest"], self.pinned["target"]["sourceContractDigest"])
        expected = deepcopy(before)
        expected["schema"] = after["schema"]
        expected["rows"][migration.CONTRACT_TABLE] = new_contract
        expected["rows"][TABLE] = after["rows"][TABLE]
        self.assertEqual(after, expected)  # Every other old value and audit rowid is exact.
        self.assertEqual({k: v for k, v in self.files().items() if k != migration.DATABASE},
            {k: v for k, v in before_files.items() if k != migration.DATABASE})
        self.assertEqual(migration.sha(self.backup.read_bytes()), before_files[migration.DATABASE][2])
        self.assertEqual((list(self.custody.iterdir()), list(self.provider.iterdir())), ([], []))

    def assert_refused_without_write(self, call):
        before = self.files()
        with self.assertRaises(migration.Refused):
            call()
        self.assertEqual(self.files(), before)

    def restore_database(self):
        migration.sidecars_absent(self.directory)
        shutil.copyfile(self.backup, self.directory / migration.DATABASE)

    def test_fixed_pins_bind_exact_old_and_target_sources(self):
        self.assertEqual((migration.OLD_COMMIT, migration.TARGET_COMMIT), (OLD_COMMIT, TARGET_COMMIT))
        self.assertEqual(self.pinned["transitionId"], "native-jit-pair-v1")
        self.assertEqual(migration.sha(migration.PIN_FILE.read_bytes()), migration.PIN_SHA256)
        self.assertEqual((len(self.pinned["old"]["optionalTables"]),
            len(self.pinned["target"]["optionalTables"])), (217, 218))
        self.assertEqual((len(self.pinned["old"]["emptyTables"]),
            len(self.pinned["target"]["emptyTables"])), (185, 186))
        for table in ordinary.QUOTA:
            self.assertNotIn(table, self.pinned["old"]["emptyTables"])
        changed = deepcopy(self.pinned)
        changed["old"]["sourceContractDigest"] = "sha256:" + "0" * 64
        self.assert_refused_without_write(lambda: migration.plan(self.directory, changed, self.helpers))
        self.child("--source-refusal", self.directory, expected=b'{"changedSourceRefusedBeforeImport":true}\n')

    def test_plan_is_read_only_and_transition_changes_only_three_cells_and_four_objects(self):
        before, files = self.logical(), self.files()
        identities = {str(path): migration.identity(path.stat()) for path in self.directory.rglob("*")}
        reviewed = self.plan()
        self.assertEqual(self.files(), files)
        self.assertEqual({str(path): migration.identity(path.stat()) for path in self.directory.rglob("*")}, identities)
        self.assertEqual(reviewed["schema"], "serverware.operatorNativeJitSchemaMigrationPlan/v1")
        self.assertEqual(reviewed["variant"], "optional")
        self.assertEqual(len(reviewed["rows"]), 217)
        for table in ("credentials", "credential_generations", "operator_catalog_credentials",
                "operator_catalog_applications", "operator_catalog_rules", "operator_demo_policy",
                "audit_events", "operator_upstream_setups", *ordinary.QUOTA):
            self.assertGreater(reviewed["rows"][table]["count"], 0, table)
        self.assertEqual(reviewed["rows"][ordinary.QUOTA[3]]["count"], 3)
        for name in ("master.key", "mitmproxy/mitmproxy-ca.pem", "mitmproxy/mitmproxy-ca-cert.pem"):
            self.assertIn(name, files)
        receipt = self.apply(reviewed)
        self.assertEqual((receipt["status"], receipt["newTableRows"]), ("committed", 0))
        self.assertEqual(receipt["schema"], "serverware.operatorNativeJitSchemaMigrationReceipt/v1")
        self.assertEqual(receipt["pinsSha256"], migration.PIN_SHA256)
        self.assertEqual(receipt["planSha256"], migration.sha(migration.canonical(reviewed)))
        self.assertEqual(receipt["orderedAudit"], reviewed["orderedAudit"])
        self.assert_preserved_except_addition(before, files)
        with self.db() as conn, self.assertRaises(sqlite3.IntegrityError):
            conn.execute("UPDATE policy_authority_schema_contracts SET installed_at='changed'")
        self.assert_refused_without_write(self.plan)
        self.assert_refused_without_write(lambda: self.apply(reviewed))

    def test_two_actual_target_starts_preserve_all_rows_except_existing_startup_timestamp(self):
        self.apply(self.plan())
        for _ in range(2):
            before, files = self.logical(), self.files()
            started = datetime.now(timezone.utc)
            self.child("--cold-start", self.directory, expected=START_OUTPUT)
            finished, after = datetime.now(timezone.utc), self.logical()
            rows = after["rows"]["serverware_store_migrations"]
            name_index, time_index = rows["columns"].index("migration"), rows["columns"].index("applied_at")
            selected = [row for row in rows["values"] if row[name_index] == ["str", "policy_candidate_authority"]]
            prior = [row for row in before["rows"]["serverware_store_migrations"]["values"]
                if row[name_index] == ["str", "policy_candidate_authority"]]
            self.assertEqual((len(selected), len(prior)), (1, 1))
            observed = datetime.fromisoformat(selected[0][time_index][1])
            self.assertIsNotNone(observed.utcoffset())
            self.assertGreaterEqual(observed, started)
            self.assertLessEqual(observed, finished)
            selected[0][time_index] = prior[0][time_index]
            rows["values"].sort(key=migration.canonical)
            self.assertEqual(after, before)
            self.assertEqual({k: v for k, v in self.files().items() if k != migration.DATABASE},
                {k: v for k, v in files.items() if k != migration.DATABASE})
            with self.db() as conn:
                migration.inspect(conn, self.pinned, self.helpers, target=True)
            self.assertEqual((list(self.custody.iterdir()), list(self.provider.iterdir())), ([], []))

    def test_each_precommit_failure_rolls_back_ddl_cells_guards_and_all_bytes(self):
        for stage in STAGES:
            with self.subTest(stage=stage):
                reviewed, before, files = self.plan(), self.logical(), self.files()
                sentinel, reached = RuntimeError("synthetic rollback"), []
                def fail(actual):
                    reached.append(actual)
                    if actual == stage:
                        raise sentinel
                with self.assertRaises(RuntimeError) as raised:
                    self.apply(reviewed, checkpoint=fail)
                self.assertIs(raised.exception, sentinel)
                self.assertEqual(reached[-1], stage)
                self.assertEqual(self.files(), files)
                self.assertEqual(self.logical(), before)
                replanned = self.plan()
                # Rollback can change inode mtime/ctime but not any content.
                self.assertEqual({k: v for k, v in replanned.items() if k != "databaseIdentity"},
                    {k: v for k, v in reviewed.items() if k != "databaseIdentity"})

    def test_lost_postcommit_receipt_is_unknown_outcome_not_retry_or_rollback(self):
        reviewed, before, files = self.plan(), self.logical(), self.files()
        sentinel = RuntimeError("synthetic external receipt loss")
        reached = []
        def fail(stage):
            reached.append(stage)
            if stage == "after_commit":
                raise sentinel
        with self.assertRaises(RuntimeError) as raised:
            self.apply(reviewed, checkpoint=fail)
        self.assertIs(raised.exception, sentinel)
        self.assertEqual(reached, [*STAGES, "after_commit"])
        self.assert_preserved_except_addition(before, files)
        self.assert_refused_without_write(self.plan)
        self.assert_refused_without_write(lambda: self.apply(reviewed))

    def test_nonempty_old_authority_and_challenge_refused(self):
        cases = (("rbac_authority_state", "INSERT INTO rbac_authority_state "
            "(authority_id,generation,state_digest,updated_at) VALUES(1,0,?,'2026-10-12T00:00:00+00:00')",
            ("sha256:" + "1" * 64,)),
            ("webauthn_challenges", "INSERT INTO webauthn_challenges "
             "(id,challenge,challenge_type,user_id,payload_json,expires_at,created_at) VALUES(?,?,?,?,?,?,?)",
             (str(uuid.UUID(int=91)), "synthetic-challenge", "jit.deny", "synthetic-user", "{}",
              "2030-01-01T00:01:00+00:00", "2030-01-01T00:00:00+00:00")))
        for table, sql, arguments in cases:
            with self.subTest(table=table):
                reviewed = self.plan()
                self.assertIn(table, self.pinned["old"]["emptyTables"])
                with self.db() as conn:
                    conn.execute(sql, arguments)
                self.assert_refused_without_write(self.plan)
                self.assert_refused_without_write(lambda: self.apply(reviewed))
                self.restore_database()

    def test_nonempty_recovery_witness_refused(self):
        reviewed = self.plan()
        with closing(sqlite3.connect(self.directory / migration.WITNESS)) as conn, conn:
            conn.execute("INSERT INTO recovery_witness_heads (root_key_id,user_id,last_sequence,updated_at) "
                "VALUES('synthetic-root','synthetic-user',1,'2026-10-12T00:00:00+00:00')")
        self.assert_refused_without_write(self.plan)
        self.assert_refused_without_write(lambda: self.apply(reviewed))

    def test_preexisting_actual_new_table_is_not_adopted(self):
        reviewed = self.plan()
        with self.db() as conn:
            self.helpers[0]._execute_metadata_schema_statements(conn, self.helpers[3])
            self.assertEqual(conn.execute('SELECT count(*) FROM "' + TABLE + '"').fetchone()[0], 0)
        self.assert_refused_without_write(self.plan)
        self.assert_refused_without_write(lambda: self.apply(reviewed))

    def test_changed_old_schema_unknown_table_and_partial_quota_refused(self):
        for sql in ("ALTER TABLE approval_requests ADD COLUMN unreviewed TEXT",
                "CREATE TABLE unreviewed_table(value TEXT)", "DROP INDEX operator_x_quota_expiry"):
            with self.subTest(sql=sql):
                reviewed = self.plan()
                with self.db() as conn:
                    conn.execute(sql)
                self.assert_refused_without_write(self.plan)
                self.assert_refused_without_write(lambda: self.apply(reviewed))
                self.restore_database()

    def test_stale_plan_and_changed_closed_plan_fields_refused(self):
        reviewed = self.plan()
        for change in ({"schema": "serverware.operatorAuthorityContractMigrationPlan/v1"},
                {"transitionId": "historical"}, {"extra": True}, {"pinsSha256": "sha256:" + "0" * 64}):
            self.assert_refused_without_write(lambda: self.apply({**reviewed, **change}))
        self.assert_refused_without_write(lambda: migration.apply(self.directory, self.pinned, self.helpers,
            reviewed, "sha256:" + "0" * 64, self.backup))
        with self.db() as conn:
            conn.execute("UPDATE operator_catalog_state SET revision=revision+1")
        self.assert_refused_without_write(lambda: self.apply(reviewed))

    def test_wrong_hardlinked_and_symlinked_backup_refused(self):
        reviewed, raw = self.plan(), self.backup.read_bytes()
        self.backup.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
        self.assert_refused_without_write(lambda: self.apply(reviewed))
        self.backup.unlink()
        os.link(self.directory / migration.DATABASE, self.backup)
        self.assert_refused_without_write(lambda: self.apply(reviewed))
        self.backup.unlink()
        self.backup.write_bytes(raw)
        alias = self.base / (self._testMethodName + ".alias")
        alias.symlink_to(self.backup)
        self.assert_refused_without_write(lambda: migration.apply(self.directory, self.pinned, self.helpers,
            self.plan(), migration.sha(migration.canonical(self.plan())), alias))

    def test_marker_sidecar_and_live_writer_refused(self):
        marker = self.directory / migration.MARKER
        raw = marker.read_bytes()
        marker.unlink()
        before = self.files()
        with self.assertRaises((OSError, migration.Refused)):
            self.plan()
        self.assertEqual(self.files(), before)
        marker.write_bytes(raw)
        marker.chmod(0o600)
        sidecar = self.directory / (migration.DATABASE + "-wal")
        sidecar.write_bytes(b"synthetic stale WAL")
        self.assert_refused_without_write(self.plan)
        sidecar.unlink()
        with (self.directory / (migration.DATABASE + ".migration.lock")).open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises((OSError, migration.Refused)):
                self.plan()
        reviewed = self.plan()
        with closing(sqlite3.connect(self.directory / migration.DATABASE)) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("UPDATE operator_catalog_state SET revision=revision+1")
                with self.assertRaises((OSError, sqlite3.Error, migration.Refused)):
                    self.apply(reviewed)
            finally:
                conn.rollback()


def local_only(event, arguments):
    if event.startswith("socket.") or event in {"os.system", "os.exec", "os.posix_spawn"}:
        raise RuntimeError("migration fixture external I/O refused")
    if event == "sqlite3.connect" and arguments[0] != ":memory:":
        raw = os.fspath(arguments[0])
        path = Path(unquote(urlsplit(raw).path)) if raw.startswith("file:") else Path(raw)
        require(_OWNED_ROOT is not None and path.is_absolute()
            and path.resolve().is_relative_to(_OWNED_ROOT.resolve()))


if __name__ == "__main__":
    os.umask(0o077)
    signal.alarm(240)
    sys.addaudithook(local_only)
    if len(sys.argv) == 3 and sys.argv[1] in {"--seed", "--cold-start", "--source-refusal"}:
        _OWNED_ROOT = Path(sys.argv[2])
        require(_OWNED_ROOT.is_absolute() and _OWNED_ROOT.is_relative_to("/tmp")
            and _OWNED_ROOT != Path("/tmp"))
        {"--seed": seed, "--cold-start": cold_start, "--source-refusal": source_refusal}[sys.argv[1]](sys.argv[2])
    elif len(sys.argv) == 1:
        unittest.main(verbosity=2)
    else:
        raise SystemExit("migration test invocation refused")
