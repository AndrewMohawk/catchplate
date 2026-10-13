#!/usr/bin/env python3
"""Single-process real SQLite quota components, not account/provider acceptance.

Admission/publication ownership and the retained public configuration are
explicit fixture doubles. The actual catalog account/route/currentness join,
lease metadata projection, quota SQL constraints and real audit appender run.
No tokens, provider contacts, production database or synthetic native authority
are involved. The separate joined lifecycle/proxy fixture owns those claims.
"""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def no_external_effects(event, _args):
    if event in {"socket.connect", "socket.getaddrinfo", "socket.bind"} or event.startswith("subprocess."):
        raise AssertionError("quota component tests forbid network and child processes")


sys.addaudithook(no_external_effects)
from serverware import app, db, operator_publication as publication
from serverware import operator_x_quota as quota
from serverware import operator_x_configuration as configuration
from serverware import operator_x_oauth_profile as profiles
from serverware import operator_catalog_x_oauth as accounts
from serverware import operator_catalog_x_post as posting

IDS = [str(uuid.UUID(int=n)) for n in range(1, 20)]
POLICY = "sha256:" + "a" * 64
STAMP = "2030-03-17T12:00:00+00:00"


class QuotaStorageTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        directory = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="x-quota-component-"))
        self.path = Path(directory) / "component.sqlite3"
        self.conn = self.open()
        self.addCleanup(self.conn.close)
        self.now = 22_000 * quota.DAY_MS + 12_000
        self.held, self.admitted, self.sequence = False, True, 0
        self.profile = profiles.build_profile(client_id="synthetic-component-client",
            public_origin="https://console.example.com")
        self.configuration = {"owner_id": IDS[0], "operation_id": IDS[1], "config_version": 1,
            "profile_binding_digest": self.profile.binding_digest,
            "public_profile": profiles.public_record(self.profile)}
        self.stack.enter_context(patch.dict(os.environ, {quota.FLAG: "1"}))
        self.stack.enter_context(patch.object(quota.admission, "require_runtime", side_effect=self.require_runtime))
        self.stack.enter_context(patch.object(quota.admission, "check_connection", side_effect=self.check_connection))
        self.stack.enter_context(patch.object(publication, "assert_held", side_effect=self.assert_held))
        self.stack.enter_context(patch.object(configuration, "retained_public_binding",
            side_effect=lambda _conn: deepcopy(self.configuration)))
        self.stack.enter_context(patch.object(quota, "_clock", side_effect=lambda: self.now))
        self.stack.enter_context(patch.object(accounts.time, "time_ns", side_effect=lambda: self.now * 1_000_000))
        self.stack.enter_context(patch.object(db, "audit_uses_postgres", return_value=False))
        self.conn.executescript("""
            CREATE TABLE operator_catalog_state(singleton INTEGER PRIMARY KEY,schema_version INTEGER,revision INTEGER);
            INSERT INTO operator_catalog_state VALUES(1,1,1);
            CREATE TABLE operator_catalog_credentials(id TEXT PRIMARY KEY,ordinal INTEGER,data_json TEXT);
            CREATE TABLE operator_catalog_applications(id TEXT PRIMARY KEY,ordinal INTEGER,data_json TEXT);
            CREATE TABLE operator_catalog_rules(id TEXT PRIMARY KEY,ordinal INTEGER,data_json TEXT);
            CREATE TABLE operator_demo_policy(singleton INTEGER PRIMARY KEY,policy_hash TEXT);
            CREATE TABLE credentials(id TEXT PRIMARY KEY,kind TEXT,credential_version INTEGER,metadata TEXT,lifecycle_status TEXT);
            CREATE TABLE audit_events(id TEXT PRIMARY KEY,event_type TEXT,actor_type TEXT,actor_id TEXT,event_json TEXT,
                storage_format_version INTEGER,prev_event_hash TEXT,event_hash TEXT,created_at TEXT);
            CREATE INDEX audit_events_type_created_at ON audit_events(event_type,created_at);
        """)
        self.conn.execute("INSERT INTO operator_demo_policy VALUES(1,?)", (POLICY,))
        self.conn.commit()
        with self.transaction():
            quota.initialize(self.conn)
        self.add_identity(IDS[3], "123456789", IDS[4], IDS[5])

    def open(self):
        conn = sqlite3.connect(self.path, timeout=0.03)
        conn.row_factory = sqlite3.Row
        return conn

    def require_runtime(self):
        if not self.admitted:
            raise RuntimeError("synthetic native admission refusal")
        return self

    def check_connection(self, conn, selected):
        self.assertIs(selected, self)
        self.assertIsInstance(conn, sqlite3.Connection)
        self.assertTrue(conn.in_transaction)

    def assert_held(self):
        if not self.held:
            raise RuntimeError("synthetic missing publication owner")

    @contextmanager
    def transaction(self, *, read_only=False, conn=None):
        conn = self.conn if conn is None else conn
        previous = self.held
        self.held = True
        try:
            conn.execute("PRAGMA query_only=" + ("ON" if read_only else "OFF"))
            conn.execute("BEGIN" if read_only else "BEGIN IMMEDIATE")
            with conn:
                yield conn
        finally:
            self.held = previous

    def save(self, table, record):
        row = deepcopy(record)
        identifier = row.pop("id")
        ordinal = row.pop("ordinal", 1)
        self.conn.execute("INSERT OR REPLACE INTO " + table + " VALUES(?,?,?)",
            (identifier, ordinal, json.dumps(row)))

    def record(self, table, identifier):
        row = self.conn.execute("SELECT * FROM " + table + " WHERE id=?", (identifier,)).fetchone()
        return {"id": row["id"], "ordinal": row["ordinal"], **json.loads(row["data_json"])}

    def add_identity(self, credential_id, subject, application_id, rule_id, *, maximum=3, version=1):
        metadata = {"oauth": True, "provider": "x.oauth2", "provider_id": "x",
            "oauth_client_id": self.profile.client_id, "x_app_id": self.profile.client_id,
            "provider_subject": subject, "provider_account": "@Synthetic_User",
            "provider_identity_verified": True, "scopes": list(profiles.SCOPES), "refreshable": True,
            "injection_field": "access_token", "expires_at_epoch_ms": self.now + 4 * quota.DAY_MS,
            "operator_x_account": {"schema": "serverware.operatorXAccountBinding/v1",
                "owner_id": IDS[0], "configuration_operation_id": IDS[1], "config_version": 1,
                "profile_binding_digest": self.profile.binding_digest, "intent_id": IDS[2]}}
        core = {"id": credential_id, "name": "Synthetic account", "kind": "oauth2", "metadata": metadata,
            "lifecycle_status": "active", "created_at": STAMP, "credential_version": version}
        record = accounts.record_fields(core, self.profile)
        record.update(ordinal=1, version=1)
        rule = {"id": rule_id, "ordinal": 1, "version": 1, "created_at": STAMP,
            "route_id": "operator." + rule_id, "name": "Synthetic post", "status": "active",
            "application_id": application_id, "credential_id": credential_id,
            "operation_bundle": posting.BUNDLE, **posting._derived_fields()}
        if maximum is not None:
            rule["daily_post_attempt_limit"] = maximum
        with self.transaction():
            self.conn.execute("INSERT OR REPLACE INTO credentials VALUES(?,'oauth2',?,?, 'active')",
                (credential_id, version, json.dumps(metadata)))
            self.save("operator_catalog_credentials", record)
            self.save("operator_catalog_applications", {"id": application_id, "ordinal": 1, "status": "active",
                "principal_id": "operator-app." + application_id, "token_expires_at_epoch_ms": self.now + 3 * quota.DAY_MS})
            self.save("operator_catalog_rules", rule)

    def binding(self, *, credential_id=IDS[3], application_id=IDS[4], rule_id=IDS[5], **changes):
        self.sequence += 1
        row = dict(self.conn.execute("SELECT * FROM credentials WHERE id=?", (credential_id,)).fetchone())
        row["metadata"] = json.loads(row["metadata"])
        digest = app._credential_lease_metadata_sha256(app._credential_lease_public_metadata(row))
        nonce = "sha256:" + hashlib.sha256(str(self.sequence).encode()).hexdigest()
        result = {"principal_id": "operator-app." + application_id, "route_id": "operator." + rule_id,
            "credential_id": credential_id, "credential_version": row["credential_version"],
            "credential_metadata_digest": digest, "policy_hash": self.conn.execute("SELECT policy_hash FROM operator_demo_policy").fetchone()[0],
            "request_digest": nonce, "operation_digest": "sha256:" + "b" * 64, "attempt_nonce": nonce,
            "recipient_digest": "sha256:" + "c" * 64, "request_binding_digest": "sha256:" + "d" * 64,
            "expires_at_epoch_ms": self.now + 4000}
        return {**result, **changes}

    def reserved(self, binding=None):
        binding = self.binding() if binding is None else binding
        with self.transaction():
            result = quota.reserve(self.conn, binding)
        return binding, result

    def claimed(self, binding=None):
        binding, reserved = self.reserved(binding)
        with self.transaction():
            result = quota.claim(self.conn, binding, reserved["reservation_id"])
        return binding, reserved, result

    def read_usage(self, credential_id=IDS[3]):
        with self.transaction(read_only=True):
            before = self.conn.total_changes
            result = quota.usage(self.conn, credential_id)
            self.assertEqual(before, self.conn.total_changes)
        return result

    def test_explicit_install_and_reopen_are_read_only_and_audit_is_real(self):
        before = tuple(self.conn.iterdump())
        with self.transaction():
            quota.initialize(self.conn)
        with self.transaction(read_only=True):
            quota.require_ready(self.conn)
        self.assertEqual(tuple(self.conn.iterdump()), before)
        other = self.open()
        try:
            with self.transaction(read_only=True, conn=other):
                quota.require_ready(other)
        finally:
            other.close()
        rows = self.conn.execute("SELECT * FROM audit_events").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event_type"], quota.INITIALIZED)
        self.assertIsNone(rows[0]["prev_event_hash"])
        row = dict(rows[0])
        self.assertEqual(row["event_hash"], db._audit_hash(event_id=row["id"],
            **{k: row[k] for k in ("event_type", "actor_type", "actor_id", "event_json", "prev_event_hash", "created_at")}))

    def test_claim_is_one_use_and_lost_ack_never_refunds(self):
        binding, reserved, claimed = self.claimed()
        self.assertEqual(set(reserved), {"schema", "reservation_id", "bucket_key", "utc_day", "expires_at_epoch_ms", "binding_digest"})
        self.assertEqual(set(claimed), set(reserved) | {"claimed_at_epoch_ms"})
        self.assertEqual(claimed["schema"], quota.CLAIM_SCHEMA)
        self.assertEqual(claimed["binding_digest"], quota._digest(binding))
        for function, args in ((quota.reserve, (binding,)), (quota.claim, (binding, reserved["reservation_id"]))):
            with self.transaction(), self.assertRaises(quota.QuotaConflict):
                function(self.conn, *args)
        self.now += 8000
        self.assertEqual(self.read_usage()["claimed_attempts"], 1)
        self.assertEqual(self.read_usage()["outstanding_reservations"], 0)
        event = json.loads(self.conn.execute("SELECT event_json FROM audit_events WHERE event_type='operator_x.quota.claimed'").fetchone()[0])
        self.assertEqual(event, {**claimed, "binding": binding})

    def test_reservations_count_and_only_unclaimed_expire(self):
        original = [self.reserved() for _ in range(3)]
        with self.transaction(), self.assertRaises(quota.QuotaExceeded):
            quota.reserve(self.conn, self.binding())
        with self.transaction():
            quota.claim(self.conn, *[original[0][0], original[0][1]["reservation_id"]])
        self.now += 4001
        self.assertEqual(self.read_usage()["outstanding_reservations"], 0)
        self.reserved()
        self.assertEqual(self.read_usage()["claimed_attempts"], 1)
        self.assertEqual(self.read_usage()["outstanding_reservations"], 1)
        states = [r[0] for r in self.conn.execute(f"SELECT state FROM {quota.ATTEMPTS} ORDER BY rowid")]
        self.assertEqual(states, ["claimed", "expired", "expired", "reserved"])
        with self.transaction(), self.assertRaises(quota.QuotaConflict):
            quota.claim(self.conn, original[1][0], original[1][1]["reservation_id"])

    def test_same_account_across_apps_credentials_clients_and_policy_keeps_usage(self):
        first = self.claimed()[1]
        # A new retained application/client is fixture input, not configuration
        # mutation authority. The real binding validator still checks it.
        self.profile = profiles.build_profile(client_id="second-synthetic-client", public_origin="https://console.example.com")
        self.configuration.update(profile_binding_digest=self.profile.binding_digest,
            public_profile=profiles.public_record(self.profile))
        self.add_identity(IDS[6], "123456789", IDS[7], IDS[8], version=4)
        with self.transaction():
            self.conn.execute("UPDATE operator_demo_policy SET policy_hash=?", ("sha256:" + "e" * 64,))
        binding = self.binding(credential_id=IDS[6], application_id=IDS[7], rule_id=IDS[8])
        _, second, _ = self.claimed(binding)
        self.assertEqual(first["bucket_key"], second["bucket_key"])
        self.assertEqual(self.read_usage(IDS[6])["claimed_attempts"], 2)

    def test_other_subject_and_next_day_do_not_share_usage(self):
        first = self.claimed()[1]
        self.add_identity(IDS[6], "987654321", IDS[7], IDS[8])
        other = self.claimed(self.binding(credential_id=IDS[6], application_id=IDS[7], rule_id=IDS[8]))[1]
        self.assertNotEqual(first["bucket_key"], other["bucket_key"])
        self.now = (self.now // quota.DAY_MS + 1) * quota.DAY_MS + 1
        self.assertEqual(self.read_usage()["claimed_attempts"], 0)
        next_day = self.claimed()[1]
        self.assertNotEqual(first["bucket_key"], next_day["bucket_key"])
        self.assertEqual(self.conn.execute(f"SELECT sum(claimed) FROM {quota.BUCKETS}").fetchone()[0], 3)

    def test_rollback_day_and_deadline_fences(self):
        self.claimed()
        original = self.now
        self.now -= 1
        with self.transaction(read_only=True), self.assertRaises(quota.QuotaUnavailable):
            quota.usage(self.conn, IDS[3])
        self.now = original
        for expiry in (self.now, self.now - 1, self.now + 5001, True):
            with self.transaction(), self.assertRaises(quota.QuotaUnavailable):
                quota.reserve(self.conn, self.binding(expires_at_epoch_ms=expiry))
        self.now = (self.now // quota.DAY_MS + 1) * quota.DAY_MS - 50
        with self.transaction(), self.assertRaises(quota.QuotaUnavailable):
            quota.reserve(self.conn, self.binding())
        binding, reserved = self.reserved(self.binding(expires_at_epoch_ms=self.now + 50))
        self.now += 50
        with self.transaction(), self.assertRaises(quota.QuotaConflict):
            quota.claim(self.conn, binding, reserved["reservation_id"])

    def test_current_generation_metadata_policy_revoke_and_app_expiry(self):
        binding, reserved = self.reserved()
        changes = [
            ("UPDATE credentials SET credential_version=2", "UPDATE credentials SET credential_version=1"),
            ("UPDATE credentials SET lifecycle_status='revocation_pending'", "UPDATE credentials SET lifecycle_status='active'"),
            ("UPDATE operator_demo_policy SET policy_hash='changed'", "UPDATE operator_demo_policy SET policy_hash='" + POLICY + "'"),
        ]
        for mutate, restore in changes:
            with self.transaction():
                self.conn.execute(mutate)
                with self.assertRaises(quota.QuotaUnavailable):
                    quota.claim(self.conn, binding, reserved["reservation_id"])
                self.conn.execute(restore)
        application = self.record("operator_catalog_applications", IDS[4])
        for changed in ({**application, "status": "revoked"}, {**application, "token_expires_at_epoch_ms": self.now + 1}):
            with self.transaction():
                self.save("operator_catalog_applications", changed)
                with self.assertRaises(quota.QuotaUnavailable):
                    quota.claim(self.conn, binding, reserved["reservation_id"])
                self.save("operator_catalog_applications", application)
        with self.transaction():
            quota.claim(self.conn, binding, reserved["reservation_id"])
        self.assertEqual(self.read_usage()["claimed_attempts"], 1)

    def test_unbounded_interval_disconnect_and_limit_changes_never_reset(self):
        self.claimed()
        rule = self.record("operator_catalog_rules", IDS[5])
        with self.transaction():
            unbounded = dict(rule)
            unbounded.pop("daily_post_attempt_limit")
            self.save("operator_catalog_rules", unbounded)
            with self.assertRaises(quota.QuotaUnavailable):
                quota.reserve(self.conn, self.binding())
            self.save("operator_catalog_rules", {**rule, "status": "revoked"})
            with self.assertRaises(quota.QuotaUnavailable):
                quota.reserve(self.conn, self.binding())
            self.save("operator_catalog_rules", {**rule, "daily_post_attempt_limit": 1})
        with self.transaction(), self.assertRaises(quota.QuotaExceeded):
            quota.reserve(self.conn, self.binding())
        self.assertEqual(self.read_usage()["claimed_attempts"], 1)

    def test_binding_is_closed_and_original_cannot_be_substituted(self):
        binding, reserved = self.reserved()
        for field in quota.BINDING_FIELDS:
            changed = dict(binding)
            changed[field] = True if type(binding[field]) is int else "sha256:" + "f" * 64
            with self.subTest(field=field), self.transaction(), self.assertRaises(quota.QuotaUnavailable):
                quota.claim(self.conn, changed, reserved["reservation_id"])
        for changed in ({**binding, "provider_subject": "different"}, {k: v for k, v in binding.items() if k != "route_id"}):
            with self.transaction(), self.assertRaises(quota.QuotaUnavailable):
                quota.reserve(self.conn, changed)
        self.assertEqual(self.read_usage()["claimed_attempts"], 0)

    def test_flag_admission_publication_and_read_only_writes_refuse(self):
        for flag in ("0", "yes", "", "true"):
            with patch.dict(os.environ, {quota.FLAG: flag}), self.transaction(), self.assertRaises(quota.QuotaUnavailable):
                quota.require_ready(self.conn)
        self.admitted = False
        with self.transaction(), self.assertRaises(quota.QuotaUnavailable):
            quota.require_ready(self.conn)
        self.admitted = True
        with self.assertRaises(quota.QuotaUnavailable):
            quota.require_ready(self.conn)
        with self.transaction(read_only=True), self.assertRaises(quota.QuotaUnavailable):
            quota.reserve(self.conn, self.binding())

    def test_missing_state_or_counter_is_not_reinitialized(self):
        self.claimed()
        for table in (quota.ACCOUNTS, quota.BUCKETS, quota.STATE):
            with self.transaction():
                self.conn.execute("SAVEPOINT corruption_control")
                self.conn.execute("DROP TRIGGER " + table + "_no_delete")
                self.conn.execute("DELETE FROM " + table)
                self.conn.execute(quota._DDL[table + "_no_delete"])
                with self.assertRaises(quota.QuotaUnavailable):
                    quota.reserve(self.conn, self.binding())
                if table == quota.STATE:
                    with self.assertRaises(quota.QuotaUnavailable):
                        quota.initialize(self.conn)
                self.conn.execute("ROLLBACK TO corruption_control")
                self.conn.execute("RELEASE corruption_control")
        with self.transaction():
            self.conn.execute("SAVEPOINT missing_marker")
            self.conn.execute("DELETE FROM audit_events WHERE event_type=?", (quota.INITIALIZED,))
            with self.assertRaises(quota.QuotaUnavailable):
                quota.initialize(self.conn)
            self.conn.execute("ROLLBACK TO missing_marker")
            self.conn.execute("RELEASE missing_marker")

    def test_atomic_rollback_constraints_and_competing_writer(self):
        binding = self.binding()
        original = quota._audit
        def failure(conn, event, values, actor_id=None):
            original(conn, event, values, actor_id)
            if event == "reserved":
                raise RuntimeError("synthetic failure after real audit insert")
        before = tuple(self.conn.iterdump())
        with self.transaction(), patch.object(quota, "_audit", side_effect=failure):
            with self.assertRaises(quota.QuotaUnavailable):
                quota.reserve(self.conn, binding)
        self.assertEqual(tuple(self.conn.iterdump()), before)
        other = self.open()
        try:
            with self.transaction():
                quota.reserve(self.conn, binding)
                with self.assertRaises(sqlite3.OperationalError):
                    other.execute("BEGIN IMMEDIATE")
            with self.transaction(conn=other), self.assertRaises(quota.QuotaConflict):
                quota.reserve(other, binding)
        finally:
            other.close()
        with self.transaction():
            for table in (quota.STATE, quota.ACCOUNTS, quota.BUCKETS, quota.ATTEMPTS):
                with self.assertRaises(sqlite3.IntegrityError):
                    self.conn.execute("DELETE FROM " + table)


if __name__ == "__main__":
    unittest.main()
