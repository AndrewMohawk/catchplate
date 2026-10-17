#!/usr/bin/env python3
"""Real ordinary X first-save service, SQLite, EX, key and audit controls.

Each worker has its own real operator process admission. No success guard,
encryption, signing, database or publication owner is mocked. Failure-only
injection covers SQL rollback and a lost acknowledgement after real commit.
Network is denied before importing the application. These are service tests,
not HTTP/browser, provider consent, account readiness or posting evidence.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

import test_operator_workspace_store as workspace
import test_operator_publication as coordination

ROOT = Path(__file__).resolve().parents[1]
ACTOR = workspace.common._ACTOR
CLIENT = "fixture-x-public-client-id"
SECRET = "synthetic-x-application-private-canary"
KEY_DIRECTORY = "CATCHPLATE_OPERATOR_X_CUSTODY_DIR"
FLAG = "CATCHPLATE_OPERATOR_MANAGED_X_ENABLED"


def no_network(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        raise AssertionError("X configuration contacted a network endpoint")


def fixture(*, reopen=False):
    if reopen:
        config, db, store, _ = workspace.common.backend(initialize=False)
        from catchplate import operator_catalog_schema as schema
    else:
        config, db, store, _, schema, _, _ = workspace.workspace()
    from catchplate import operator_x_configuration as service
    return config, db, store, schema, service


def snapshot(config):
    with closing(sqlite3.connect(config.DB_PATH.as_uri() + "?mode=ro", uri=True)) as conn:
        conn.execute("PRAGMA query_only=ON")
        dump = tuple(conn.iterdump())
    return dump, config.POLICY_BUNDLE_PATH.read_bytes()


def key_snapshot():
    return {p.name: (p.stat().st_ino, p.stat().st_mode, hashlib.sha256(p.read_bytes()).hexdigest())
        for p in Path(os.environ[KEY_DIRECTORY]).iterdir()}


def payload(service, **changes):
    review = service.configuration(ACTOR)["review"]
    assert review is not None
    return {**review, "operation_id": str(uuid.uuid4()), "client_id": CLIENT, "client_secret": SECRET, **changes}


def refused(function, expected):
    try:
        function()
    except expected as error:
        assert SECRET not in str(error) and CLIENT not in str(error)
        return
    raise AssertionError("operation unexpectedly succeeded")


def lifecycle():
    config, db, store, schema, service = fixture()
    from catchplate import operator_catalog_inputs as inputs, operator_catalog_mutations as mutations
    credential = workspace.create_credential(db, store, schema, inputs, mutations)["credential"]
    application = workspace.create_application(db, store, schema, inputs, mutations)["application"]
    workspace.create_rule(db, store, schema, inputs, mutations, application["id"], credential["id"])

    def protected():
        with closing(db.connect()) as conn:
            return {table: tuple(tuple(row) for row in conn.execute("SELECT * FROM " + table))
                for table in (*workspace.LEGACY_TABLES, "credential_generations",
                    "operator_catalog_credentials", "operator_catalog_applications", "operator_catalog_rules")
                if table != "audit_events"}

    retained = protected()
    before = snapshot(config)
    initial = service.configuration(ACTOR)
    assert initial["state"] == "unconfigured" and initial["configuration"] is None
    assert initial["operation"] is None and initial["blocked_reason"] is None
    assert not initial["consent_ready"] and not key_snapshot() and snapshot(config) == before
    command = payload(service)
    original, writes = service.custody.insert_secret, []

    def insert(conn, owner, bound, **options):
        store.operator_publication.assert_held()
        assert conn.in_transaction and conn.execute("PRAGMA query_only").fetchone()[0] == 0
        assert not coordination.shared_probe(config.DATA_DIR / store.operator_publication.LOCK_NAME)
        original(conn, owner, bound, **options)
        writes.append(bound.config_version)

    with patch.object(service.custody, "insert_secret", side_effect=insert):
        result = service.configure(service.profiles.XOAuthApplicationInput(**command), ACTOR)
    assert writes == [1] and result["status"] == "committed" and result["config_version"] == 1
    assert result["committed_revision"] == initial["revision"] + 1
    assert result["policy_hash"] == initial["policy_hash"] and not result["consent_ready"]
    assert result["public_profile"]["client_id"] == CLIENT
    assert SECRET not in json.dumps(result) and SECRET not in "\n".join(snapshot(config)[0])
    assert snapshot(config)[1] == before[1] and len(key_snapshot()) == 1
    assert protected() == retained
    assert service.status(command["operation_id"], ACTOR) == result
    observed = service.configuration(ACTOR)
    assert observed["operation"] == result and observed["review"] is None
    assert observed["blocked_reason"] == "already_configured"
    assert service.configuration(ACTOR + "-other")["operation"] is None
    for identifier, actor in ((command["operation_id"], ACTOR + "-other"), (str(uuid.uuid4()), ACTOR)):
        refused(lambda identifier=identifier, actor=actor: service.status(identifier, actor), service.ConfigurationNotFound)
    unchanged, key = snapshot(config), key_snapshot()
    with patch.object(service.keys, "initialize_first_x", side_effect=AssertionError("GET initialized key")), \
            patch.object(db, "connect", side_effect=AssertionError("GET opened writable database")):
        assert service.configuration(ACTOR) == observed
        assert service.status(command["operation_id"], ACTOR) == result
    assert snapshot(config) == unchanged and key_snapshot() == key
    for command in (command, {**command, "operation_id": str(uuid.uuid4()),
            "expected_revision": observed["revision"]}):
        refused(lambda: service.configure(command, ACTOR), schema.CatalogConflict)
        assert snapshot(config) == unchanged and key_snapshot() == key
    chain = db.verify_audit_chain()
    assert chain["ok"] and chain["complete"]
    with closing(db.connect()) as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE event_type=?", (service.EVENT,)).fetchone()[0] == 1
        for statement in ("UPDATE operator_x_configuration SET actor_id='other'",
                "DELETE FROM operator_x_configuration"):
            refused(lambda statement=statement: conn.execute(statement), sqlite3.IntegrityError)
            conn.rollback()
    return result


def reopen():
    config, _, store, _, service = fixture(reopen=True)
    before, key = snapshot(config), key_snapshot()
    publication = store.operator_publication
    lock = config.DATA_DIR / publication.LOCK_NAME
    lock_identity = publication._file_identity(lock.lstat())
    # Admit the retained lock in this fresh process exactly as startup does.
    # Do not initialize the DB, re-provision the lock, or relax service admission.
    with publication.exclusive(startup=True):
        publication.assert_held()
    assert publication._file_identity(lock.lstat()) == lock_identity
    assert snapshot(config) == before and key_snapshot() == key
    result = service.configuration(ACTOR)
    assert result["state"] == "configured" and result["operation"] is not None
    assert snapshot(config) == before and key_snapshot() == key
    return result["operation"]


def stale():
    config, _, _, schema, service = fixture()
    command = payload(service)
    before = snapshot(config)
    for change in ({"expected_revision": command["expected_revision"] + 1},
            {"expected_policy_hash": "sha256:" + "f" * 64}):
        refused(lambda: service.configure({**command, **change}, ACTOR), schema.CatalogConflict)
        assert snapshot(config) == before and not key_snapshot()
    for change in ({"expected_revision": True}, {"client_secret": SECRET + "\n"},
            {"operation_id": "invalid"}, {"unexpected": SECRET}):
        refused(lambda: service.configure({**command, **change}, ACTOR), service.ConfigurationUnavailable)
        assert snapshot(config) == before and not key_snapshot()
    return {"prewrite_refusals": 6}


def rollback():
    config, db, _, _, service = fixture()
    command = payload(service)
    with closing(db.connect()) as conn, conn:
        conn.execute("CREATE TRIGGER x_fixture_abort BEFORE INSERT ON audit_events "
            "WHEN NEW.event_type='operator_catalog.x_oauth.configuration_saved' "
            "BEGIN SELECT RAISE(ABORT,'synthetic X audit refusal'); END")
    before = snapshot(config)
    refused(lambda: service.configure(command, ACTOR), service.ConfigurationUnavailable)
    assert snapshot(config) == before
    orphan = key_snapshot()
    assert len(orphan) == 1 and service.configuration(ACTOR)["state"] == "unconfigured"
    with closing(db.connect()) as conn, conn:
        conn.execute("DROP TRIGGER x_fixture_abort")
    # This explicit retry follows a proved SQL rollback, not a transport timeout.
    result = service.configure(command, ACTOR)
    assert result["committed_revision"] == command["expected_revision"] + 1 and key_snapshot() == orphan
    return {"atomic_rollback": True, "explicit_orphan_reuse": True}


def lost_ack():
    config, db, _, schema, service = fixture()
    command = payload(service)
    original, committed = sqlite3.connect, []

    class LostAcknowledgement(sqlite3.Connection):
        def commit(self):
            if self.in_transaction and not committed and self.execute(
                    "SELECT 1 FROM audit_events WHERE id=?", (service._AUDIT_PREFIX + command["operation_id"],)).fetchone():
                super().commit()
                committed.append(True)
                raise OSError("synthetic acknowledgement lost after real commit")
            return super().commit()

    def connect(*args, **kwargs):
        assert "factory" not in kwargs
        return original(*args, factory=LostAcknowledgement, **kwargs)

    with patch.object(sqlite3, "connect", side_effect=connect):
        refused(lambda: service.configure(command, ACTOR), service.ConfigurationUnavailable)
    assert committed == [True]
    result = service.status(command["operation_id"], ACTOR)
    before = snapshot(config)
    refused(lambda: service.configure(command, ACTOR), schema.CatalogConflict)
    assert snapshot(config) == before and result["status"] == "committed"
    assert db.verify_audit_chain()["ok"]
    return {"committed_response_recovered": True}


def pending(kind):
    config, _, _, schema, service = fixture()
    if kind == "google":
        from catchplate import operator_google_setup as setup
        review = setup.review(ACTOR)
        command = {key: review[key] for key in (
            "expected_revision", "expected_policy_hash", "expected_settings_digest")}
        setup.prepare({**command, "operation_id": str(uuid.uuid4()),
            "client_id": "123-fixture.apps.googleusercontent.com"}, ACTOR)
        reason = "pending_google_configuration"
    else:
        from catchplate import operator_upstream_setup as setup
        review = setup.review(ACTOR)
        command = {key: review[key] for key in (
            "expected_revision", "expected_policy_hash", "expected_settings_digest")}
        setup.prepare({**command, "operation_id": str(uuid.uuid4()),
            "allowed_upstreams": ["https://api.example.com", "https://another.example.com"]}, ACTOR)
        reason = "pending_upstream_configuration"
    current = service.configuration(ACTOR)
    assert current["review"] is None and current["blocked_reason"] == reason
    before = snapshot(config)
    refused(lambda: service.configure({"expected_revision": current["revision"],
        "expected_policy_hash": current["policy_hash"], "operation_id": str(uuid.uuid4()),
        "client_id": CLIENT, "client_secret": SECRET}, ACTOR), schema.CatalogConflict)
    assert snapshot(config) == before and not key_snapshot()
    return {"pending_conflict": kind}


def corrupt(kind):
    config, db, _, _, service = fixture()
    if kind == "orphan":
        with closing(db.connect()) as conn, conn:
            conn.execute("CREATE TABLE operator_x_configuration_unknown(id INTEGER)")
    else:
        service.configure(payload(service), ACTOR)
        if kind == "key":
            key = Path(os.environ[KEY_DIRECTORY]) / service.keys.FILENAME
            key.write_bytes(b"synthetic-corrupt-key")
        else:
            with closing(db.connect()) as conn, conn:
                if kind == "audit":
                    conn.execute("UPDATE audit_events SET event_hash=? WHERE event_type=?",
                        ("sha256:" + "f" * 64, service.EVENT))
                elif kind == "ciphertext":
                    conn.execute("DROP TRIGGER operator_x_provider_custody_immutable")
                    conn.execute("UPDATE operator_x_provider_custody SET ciphertext=randomblob(length(ciphertext))")
                    for name, _, _, sql in service.custody._DEFINITIONS:
                        if name == "operator_x_provider_custody_immutable":
                            conn.execute(sql)
                elif kind == "extra-version":
                    # A valid extra ciphertext still lacks a retained configuration.
                    from catchplate import operator_publication as publication
                    conn.rollback()
                    with publication.exclusive():
                        conn.execute("BEGIN IMMEDIATE")
                        directory = service.admission.require_runtime()
                        record = service._record(conn, directory)
                        owner = service.admission.admit_owner(record["owner_id"])
                        pin = service.keys.read_existing_pinned(directory, owner.owner_id)
                        try:
                            bound = service.custody.bind_x(owner, config_version=2, public_profile=record["public_profile"])
                            service.custody.insert_secret(conn, owner, bound, key=pin.material, secret=SECRET)
                        finally:
                            service.keys.close_pin(pin)
                else:
                    raise AssertionError("unknown corruption case")
    before, key = snapshot(config), key_snapshot()
    refused(lambda: service.configuration(ACTOR), service.ConfigurationUnavailable)
    assert snapshot(config) == before and key_snapshot() == key
    return {"retained_corruption_refused": kind}


def missing_database():
    config, _, _, _, service = fixture()
    command = payload(service)
    saved = config.DB_PATH.with_name("fixture-retained-missing.sqlite3")
    config.DB_PATH.rename(saved)
    refused(lambda: service.configure(command, ACTOR), service.ConfigurationUnavailable)
    assert saved.is_file() and not config.DB_PATH.exists() and not key_snapshot()
    refused(lambda: service.configuration(ACTOR), service.ConfigurationUnavailable)
    assert not config.DB_PATH.exists() and not key_snapshot()
    return {"missing_database_not_recreated": True}


class XConfigurationTests(unittest.TestCase):
    def setUp(self):
        workspace.common.OperatorDemoPersistenceTests.setUp(self)
        directory = Path(self.scratch.name) / "x-custody"
        directory.mkdir(mode=0o700)
        self.environment.update({FLAG: "1", KEY_DIRECTORY: str(directory),
            "CATCHPLATE_OPERATOR_GATE_PUBLICATION_ENABLED": "1", "CATCHPLATE_PUBLIC_URL": "https://console.example.com"})

    def run_worker(self, operation):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=60)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-35:]))
        return json.loads(result.stdout)

    def test_first_save_real_custody_audit_readonly_recovery_and_reopen(self):
        result = self.run_worker("lifecycle")
        self.assertEqual(self.run_worker("reopen"), result)

    def test_stale_and_malformed_inputs_are_prewrite_refusals(self):
        self.assertEqual(self.run_worker("stale")["prewrite_refusals"], 6)

    def test_real_sql_failure_rolls_back_all_rows_and_reuses_only_valid_orphan(self):
        self.assertTrue(self.run_worker("rollback")["atomic_rollback"])

    def test_real_commit_lost_ack_recovers_by_actor_get_without_replaying_post(self):
        self.assertTrue(self.run_worker("lost-ack")["committed_response_recovered"])

    def test_google_pending_conflicts_without_x_initialization(self):
        self.assertEqual(self.run_worker("pending-google")["pending_conflict"], "google")

    def test_upstream_pending_conflicts_without_x_initialization(self):
        self.assertEqual(self.run_worker("pending-upstream")["pending_conflict"], "upstream")

    def test_missing_exact_namespace_is_not_hidden_repair(self):
        self.assertEqual(self.run_worker("corrupt-orphan")["retained_corruption_refused"], "orphan")

    def test_corrupt_key_is_not_hidden_reinitialization(self):
        self.assertEqual(self.run_worker("corrupt-key")["retained_corruption_refused"], "key")

    def test_corrupt_audit_is_not_configured(self):
        self.assertEqual(self.run_worker("corrupt-audit")["retained_corruption_refused"], "audit")

    def test_corrupt_ciphertext_with_restored_schema_is_not_configured(self):
        self.assertEqual(self.run_worker("corrupt-ciphertext")["retained_corruption_refused"], "ciphertext")

    def test_extra_valid_custody_version_is_not_silently_selected(self):
        self.assertEqual(self.run_worker("corrupt-extra-version")["retained_corruption_refused"], "extra-version")

    def test_missing_retained_database_is_not_recreated_by_post_or_get(self):
        self.assertTrue(self.run_worker("missing-database")["missing_database_not_recreated"])


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(no_network)
        name = sys.argv[2]
        if name.startswith("pending-"):
            result = pending(name.removeprefix("pending-"))
        elif name.startswith("corrupt-"):
            result = corrupt(name.removeprefix("corrupt-"))
        else:
            result = {"lifecycle": lifecycle, "reopen": reopen, "stale": stale,
                "rollback": rollback, "lost-ack": lost_ack, "missing-database": missing_database}[name]()
        print(json.dumps(result, sort_keys=True))
    else:
        unittest.main(verbosity=2)
