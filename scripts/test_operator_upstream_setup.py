#!/usr/bin/env python3
"""Connected upstream setup through real ASGI, retained SQLite and cold startup.

Run only in the root-owned bounded, network-none cached application harness.
Each restart is a fresh process. Catalog, encryption, signing, publication,
preflight and activation guards are real. Network attempts fail rather than
returning simulated provider successes. No proxy/provider/browser readiness is
claimed by these storage/startup checks.
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

import test_operator_google_setup as google
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
PATH = "/api/operator-demo/proxy/upstreams"
TABLE = "operator_upstream_setups"
NEW_ORIGIN = "https://registry.npmjs.org"
OLD = list(google.OLD_ORIGINS)
TARGET = [*OLD, NEW_ORIGIN]
GOOGLE_TARGET = [*google.TARGET_ORIGINS, NEW_ORIGIN]
EVENT_PREFIX = "operator_catalog.upstream_setup."
NOTIFICATION_URL = "https://receiver.example.com/upstream-preservation/SYNTHETIC_PRIVATE_DESTINATION"
NOTIFICATION_TABLES = {
    "operator_notification_meta": "singleton",
    "operator_notification_config": "slot,revision",
    "operator_notification_operations": "operation_id",
    "operator_notification_deliveries": "delivery_id",
    "operator_notification_attempts": "delivery_id,attempt",
}


def no_network(event, _arguments):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        raise AssertionError("upstream setup fixture attempted network contact")


class Fixture(google.Fixture):
    def __init__(self):
        super().__init__()
        from serverware import operator_upstream_setup
        self.upstream = operator_upstream_setup

    def rows(self, table):
        if table == TABLE:
            with closing(self.db.connect()) as conn:
                return [dict(row) for row in conn.execute("SELECT * FROM " + TABLE + " ORDER BY operation_id")]
        return super().rows(table)

    def authority(self):
        result = super().authority()
        with closing(self.db.connect()) as conn:
            if conn.execute("SELECT 1 FROM sqlite_master WHERE name='operator_catalog_oauth_profile'").fetchone():
                result["google_profile"] = [dict(row) for row in conn.execute("SELECT * FROM operator_catalog_oauth_profile")]
            if conn.execute("SELECT 1 FROM sqlite_master WHERE name='operator_notification_meta'").fetchone():
                from serverware import operator_notification_custody as custody
                result["notifications"] = {table: [{key: ({"hex": value.hex()} if isinstance(value, bytes) else value)
                    for key, value in dict(row).items()} for row in conn.execute("SELECT * FROM " + table + " ORDER BY " + order)]
                    for table, order in NOTIFICATION_TABLES.items()}
                directory = Path(os.environ["SERVERWARE_OPERATOR_NOTIFICATIONS_CUSTODY_DIR"])
                key_path = directory / custody.FILENAME
                info = key_path.stat()
                result["notification_key"] = {"sha256": hashlib.sha256(key_path.read_bytes()).hexdigest(),
                    "device": info.st_dev, "inode": info.st_ino, "mode": info.st_mode & 0o777}
                owner = conn.execute("SELECT owner_id FROM operator_notification_meta").fetchone()[0]
                saved = conn.execute("SELECT * FROM operator_notification_config").fetchall()
                assert len(saved) == 1 and saved[0]["enabled"] == 0
                assert custody.unseal(custody.read(directory, owner), saved[0]["slot"], saved[0]["revision"],
                    saved[0]["nonce"], saved[0]["ciphertext"]) == NOTIFICATION_URL
                assert result["notifications"]["operator_notification_deliveries"] == []
                assert result["notifications"]["operator_notification_attempts"] == []
        return result

    def call(self, method, path=PATH, **options):
        return super().call(method, path, **options)

    def setup_review(self):
        result = self.call("GET")
        assert result["schema"] == "serverware.operatorUpstreamSetupReview/v1"
        assert result["cold_restart_required"] is True
        return result

    def payload(self, origins=None):
        review = self.setup_review()
        assert review["eligible"] is True
        return {key: review[key] for key in (
            "expected_revision", "expected_policy_hash", "expected_settings_digest")} | {
                "operation_id": str(uuid.uuid4()), "allowed_upstreams": list(TARGET if origins is None else origins)}

    def public(self, identifier):
        result = self.call("GET", PATH + "/" + identifier)
        assert result["schema"] == "serverware.operatorUpstreamSetup/v1"
        return result

    def prepare(self, origins=None):
        authority, settings = self.authority(), self.rows("operator_demo_settings")
        payload = self.payload(origins)
        result = self.call("POST", body=payload, expected=201)
        assert result["status"] == "pending" and result["operation_id"] == payload["operation_id"]
        assert result["reviewed_revision"] == payload["expected_revision"]
        assert result["staged_revision"] == result["revision"] == payload["expected_revision"] + 1
        assert result["policy_hash"] == payload["expected_policy_hash"] and result["activation_receipt"] is None
        assert result["target_settings"] == {"allowed_upstreams": payload["allowed_upstreams"], "fixture_cidrs": google.CIDRS}
        assert self.public(payload["operation_id"]) == result
        assert self.authority() == authority and self.rows("operator_demo_settings") == settings
        assert self.demo.settings()["allowed_upstreams"] == result["old_settings"]["allowed_upstreams"]
        assert self.demo.settings()["fixture_cidrs"] == google.CIDRS
        assert self.setup_review()["eligible"] is False
        assert not self.provider_calls
        return result


def seed():
    fixture = Fixture()
    fixture.seed()
    return {"authority": fixture.authority(), "provider_contacts": len(fixture.provider_calls)}


def prepare(*, activation_failure=False, active_google=False):
    fixture = Fixture()
    fixture.seed()
    if os.environ.get("SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED") == "1":
        from serverware import operator_notification_store as notifications
        receipt = notifications.save({"operation_id": str(uuid.uuid4()), "slot": "audit_log.webhook",
            "expected_revision": 0, "label": "Disabled preservation fixture", "enabled": False,
            "event_types": ["operator_catalog.application.created"], "max_attempts": 1,
            "url_action": "replace", "url": NOTIFICATION_URL}, workspace.common._ACTOR)
        assert receipt["status"] == "saved" and receipt["revision"] == 1
        assert notifications.operation_status(receipt["operation_id"], workspace.common._ACTOR) == receipt
        assert NOTIFICATION_URL not in json.dumps(receipt)
    if active_google:
        profile = fixture.profiles.require_profile()
        before = fixture.snapshot()
        removal = fixture.payload(TARGET)
        refused(fixture, "POST", body=removal, expected=422)
        assert fixture.snapshot() == before and profile.binding_digest
    operation = fixture.prepare(GOOGLE_TARGET if active_google else TARGET)
    if activation_failure:
        with closing(fixture.db.connect()) as conn, conn:
            conn.execute("CREATE TRIGGER upstream_activation_abort BEFORE INSERT ON audit_events "
                "WHEN NEW.event_type='operator_catalog.upstream_setup.activated' "
                "BEGIN SELECT RAISE(ABORT,'synthetic upstream activation audit refusal'); END")
    return {"operation": operation, "authority": fixture.authority(), "audit": fixture.rows("audit_events")}


def activate(identifier):
    fixture = Fixture()
    operation = fixture.public(identifier)
    assert operation["status"] == "activated"
    assert fixture.demo.settings()["allowed_upstreams"] == operation["target_settings"]["allowed_upstreams"]
    assert fixture.demo.settings()["fixture_cidrs"] == operation["target_settings"]["fixture_cidrs"] == google.CIDRS
    assert operation["revision"] == operation["staged_revision"] + 1
    receipt = operation["activation_receipt"]
    assert receipt == {"schema": "serverware.operatorUpstreamSetupActivation/v1",
        "operation_id": identifier, "activated_revision": operation["revision"],
        "policy_hash": operation["policy_hash"], "settings_digest": operation["target_settings_digest"],
        "activated_at": operation["completed_at"]}
    workspace.verify_signed(fixture.config, fixture.db, fixture.store, fixture.bundles)
    for row in workspace.catalog(fixture.db, fixture.schema)["credentials"]:
        assert fixture.db.get_credential(row["id"], include_secret=True)["secret"] == workspace.common._PROVIDER_SECRET
    assert not fixture.provider_calls
    return {"operation": operation, "authority": fixture.authority(), "audit": fixture.rows("audit_events"),
        "settings": fixture.rows("operator_demo_settings"), "revision": fixture.review()["expected_revision"]}


def refused(fixture, method, path=PATH, *, expected, **options):
    before = fixture.snapshot()
    fixture.call(method, path, expected=expected, **options)
    assert fixture.snapshot() == before, "refused upstream operation changed retained state"
    assert not fixture.provider_calls


def refused_restart():
    before = google.readonly_snapshot()
    from serverware import db
    initializers, contacts = [], []

    def forbidden_initializer():
        initializers.append(True)
        raise AssertionError("refused upstream startup reached generic database initialization")

    with patch.object(db, "init_db", side_effect=forbidden_initializer):
        try:
            google.cold_startup(contacts)
        except RuntimeError:
            pass
        else:
            raise AssertionError("unreviewed or stale upstream startup was admitted")
    assert initializers == [] and contacts == []
    assert google.readonly_snapshot() == before
    return {"refused_before_generic_db_init": True, "retained_state_unchanged": True}


def advance(kind):
    fixture = Fixture()
    before, pending = fixture.review(), fixture.rows(TABLE)
    if kind == "revision":
        workspace.create_credential(fixture.db, fixture.store, fixture.schema, fixture.inputs,
            fixture.mutations, "Intervening synthetic static credential")
    else:
        assert kind == "policy"
        rule = next(row for row in workspace.catalog(fixture.db, fixture.schema)["access_rules"] if row["status"] == "active")
        fixture.mutations.revoke_application(fixture.inputs.TargetInput(**fixture.review(),
            id=rule["application_id"]), workspace.common._ACTOR)
    after = fixture.review()
    assert after["expected_revision"] == before["expected_revision"] + 1
    assert (after["expected_policy_hash"] == before["expected_policy_hash"]) == (kind == "revision")
    assert fixture.rows(TABLE) == pending and not fixture.provider_calls
    return {"advanced": kind}


def activation_rollback():
    from serverware import operator_demo, operator_upstream_setup
    original_bootstrap, boundary, contacts = operator_demo.bootstrap, [], []

    def observed_bootstrap():
        # Generic initialization may legitimately update migration timestamps;
        # compare the exact actual publication/activation boundary instead.
        boundary.append(google.readonly_snapshot())
        return original_bootstrap()

    with patch.object(operator_demo, "bootstrap", side_effect=observed_bootstrap):
        try:
            google.cold_startup(contacts)
        except operator_upstream_setup.SetupUnavailable as error:
            assert str(error) == "operator upstream setup unavailable"
        else:
            raise AssertionError("upstream activation ignored audit failure")
    assert len(boundary) == 1 and contacts == []
    assert google.readonly_snapshot() == boundary[0]
    return {"activation_audit_failure_full_rollback": True}


def checks(name):
    from operator_upstream_setup_checks import ACTIONS
    fixture = Fixture()
    result = ACTIONS[name](fixture)
    assert not fixture.provider_calls
    return result


class OperatorUpstreamBoundsTests(unittest.TestCase):
    def test_explicit_origin_capacity_matches_startup_and_prepare(self):
        from serverware import operator_demo, operator_upstream_setup
        origins = ["https://service-" + str(index) + ".example.com" for index in range(16)]
        payload = {"expected_revision": 1, "expected_policy_hash": "sha256:" + "0" * 64,
            "operation_id": str(uuid.uuid4()), "allowed_upstreams": origins,
            "expected_settings_digest": "sha256:" + "1" * 64}
        self.assertEqual(operator_upstream_setup.PrepareInput(**payload).allowed_upstreams, origins)
        self.assertEqual(operator_demo._destinations(origins, []), (tuple(origins), ()))
        from serverware import operator_google_setup
        retained = {"allowed_upstreams": origins, "fixture_cidrs": []}
        self.assertEqual(operator_google_setup._settings(json.dumps(retained, sort_keys=True)), retained)
        google_target = operator_google_setup._target({"allowed_upstreams": origins[:-1], "fixture_cidrs": []})
        self.assertEqual(len(google_target["allowed_upstreams"]), 16)
        self.assertEqual(google_target["allowed_upstreams"][-1], "https://gmail.googleapis.com")
        with self.assertRaises(operator_google_setup.SetupUnavailable):
            operator_google_setup._target(retained)
        for invalid in ([], origins + ["https://overflow.example.com"], origins + [origins[0]]):
            with self.assertRaises(ValueError):
                operator_upstream_setup.PrepareInput(**{**payload, "allowed_upstreams": invalid})
            with self.assertRaises(RuntimeError):
                operator_demo._destinations(invalid, [])


class OperatorUpstreamSetupTests(unittest.TestCase):
    def setUp(self):
        google.OperatorGoogleSetupTests.setUp(self)
        # No management health probe is part of this settings transaction test.
        self.environment["SERVERWARE_DECISION_GATE_BASE"] = ""
        self.google_environment["SERVERWARE_DECISION_GATE_BASE"] = ""

    def worker(self, operation, *, origins=None, google_enabled=False, changes=None, identifier=None):
        environment = dict(self.google_environment if google_enabled else self.environment)
        if origins is not None:
            environment["SERVERWARE_OPERATOR_DEMO_UPSTREAMS"] = json.dumps(origins)
        environment.update(changes or {})
        command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation]
        if identifier is not None:
            command.append(identifier)
        result = subprocess.run(command, cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        return json.loads(result.stdout)

    def test_review_prepare_exact_cold_activation_and_second_restart_preserve_authority(self):
        notification_directory = Path(self.scratch.name) / "notification-custody"
        notification_directory.mkdir(mode=0o700)
        changes = {"SERVERWARE_OPERATOR_NOTIFICATIONS_ENABLED": "1",
            "SERVERWARE_OPERATOR_NOTIFICATIONS_CUSTODY_DIR": str(notification_directory)}
        prepared = self.worker("prepare", changes=changes)
        self.assertIn("notifications", prepared["authority"])
        self.assertIn("notification_key", prepared["authority"])
        identifier = prepared["operation"]["operation_id"]
        activated = self.worker("activate", origins=TARGET, identifier=identifier, changes=changes)
        self.assertEqual(activated["authority"], prepared["authority"])
        self.assertEqual(activated["audit"][:len(prepared["audit"])], prepared["audit"])
        events = [row for row in activated["audit"] if row["event_type"] == EVENT_PREFIX + "activated"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["id"], "operator-upstream-setup:" + identifier + ":activated")
        self.assertEqual(json.loads(activated["settings"][0]["settings_json"]), prepared["operation"]["target_settings"])
        self.assertEqual(self.worker("activate", origins=TARGET, identifier=identifier, changes=changes), activated)

    def test_review_protected_origins_canonical_inputs_and_exact_cas(self):
        self.worker("review_checks")

    def test_unprepared_and_different_environment_refuse_before_database_initialization(self):
        self.worker("seed")
        self.worker("refused_restart", origins=TARGET)
        self.worker("prepare_existing")
        self.worker("refused_restart", origins=[*OLD, "https://different.example.com"])
        self.worker("refused_restart", origins=TARGET,
            changes={"SERVERWARE_OPERATOR_DEMO_FIXTURE_CIDRS": '["127.0.0.2/32"]'})

    def test_stale_catalog_revision_and_policy_hash_refuse_cold_activation(self):
        for kind in ("revision", "policy"):
            changes = {"SERVERWARE_DATA_DIR": str(Path(self.scratch.name) / ("stale-" + kind))}
            self.worker("prepare", changes=changes)
            self.worker("advance_" + kind, changes=changes)
            self.worker("refused_restart", origins=TARGET, changes=changes)

    def test_actor_owned_lost_receipt_get_and_explicit_cancel(self):
        self.worker("receipt_checks")

    def test_prepare_audit_failure_is_atomic(self):
        self.worker("prepare_rollback")

    def test_activation_audit_failure_is_atomic(self):
        self.worker("prepare_activation_rollback")
        self.worker("activation_rollback", origins=TARGET)

    def test_pending_google_exclusion_and_retained_active_google_binding(self):
        self.worker("google_pending_checks")
        changes = {"SERVERWARE_DATA_DIR": str(Path(self.scratch.name) / "active-google")}
        prepared = self.worker("prepare_active_google", google_enabled=True, changes=changes)
        identifier = prepared["operation"]["operation_id"]
        self.worker("refused_restart", origins=GOOGLE_TARGET, changes=changes)
        self.worker("refused_restart", origins=GOOGLE_TARGET, google_enabled=True,
            changes={**changes, "SERVERWARE_GOOGLE_OAUTH_CLIENT_ID": "456-other.apps.googleusercontent.com"})
        activated = self.worker("activate", origins=GOOGLE_TARGET, google_enabled=True, changes=changes, identifier=identifier)
        self.assertEqual(activated["authority"], prepared["authority"])


if __name__ == "__main__":
    if len(sys.argv) in (3, 4) and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(no_network)
        name = sys.argv[2]
        if name == "activate":
            assert len(sys.argv) == 4
            result = activate(sys.argv[3])
        elif name.startswith("advance_"):
            result = advance(name.removeprefix("advance_"))
        elif name in {"review_checks", "receipt_checks", "prepare_rollback", "google_pending_checks"}:
            result = checks(name)
        elif name == "prepare_existing":
            result = Fixture().prepare()
        else:
            result = {"seed": seed, "prepare": prepare, "refused_restart": refused_restart,
                "prepare_active_google": lambda: prepare(active_google=True),
                "prepare_activation_rollback": lambda: prepare(activation_failure=True),
                "activation_rollback": activation_rollback}[name]()
        print(json.dumps(result, sort_keys=True))
    else:
        unittest.main(verbosity=2)
