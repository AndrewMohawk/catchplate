#!/usr/bin/env python3
"""Real SQLite/ASGI cleanup-fence regressions with synthetic provider transport.

No capability, identity, collision, encryption, policy or cleanup guard is
substituted for a successful assertion. Fault patches/triggers are refusal
controls only. These tests do not authorize Google contact, deployment, or
native/enrolled cleanup. Run in the bounded network-none backend harness.
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
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_operator_google_consent as consent_tests
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
REVOKE = "https://oauth2.googleapis.com/revoke"
TOKEN = "https://oauth2.googleapis.com/token"
OLD = "2000-01-01T00:00:00+00:00"
WORK_TABLE = "operator_google_cleanup_work"
TABLES = (*workspace.LEGACY_TABLES, *workspace.CATALOG_TABLES,
    "operator_catalog_oauth_profile", "operator_catalog_oauth_intents",
    "oauth_revocation_work", WORK_TABLE)


class Fixture(consent_tests.Fixture):
    def __init__(self):
        super().__init__()
        from serverware import operator_google_cleanup as cleanup
        from serverware import operator_google_cleanup_store as cleanup_store
        self.cleanup, self.cleanup_store = cleanup, cleanup_store
        self.history, self.reservations, self.transport_checks = [], [], []
        self.revocations = 0
        self.fail_revocation = False
        self.refresh_core = None

    def snapshot(self):
        with closing(self.db.connect()) as conn:
            return {table: sorted(tuple(row) for row in conn.execute("SELECT * FROM " + table))
                for table in TABLES}, self.config.POLICY_BUNDLE_PATH.read_bytes()

    def transport(self, request, **options):
        url = request.full_url
        self.history.append((request.get_method(), url))
        check_index = len(self.transport_checks)
        self.transport_checks.append(False)
        if url == REVOKE:
            # Count attempts before any oracle can throw into a production
            # error handler. A swallowed assertion cannot hide provider contact.
            self.revocations += 1
        # Provider I/O must be outside the publisher's EX and SQLite writer.
        try:
            self.store.operator_publication.assert_held()
        except RuntimeError:
            pass
        else:
            raise AssertionError("provider transport entered under publication EX")
        with closing(self.db.connect()) as conn:
            conn.execute("PRAGMA busy_timeout=0")
            conn.execute("BEGIN IMMEDIATE")
            conn.rollback()
        if url == TOKEN:
            candidates = [row for row in self.rows("oauth_revocation_work")
                if row["status"] == "exchange_in_flight"]
            assert len(candidates) == 1
            row = candidates[0]
            retained = self.cleanup_store.get_work(row["id"])
            assert retained is not None and retained["work_id"] == row["id"]
            assert retained["source"] == row["source"]
            association = retained["association"]
            assert association["work_id"] == row["id"]
            assert association["profile_binding_digest"] == self.profile.binding_digest
            assert association["oauth_client_id"] == self.profile.client_id
            if self.refresh_core is None:
                assert row["source"] == "operator_google_initial_v1"
                assert association["operation"] == "initial"
                assert association["intent_id"] == self.started["operatorGoogleIntent"]["id"]
                assert association["credential_id"] is None and association["credential_generation"] is None
                assert association["credential_metadata_sha256"] is None
            else:
                assert row["source"] == "operator_google_refresh_v1"
                assert association["operation"] == "refresh"
                assert association["credential_id"] == self.refresh_core["id"]
                assert association["credential_generation"] == self.refresh_core["credential_version"]
                canonical = json.dumps(self.refresh_core["metadata"], sort_keys=True,
                    separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
                assert association["credential_metadata_sha256"] == "sha256:" + hashlib.sha256(canonical).hexdigest()
                assert retained["identity"] == {key: self.refresh_core["metadata"][key]
                    for key in ("provider_subject", "provider_account")}
            assert retained["fence"] is None
            self.reservations.append(retained)
        elif url == REVOKE:
            # Check the durable guard independently at the provider boundary.
            with closing(self.db.connect()) as conn:
                candidates = conn.execute("SELECT * FROM oauth_revocation_work").fetchall()
                assert any(self.cleanup_store.eligible(conn, row) for row in candidates)
        response = super().transport(request, **options)
        self.transport_checks[check_index] = True
        if url == REVOKE and self.fail_revocation:
            return SimpleNamespace(status=503, body=b'{"error":"synthetic unavailable"}', headers={})
        return response

    def begin(self):
        self.calls.clear()  # The inherited one-flow assertion is not a total counter.
        return super().begin()

    def connect(self):
        self.begin()
        status, _, _ = self.callback()
        assert status == 200
        records = workspace.catalog(self.db, self.schema)["credentials"]
        record = next(row for row in records
            if row.get("oauth_intent_id") == self.started["operatorGoogleIntent"]["id"])
        core = self.db.get_credential(record["id"], include_secret=True)
        assert core is not None and core["lifecycle_status"] == "active"
        assert not self.rows("oauth_revocation_work") and not self.rows(WORK_TABLE)
        return core

    def application_and_rule(self, credential, *, google=True):
        application = workspace.create_application(self.db, self.store, self.schema,
            self.inputs, self.mutations)["application"]
        result = self.mutations.create_rule(self.inputs.RuleInput(**self.review(),
            name="Cleanup boundary rule", application_id=application["id"], credential_id=credential["id"],
            upstream_url="https://gmail.googleapis.com/gmail/v1/users/me/messages"
                if google else "https://api.example.com/v1/items",
            methods=["GET"], response_fields=["id"]), workspace.common._ACTOR)
        return application, result["access_rule"]

    def with_shared_family(self):
        core = self.connect()
        _, affected = self.application_and_rule(core)
        static = workspace.create_credential(self.db, self.store, self.schema,
            self.inputs, self.mutations)["credential"]
        application, unaffected = self.application_and_rule(static, google=False)
        self.identity_changes = {"sub": core["metadata"]["provider_subject"]}
        self.begin()
        return core, affected, static, application, unaffected

    def held(self):
        exchanged = self.exchange()
        work_id = exchanged["revocationWorkId"]
        row = self.cleanup_store.get_work(work_id)
        assert row is not None and row["fence"] is None
        assert row["identity"] == {key: exchanged["metadata"][key]
            for key in ("provider_subject", "provider_account")}
        assert row["material_sha256"] is not None
        return work_id

    def due(self, work_id=None):
        with closing(self.db.connect()) as conn, conn:
            clause, values = ("", ()) if work_id is None else (" WHERE id=?", (work_id,))
            conn.execute("UPDATE oauth_revocation_work SET next_attempt_at=?,lease_until=NULL,lease_owner=NULL"
                + clause, (OLD, *values))

    def ineligible(self, work_id):
        with closing(self.db.connect()) as conn:
            row = conn.execute("SELECT * FROM oauth_revocation_work WHERE id=?", (work_id,)).fetchone()
            assert row is not None
            assert self.cleanup_store.eligible(conn, row) is False
            secret = json.loads(self.db.decrypt_secret_envelope(row))
        consent_tests.refused(lambda: self.cleanup_store.require_permit(work_id=work_id, secret=secret), ValueError)
        for binding in ({}, {"_operator_cleanup_work_id": work_id}):
            consent_tests.refused(lambda: self.oauth.revoke_oauth_token(provider_id="google",
                token_secret=secret, **binding), self.oauth.OAuthError)
        assert not self.db.claim_oauth_revocations(worker_id="synthetic-cleanup-check", limit=8)
        result = self.app._reconcile_oauth_revocations(limit=8)
        assert result["revoked"] == 0 and self.revocations == 0
        assert all(self.transport_checks), "a provider-boundary assertion was swallowed"

    def coherent_quarantine(self, core, affected, static, application, unaffected):
        catalog = workspace.catalog(self.db, self.schema)
        row = next(item for item in catalog["credentials"] if item["id"] == core["id"])
        assert row["status"] != "active"
        with closing(self.db.connect()) as conn:
            retained = dict(conn.execute("SELECT * FROM credentials WHERE id=?", (core["id"],)).fetchone())
            static_row = dict(conn.execute("SELECT * FROM credentials WHERE id=?", (static["id"],)).fetchone())
        assert retained["lifecycle_status"] == "revocation_pending"
        assert retained["credential_version"] == core["credential_version"] + 1
        assert retained["secret_ciphertext"] and retained["encrypted_dek"]
        assert static_row["lifecycle_status"] == "active"
        signed = workspace.verify_signed(self.config, self.db, self.store, self.bundles)
        route_ids = {item["id"] for item in signed["routes"]}
        assert affected["route_id"] not in route_ids and unaffected["route_id"] in route_ids
        status = self.mutations.catalog_status()
        assert any(item["id"] == static["id"] for item in status["credentials"])
        # A real unrelated mutation proves the catalog is not globally poisoned.
        self.mutations.rotate_application_token(self.inputs.RotateApplicationInput(**self.review(),
            id=application["id"], token_lifetime_seconds=3600), workspace.common._ACTOR)
        workspace.create_credential(self.db, self.store, self.schema, self.inputs, self.mutations,
            name="Unrelated credential after quarantine")
        workspace.catalog(self.db, self.schema)
        self.assert_redacted_cleanup()

    def assert_redacted_cleanup(self):
        assert all(self.transport_checks), "a provider-boundary assertion was swallowed"
        with closing(self.db.connect()) as conn:
            retained = "\n".join(conn.iterdump())
        for value in (consent_tests.ACCESS, consent_tests.REFRESH, consent_tests.REFRESHED,
                consent_tests.CODE, consent_tests.ADMIN, consent_tests.google_tests.CLIENT_SECRET):
            assert value not in retained
        assert self.db.verify_audit_chain()["ok"]


def aged_work():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        work_id = f.held()
        f.due(work_id)
        f.ineligible(work_id)
        consent_tests.refused(lambda: f.db.mark_oauth_revocation_work_pending(work_id,
            error="synthetic pending request"), ValueError)
        # Corrupt only this private negative fixture: pending is not authority.
        with closing(f.db.connect()) as conn, conn:
            conn.execute("UPDATE oauth_revocation_work SET status='pending' WHERE id=?", (work_id,))
        f.due(work_id)
        f.ineligible(work_id)
        assert f.cleanup_store.get_work(work_id)["fence"] is None
        previous_contacts = len(f.history)
        # A smaller synthetic capacity exercises the real exhausted-count guard
        # without allocating hundreds of encrypted reservations on this host.
        with patch.object(f.db, "_OAUTH_REVOCATION_BACKLOG_MAX_COUNT", 1):
            f.begin()
            assert f.callback()[0] in {400, 409, 503}
        assert len(f.history) == previous_contacts and len(f.rows("oauth_revocation_work")) == 1
        f.assert_redacted_cleanup()
    return {"aged_held_and_pending_blocked": True, "revocations": f.revocations}


def missing_association():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        work_id = f.held()
        original = f.cleanup_store.get_work(work_id)
        for table, column, value, key in (
                ("oauth_revocation_work", "source", "authorization_code_exchange", "id"),
                ("oauth_revocation_work", "provider_id", "x", "id"),
                (WORK_TABLE, "association_json", "{}", "work_id")):
            with closing(f.db.connect()) as conn, conn:
                consent_tests.refused(lambda: conn.execute("UPDATE " + table + " SET " + column
                    + "=? WHERE " + key + "=?", (value, work_id)), sqlite3.IntegrityError)
            assert f.cleanup_store.get_work(work_id) == original
        before = f.snapshot()
        for source in ("operator_google_initial_v1", "operator_google_unknown_v1"):
            consent_tests.refused(lambda: f.db.reserve_oauth_revocation_work(provider_id="google",
                actor_id="synthetic-caller", source=source), ValueError)
            assert f.snapshot() == before
        with closing(f.db.connect()) as conn, conn:
            conn.execute("DELETE FROM " + WORK_TABLE + " WHERE work_id=?", (work_id,))
        f.due(work_id)
        f.ineligible(work_id)
        consent_tests.refused(lambda: f.db.mark_oauth_revocation_work_pending(work_id,
            error="synthetic missing association"), ValueError)
        with closing(f.db.connect()) as conn, conn:
            conn.execute("UPDATE oauth_revocation_work SET status='pending' WHERE id=?", (work_id,))
        f.ineligible(work_id)
        row = next(row for row in f.rows("oauth_revocation_work") if row["id"] == work_id)
        assert row["source"] == "operator_google_initial_v1"
        assert row["secret_ciphertext"]
    return {"missing_association_not_downgraded": True}


def unknown_identity():
    f = Fixture()
    f.identity_changes = {"sub": None}
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        status, _, _ = f.callback()
        assert status == 409
        work = f.rows("oauth_revocation_work")
        assert len(work) == 1 and work[0]["secret_ciphertext"]
        retained = f.cleanup_store.get_work(work[0]["id"])
        assert retained["identity"] is None and retained["fence"] is None
        outcome = f.cleanup.fence(work[0]["id"])
        assert outcome.status == "deferred" and outcome.receipt is None
        f.due(work[0]["id"])
        f.ineligible(work[0]["id"])
        assert not f.rows("credentials")
        f.assert_redacted_cleanup()
    return {"unknown_family_deferred": True, "revocations": f.revocations}


def expired_core(f):
    core = f.connect()
    f.application_and_rule(core)
    secret = {**json.loads(core["secret"]), "expires_at_epoch_ms": 1}
    expired, changed = f.db.update_credential_secret_if_version(core["id"],
        expected_version=core["credential_version"], secret=json.dumps(secret),
        metadata={**core["metadata"], "expires_at_epoch_ms": 1})
    assert changed
    f.app.runtime.invalidate_secret_leases(core["id"])
    f.refresh_core = expired
    return expired


def retention_failure(operation):
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        core = expired_core(f) if operation == "refresh" else None
        if core is None:
            f.begin()
        with patch.object(f.db, "attach_oauth_revocation_material",
                side_effect=RuntimeError("synthetic durable material retention failure")):
            if core is None:
                assert f.callback()[0] in {400, 409, 503}
            else:
                from fastapi import HTTPException
                consent_tests.refused(lambda: f.app._credential_for_lease(core["id"]), HTTPException)
        assert f.revocations == 0
        work = f.rows("oauth_revocation_work")
        assert len(work) == 1 and work[0]["source"] == "operator_google_" + operation + "_v1"
        # A reservation is not proof the returned token was retained.
        assert json.loads(f.db.decrypt_secret_envelope(work[0])) == {}
        retained = f.cleanup_store.get_work(work[0]["id"])
        assert retained["material_sha256"] is None and retained["fence"] is None
        f.due(work[0]["id"])
        with closing(f.db.connect()) as conn:
            assert f.cleanup_store.eligible(conn, work[0]) is False
        f.app._reconcile_oauth_revocations(limit=8)
        assert f.revocations == 0
        assert sum(url == TOKEN for _method, url in f.history) == (1 if operation == "initial" else 2)
        f.assert_redacted_cleanup()
    return {"operation": operation, "immediate_revoke_blocked": True, "retention_not_claimed": True}


def duplicate_collision():
    f = Fixture()
    f.fail_revocation = True
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        affected = f.with_shared_family()
        status, _, _ = f.callback()
        assert status == 409
        f.coherent_quarantine(*affected)
        work = f.rows("oauth_revocation_work")
        assert len(work) == 1
        outcome = f.cleanup.fence(work[0]["id"])
        assert outcome.status == "committed" and outcome.receipt is not None
        before = f.snapshot()
        repeated = f.cleanup.fence(work[0]["id"])
        assert repeated.receipt == outcome.receipt and f.snapshot() == before
        f.fail_revocation = False
        f.due(work[0]["id"])
        result = f.app._reconcile_oauth_revocations(limit=8)
        assert result["revoked"] == 1 and not f.rows("oauth_revocation_work") and not f.rows(WORK_TABLE)
        workspace.catalog(f.db, f.schema)
        f.assert_redacted_cleanup()
    return {"atomic_collision_quarantine": True, "unrelated_catalog_usable": True, "cleanup_completed": True}


def refresh_rejection():
    f = Fixture()
    f.fail_revocation = True
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        core = expired_core(f)
        f.refresh_scope_string = "openid email https://www.googleapis.com/auth/gmail.modify"
        from fastapi import HTTPException
        consent_tests.refused(lambda: f.app._credential_for_lease(core["id"]), HTTPException)
        work = f.rows("oauth_revocation_work")
        assert len(work) == 1 and work[0]["source"] == "operator_google_refresh_v1"
        retained = f.cleanup_store.get_work(work[0]["id"])
        assert retained["fence"] is not None
        with closing(f.db.connect()) as conn:
            actual = conn.execute("SELECT credential_version,lifecycle_status FROM credentials WHERE id=?",
                (core["id"],)).fetchone()
        assert actual["credential_version"] == core["credential_version"] + 1
        assert actual["lifecycle_status"] == "revocation_pending"
        assert not [row for row in workspace.catalog(f.db, f.schema)["access_rules"] if row["status"] == "active"]
        signed = workspace.verify_signed(f.config, f.db, f.store, f.bundles)
        assert all(route.get("credentialRef") != core["id"] for route in signed["routes"])
        f.assert_redacted_cleanup()
    return {"refresh_scope_refusal_fenced": True}


def initial_scope_rejection():
    f = Fixture()
    f.fail_revocation = True
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        affected = f.with_shared_family()
        # Identity has been verified before this scope refusal; no duplicate
        # credential INSERT is attempted, so collision-only cleanup is insufficient.
        f.scope_string += " https://www.googleapis.com/auth/gmail.modify"
        assert f.callback()[0] == 409
        f.coherent_quarantine(*affected)
        work = f.rows("oauth_revocation_work")
        assert len(work) == 1 and f.cleanup_store.get_work(work[0]["id"])["fence"] is not None
    return {"initial_post_identity_scope_refusal_fenced": True}


def registration_failure():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        with closing(f.db.connect()) as conn, conn:
            conn.execute("CREATE TRIGGER registration_abort BEFORE INSERT ON operator_catalog_credentials "
                "BEGIN SELECT RAISE(ABORT, 'synthetic registration refusal'); END")
        status, raw, _ = f.callback()
        assert status == 409
        disposition = json.loads(raw)["operator_google_cleanup"]
        assert disposition["status"] == "deferred" and "fence" not in disposition
        assert not f.rows("credentials") and not f.rows("operator_catalog_credentials")
        work = f.rows("oauth_revocation_work")
        assert len(work) == 1 and work[0]["status"] == "held"
        retained = f.cleanup_store.get_work(work[0]["id"])
        assert retained["identity"] is not None and retained["material_sha256"] is not None
        assert retained["fence"] is None
        f.due(work[0]["id"])
        f.ineligible(work[0]["id"])
        with closing(f.db.connect()) as conn, conn:
            conn.execute("DROP TRIGGER registration_abort")
        workspace.create_credential(f.db, f.store, f.schema, f.inputs, f.mutations)
        workspace.catalog(f.db, f.schema)
        f.assert_redacted_cleanup()
    return {"registration_failure_empty_family_deferred": True, "no_half_registration": True,
        "revocations": f.revocations}


def empty_family_later_consent():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        f.scope_string += " https://www.googleapis.com/auth/gmail.modify"
        status, raw, _ = f.callback()
        assert status == 409
        disposition = json.loads(raw)["operator_google_cleanup"]
        assert disposition["status"] == "deferred" and "fence" not in disposition
        work = f.rows("oauth_revocation_work")
        assert len(work) == 1 and work[0]["status"] == "held"
        work_id = work[0]["id"]
        retained = f.cleanup_store.get_work(work_id)
        assert retained["identity"] is not None and retained["material_sha256"] is not None
        assert retained["fence"] is None and not f.rows("credentials")
        before = f.snapshot()
        outcome = f.cleanup.fence(work_id)
        assert outcome.status == "deferred" and outcome.receipt is None
        assert f.snapshot() == before, "empty-family fence left partial authoritative state"
        f.due(work_id)
        f.ineligible(work_id)

        # A later real consent may adopt this account; old withheld cleanup
        # must not become generic work or revoke its newly usable grant.
        f.scope_string = " ".join(f.profile.scopes)
        f.identity_changes = {"sub": retained["identity"]["provider_subject"]}
        f.begin()
        assert f.callback()[0] == 200
        catalog = workspace.catalog(f.db, f.schema)
        assert len(catalog["credentials"]) == 1
        credential = catalog["credentials"][0]
        core = f.db.get_credential(credential["id"], include_secret=True)
        assert core["lifecycle_status"] == "active"
        assert core["metadata"]["provider_subject"] == retained["identity"]["provider_subject"]
        assert core["metadata"]["oauth_client_id"] == retained["association"]["oauth_client_id"]
        assert [row["id"] for row in f.rows("oauth_revocation_work")] == [work_id]
        assert f.cleanup_store.get_work(work_id) == retained
        _, rule = f.application_and_rule(core)
        signed = workspace.verify_signed(f.config, f.db, f.store, f.bundles)
        assert rule["route_id"] in {route["id"] for route in signed["routes"]}
        f.due(work_id)
        f.ineligible(work_id)
        assert f.db.get_credential(core["id"], include_secret=True) == core
        assert f.cleanup_store.get_work(work_id) == retained
        assert sum(url == TOKEN for _method, url in f.history) == 2
        f.assert_redacted_cleanup()
    return {"empty_family_deferred": True, "later_same_family_active": True,
        "revocations": f.revocations}


def historical_empty_fence():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        work_id = f.held()
        work = f.cleanup_store.get_work(work_id)
        review = f.review()
        # Negative retained-state fixture only: an old structurally valid
        # empty receipt is not a current cleanup permit. No guard is replaced.
        receipt = {"schema": f.cleanup_store.FENCE_SCHEMA, "work_id": work_id,
            "source": work["source"],
            "profile_binding_digest": work["association"]["profile_binding_digest"],
            "oauth_client_id": work["association"]["oauth_client_id"], **work["identity"],
            "policy_hash": review["expected_policy_hash"],
            "catalog_revision": review["expected_revision"], "credential_ids": [],
            "fenced_at": f.db.iso_now()}
        with closing(f.db.connect()) as conn, conn:
            conn.execute("UPDATE " + WORK_TABLE + " SET fence_json=? WHERE work_id=?",
                (json.dumps(receipt, sort_keys=True, separators=(",", ":")), work_id))
            conn.execute("UPDATE oauth_revocation_work SET status='pending' WHERE id=?", (work_id,))
        assert f.cleanup_store.get_work(work_id)["fence"] == receipt
        assert not f.rows("credentials") and not f.rows("pending_oauth_credentials")
        f.due(work_id)
        before = f.snapshot()
        f.ineligible(work_id)
        assert f.snapshot() == before
        f.assert_redacted_cleanup()
    return {"historical_empty_receipt_not_authority": True, "revocations": f.revocations}


def rollback(stage):
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.with_shared_family()
        work_id = f.held()
        triggers = {
            "core": ("UPDATE", "credentials", ""),
            "catalog": ("UPDATE", "operator_catalog_credentials", ""),
            "rules": ("UPDATE", "operator_catalog_rules", ""),
            "policy": ("UPDATE", "operator_demo_policy", ""),
            "revision": ("UPDATE", "operator_catalog_state", ""),
            "intent": ("UPDATE", "operator_catalog_oauth_intents", ""),
            "audit": ("INSERT", "audit_events", ""),
        }
        if stage in triggers:
            action, table, condition = triggers[stage]
            with closing(f.db.connect()) as conn, conn:
                conn.execute("CREATE TRIGGER cleanup_fence_abort BEFORE " + action + " ON " + table + condition
                    + " BEGIN SELECT RAISE(ABORT, 'synthetic cleanup fence rollback'); END")
        elif stage == "commit":
            with closing(f.db.connect()) as conn, conn:
                conn.execute("CREATE TABLE cleanup_commit_failure (id INTEGER REFERENCES operator_demo_policy(singleton) "
                    "DEFERRABLE INITIALLY DEFERRED)")
                conn.execute("CREATE TRIGGER cleanup_fence_abort AFTER UPDATE ON credentials "
                    "BEGIN INSERT INTO cleanup_commit_failure VALUES (99); END")
        before = f.snapshot()
        if stage == "signing":
            with patch.object(f.bundles, "sign_policy_bundle", side_effect=RuntimeError("synthetic signing refusal")):
                outcome = f.cleanup.fence(work_id)
        else:
            outcome = f.cleanup.fence(work_id)
        assert outcome.status == "deferred" and outcome.receipt is None
        assert f.snapshot() == before, "failed fence left partial authoritative state"
        f.due(work_id)
        f.ineligible(work_id)
        if stage != "signing":
            with closing(f.db.connect()) as conn, conn:
                conn.execute("DROP TRIGGER cleanup_fence_abort")
                if stage == "commit":
                    conn.execute("DROP TABLE cleanup_commit_failure")
        f.assert_redacted_cleanup()
    return {"stage": stage, "whole_fence_rolled_back": True, "revocations": f.revocations}


def materialization_failure():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        core, affected, static, application, unaffected = f.with_shared_family()
        work_id = f.held()
        before_file = f.config.POLICY_BUNDLE_PATH.read_bytes()
        with patch.object(f.store, "materialize", side_effect=OSError("synthetic committed publication failure")):
            result = f.cleanup.fence(work_id)
        assert result.status == "committed" and result.publication == "pending" and result.receipt is not None
        assert f.config.POLICY_BUNDLE_PATH.read_bytes() == before_file
        assert f.bundles.get_policy_snapshot() is None, "stale pre-fence file remained authoritative"
        receipt = f.cleanup_store.get_work(work_id)["fence"]
        assert receipt == result.receipt
        assert f.revocations == 0, "fencing itself performed provider cleanup"
        with closing(f.db.connect()) as conn:
            generation = conn.execute("SELECT credential_version FROM credentials WHERE id=?", (core["id"],)).fetchone()[0]
        assert generation == core["credential_version"] + 1
        f.assert_redacted_cleanup()
        return {"receipt": receipt, "work_id": work_id, "core_id": core["id"], "generation": generation}


def materialization_reopen():
    # Original startup, no initializer patch: the DB's committed policy is
    # materialized before catalog use after a real process boundary.
    f = Fixture()
    work = f.rows("oauth_revocation_work")
    assert len(work) == 1
    receipt = f.cleanup_store.get_work(work[0]["id"])["fence"]
    assert receipt is not None and len(receipt["credential_ids"]) == 1
    core_id = receipt["credential_ids"][0]
    before = f.snapshot()
    result = f.cleanup.fence(work[0]["id"])
    assert result.status == "committed" and result.receipt == receipt
    assert f.snapshot() == before, "restart repeated quarantine instead of observing its receipt"
    with closing(f.db.connect()) as conn:
        core = dict(conn.execute("SELECT * FROM credentials WHERE id=?", (core_id,)).fetchone())
    assert core["lifecycle_status"] == "revocation_pending"
    catalog = workspace.catalog(f.db, f.schema)
    assert all(rule["credential_id"] != core_id for rule in catalog["access_rules"] if rule["status"] == "active")
    signed = workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    assert all(route.get("credentialRef") != core_id for route in signed["routes"])
    assert any(row["auth_type"] == "bearer" and row["status"] == "active" for row in catalog["credentials"])
    assert f.revocations == 0
    return {"receipt": receipt, "work_id": work[0]["id"], "core_id": core_id, "generation": core["credential_version"]}


def restart_prepare():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        work_id = f.held()
        f.due(work_id)
        f.ineligible(work_id)
    return {"work_id": work_id, "association": f.cleanup_store.get_work(work_id)["association"]}


def restart_check():
    f = Fixture()  # Real cold admission and original startup on the retained store.
    work = f.rows("oauth_revocation_work")
    assert len(work) == 1
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.ineligible(work[0]["id"])
    return {"work_id": work[0]["id"], "association": f.cleanup_store.get_work(work[0]["id"])["association"]}


OPERATIONS = {"aged-work": aged_work, "missing-association": missing_association,
    "unknown-identity": unknown_identity, "retention-initial": lambda: retention_failure("initial"),
    "retention-refresh": lambda: retention_failure("refresh"), "duplicate-collision": duplicate_collision,
    "refresh-rejection": refresh_rejection, "initial-scope-rejection": initial_scope_rejection,
    "registration-failure": registration_failure, "empty-family-later-consent": empty_family_later_consent,
    "historical-empty-fence": historical_empty_fence,
    "materialization-failure": materialization_failure,
    "materialization-reopen": materialization_reopen,
    "restart-prepare": restart_prepare, "restart-check": restart_check}
for _stage in ("core", "catalog", "rules", "policy", "revision", "intent", "audit", "signing", "commit"):
    OPERATIONS["rollback-" + _stage] = lambda stage=_stage: rollback(stage)


class OperatorGoogleCleanupTests(unittest.TestCase):
    setUp = consent_tests.OperatorGoogleConsentTests.setUp

    def worker(self, operation):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        return json.loads(result.stdout)

    def test_unfenced_work_survives_restart(self):
        self.assertEqual(self.worker("restart-prepare"), self.worker("restart-check"))

    def test_materialization_failure_survives_restart(self):
        self.assertEqual(self.worker("materialization-failure"), self.worker("materialization-reopen"))


def _test(operation):
    def check(self):
        self.worker(operation)
    return check


for _operation in OPERATIONS:
    if not _operation.startswith(("restart-", "materialization-")):
        setattr(OperatorGoogleCleanupTests, "test_" + _operation.replace("-", "_"), _test(_operation))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
