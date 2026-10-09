#!/usr/bin/env python3
"""Explicit Google disconnect using real SQLite, signing, CAS and ASGI.

Only provider transport is synthetic. Refusal-only signing/storage faults do
not replace a successful guard. Each worker uses the original cold startup;
these tests prove neither Google propagation nor Rust/live enforcement. Run
only in the bounded network-none, read-only-source backend harness.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_operator_google_cleanup as cleanup_tests
import test_operator_google_consent as consent_tests
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
PATH = "/api/operator-demo/oauth/google/disconnect"
MISSING = "00000000-0000-4000-8000-000000000001"


class Fixture(cleanup_tests.Fixture):
    def __init__(self):
        super().__init__()
        from serverware import operator_google_disconnect
        self.disconnect = operator_google_disconnect

    def snapshot(self):
        # Include the new receipt table, generations, audit, and every other
        # real table without maintaining a selective rollback allowlist.
        with closing(self.db.connect()) as conn:
            dump = tuple(conn.iterdump())
        return dump, self.config.POLICY_BUNDLE_PATH.read_bytes()

    def family(self):
        core = self.connect()
        app_a, rule_a = self.application_and_rule(core)
        app_b, rule_b = self.application_and_rule(core)
        static = workspace.create_credential(self.db, self.store, self.schema,
            self.inputs, self.mutations)["credential"]
        other_app, other_rule = self.application_and_rule(static, google=False)
        return core, [app_a, app_b], [rule_a, rule_b], static, other_app, other_rule

    def payload(self, core, rules):
        return {**self.review(), "id": core["id"],
            "confirmed_affected_rule_ids": sorted(rule["id"] for rule in rules),
            "acknowledge_project_wide_revocation": True}

    def public(self, credential_id):
        code, raw, headers = self.request("GET", PATH + "/" + credential_id)
        assert code == 200, (code, raw)
        assert [value for name, value in headers if name.lower() == b"cache-control"] == [b"no-store"]
        return json.loads(raw)

    def events(self, event_type):
        return [json.loads(row["event_json"]) for row in self.rows("audit_events")
            if row["event_type"] == event_type]

    def start(self, core, rules):
        before_contacts = list(self.history)
        code, raw, _ = self.request("POST", PATH, body=self.payload(core, rules))
        assert code == 202, (code, raw)
        result = json.loads(raw)
        assert result["outcome"] == "committed"
        operation = result["disconnect"]
        assert operation["schema"] == "serverware.operatorGoogleDisconnect/v1"
        assert operation["credential_id"] == core["id"]
        assert operation["credential_ids"] == [core["id"]]
        assert operation["affected_rule_ids"] == sorted(rule["id"] for rule in rules)
        assert operation["affected_application_ids"] == sorted({rule["application_id"] for rule in rules})
        assert operation["status"] == "pending" and operation["attempts"] == 0
        assert operation["provider_accepted_at"] is None
        assert operation["provider_revocation"] == "not_proven"
        self.blocked_receipt(operation)
        work = self.rows("oauth_revocation_work")
        assert len(work) == 1 and work[0]["id"] == operation["operation_id"]
        assert work[0]["source"] == "operator_google_disconnect_v1"
        assert work[0]["secret_ciphertext"] and work[0]["encrypted_dek"]
        assert self.cleanup_store.get_work(work[0]["id"])["fence"] is not None
        events = self.events("operator_catalog.oauth.disconnect_requested")
        assert len(events) == 1
        assert events[0]["operation_id"] == operation["operation_id"]
        assert events[0]["credential_id"] == core["id"]
        assert events[0]["affected_rule_ids"] == operation["affected_rule_ids"]
        assert events[0]["revision"] == result["revision"]
        assert events[0]["policy_hash"] == result["policy"]["policy_hash"]
        assert self.history == before_contacts, "initial mutation contacted provider"
        return result

    @staticmethod
    def blocked_receipt(operation):
        assert operation["propagation"] == "not_proven"
        assert operation["reconnect"] == "blocked"
        assert operation["local_enforcement"] in {"pending", "enforced"}
        assert operation["in_flight_requests"] == "not_recalled"
        assert operation["automatic_replay_allowed"] is False

    def reduced(self, core, rules):
        catalog = workspace.catalog(self.db, self.schema)
        record = next(row for row in catalog["credentials"] if row["id"] == core["id"])
        assert record["status"] == "quarantined"
        assert self.db.get_credential(core["id"], include_secret=True) is None
        current = self.db.get_credential(core["id"], include_secret=True, include_inactive=True)
        assert current is not None and current["lifecycle_status"] == "revocation_pending"
        assert current["credential_version"] == core["credential_version"] + 1
        assert current["secret"] == core["secret"]
        affected = {rule["id"] for rule in rules}
        assert all(row["status"] == "revoked" for row in catalog["access_rules"] if row["id"] in affected)
        signed = workspace.verify_signed(self.config, self.db, self.store, self.bundles)
        assert not {rule["route_id"] for rule in rules} & {route["id"] for route in signed["routes"]}
        return catalog, current

    def refused_request(self, payload, expected, **options):
        before, contacts = self.snapshot(), list(self.history)
        code, raw, _ = self.request("POST", PATH, body=payload, **options)
        assert code == expected, (code, expected, raw)
        assert self.snapshot() == before, "refused mutation changed durable state"
        assert self.history == contacts, "refused mutation contacted provider"

    def new_consent_and_refresh_refused(self, core):
        before, contacts = self.snapshot(), list(self.history)
        code, raw, _ = self.request("POST", consent_tests.START, body={**self.review(),
            "name": "Not an implicit reconnect", "permission_preset": "gmail_readonly"})
        assert code == 409, (code, raw)
        # Use original verified metadata/token material, not an already-filtered
        # None credential, so the refresh path itself must reject the fence.
        consent_tests.refused(lambda: self.oauth.refresh_access_token(provider_id="google",
            token_secret=json.loads(core["secret"]), metadata=core["metadata"]), self.oauth.OAuthError)
        assert self.snapshot() == before and self.history == contacts


def shared_family():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        core, apps, rules, static, other_app, other_rule = f.family()
        before = workspace.catalog(f.db, f.schema)
        high_water = f.store.get_policy_high_water()
        static_core = f.db.get_credential(static["id"], include_secret=True)
        original_payload = f.payload(core, rules)
        result = f.start(core, rules)
        after, _ = f.reduced(core, rules)
        assert result["revision"] == before["revision"] + 1 == after["revision"]
        assert result["policy"]["policy_hash"] != high_water["policy_hash"]
        assert result["policy"]["sequence"] == high_water["sequence"] + 1
        assert after["applications"] == before["applications"]
        assert next(row for row in after["credentials"] if row["id"] == static["id"]) == next(
            row for row in before["credentials"] if row["id"] == static["id"])
        assert next(row for row in after["access_rules"] if row["id"] == other_rule["id"]) == next(
            row for row in before["access_rules"] if row["id"] == other_rule["id"])
        assert f.db.get_credential(static["id"], include_secret=True) == static_core
        signed = workspace.verify_signed(f.config, f.db, f.store, f.bundles)
        assert {row["id"] for row in signed["routes"]} == {other_rule["route_id"]}
        saved = f.snapshot()
        assert f.public(core["id"])["disconnect"] == result["disconnect"]
        # Recovery is actor-bound and read-only; another actor sees no receipt.
        assert f.disconnect.status_for_credential(core["id"], "different-synthetic-admin") is None
        assert f.snapshot() == saved and f.revocations == 0
        f.refused_request(original_payload, 409)
        f.refused_request(f.payload(core, rules), 409)
        f.assert_redacted_cleanup()
    return {"affected_rules": 2, "unrelated_rule_preserved": True, "provider_contacts_during_disconnect": 0}


def confirmation_guards():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        core, _apps, rules, static, _other_app, _other_rule = f.family()
        body = f.payload(core, rules)
        for changes, expected in (
                ({"expected_revision": body["expected_revision"] - 1}, 409),
                ({"expected_policy_hash": "sha256:" + "0" * 64}, 409),
                ({"confirmed_affected_rule_ids": body["confirmed_affected_rule_ids"][:1]}, 409),
                ({"confirmed_affected_rule_ids": sorted([*body["confirmed_affected_rule_ids"], MISSING])}, 409),
                ({"confirmed_affected_rule_ids": list(reversed(body["confirmed_affected_rule_ids"]))}, 422),
                ({"confirmed_affected_rule_ids": [rules[0]["id"], rules[0]["id"]]}, 422),
                ({"confirmed_affected_rule_ids": [MISSING] * 65}, 422),
                ({"acknowledge_project_wide_revocation": False}, 422),
                ({"acknowledge_project_wide_revocation": 1}, 422),
                ({"expected_revision": True}, 422),
                ({"id": static["id"]}, 409), ({"id": MISSING}, 404)):
            f.refused_request({**body, **changes}, expected)
        f.assert_redacted_cleanup()
    return {"exact_review_and_resource_guards": True}


def http_guards():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        core = f.connect()
        _app, rule = f.application_and_rule(core)
        body = f.payload(core, [rule])
        f.refused_request(body, 401, auth=False)
        f.refused_request(body, 403, origin=False)
        f.refused_request({**body, "provider": "google"}, 422)
        f.refused_request(b" " * 8193, 413)
        f.refused_request(body, 415, headers=(("Content-Encoding", "identity"),))
        before, contacts = f.snapshot(), list(f.history)
        for path, options, expected in ((PATH + "/" + core["id"], {"auth": False}, 401),
                (PATH + "/" + core["id"] + "?extra=1", {}, 422),
                (PATH + "/" + core["id"], {"body": {}}, 400),
                (PATH + "/not-a-canonical-uuid", {}, 422),
                (PATH + "/" + MISSING, {}, 404)):
            assert f.request("GET", path, **options)[0] == expected
            assert f.snapshot() == before and f.history == contacts
        capability = f.mutations.catalog_status()["capabilities"]["google_disconnect"]
        assert capability == {"schema": "serverware.operatorGoogleDisconnectCapability/v1",
            "path": PATH, "status_path_prefix": PATH + "/", "requires_affected_rule_confirmation": True,
            "requires_project_wide_revocation_acknowledgement": True, "reconnect_supported": False}
        # Negative pre-upgrade fixture: no disconnect has ever been reserved.
        # Remove only the new empty operator-owned table (its triggers follow),
        # then run the original initializer. Absence must not auto-upgrade a
        # retained profile or advertise a mutation which it cannot persist.
        with closing(f.db.connect()) as conn, conn:
            assert conn.execute("SELECT COUNT(*) FROM operator_google_disconnects").fetchone()[0] == 0
            conn.execute("DROP TABLE operator_google_disconnects")
        before = f.snapshot()
        f.store.initialize()
        assert f.snapshot() == before
        assert f.mutations.catalog_status()["capabilities"]["google_disconnect"] is None
        f.refused_request(body, 503)
        f.assert_redacted_cleanup()
    return {"http_guards": True, "capability_requires_explicit_review": True}


def disabled_capability():
    config, db, store, _bundles, _schema, _inputs, mutations = workspace.workspace()
    with closing(db.connect()) as conn:
        before = tuple(conn.iterdump())
    policy = config.POLICY_BUNDLE_PATH.read_bytes()
    capabilities = mutations.catalog_status()["capabilities"]
    assert capabilities["google_oauth"] is None and capabilities["google_disconnect"] is None
    with closing(db.connect()) as conn:
        assert tuple(conn.iterdump()) == before
        assert conn.execute("SELECT 1 FROM sqlite_master WHERE name='operator_google_disconnects'").fetchone() is None
    assert config.POLICY_BUNDLE_PATH.read_bytes() == policy
    return {"disabled_capability": None, "no_schema_upgrade": True}


def rollback(stage):
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        core = f.connect()
        _app, rule = f.application_and_rule(core)
        body = f.payload(core, [rule])
        if stage == "audit":
            with closing(f.db.connect()) as conn, conn:
                conn.execute("CREATE TRIGGER disconnect_test_abort BEFORE INSERT ON audit_events "
                    "BEGIN SELECT RAISE(ABORT,'synthetic disconnect audit refusal'); END")
        before, contacts = f.snapshot(), list(f.history)
        if stage == "signing":
            with patch.object(f.bundles, "sign_policy_bundle", side_effect=RuntimeError("synthetic signing refusal")):
                code, raw, _ = f.request("POST", PATH, body=body)
        else:
            code, raw, _ = f.request("POST", PATH, body=body)
        assert code == 503, (code, raw)
        assert f.snapshot() == before, "precommit failure left partial disconnect authority"
        assert f.history == contacts and not f.rows("oauth_revocation_work")
        assert f.request("GET", PATH + "/" + core["id"])[0] == 404
        if stage == "audit":
            with closing(f.db.connect()) as conn, conn:
                conn.execute("DROP TRIGGER disconnect_test_abort")
        f.assert_redacted_cleanup()
    return {"rolled_back": stage}


def provider_failure():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        core = f.connect()
        _app, rule = f.application_and_rule(core)
        pending = f.start(core, [rule])["disconnect"]
        f.fail_revocation = True
        f.due(pending["operation_id"])
        result = f.app._reconcile_oauth_revocations(limit=8)
        assert result["claimed"] == result["failed"] == 1 and result["revoked"] == 0
        retry = f.public(core["id"])["disconnect"]
        assert retry["status"] == "retry" and retry["attempts"] == 1
        assert retry["next_attempt_at"] is not None and retry["provider_accepted_at"] is None
        assert retry["provider_revocation"] == "not_proven"
        f.blocked_receipt(retry)
        f.reduced(core, [rule])
        f.new_consent_and_refresh_refused(core)
        f.fail_revocation = False

        def lost_provider_response(request, **options):
            response = f.transport(request, **options)
            if request.full_url == cleanup_tests.REVOKE:
                # The real consumer does not receive the synthetic acceptance;
                # timeout means an unknown outcome, not permission to reconnect.
                raise TimeoutError("synthetic response lost after provider contact")
            return response

        f.due(pending["operation_id"])
        with patch.object(f.oauth, "request_bytes", side_effect=lost_provider_response):
            result = f.app._reconcile_oauth_revocations(limit=8)
        assert result["failed"] == 1 and result["revoked"] == 0 and f.revocations == 2
        unknown = f.public(core["id"])["disconnect"]
        assert unknown["operation_id"] == pending["operation_id"]
        assert unknown["status"] == "retry" and unknown["attempts"] == 2
        assert unknown["provider_accepted_at"] is None and unknown["provider_revocation"] == "not_proven"
        assert len(f.rows("oauth_revocation_work")) == len(f.rows(cleanup_tests.WORK_TABLE)) == 1
        f.blocked_receipt(unknown)
        f.reduced(core, [rule])
        f.new_consent_and_refresh_refused(core)
        retry_events = f.events("operator_catalog.oauth.disconnect_retry_retained")
        assert [event["attempts"] for event in retry_events] == [1, 2]
        assert all(event["operation_id"] == pending["operation_id"]
            and event["provider_outcome"] == "not_proven" for event in retry_events)
        assert not f.events("operator_catalog.oauth.disconnect_provider_accepted")
        f.assert_redacted_cleanup()
    return {"retry_retained": True, "unknown_outcome_not_accepted": True}


def accepted_prepare():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        core = f.connect()
        _app, rule = f.application_and_rule(core)
        pending = f.start(core, [rule])["disconnect"]
        f.due(pending["operation_id"])
        locked_health_calls = []
        original_health = f.store.loaded_policy_hash

        def health_outside_publication():
            try:
                f.store.operator_publication.assert_held()
            except RuntimeError:
                return original_health()
            locked_health_calls.append(True)
            # Refusal-only spy: do not let a bug perform gate HTTP beneath EX.
            # The separate call record also catches an exception swallowed by
            # optional observation, without replacing any successful guard.
            raise AssertionError("gate health observation entered under publication EX")

        with patch.object(f.store, "loaded_policy_hash", side_effect=health_outside_publication):
            result = f.app._reconcile_oauth_revocations(limit=8)
        assert not locked_health_calls
        assert result["claimed"] == result["accepted"] == 1
        assert result["revoked"] == result["failed"] == 0
        accepted = f.public(core["id"])["disconnect"]
        assert accepted["operation_id"] == pending["operation_id"] and accepted["status"] == "accepted"
        assert accepted["provider_revocation"] == "accepted" and accepted["provider_accepted_at"] is not None
        f.blocked_receipt(accepted)
        assert not f.rows("oauth_revocation_work") and not f.rows(cleanup_tests.WORK_TABLE)
        _catalog, retained_core = f.reduced(core, [rule])
        f.new_consent_and_refresh_refused(core)
        assert f.app._reconcile_oauth_revocations(limit=8)["claimed"] == 0 and f.revocations == 1
        events = f.events("operator_catalog.oauth.disconnect_provider_accepted")
        assert len(events) == 1 and events[0]["operation_id"] == pending["operation_id"]
        assert events[0]["provider_outcome"] == "accepted" and events[0]["propagation"] == "not_proven"
        assert events[0]["reconnect"] == "blocked"
        worker_events = f.events("credential.oauth_disconnect_provider_accepted")
        assert len(worker_events) == 1
        assert worker_events[0]["revocation_work_id"] == pending["operation_id"]
        assert worker_events[0]["result"] == "provider_accepted"
        assert worker_events[0]["propagation"] == "not_proven" and worker_events[0]["reconnect"] == "blocked"
        assert not f.events("credential.oauth_exchange_revoked")
        f.assert_redacted_cleanup()
    return {"credential_id": core["id"], "generation": retained_core["credential_version"], "disconnect": accepted}


def accepted_reopen():
    f = Fixture()  # Original startup, including the pinned native schema guard.
    core_id = os.environ["DISCONNECT_TEST_CREDENTIAL_ID"]
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        saved = f.snapshot()
        accepted = f.public(core_id)["disconnect"]
        assert accepted["status"] == "accepted"
        f.blocked_receipt(accepted)
        assert f.snapshot() == saved and not f.rows("oauth_revocation_work")
        assert not f.rows(cleanup_tests.WORK_TABLE)
        core = f.db.get_credential(core_id, include_secret=True, include_inactive=True)
        assert core["lifecycle_status"] == "revocation_pending"
        f.new_consent_and_refresh_refused(core)
        signed = workspace.verify_signed(f.config, f.db, f.store, f.bundles)
        assert all(route.get("credentialRef") != core_id for route in signed["routes"])
        assert f.app._reconcile_oauth_revocations(limit=8)["claimed"] == 0 and not f.history
        f.assert_redacted_cleanup()
    return {"credential_id": core_id, "generation": core["credential_version"], "disconnect": accepted}


def initial_race():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        core = f.connect()
        _app, rule = f.application_and_rule(core)
        f.identity_changes = {"sub": core["metadata"]["provider_subject"]}
        f.begin()
        f.refused_request(f.payload(core, [rule]), 409)
        work_id = f.held()
        f.refused_request(f.payload(core, [rule]), 409)
        assert f.cleanup_store.get_work(work_id)["fence"] is None and f.revocations == 0
        assert f.db.get_credential(core["id"], include_secret=True) == core
        f.assert_redacted_cleanup()
    return {"prepared_and_issued_initial_work_blocks_disconnect": True}


def refresh_race():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        core = cleanup_tests.expired_core(f)
    rules = [row for row in workspace.catalog(f.db, f.schema)["access_rules"] if row["credential_id"] == core["id"]]
    observations = []

    def during_refresh(request, **options):
        response = f.transport(request, **options)
        if request.full_url == cleanup_tests.TOKEN:
            observations.append(False)
            f.refused_request(f.payload(core, rules), 409)
            observations[-1] = True
        return response

    with patch.object(f.oauth, "request_bytes", side_effect=during_refresh):
        refreshed = f.app._credential_for_lease(core["id"])
        assert observations == [True], "refresh race assertion did not complete"
        assert refreshed["credential_version"] == core["credential_version"] + 1
        assert json.loads(refreshed["secret"])["access_token"] == consent_tests.REFRESHED
        assert not f.rows("oauth_revocation_work") and not f.rows(cleanup_tests.WORK_TABLE)
        assert f.request("GET", PATH + "/" + core["id"])[0] == 404
        assert f.revocations == 0
        f.assert_redacted_cleanup()
    return {"refresh_in_flight_blocks_disconnect": True, "original_refresh_adopted": True}


def publication_failure():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        core = f.connect()
        _app, rule = f.application_and_rule(core)
        prior_file = f.config.POLICY_BUNDLE_PATH.read_bytes()
        with patch.object(f.store, "materialize", side_effect=OSError("synthetic publication unavailable")):
            pending = f.start(core, [rule])
        assert pending["disconnect"]["local_enforcement"] == "pending"
        assert f.config.POLICY_BUNDLE_PATH.read_bytes() == prior_file
        assert f.bundles.get_policy_snapshot() is None, "old policy stayed authoritative after commit"
        assert f.public(core["id"])["disconnect"]["operation_id"] == pending["disconnect"]["operation_id"]
        f.new_consent_and_refresh_refused(core)
        # Original materialization recovers the committed reduced policy. The
        # receipt is observed, not a second mutation/revocation attempt.
        before_db = f.snapshot()[0]
        f.store.materialize()
        assert f.snapshot()[0] == before_db
        f.reduced(core, [rule])
        f.new_consent_and_refresh_refused(core)
        assert f.revocations == 0
        f.assert_redacted_cleanup()
    return {"committed_publication_pending": True, "new_consent_and_refresh_blocked": True}


def damaged_disconnect_ownership(damage):
    """A real preexisting worker claim cannot outlive its durable authority."""
    from serverware import operator_google_disconnect_store as durable
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        core = f.connect()
        _app, rule = f.application_and_rule(core)
        operation = f.start(core, [rule])["disconnect"]
        work_id = operation["operation_id"]
        f.due(work_id)
        worker_id = "synthetic-disconnect-before-damage"
        claimed = f.db.claim_oauth_revocations(worker_id=worker_id, limit=8)
        assert len(claimed) == 1 and claimed[0]["id"] == work_id
        assert claimed[0]["operator_google_cleanup_work_id"] == work_id
        secret = json.loads(claimed[0]["secret"])
        work_before = f.rows("oauth_revocation_work")
        owner_before = f.rows(cleanup_tests.WORK_TABLE)
        assert work_before[0]["status"] == "pending" and work_before[0]["lease_owner"] == worker_id
        contacts = list(f.history)

        # Damage only this disposable negative fixture. Guards are removed
        # solely to construct lost/corrupt persistence, never to obtain a
        # successful permit. Restore exact trigger SQL when the table survives
        # so missing-row/binding tests do not stop at a missing-schema guard.
        with closing(f.db.connect()) as conn, conn:
            guard = durable._TRIGGER if damage == "receipt-binding" else durable._DELETE
            definition = conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (guard,)).fetchone()[0]
            conn.execute("DROP TRIGGER " + guard)
            if damage == "table":
                conn.execute("DROP TABLE " + durable.TABLE)
            elif damage == "receipt":
                conn.execute("DELETE FROM " + durable.TABLE + " WHERE operation_id=?", (work_id,))
                conn.execute(definition)
            elif damage == "receipt-binding":
                receipt = json.loads(conn.execute("SELECT receipt_json FROM " + durable.TABLE
                    + " WHERE operation_id=?", (work_id,)).fetchone()[0])
                receipt["policy_hash"] = "sha256:" + "0" * 64
                conn.execute("UPDATE " + durable.TABLE + " SET receipt_json=? WHERE operation_id=?",
                    (json.dumps(receipt, sort_keys=True, separators=(",", ":")), work_id))
                conn.execute(definition)
            else:
                raise AssertionError("unknown negative fixture")

        before = f.snapshot()
        with closing(f.db.connect()) as conn:
            row = conn.execute("SELECT * FROM oauth_revocation_work WHERE id=?", (work_id,)).fetchone()
            assert f.cleanup_store.eligible(conn, row) is False
        consent_tests.refused(lambda: f.cleanup_store.require_permit(work_id=work_id, secret=secret), ValueError)
        consent_tests.refused(lambda: f.oauth.revoke_oauth_token(provider_id="google", token_secret=secret,
            _operator_cleanup_work_id=work_id), f.oauth.OAuthError)
        consent_tests.refused(lambda: f.db.finish_oauth_revocation_work(work_id,
            worker_id=worker_id, succeeded=True),
            f.cleanup_store.CleanupStoreError if damage == "receipt-binding" else f.disconnect.DisconnectUnavailable)
        status, raw, _ = f.request("GET", PATH + "/" + core["id"])
        assert status == (404 if damage == "receipt" else 503), (status, raw)
        if damage == "receipt":
            assert json.loads(raw)["detail"] == "Google disconnect operation not found; absence does not authorize retry"
        assert f.snapshot() == before, "failed ownership check changed durable work or receipt"
        assert f.rows("oauth_revocation_work") == work_before
        assert f.rows(cleanup_tests.WORK_TABLE) == owner_before

        # Expire the existing private claim explicitly; ordinary background
        # selection must also skip the now-unowned request before decryption.
        f.due(work_id)
        due = f.snapshot()
        assert not f.db.claim_oauth_revocations(worker_id="synthetic-after-damage", limit=8)
        counts = f.app._reconcile_oauth_revocations(limit=8)
        assert counts["claimed"] == counts["revoked"] == counts["failed"] == 0
        assert counts.get("accepted", 0) == 0
        assert f.snapshot() == due and f.rows(cleanup_tests.WORK_TABLE) == owner_before
        assert f.history == contacts and f.revocations == 0
        assert f.db.get_credential(core["id"]) is None
        retained = f.db.get_credential(core["id"], include_inactive=True)
        assert retained["lifecycle_status"] == "revocation_pending"
        assert retained["credential_version"] == core["credential_version"] + 1
        assert not f.events("operator_catalog.oauth.disconnect_provider_accepted")
        f.assert_redacted_cleanup()
    return {"damage": damage, "preexisting_claim_refused": True,
        "encrypted_work_and_fence_retained": True, "provider_contacts_after_damage": 0}


OPERATIONS = {"shared-family": shared_family, "confirmation-guards": confirmation_guards,
    "http-guards": http_guards, "disabled-capability": disabled_capability,
    "rollback-signing": lambda: rollback("signing"),
    "rollback-audit": lambda: rollback("audit"), "provider-failure": provider_failure,
    "accepted-prepare": accepted_prepare, "accepted-reopen": accepted_reopen,
    "initial-race": initial_race, "refresh-race": refresh_race,
    "publication-failure": publication_failure,
    "missing-ownership-table": lambda: damaged_disconnect_ownership("table"),
    "missing-ownership-receipt": lambda: damaged_disconnect_ownership("receipt"),
    "corrupt-ownership-binding": lambda: damaged_disconnect_ownership("receipt-binding")}


class OperatorGoogleDisconnectTests(unittest.TestCase):
    setUp = consent_tests.OperatorGoogleConsentTests.setUp

    def worker(self, operation, *, fresh=None, credential_id=None):
        environment = dict(self.environment)
        if operation == "disabled-capability":
            environment = {key: value for key, value in environment.items() if not key.startswith("SERVERWARE_")}
            environment.update(workspace.common._ENVIRONMENT)
        if fresh is not None:
            environment["SERVERWARE_DATA_DIR"] = str(self.directory.parent / fresh)
        if credential_id is not None:
            environment["DISCONNECT_TEST_CREDENTIAL_ID"] = credential_id
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        return json.loads(result.stdout)

    def test_shared_family_quarantine_preserves_unrelated_state(self):
        self.worker("shared-family")

    def test_exact_confirmation_cas_and_resource_guards(self):
        self.worker("confirmation-guards")

    def test_http_auth_origin_and_bounded_input_guards(self):
        self.worker("http-guards")
        self.worker("disabled-capability", fresh="disabled")

    def test_signing_and_audit_failures_roll_back(self):
        self.worker("rollback-signing", fresh="signing")
        self.worker("rollback-audit", fresh="audit")

    def test_failed_and_unknown_provider_outcomes_retain_retry(self):
        self.worker("provider-failure")

    def test_accepted_receipt_survives_work_retirement_and_reopen(self):
        prepared = self.worker("accepted-prepare")
        self.assertEqual(prepared, self.worker("accepted-reopen", credential_id=prepared["credential_id"]))

    def test_initial_and_refresh_inflight_races_refuse_disconnect(self):
        self.worker("initial-race", fresh="initial")
        self.worker("refresh-race", fresh="refresh")

    def test_committed_publication_failure_still_blocks_new_oauth(self):
        self.worker("publication-failure")

    def test_missing_or_corrupt_disconnect_ownership_blocks_provider_and_completion(self):
        self.worker("missing-ownership-table", fresh="missing-table")
        self.worker("missing-ownership-receipt", fresh="missing-receipt")
        self.worker("corrupt-ownership-binding", fresh="corrupt-binding")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
