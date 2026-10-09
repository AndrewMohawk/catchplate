#!/usr/bin/env python3
"""Synthetic refresh-denial checks with real custody, SQLite and signed policy.

Only request_bytes supplies provider responses. Rejection proofs are produced
by the actual transport classifier, never constructed or substituted. Refusal
faults affect only disposable test state. No Google, native authority, deployed
proxy, or provider revocation/propagation claim is made by this suite.
"""
from __future__ import annotations

from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch

import test_operator_google_cleanup as cleanup_tests
import test_operator_google_consent as consent_tests
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
EVENT = "operator_catalog.oauth.refresh_rejected"
MISSING = "00000000-0000-4000-8000-000000000071"


class Fixture(cleanup_tests.Fixture):
    def __init__(self):
        super().__init__()
        self.reply = None
        self.before_response = None
        self.checked_responses = []

    def provider(self, request, **options):
        normal = self.transport(request, **options)
        if request.full_url != cleanup_tests.TOKEN or self.reply is None:
            return normal
        check = len(self.checked_responses)
        self.checked_responses.append(False)
        if self.refresh_core is not None:
            assert tuple(options["expected_statuses"]) == (200, 400, 401)
            assert options["require_https"] is True and options["timeout"] == 20
            assert options["max_bytes"] == 256 * 1024
        work = [row for row in self.rows("oauth_revocation_work") if row["status"] == "exchange_in_flight"]
        assert len(work) == 1
        if self.before_response is not None:
            self.before_response(work[0])
        self.checked_responses[check] = True
        if self.reply == "timeout":
            raise TimeoutError("synthetic refresh response unavailable")
        from serverware.http_client import HttpResponse
        status, body, raw_headers = self.reply
        return HttpResponse(status=status, body=body, raw_headers=raw_headers,
            headers={name.lower(): value for name, value in raw_headers})

    def setup_account(self):
        core = cleanup_tests.expired_core(self)
        self.application_and_rule(core)
        static = workspace.create_credential(self.db, self.store, self.schema,
            self.inputs, self.mutations)["credential"]
        self.application_and_rule(static, google=False)
        return core

    def authority(self):
        # Exclude only legitimate work/audit changes, not account generations,
        # applications, route assignments, publication pins or signed bytes.
        return {"core": self.rows("credentials"), "generations": self.rows("credential_generations"),
            "catalog": workspace.catalog(self.db, self.schema), "policy": self.rows("operator_demo_policy"),
            "file": self.config.POLICY_BUNDLE_PATH.read_bytes()}

    def snapshot(self):
        with closing(self.db.connect()) as conn:
            return tuple(conn.iterdump()), self.config.POLICY_BUNDLE_PATH.read_bytes()

    def events(self):
        return [row for row in self.rows("audit_events") if row["event_type"] == EVENT]

    def error(self, core, *, app_path=False):
        try:
            if app_path:
                self.app._credential_for_lease(core["id"])
            else:
                self.oauth.refresh_access_token(provider_id="google", token_secret=json.loads(core["secret"]),
                    metadata=core["metadata"])
        except self.app.HTTPException as exc:
            assert app_path and exc.status_code == 503
            assert "reconnect" not in str(exc.detail).lower()
            assert isinstance(exc.__cause__, self.oauth.OAuthError)
            return exc.__cause__
        except self.oauth.OAuthError as exc:
            assert not app_path
            return exc
        raise AssertionError("rejected refresh unexpectedly supplied a credential")

    def assert_checks(self):
        assert all(self.checked_responses), "a response-boundary assertion was swallowed"
        assert self.revocations == 0
        self.assert_redacted_cleanup()


def reply(status=400, body=b'{"error":"invalid_grant"}', raw_headers=None):
    return status, body, (("Content-Type", "application/json"),) if raw_headers is None else raw_headers


def definite():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core = f.setup_account()
        before = f.authority()
        cases = [(400, code, False) for code in ("invalid_request", "invalid_client", "invalid_grant",
            "unauthorized_client", "unsupported_grant_type", "invalid_scope")]
        cases.append((401, "invalid_client", True))
        for status, code, app_path in cases:
            f.reply = reply(status, json.dumps({"error": code, "error_description": "synthetic denial"}).encode())
            failure = f.error(core, app_path=app_path)
            assert failure.issuance_uncertain is False
            outcome = failure.operator_refresh_rejection
            assert outcome["status"] == "retired" and outcome["reason"] == "definite_refresh_rejected"
            assert f.authority() == before
            assert not f.rows("oauth_revocation_work") and not f.rows(cleanup_tests.WORK_TABLE)
            row = f.events()[-1]
            event = json.loads(row["event_json"])
            assert row["id"] == "operator-google-refresh-rejected:" + outcome["work_id"]
            assert row["actor_type"] == "system"
            assert event["schema"] == "serverware.operatorGoogleRefreshRejected/v1"
            assert event["work_id"] == outcome["work_id"] and event["http_status"] == status
            assert event["error_code"] == code and event["credential_id"] == core["id"]
            assert event["credential_generation"] == core["credential_version"]
            assert event["source"] == "operator_google_refresh_v1" and event["issued_material"] is False
            assert event["provider_revocation"] == "not_requested"
            assert "synthetic denial" not in row["event_json"]
        assert len(f.events()) == len(cases) and len(f.checked_responses) == len(cases)
        f.assert_checks()
    return {"confirmed_responses": len(cases), "authority_unchanged": True, "provider_revocations": 0}


def uncertain_empty():
    f = Fixture()
    cases = ["timeout", reply(body=b'{"error":'), reply(body=b'\xff'),
        reply(body=b'{"error":"invalid_grant","error":"invalid_grant"}'),
        reply(body=b'{"error":"temporarily_unavailable"}'), reply(200),
        reply(raw_headers=(("Content-Type", "application/json"), ("Content-Type", "application/json"))),
        reply(body=b'{"error":"invalid_grant","unexpected":true}'),
        reply(401), reply(raw_headers=(("Content-Type", "text/plain"),)), reply(raw_headers=()),
        reply(body=json.dumps({"error": "invalid_grant", "error_description": "x" * (16 * 1024)}).encode()),
        reply(body=json.dumps({"error": "invalid_grant", "error_description": "x" * (256 * 1024)}).encode())]
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core = f.setup_account()
        before = f.authority()
        retained_ids = set()
        for case in cases:
            f.reply = case
            failure = f.error(core)
            assert getattr(failure, "operator_refresh_rejection", None) is None
            assert failure.issuance_uncertain is True
            rows = f.rows("oauth_revocation_work")
            added = [row for row in rows if row["id"] not in retained_ids]
            assert len(added) == 1 and added[0]["status"] == "issuance_uncertain_unreported"
            owned = f.cleanup_store.get_work(added[0]["id"])
            assert owned["material_sha256"] is None and owned["fence"] is None
            assert f.db.decrypt_secret_envelope(added[0]) == "{}"
            retained_ids.add(added[0]["id"])
            assert len(rows) == len(retained_ids) and f.authority() == before
            assert not f.events()
        f.assert_checks()
    return {"uncertain_responses": len(cases), "retained_empty_work": len(retained_ids)}


def token_bearing(status):
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core = f.setup_account()
        f.reply = reply(status, json.dumps({"error": "invalid_grant" if status == 400 else "invalid_client",
            "access_token": consent_tests.REFRESHED, "token_type": "Bearer"}).encode())
        failure = f.error(core)
        assert getattr(failure, "operator_refresh_rejection", None) is None
        work = f.rows("oauth_revocation_work")
        assert len(work) == 1
        retained = f.cleanup_store.get_work(work[0]["id"])
        assert retained["material_sha256"] is not None and retained["fence"] is not None
        assert json.loads(f.db.decrypt_secret_envelope(work[0]))["access_token"] == consent_tests.REFRESHED
        current = f.db.get_credential(core["id"], include_secret=True, include_inactive=True)
        assert current["lifecycle_status"] == "revocation_pending"
        assert current["credential_version"] == core["credential_version"] + 1
        assert current["secret"] == core["secret"], "error payload was adopted"
        signed = workspace.verify_signed(f.config, f.db, f.store, f.bundles)
        assert all(route.get("credentialRef") != core["id"] for route in signed["routes"])
        assert not f.events()
        f.assert_checks()
    return {"http_status": status, "material_retained_not_adopted": True, "family_fenced": True}


def scoped_work():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core = f.setup_account()
        f.reply = "timeout"
        f.error(core)
        old_work, old_owner = f.rows("oauth_revocation_work"), f.rows(cleanup_tests.WORK_TABLE)
        f.reply = reply()
        assert f.error(core).operator_refresh_rejection["status"] == "retired"
        assert f.rows("oauth_revocation_work") == old_work and f.rows(cleanup_tests.WORK_TABLE) == old_owner
        # Authorization-code exchange is not this refresh-only exception.
        f.refresh_core = None
        f.reply = None
        f.begin()
        f.reply = reply()
        assert f.callback()[0] == 409
        initial = [row for row in f.rows("oauth_revocation_work") if row["source"] == "operator_google_initial_v1"]
        assert len(initial) == 1 and f.cleanup_store.get_work(initial[0]["id"])["fence"] is None
        assert len(f.events()) == 1
        f.assert_checks()
    return {"old_uncertainty_preserved": True, "initial_exchange_not_retired": True}


def bound_guard(case):
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core = f.setup_account()
        captured = []

        def change(work):
            if case == "wrong-source":
                with closing(f.db.connect()) as conn, conn:
                    conn.execute("UPDATE oauth_revocation_work SET source='refresh_token_exchange' WHERE id=?", (work["id"],))
            elif case == "held":
                with closing(f.db.connect()) as conn, conn:
                    conn.execute("UPDATE oauth_revocation_work SET status='held' WHERE id=?", (work["id"],))
            elif case in {"material", "fenced"}:
                f.db.attach_oauth_revocation_material(work["id"],
                    secret=json.dumps({"access_token": consent_tests.REFRESHED, "token_type": "Bearer"}))
                if case == "fenced":
                    assert f.cleanup.fence(work["id"], reason="refresh_failed").status == "committed"
            elif case == "generation":
                updated, changed = f.db.update_credential_secret_if_version(core["id"],
                    expected_version=core["credential_version"],
                    secret=json.dumps({**json.loads(core["secret"]), "expires_at_epoch_ms": 2}),
                    metadata={**core["metadata"], "expires_at_epoch_ms": 2})
                assert changed and updated["credential_version"] == core["credential_version"] + 1
            else:
                raise AssertionError("unknown private negative fixture")
            captured.append(f.snapshot())

        f.before_response = change
        f.reply = reply()
        failure = f.error(core)
        assert failure.issuance_uncertain is False
        assert failure.operator_refresh_rejection["status"] == "deferred"
        assert len(captured) == 1 and f.snapshot() == captured[0]
        assert len(f.rows("oauth_revocation_work")) == len(f.rows(cleanup_tests.WORK_TABLE)) == 1
        assert not f.events()
        f.assert_checks()
    return {"bound_guard": case, "work_preserved": True}


def audit_rollback():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core = f.setup_account()
        with closing(f.db.connect()) as conn, conn:
            conn.execute("CREATE TRIGGER refresh_rejection_abort BEFORE INSERT ON audit_events "
                "WHEN NEW.event_type='operator_catalog.oauth.refresh_rejected' "
                "BEGIN SELECT RAISE(ABORT,'synthetic rejection audit refusal'); END")
        captured = []
        f.before_response = lambda _work: captured.append(f.snapshot())
        f.reply = reply()
        failure = f.error(core)
        assert failure.issuance_uncertain is False and failure.operator_refresh_rejection["status"] == "deferred"
        assert len(captured) == 1 and f.snapshot() == captured[0]
        assert not f.events() and len(f.rows("oauth_revocation_work")) == 1
        before = f.snapshot()
        assert f.cleanup.retire_definite_refresh_rejection(failure.__cause__)["status"] == "deferred"
        assert f.snapshot() == before, "burned proof repeated a failed writer"
        with closing(f.db.connect()) as conn, conn:
            conn.execute("DROP TRIGGER refresh_rejection_abort")
        f.assert_checks()
    return {"audit_and_retirement_rollback": True, "known_rejection_not_issuance_uncertainty": True}


def lost_commit_ack():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core = f.setup_account()
        before = f.authority()
        committed = []
        real_connect = sqlite3.connect

        class LostAck(sqlite3.Connection):
            def commit(self):
                terminal = self.in_transaction and self.execute(
                    "SELECT id FROM audit_events WHERE event_type=?", (EVENT,)).fetchone()
                if terminal and not committed:
                    super().commit()
                    committed.append(terminal[0])
                    raise OSError("synthetic committed acknowledgement lost")
                return super().commit()

        def connection(*args, **kwargs):
            assert "factory" not in kwargs
            return real_connect(*args, factory=LostAck, **kwargs)

        f.reply = reply()
        # db.connect still performs all real connection/schema/retirement UDF
        # configuration. This actual sqlite Connection changes only one ACK.
        with patch.object(sqlite3, "connect", side_effect=connection):
            failure = f.error(core)
        outcome = failure.operator_refresh_rejection
        assert outcome["status"] == "retired" and failure.issuance_uncertain is False
        assert committed == ["operator-google-refresh-rejected:" + outcome["work_id"]]
        assert len(f.events()) == 1 and not f.rows("oauth_revocation_work")
        assert not f.rows(cleanup_tests.WORK_TABLE) and f.authority() == before
        f.assert_checks()
    return {"actual_commit_ack_lost": True, "exact_audit_and_absent_pair_reobserved": True}


def proof_and_absence():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core = f.setup_account()
        f.reply = reply()
        failure = f.error(core)
        assert failure.operator_refresh_rejection["status"] == "retired"
        rejection = failure.__cause__
        summary = {key: getattr(rejection, key) for key in
            ("work_id", "profile_binding_digest", "oauth_client_id", "http_status", "error_code")}
        before = f.snapshot()
        assert f.cleanup.retire_definite_refresh_rejection(rejection)["status"] == "deferred"
        with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            for original in (summary, rejection):
                consent_tests.refused(lambda original=original: f.cleanup_store.retire_rejected_refresh(
                    conn, original, summary), ValueError)
            conn.rollback()
        assert f.snapshot() == before
        row = f.events()[0]
        audit = {**row, "event": json.loads(row["event_json"])}
        # Readback requires an actual exact audit, not two absent work rows.
        absent = {**audit, "id": "operator-google-refresh-rejected:" + MISSING,
            "event": {**audit["event"], "work_id": MISSING}}
        with closing(f.db.connect()) as conn:
            conn.execute("BEGIN")
            f.cleanup_store.observe_rejected_refresh(conn, audit)
            consent_tests.refused(lambda: f.cleanup_store.observe_rejected_refresh(conn, absent),
                f.cleanup_store.CleanupStoreError)
        assert f.snapshot() == before
        f.assert_checks()
    return {"consumed_and_raw_proof_refused": True, "absence_alone_refused": True}


def successful_refresh():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core = f.setup_account()
        catalog, policy = workspace.catalog(f.db, f.schema), f.config.POLICY_BUNDLE_PATH.read_bytes()
        refreshed = f.app._credential_for_lease(core["id"])
        assert refreshed["credential_version"] == core["credential_version"] + 1
        assert json.loads(refreshed["secret"])["access_token"] == consent_tests.REFRESHED
        assert refreshed["metadata"]["expires_at_epoch_ms"] > core["metadata"]["expires_at_epoch_ms"]
        assert workspace.catalog(f.db, f.schema) == catalog and f.config.POLICY_BUNDLE_PATH.read_bytes() == policy
        assert not f.rows("oauth_revocation_work") and not f.rows(cleanup_tests.WORK_TABLE) and not f.events()
        f.assert_checks()
    return {"automatic_refresh_adopted": True}


def restart_prepare():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core = f.setup_account()
        f.reply = reply()
        failure = f.error(core)
        assert failure.operator_refresh_rejection["status"] == "retired"
        f.assert_checks()
    return {"audit": f.events(), "core_id": core["id"], "generation": core["credential_version"],
        "policy_hash": f.store.get_policy_high_water()["policy_hash"]}


def restart_observe():
    f = Fixture()  # Original cold startup; no schema, profile or clock bypass.
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        rows = f.events()
        assert len(rows) == 1
        event = json.loads(rows[0]["event_json"])
        core = f.db.get_credential(event["credential_id"], include_secret=True)
        assert core is not None and core["lifecycle_status"] == "active"
        assert core["credential_version"] == event["credential_generation"]
        assert not f.rows("oauth_revocation_work") and not f.rows(cleanup_tests.WORK_TABLE)
        before = f.snapshot()
        assert f.app._reconcile_oauth_revocations(limit=8)["claimed"] == 0
        assert f.snapshot() == before and not f.history
        f.assert_checks()
    return {"audit": rows, "core_id": core["id"], "generation": core["credential_version"],
        "policy_hash": f.store.get_policy_high_water()["policy_hash"]}


OPERATIONS = {"definite": definite, "uncertain-empty": uncertain_empty, "scoped-work": scoped_work,
    "token-400": lambda: token_bearing(400), "token-401": lambda: token_bearing(401),
    "audit-rollback": audit_rollback, "lost-commit-ack": lost_commit_ack, "proof": proof_and_absence,
    "success": successful_refresh, "restart-prepare": restart_prepare, "restart-observe": restart_observe}
for _case in ("wrong-source", "held", "material", "fenced", "generation"):
    OPERATIONS["bound-" + _case] = lambda case=_case: bound_guard(case)


class OperatorGoogleRefreshRejectionTests(unittest.TestCase):
    setUp = consent_tests.OperatorGoogleConsentTests.setUp

    def worker(self, operation, *, fresh=None):
        environment = dict(self.environment)
        if fresh is not None:
            environment["SERVERWARE_DATA_DIR"] = str(self.directory.parent / fresh)
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        return json.loads(result.stdout)

    def test_definite_rejections_preserve_account_authority(self):
        self.worker("definite")

    def test_ambiguous_empty_responses_retain_uncertainty(self):
        self.worker("uncertain-empty")

    def test_token_bearing_errors_retain_and_fence_material(self):
        self.worker("token-400", fresh="token400")
        self.worker("token-401", fresh="token401")

    def test_initial_and_older_work_are_not_retired(self):
        self.worker("scoped-work")

    def test_retirement_requires_current_empty_refresh_binding(self):
        for case in ("wrong-source", "held", "material", "fenced", "generation"):
            self.worker("bound-" + case, fresh=case)

    def test_audit_rollback_and_lost_commit_acknowledgement(self):
        self.worker("audit-rollback", fresh="rollback")
        self.worker("lost-commit-ack", fresh="committed")

    def test_consumed_proof_and_absence_alone_cannot_retire_work(self):
        self.worker("proof")

    def test_successful_refresh_and_rejection_receipt_restart(self):
        self.worker("success", fresh="success")
        self.assertEqual(self.worker("restart-prepare"), self.worker("restart-observe"))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
