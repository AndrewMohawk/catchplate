#!/usr/bin/env python3
"""Active-account reauthorization through real ASGI, PKCE and durable custody.

Only the fixed provider transport is synthetic. The cold development profile,
browser state, account bindings, encrypted tokens, SQLite, signed policy and
audit are real. Faults only exercise refusal/rollback; no successful guard is
patched. This suite does not prove Google consent, revocation, Rust enforcement
or deployed readiness. Execute only in the bounded network-none harness.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import uuid

import test_operator_google_cleanup as cleanup_tests
import test_operator_google_consent as consent_tests
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
PATH = "/api/operator-demo/oauth/google/reauthorize"
STORAGE_PATH = "/api/operator-demo/oauth/google/reauthorization-storage"
TABLE = "operator_google_reauthorizations"
SOURCE = "operator_google_reauthorization_v1"
EVENT = "operator_catalog.oauth.reauthorized"
NEW_ACCESS = "synthetic-google-reauthorization-access-token"
NEW_REFRESH = "synthetic-google-reauthorization-refresh-token"
LATER_ACCESS = "synthetic-google-reauthorization-refreshed-access-token"


class Fixture(cleanup_tests.Fixture):
    def __init__(self):
        super().__init__()
        from catchplate import operator_google_reauthorization as lifecycle
        from catchplate import operator_google_reauthorization_store as durable
        self.lifecycle, self.durable = lifecycle, durable
        self.phase = "initial"
        self.before_token = None
        self.after_identity = None
        self.subject = None
        self.reauth_scopes = " ".join(self.profile.scopes)
        self.reauth_expiry = 3600
        self.reauth_checks = []
        self.client_tokens = []

    def rows(self, table):
        if table == TABLE:
            with closing(self.db.connect()) as conn:
                return [dict(row) for row in conn.execute("SELECT * FROM " + TABLE + " ORDER BY operation_id")]
        return super().rows(table)

    def snapshot(self):
        with closing(self.db.connect()) as conn:
            return tuple(conn.iterdump()), self.config.POLICY_BUNDLE_PATH.read_bytes()

    def request(self, *args, **kwargs):
        result = super().request(*args, **kwargs)
        exposed = result[1] + b"\n".join(name + b":" + value for name, value in result[2])
        for secret in (NEW_ACCESS, NEW_REFRESH, LATER_ACCESS, *self.client_tokens):
            assert secret.encode() not in exposed, "synthetic secret entered an HTTP response"
        return result

    def authority(self):
        return {"catalog": workspace.catalog(self.db, self.schema),
            "core": self.rows("credentials"), "generations": self.rows("credential_generations"),
            "intents": self.rows("operator_catalog_oauth_intents"),
            "policy": self.rows("operator_demo_policy"), "file": self.config.POLICY_BUNDLE_PATH.read_bytes()}

    def events(self):
        return [row for row in self.rows("audit_events") if row["event_type"] == EVENT]

    def setup_account(self):
        core = self.connect()  # The unchanged initial-consent positive path.
        self.subject = core["metadata"]["provider_subject"]
        rules = []
        for index in range(2):
            created = workspace.create_application(self.db, self.store, self.schema, self.inputs, self.mutations)
            self.client_tokens.append(created["client_token"])
            rules.append(self.mutations.create_rule(self.inputs.RuleInput(**self.review(),
                name="Reauthorization assignment " + str(index), application_id=created["application"]["id"],
                credential_id=core["id"], upstream_url="https://gmail.googleapis.com/gmail/v1/users/me/messages",
                methods=["GET"], response_fields=["id"]), workspace.common._ACTOR)["access_rule"])
        historical_app, historical_rule = self.application_and_rule(core)
        self.mutations.revoke_application(self.inputs.TargetInput(**self.review(), id=historical_app["id"]),
            workspace.common._ACTOR)
        saved = workspace.catalog(self.db, self.schema)
        assert next(row for row in saved["applications"] if row["id"] == historical_app["id"])["status"] == "revoked"
        assert next(row for row in saved["access_rules"] if row["id"] == historical_rule["id"])["status"] == "revoked"
        static = workspace.create_credential(self.db, self.store, self.schema, self.inputs, self.mutations)["credential"]
        self.application_and_rule(static, google=False)
        return core, rules

    def review_account(self, core, *, eligible=True):
        status, raw, _ = self.request("GET", PATH + "/" + core["id"] + "/review")
        assert status == 200, (status, raw)
        result = json.loads(raw)
        assert result["schema"] == "catchplate.operatorGoogleReauthorizationReview/v1"
        assert result["credential_id"] == core["id"] and result["eligible"] is eligible
        assert result["expected_credential_generation"] == core["credential_version"]
        return result

    def payload(self, core, rules):
        review = self.review_account(core)
        assert review["affected_rule_ids"] == sorted(rule["id"] for rule in rules)
        return {key: review[key] for key in ("credential_id", "expected_revision", "expected_policy_hash",
            "expected_credential_generation", "affected_rule_ids")} | {"operation_id": str(uuid.uuid4())}

    def public(self, operation_id):
        status, raw, headers = self.request("GET", PATH + "/" + operation_id)
        assert status == 200, (status, raw)
        assert [value for name, value in headers if name.lower() == b"cache-control"] == [b"no-store"]
        value = json.loads(raw)
        assert value["schema"] == "catchplate.operatorGoogleReauthorization/v1"
        return value

    def begin_reauthorization(self, core, rules):
        self.phase = "reauthorize"
        self.start_payload = self.payload(core, rules)
        before, contacts = self.authority(), list(self.history)
        code, raw, headers = self.request("POST", PATH, body=self.start_payload)
        assert code == 200, (code, raw)
        self.started = json.loads(raw)
        operation = self.started["operatorGoogleReauthorization"]
        assert operation["operation_id"] == self.start_payload["operation_id"]
        assert operation["status"] == "awaiting_consent"
        assert self.public(operation["operation_id"]) == operation
        assert self.review_account(core, eligible=False)["affected_rule_ids"] == self.start_payload["affected_rule_ids"]
        cookies = [value.decode() for name, value in headers if name.lower() == b"set-cookie"]
        assert len(cookies) == 1 and all(word in cookies[0].lower() for word in ("secure", "httponly", "samesite=lax"))
        parsed = SimpleCookie(cookies[0])
        name = self.oauth.browser_cookie_name(self.started["state"])
        assert set(parsed) == {name}
        self.browser_nonce = parsed[name].value
        self.cookie = name + "=" + self.browser_nonce
        authorization = urlsplit(self.started["authorizationUrl"])
        assert (authorization.scheme, authorization.netloc, authorization.path) == (
            "https", "accounts.google.com", "/o/oauth2/v2/auth")
        query = parse_qs(authorization.query, strict_parsing=True)
        assert query["state"] == [self.started["state"]]
        assert query["client_id"] == [self.profile.client_id] and query["redirect_uri"] == [self.profile.redirect_uri]
        assert query["scope"] == [" ".join(self.profile.scopes)]
        assert query["code_challenge_method"] == ["S256"] and query["access_type"] == ["offline"]
        self.challenge = query["code_challenge"][0]
        state = self.oauth._read_states()["states"][self.started["state"]]
        assert state["operator_google_reauthorization_id"] == operation["operation_id"]
        assert "operator_catalog_intent_id" not in state
        assert state["browser_nonce_sha256"] == "sha256:" + hashlib.sha256(self.browser_nonce.encode()).hexdigest()
        assert self.oauth._code_challenge(state["code_verifier"]) == self.challenge
        assert self.authority() == before and self.history == contacts
        return operation

    def provider(self, request, **options):
        if self.phase == "initial":
            return super().transport(request, **options)
        url, method = request.full_url, request.get_method()
        self.history.append((method, url))
        index = len(self.reauth_checks)
        self.reauth_checks.append(False)
        if url == cleanup_tests.REVOKE:
            self.revocations += 1
            raise AssertionError("active-account reauthorization must not revoke a provider grant")
        assert options["require_https"] is True and 0 < options["timeout"] <= 20
        assert 0 < options["max_bytes"] <= 256 * 1024
        consent_tests.refused(self.store.operator_publication.assert_held, RuntimeError)
        with closing(self.db.connect()) as conn:
            conn.execute("PRAGMA busy_timeout=0")
            conn.execute("BEGIN IMMEDIATE")
            conn.rollback()
        if url == cleanup_tests.TOKEN:
            assert method == "POST"
            form = parse_qs(request.data.decode(), strict_parsing=True)
            assert form["client_id"] == [self.profile.client_id]
            assert form["client_secret"] == [consent_tests.google_tests.CLIENT_SECRET]
            work = [row for row in self.rows("oauth_revocation_work") if row["status"] == "exchange_in_flight"]
            assert len(work) == 1
            retained = self.cleanup_store.get_work(work[0]["id"])
            assert retained is not None and retained["fence"] is None
            association = retained["association"]
            assert association["profile_binding_digest"] == self.profile.binding_digest
            assert association["oauth_client_id"] == self.profile.client_id
            if self.phase == "reauthorize":
                assert set(form) == {"grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier"}
                assert form["grant_type"] == ["authorization_code"] and form["code"] == [consent_tests.CODE]
                assert form["redirect_uri"] == [self.profile.redirect_uri]
                assert self.oauth._code_challenge(form["code_verifier"][0]) == self.challenge
                assert self.started["state"] not in self.oauth._read_states()["states"]
                assert work[0]["source"] == SOURCE
                operation = self.public(self.start_payload["operation_id"])
                assert operation["status"] == "exchanging"
                assert association["credential_id"] == self.start_payload["credential_id"]
                assert association["credential_generation"] == self.start_payload["expected_credential_generation"]
                if self.before_token is not None:
                    self.before_token(work[0])
                payload = {"access_token": NEW_ACCESS, "refresh_token": NEW_REFRESH, "token_type": "Bearer",
                    "expires_in": self.reauth_expiry, "scope": self.reauth_scopes}
            else:
                assert self.phase == "refresh" and work[0]["source"] == "operator_google_refresh_v1"
                assert set(form) == {"grant_type", "refresh_token", "client_id", "client_secret"}
                assert form["grant_type"] == ["refresh_token"] and form["refresh_token"] == [NEW_REFRESH]
                assert association["credential_id"] == self.start_payload["credential_id"]
                payload = {"access_token": LATER_ACCESS, "token_type": "Bearer", "expires_in": 3600,
                    "scope": " ".join(self.profile.scopes)}
        elif url == "https://openidconnect.googleapis.com/v1/userinfo":
            assert self.phase == "reauthorize" and method == "GET" and request.data is None
            assert request.get_header("Authorization") == "Bearer " + NEW_ACCESS
            payload = {"sub": self.subject, "email": "fixture@example.com", "email_verified": True}
            if self.after_identity is not None:
                self.after_identity()
        else:
            raise AssertionError("unapproved synthetic provider endpoint")
        self.reauth_checks[index] = True
        return SimpleNamespace(status=200, body=json.dumps(payload).encode(),
            headers={"content-type": "application/json"}, raw_headers=(("Content-Type", "application/json"),))

    def assert_checks(self):
        assert self.revocations == 0 and all(self.reauth_checks), "provider-boundary assertion was swallowed"
        self.assert_redacted_cleanup()
        with closing(self.db.connect()) as conn:
            dump = "\n".join(conn.iterdump())
        for secret in (NEW_ACCESS, NEW_REFRESH, LATER_ACCESS, *self.client_tokens):
            assert secret not in dump

    def adopted(self, core, before):
        public = self.public(self.start_payload["operation_id"])
        assert public["status"] == "adopted"
        receipt = public["receipt"]
        current = self.db.get_credential(core["id"], include_secret=True)
        assert current["lifecycle_status"] == "active" and current["credential_version"] == core["credential_version"] + 1
        secret = json.loads(current["secret"])
        assert secret["access_token"] == NEW_ACCESS and secret["refresh_token"] == NEW_REFRESH
        for key in ("provider_subject", "provider_account", "oauth_client_id", "scopes", "oauth_intent_id",
                "oauth_profile_binding_digest"):
            assert current["metadata"][key] == core["metadata"][key]
        mutable_metadata = {"expires_at_epoch_ms", "refresh_token_expires_at_epoch_ms", "token_type"}
        assert {key: value for key, value in current["metadata"].items() if key not in mutable_metadata} == {
            key: value for key, value in core["metadata"].items() if key not in mutable_metadata}
        after = self.authority()
        for key in ("catalog", "intents", "policy", "file"):
            assert after[key] == before[key], "reauthorization changed existing authority: " + key
        assert [row for row in after["core"] if row["id"] != core["id"]] == [
            row for row in before["core"] if row["id"] != core["id"]]
        mutable_core = {"encrypted_secret", "encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id",
            "credential_version", "secret_updated_at", "metadata", "updated_at"}
        original_row = next(row for row in before["core"] if row["id"] == core["id"])
        current_row = next(row for row in after["core"] if row["id"] == core["id"])
        assert {key: value for key, value in original_row.items() if key not in mutable_core} == {
            key: value for key, value in current_row.items() if key not in mutable_core}
        assert len(after["generations"]) == len(before["generations"])
        for old in before["generations"]:
            new = next(row for row in after["generations"] if row["credential_id"] == old["credential_id"])
            if old["credential_id"] == core["id"]:
                assert new["last_version"] == old["last_version"] + 1
            else:
                assert new == old
        assert receipt["schema"] == "catchplate.operatorGoogleReauthorizationReceipt/v1"
        assert receipt["operation_id"] == self.start_payload["operation_id"] and receipt["credential_id"] == core["id"]
        assert receipt["previous_credential_generation"] == core["credential_version"]
        assert receipt["credential_generation"] == current["credential_version"]
        assert receipt["original_oauth_intent_id"] == core["metadata"]["oauth_intent_id"]
        assert receipt["revision"] == before["catalog"]["revision"]
        assert receipt["policy_hash"] == self.start_payload["expected_policy_hash"]
        assert receipt["affected_rule_ids"] == self.start_payload["affected_rule_ids"]
        assert receipt["application_ids"] == sorted({row["application_id"] for row in before["catalog"]["access_rules"]
            if row["id"] in self.start_payload["affected_rule_ids"]})
        events = self.events()
        assert len(events) == 1 and events[0]["id"] == "operator-google-reauthorized:" + receipt["operation_id"]
        assert not self.rows("oauth_revocation_work") and not self.rows(cleanup_tests.WORK_TABLE)
        workspace.verify_signed(self.config, self.db, self.store, self.bundles)
        self.assert_checks()
        return current, public


def successful_refresh():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core, rules = f.setup_account()
        before = f.authority()
        f.reauth_expiry = 30  # Real refresh-window admission; not a natural-expiry timing claim.
        f.begin_reauthorization(core, rules)
        code, raw, _ = f.callback()
        assert code == 200, (code, raw)
        current, public = f.adopted(core, before)
        f.phase = "refresh"
        refreshed = f.app._credential_for_lease(core["id"])
        assert refreshed["credential_version"] == current["credential_version"] + 1
        assert json.loads(refreshed["secret"])["access_token"] == LATER_ACCESS
        assert json.loads(refreshed["secret"])["refresh_token"] == NEW_REFRESH
        assert f.public(public["operation_id"]) == public
        assert f.review_account(refreshed)["expected_credential_generation"] == refreshed["credential_version"]
        after = f.authority()
        for key in ("catalog", "intents", "policy", "file"):
            assert after[key] == before[key]
        assert not f.rows("oauth_revocation_work") and not f.rows(cleanup_tests.WORK_TABLE)
        assert len(f.events()) == 1
        f.assert_checks()
    return {"adopted_generation": current["credential_version"], "refreshed_generation": refreshed["credential_version"]}


def rejected_candidate(case):
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core, rules = f.setup_account()
        before = f.authority()
        f.begin_reauthorization(core, rules)
        if case == "account":
            f.subject = "synthetic-other-google-subject"
        elif case == "scopes":
            f.reauth_scopes += " https://www.googleapis.com/auth/drive.readonly"
        else:
            raise AssertionError("unknown refusal case")
        contacts = len(f.history)
        code, _, _ = f.callback()
        assert code == 409
        operation = f.public(f.start_payload["operation_id"])
        assert operation["status"] == "review_required" and operation["receipt"] is None
        assert f.authority() == before and not f.events()
        work = f.rows("oauth_revocation_work")
        assert len(work) == 1 and work[0]["source"] == SOURCE and work[0]["status"] == "held"
        assert json.loads(f.db.decrypt_secret_envelope(work[0]))["refresh_token"] == NEW_REFRESH
        owned = f.cleanup_store.get_work(work[0]["id"])
        assert owned["material_sha256"] is not None and owned["fence"] is None
        assert len(f.history) == contacts + (2 if case == "account" else 1)
        f.due(work[0]["id"])
        held = f.snapshot()
        f.ineligible(work[0]["id"])
        assert f.snapshot() == held and f.authority() == before
        f.assert_checks()
    return {"refused": case, "retained_without_adoption_or_revocation": True}


def stale_generation():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core, rules = f.setup_account()
        f.begin_reauthorization(core, rules)
        old_secret = json.loads(core["secret"])
        expiry = old_secret["expires_at_epoch_ms"] + 1000
        newer, changed = f.db.update_credential_secret_if_version(core["id"],
            expected_version=core["credential_version"], secret=json.dumps({**old_secret, "expires_at_epoch_ms": expiry}),
            metadata={**core["metadata"], "expires_at_epoch_ms": expiry})
        assert changed and newer["credential_version"] == core["credential_version"] + 1
        before, contacts = f.authority(), list(f.history)
        assert f.callback()[0] == 409
        assert f.authority() == before and f.history == contacts
        assert f.public(f.start_payload["operation_id"])["status"] == "failed"
        assert not f.rows("oauth_revocation_work") and not f.events()
        f.assert_checks()
    return {"stale_review_refused_before_exchange": True}


def concurrent_refresh():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core, rules = f.setup_account()
        before = f.authority()
        f.begin_reauthorization(core, rules)
        checked = []

        def attempt(_work):
            snapshot, contacts = f.snapshot(), list(f.history)
            consent_tests.refused(lambda: f.oauth.refresh_access_token(provider_id="google",
                token_secret=json.loads(core["secret"]), metadata=core["metadata"]), f.oauth.OAuthError)
            assert f.snapshot() == snapshot and f.history == contacts
            checked.append(True)

        f.before_token = attempt
        assert f.callback()[0] == 200
        assert checked == [True]
        f.adopted(core, before)
    return {"refresh_refused_while_actual_exchange_owns_barrier": True}


def browser_denial():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core, rules = f.setup_account()
        before = f.authority()
        f.begin_reauthorization(core, rules)
        saved_cookie = f.cookie
        contacts = list(f.history)
        for invalid in (None, saved_cookie.split("=", 1)[0] + "=" + "z" * 43):
            f.cookie = invalid
            snapshot = f.snapshot()
            assert f.callback()[0] == 400
            assert f.snapshot() == snapshot and f.history == contacts
            assert f.started["state"] in f.oauth._read_states()["states"]
        f.cookie = saved_cookie
        assert f.callback(error="access_denied", error_description="Synthetic user refusal")[0] == 409
        assert f.public(f.start_payload["operation_id"])["status"] == "denied"
        assert f.authority() == before and f.history == contacts
        snapshot = f.snapshot()
        assert f.callback()[0] == 400
        assert f.snapshot() == snapshot and f.history == contacts
        assert not f.rows("oauth_revocation_work") and not f.events()
        f.assert_checks()
    return {"browser_bound_denial_and_replay": True}


def expired_state():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core, rules = f.setup_account()
        f.begin_reauthorization(core, rules)
        before, contacts = f.authority(), list(f.history)
        # Expire only the real persisted browser-state record. This is a
        # deterministic refusal control, not a natural-lifetime acceptance.
        with f.oauth._oauth_state_lock():
            states = f.oauth._read_states()
            states["states"][f.started["state"]]["expires_at_epoch"] = 1
            f.oauth._write_states(states)
        assert f.callback()[0] == 400
        assert f.started["state"] not in f.oauth._read_states()["states"]
        assert f.authority() == before and f.history == contacts
        assert not f.rows("oauth_revocation_work") and not f.events()
        assert f.public(f.start_payload["operation_id"])["status"] != "adopted"
        f.assert_checks()
    return {"expired_real_state_refused_before_contact": True}


def lost_start():
    f = Fixture()
    from catchplate import operator_catalog_api
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core, rules = f.setup_account()
        payload = f.payload(core, rules)
        before, contacts = f.authority(), list(f.history)
        bad_bodies = (({**payload, "expected_revision": payload["expected_revision"] + 1}, 409),
            ({**payload, "affected_rule_ids": []}, 409), ({**payload, "unexpected": True}, 422),
            ({**payload, "expected_credential_generation": True}, 422), (b" " * 8193, 413))
        for body, expected in bad_bodies:
            snapshot = f.snapshot()
            assert f.request("POST", PATH, body=body)[0] == expected
            assert f.snapshot() == snapshot and f.history == contacts
        for options, expected in (({"auth": False}, 401), ({"origin": False}, 403)):
            snapshot = f.snapshot()
            assert f.request("POST", PATH, body=payload, **options)[0] == expected
            assert f.snapshot() == snapshot and f.history == contacts
        with patch.object(operator_catalog_api.JSONResponse, "set_cookie", side_effect=OSError("synthetic response lost")):
            code, _, _ = f.request("POST", PATH, body=payload)
        assert code == 503
        public = f.public(payload["operation_id"])
        assert public["status"] == "awaiting_consent" and public["receipt"] is None
        assert f.authority() == before and f.history == contacts
        snapshot = f.snapshot()
        assert f.request("POST", PATH, body=payload)[0] == 409
        assert f.lifecycle.status(payload["operation_id"], "synthetic-other-actor") is None
        assert f.request("GET", PATH + "/" + payload["operation_id"], auth=False)[0] == 401
        assert f.request("GET", PATH + "/" + payload["operation_id"] + "?retry=1")[0] == 422
        assert f.snapshot() == snapshot and f.history == contacts
        f.assert_checks()
    return {"lost_start_located_without_replay": True, "actor_isolated": True}


def audit_failure():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core, rules = f.setup_account()
        before = f.authority()
        f.begin_reauthorization(core, rules)
        with closing(f.db.connect()) as conn, conn:
            conn.execute("CREATE TRIGGER reauthorization_audit_abort BEFORE INSERT ON audit_events "
                "WHEN NEW.event_type='operator_catalog.oauth.reauthorized' "
                "BEGIN SELECT RAISE(ABORT,'synthetic reauthorization audit refusal'); END")
        code, _, _ = f.callback()
        assert code == 409 and f.authority() == before and not f.events()
        assert f.public(f.start_payload["operation_id"])["status"] == "review_required"
        work = f.rows("oauth_revocation_work")
        assert len(work) == 1 and work[0]["status"] == "held"
        assert json.loads(f.db.decrypt_secret_envelope(work[0]))["refresh_token"] == NEW_REFRESH
        with closing(f.db.connect()) as conn, conn:
            conn.execute("DROP TRIGGER reauthorization_audit_abort")
        snapshot, contacts = f.snapshot(), list(f.history)
        assert f.callback()[0] == 400
        assert f.snapshot() == snapshot and f.history == contacts
        f.assert_checks()
    return {"adoption_and_audit_rolled_back_together": True, "candidate_retained": True}


def lost_commit():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core, rules = f.setup_account()
        before = f.authority()
        f.begin_reauthorization(core, rules)
        committed, original_connect = [], sqlite3.connect

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
            return original_connect(*args, factory=LostAck, **kwargs)

        with patch.object(sqlite3, "connect", side_effect=connection):
            assert f.callback()[0] == 200
        _, public = f.adopted(core, before)
        assert committed == ["operator-google-reauthorized:" + public["operation_id"]]
        snapshot, contacts = f.snapshot(), list(f.history)
        assert f.callback()[0] == 400
        assert f.public(public["operation_id"]) == public
        assert f.snapshot() == snapshot and f.history == contacts
    return {"actual_commit_reobserved_without_exchange_or_adoption_replay": True}


def restart_prepare():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core, rules = f.setup_account()
        before = f.authority()
        f.begin_reauthorization(core, rules)
        assert f.callback()[0] == 200
        _, public = f.adopted(core, before)
        return {"operation": public, "authority": f.authority() | {"file": before["file"].decode()}, "audit": f.events()}


def restart_observe():
    f = Fixture()  # Original cold startup, no schema or admission replacement.
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        rows = f.rows(TABLE)
        assert len(rows) == 1 and rows[0]["status"] == "adopted"
        before = f.snapshot()
        public = f.public(rows[0]["operation_id"])
        assert not f.rows("oauth_revocation_work") and not f.rows(cleanup_tests.WORK_TABLE)
        assert f.app._reconcile_oauth_revocations(limit=8)["claimed"] == 0
        assert not f.history and f.snapshot() == before
        f.assert_checks()
        return {"operation": public, "authority": f.authority() | {
            "file": f.config.POLICY_BUNDLE_PATH.read_bytes().decode()}, "audit": f.events()}


def unique_ownership_retention(f):
    """SQL-only negative fixture; the unbound sibling is never committed/admitted."""
    before = f.snapshot()
    with closing(f.db.connect()) as conn:
        conn.execute("PRAGMA recursive_triggers=OFF")
        assert conn.execute("PRAGMA recursive_triggers").fetchone()[0] == 0
        conn.execute("BEGIN IMMEDIATE")
        original = dict(conn.execute("SELECT * FROM " + TABLE + " WHERE operation_id=?",
            (f.start_payload["operation_id"],)).fetchone())
        # The real start and callback already bound these two values; their
        # actual encrypted work must survive all four replacement statements.
        assert original["state_digest"] is not None and original["work_id"] is not None
        assert conn.execute("SELECT status FROM oauth_revocation_work WHERE id=?",
            (original["work_id"],)).fetchone()[0] == "held"
        sibling_id = str(uuid.uuid4())
        sibling = {**original, "operation_id": sibling_id, "status": "prepared", "state_digest": None,
            "work_id": None, "candidate_json": None, "receipt_json": None, "reason": None,
            "binding_json": json.dumps({**json.loads(original["binding_json"]), "operation_id": sibling_id},
                sort_keys=True, separators=(",", ":"))}
        columns = tuple(sibling)
        names, placeholders = ",".join(columns), ",".join("?" for _ in columns)
        conn.execute("INSERT INTO " + TABLE + " (" + names + ") VALUES (" + placeholders + ")",
            tuple(sibling[key] for key in columns))
        assert f.durable._read(conn.execute("SELECT * FROM " + TABLE + " WHERE operation_id=?",
            (sibling_id,)).fetchone())["status"] == "prepared"
        retained = tuple(conn.iterdump())  # Both operations, encrypted work/owner and audit.
        for field in ("state_digest", "work_id"):
            inserted_id = str(uuid.uuid4())
            candidate = {**sibling, "operation_id": inserted_id, field: original[field],
                "binding_json": json.dumps({**json.loads(sibling["binding_json"]), "operation_id": inserted_id},
                    sort_keys=True, separators=(",", ":"))}
            statements = (("INSERT OR REPLACE INTO " + TABLE + " (" + names + ") VALUES (" + placeholders + ")",
                tuple(candidate[key] for key in columns), "operator reauthorization already exists"),
                ("UPDATE OR REPLACE " + TABLE + " SET " + field + "=? WHERE operation_id=?",
                    (original[field], sibling_id), "operator reauthorization binding is immutable"))
            for statement, parameters, expected in statements:
                try:
                    conn.execute(statement, parameters)
                except sqlite3.IntegrityError as error:
                    assert str(error) == expected
                else:
                    raise AssertionError("cross-row replacement evicted retained reauthorization ownership")
                assert tuple(conn.iterdump()) == retained
        conn.rollback()
    assert f.snapshot() == before


def missing_owner():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core, rules = f.setup_account()
        before = f.authority()
        f.begin_reauthorization(core, rules)
        removed = []

        def remove_operation():
            unique_ownership_retention(f)
            # Corrupt disposable ownership AFTER actual token custody, not by
            # constructing a fake successful reservation/association.
            work = f.rows("oauth_revocation_work")
            assert len(work) == 1 and work[0]["status"] == "held"
            assert json.loads(f.db.decrypt_secret_envelope(work[0]))["access_token"] == NEW_ACCESS
            with closing(f.db.connect()) as conn, conn:
                trigger = conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (f.durable._DELETE,)).fetchone()[0]
                conn.execute("DROP TRIGGER " + f.durable._DELETE)
                assert conn.execute("DELETE FROM " + TABLE + " WHERE operation_id=?",
                    (f.start_payload["operation_id"],)).rowcount == 1
                conn.execute(trigger)
            removed.append(work[0]["id"])

        f.after_identity = remove_operation
        assert f.callback()[0] == 409
        assert len(removed) == 1 and f.authority() == before and not f.events()
        work = f.rows("oauth_revocation_work")
        assert len(work) == 1 and work[0]["id"] == removed[0] and work[0]["source"] == SOURCE
        assert len(f.rows(cleanup_tests.WORK_TABLE)) == 1
        f.due(removed[0])
        snapshot, contacts = f.snapshot(), list(f.history)
        with closing(f.db.connect()) as conn:
            row = conn.execute("SELECT * FROM oauth_revocation_work WHERE id=?", (removed[0],)).fetchone()
            assert f.cleanup_store.eligible(conn, row) is False
            secret = json.loads(f.db.decrypt_secret_envelope(row))
        consent_tests.refused(lambda: f.oauth.revoke_oauth_token(provider_id="google", token_secret=secret,
            _operator_cleanup_work_id=removed[0]), f.oauth.OAuthError)
        assert not f.db.claim_oauth_revocations(worker_id="synthetic-reauthorization-owner", limit=8)
        assert f.app._reconcile_oauth_revocations(limit=8)["claimed"] == 0
        consent_tests.refused(lambda: f.oauth.refresh_access_token(provider_id="google",
            token_secret=json.loads(core["secret"]), metadata=core["metadata"]), f.oauth.OAuthError)
        assert f.request("POST", consent_tests.START, body={**f.review(),
            "name": "Orphan does not authorize new consent", "permission_preset": "gmail_readonly"})[0] == 503
        assert f.snapshot() == snapshot and f.history == contacts
        f.assert_checks()
    return {"missing_operation_keeps_encrypted_work_nonrevocable": True}


def retained_upgrade():
    # Reproduce an older bootstrap that predates ONLY this new owner schema;
    # no existing schema is dropped and no validation guard is patched after
    # initialization. The real reviewed upgrade is the only successful writer.
    from catchplate import operator_demo
    operator_demo.activate()
    from catchplate import operator_google_reauthorization_store as durable
    from catchplate import operator_catalog_capabilities
    with patch.object(durable, "initialize", return_value=None):
        f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core, rules = f.setup_account()
        before, contacts = f.authority(), list(f.history)
        with closing(f.db.connect()) as conn:
            assert not durable.available(conn)
        assert f.request("GET", PATH + "/" + core["id"] + "/review")[0] == 503
        f.store.initialize()  # Retained startup must not silently install it.
        with closing(f.db.connect()) as conn:
            assert not durable.available(conn)
        status, raw, _ = f.request("GET", STORAGE_PATH)
        assert status == 200
        setup = json.loads(raw)
        assert setup["schema"] == "catchplate.operatorGoogleReauthorizationStorage/v1"
        assert setup["available"] is False and setup["admission"] is None
        pins = setup["review"]
        assert pins == {**f.review(), "profile_binding_digest": f.profile.binding_digest}
        with closing(f.db.connect()) as conn:
            conn.execute("BEGIN")
            assert operator_catalog_capabilities.google_reauthorization(conn) is None
        failures = [({**pins, "expected_revision": pins["expected_revision"] + 1}, {}, 409),
            ({**pins, "expected_policy_hash": "sha256:" + "0" * 64}, {}, 409),
            ({**pins, "profile_binding_digest": "sha256:" + "0" * 64}, {}, 409),
            ({**pins, "extra": True}, {}, 422), (pins, {"auth": False}, 401),
            (pins, {"origin": False}, 403), (b" " * 2049, {}, 413),
            (pins, {"headers": (("content-length", "0"),)}, 400)]
        for body, options, expected in failures:
            snapshot = f.snapshot()
            assert f.request("POST", STORAGE_PATH, body=body, **options)[0] == expected
            assert f.snapshot() == snapshot and f.history == contacts
        for path, options, expected in ((STORAGE_PATH + "?retry=1", {}, 422),
                (STORAGE_PATH, {"auth": False}, 401),
                (STORAGE_PATH, {"headers": (("content-length", "1"),)}, 400)):
            snapshot = f.snapshot()
            assert f.request("GET", path, **options)[0] == expected
            assert f.snapshot() == snapshot and f.history == contacts
        acknowledgements, original_connect = [], sqlite3.connect

        class LostSetupAck(sqlite3.Connection):
            def commit(self):
                receipt_row = self.in_transaction and self.execute(
                    "SELECT id FROM audit_events WHERE id=?", (durable.ADMISSION_ID,)).fetchone()
                if receipt_row and not acknowledgements:
                    super().commit()
                    acknowledgements.append(receipt_row[0])
                    raise OSError("synthetic committed setup acknowledgement lost")
                return super().commit()

        def connection(*args, **kwargs):
            assert "factory" not in kwargs
            return original_connect(*args, factory=LostSetupAck, **kwargs)

        raw = json.dumps(pins).encode()
        assert len(raw) < 2048
        with patch.object(sqlite3, "connect", side_effect=connection):
            code, result, _ = f.request("POST", STORAGE_PATH, body=raw + b" " * (2048 - len(raw)))
        assert code == 200 and acknowledgements == [durable.ADMISSION_ID]
        enabled = json.loads(result)
        assert enabled["available"] is True and enabled["provider_contact"] is False
        assert enabled["account_permissions_changed"] is False
        receipt = enabled["admission"]
        assert receipt["mode"] == "upgrade" and f.authority() == before and f.history == contacts
        f.store.initialize()
        assert f.review_account(core)["affected_rule_ids"] == sorted(rule["id"] for rule in rules)
        with closing(f.db.connect()) as conn:
            durable.observe_upgrade(conn, receipt)
            consent_tests.refused(lambda: durable.observe_upgrade(conn,
                {**receipt, "admission_id": str(uuid.uuid4())}), durable.ReauthorizationUnavailable)
            conn.execute("BEGIN")
            assert operator_catalog_capabilities.google_reauthorization(conn)["existing_account_only"] is True
        snapshot = f.snapshot()
        assert f.request("POST", STORAGE_PATH, body=pins)[0] == 503
        assert f.snapshot() == snapshot and f.history == contacts
        # A missing required trigger is never silently reconstructed either.
        with closing(f.db.connect()) as conn, conn:
            trigger = conn.execute("SELECT sql FROM sqlite_master WHERE name=?", (durable._INSERT,)).fetchone()[0]
            conn.execute("DROP TRIGGER " + durable._INSERT)
        damaged = f.snapshot()
        assert f.request("GET", STORAGE_PATH)[0] == 503
        assert f.request("POST", STORAGE_PATH, body=pins)[0] == 503
        assert f.snapshot() == damaged
        with closing(f.db.connect()) as conn, conn:
            conn.execute(trigger)  # Restore only the exact private fault before the independent missing-table control.
        # Retained admission marker must make a subsequently lost table an
        # error, never an apparently pre-feature store eligible for repair.
        with closing(f.db.connect()) as conn, conn:
            conn.execute("DROP TABLE " + TABLE)
        snapshot = f.snapshot()
        with closing(f.db.connect()) as conn:
            consent_tests.refused(lambda: durable.available(conn), durable.ReauthorizationUnavailable)
        consent_tests.refused(f.store.initialize, durable.ReauthorizationUnavailable)
        assert f.snapshot() == snapshot and f.history == contacts
        assert f.request("GET", PATH + "/" + core["id"] + "/review")[0] == 503
        f.assert_checks()
    return {"reviewed_upgrade_only": True, "lost_admitted_schema_not_recreated": True}


def disabled_profile():
    config, db, store, bundles, schema, inputs, mutations = workspace.workspace()
    from catchplate import app, oauth
    f = consent_tests.Fixture.__new__(consent_tests.Fixture)
    f.config, f.app, f.cookie = config, app, None

    def snapshot():
        with closing(db.connect()) as conn:
            return tuple(conn.iterdump()), config.POLICY_BUNDLE_PATH.read_bytes()

    before = snapshot()
    identifier = str(uuid.uuid4())
    body = {**workspace.review(db, store, schema), "operation_id": str(uuid.uuid4()),
        "credential_id": identifier, "expected_credential_generation": 1, "affected_rule_ids": []}
    with patch.object(oauth, "request_bytes", side_effect=AssertionError("disabled profile contacted provider")) as provider:
        assert f.request("POST", PATH, body=body)[0] == 503
        assert f.request("GET", PATH + "/" + identifier + "/review")[0] == 503
        assert provider.call_count == 0 and snapshot() == before
    return {"disabled_profile_no_contact_or_mutation": True}


OPERATIONS = {"success": successful_refresh, "wrong-account": lambda: rejected_candidate("account"),
    "wrong-scopes": lambda: rejected_candidate("scopes"), "stale": stale_generation,
    "concurrent": concurrent_refresh, "owner": missing_owner, "upgrade": retained_upgrade,
    "browser": browser_denial, "expiry": expired_state, "start": lost_start, "disabled": disabled_profile,
    "rollback": audit_failure, "commit": lost_commit, "restart-prepare": restart_prepare,
    "restart-observe": restart_observe}


class OperatorGoogleReauthorizationTests(unittest.TestCase):
    setUp = consent_tests.OperatorGoogleConsentTests.setUp

    def worker(self, operation, *, fresh=None):
        environment = dict(self.environment)
        if fresh is not None:
            environment["CATCHPLATE_DATA_DIR"] = str(self.directory.parent / fresh)
        if operation == "disabled":
            for key in tuple(environment):
                if key == "CATCHPLATE_OPERATOR_GOOGLE_PROFILE" or key.startswith("CATCHPLATE_GOOGLE_"):
                    del environment[key]
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        return json.loads(result.stdout)

    def test_same_account_adoption_preserves_authority_and_refreshes(self):
        self.worker("success")

    def test_wrong_account_and_scopes_retain_without_adoption_or_revocation(self):
        self.worker("wrong-account", fresh="wrong-account")
        self.worker("wrong-scopes", fresh="wrong-scopes")

    def test_stale_generation_and_concurrent_refresh_refuse_before_contact(self):
        self.worker("stale", fresh="stale")
        self.worker("concurrent", fresh="concurrent")

    def test_missing_ownership_blocks_adoption_and_generic_cleanup(self):
        self.worker("owner", fresh="owner")
        self.worker("upgrade", fresh="upgrade")

    def test_browser_binding_denial_expiry_and_callback_replay(self):
        self.worker("browser", fresh="browser")
        self.worker("expiry", fresh="expiry")

    def test_lost_start_locator_http_guards_and_actor_isolation(self):
        self.worker("start", fresh="start")
        self.worker("disabled", fresh="disabled")

    def test_audit_rollback_and_lost_commit_receipt(self):
        self.worker("rollback", fresh="rollback")
        self.worker("commit", fresh="commit")

    def test_adopted_receipt_and_authority_survive_cold_restart(self):
        self.assertEqual(self.worker("restart-prepare"), self.worker("restart-observe"))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
