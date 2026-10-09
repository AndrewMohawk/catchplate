#!/usr/bin/env python3
"""Synthetic operator Google consent through real ASGI and encrypted storage.

Run only in the bounded network-none, read-only-source backend harness. Each
worker cold-admits a fresh development profile. Only oauth.request_bytes is
stubbed: token, verified userinfo and revocation responses use exact fixed URLs.
State, browser cookie, PKCE, admission, catalog CAS, vault encryption, cleanup
reservation, SQLite and refresh generations are real. No lifecycle/profile
guards are replaced. This does NOT prove Google TLS/consent, Rust enforcement,
native authority, a production protected activation, or deployed readiness.
"""
from __future__ import annotations

import asyncio
from contextlib import closing
import hashlib
from http.cookies import SimpleCookie
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlencode, urlsplit

import test_operator_catalog_google as google_tests
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
START = "/api/operator-demo/oauth/google/start"
CALLBACK = "/api/oauth/callback/google"
INTENTS = "/api/operator-demo/oauth/google/intents"
ADMIN = "synthetic-operator-google-consent-admin-token"
CODE = "synthetic-google-authorization-code"
ACCESS = "synthetic-google-consent-access-token"
REFRESH = "synthetic-google-consent-refresh-token"
REFRESHED = "synthetic-google-consent-refreshed-access-token"
ALIAS = "https://www.googleapis.com/auth/userinfo.email"


def refused(function, exception):
    try:
        function()
    except exception:
        return
    raise AssertionError("synthetic Google consent boundary unexpectedly accepted input")


class Fixture:
    def __init__(self):
        (self.config, self.db, self.store, self.bundles, self.schema,
            self.inputs, self.mutations) = workspace.workspace()
        from serverware import app, auth, oauth, operator_catalog_oauth, operator_catalog_oauth_profile
        self.app, self.auth, self.oauth = app, auth, oauth
        self.consent, self.profiles = operator_catalog_oauth, operator_catalog_oauth_profile
        self.profile = self.profiles.require_profile()
        self.policy = self.config.POLICY_BUNDLE_PATH.read_bytes()
        self.calls, self.cookie, self.started = [], None, None
        self.account_number = 0
        self.scope_string = " ".join(self.profile.scopes)
        self.refresh_scope_string = None
        self.omit_initial_scope = self.omit_refresh_scope = False
        self.token_changes, self.identity_changes = {}, {}

    def review(self):
        return workspace.review(self.db, self.store, self.schema)

    def rows(self, table):
        return workspace.rows(self.db, table)

    def snapshot(self):
        tables = (*workspace.LEGACY_TABLES, *workspace.CATALOG_TABLES,
            "operator_catalog_oauth_profile", "operator_catalog_oauth_intents", "oauth_revocation_work",
            "operator_google_cleanup_work")
        with closing(self.db.connect()) as conn:
            return {table: sorted(tuple(row) for row in conn.execute("SELECT * FROM " + table)) for table in tables}

    def assert_redacted(self):
        with closing(self.db.connect()) as conn:
            persisted = "\n".join(conn.iterdump())
        for secret in (CODE, ACCESS, REFRESH, REFRESHED, google_tests.CLIENT_SECRET, ADMIN):
            assert secret not in persisted, "plaintext synthetic secret entered metadata/audit storage"
        assert self.config.POLICY_BUNDLE_PATH.read_bytes() == self.policy

    async def _request(self, method, path, *, body=None, auth=True, origin=True, cookie=True, headers=()):
        raw = b"" if body is None else body if isinstance(body, bytes) else json.dumps(body).encode()
        parsed = urlsplit(path)
        values = [(b"host", b"control.example.com")]
        if auth:
            values.append((b"x-serverware-admin-token", ADMIN.encode()))
        if origin:
            values.append((b"origin", self.config.PUBLIC_URL.encode()))
        if body is not None:
            values.extend(((b"content-type", b"application/json"), (b"content-length", str(len(raw)).encode())))
        if cookie and self.cookie:
            values.append((b"cookie", self.cookie.encode()))
        values.extend((name.lower().encode(), value.encode()) for name, value in headers)
        scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
            "http_version": "1.1", "method": method, "scheme": "https", "path": parsed.path,
            "raw_path": parsed.path.encode(), "query_string": parsed.query.encode(), "root_path": "",
            "headers": values, "client": ("127.0.0.1", 41301), "server": ("control.example.com", 443)}
        sent, messages, complete = False, [], asyncio.Event()

        async def receive():
            nonlocal sent
            if not sent:
                sent = True
                return {"type": "http.request", "body": raw, "more_body": False}
            await complete.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            messages.append(message)
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                complete.set()

        await asyncio.wait_for(self.app.app(scope, receive, send), 15)
        starts = [message for message in messages if message["type"] == "http.response.start"]
        assert len(starts) == 1 and complete.is_set()
        content = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
        assert len(content) <= 2 * 1024 * 1024
        for secret in (ACCESS, REFRESH, REFRESHED, google_tests.CLIENT_SECRET):
            assert secret.encode() not in content
        return starts[0]["status"], content, starts[0]["headers"]

    def request(self, *args, **kwargs):
        return asyncio.run(self._request(*args, **kwargs))

    def begin(self):
        self.account_number += 1
        code, raw, headers = self.request("POST", START, body={**self.review(),
            "name": "Synthetic Google account " + str(self.account_number), "permission_preset": "gmail_readonly"})
        assert code == 200, (code, raw)
        # The outer response signer emits its owned header names in title
        # case. HTTP field names are case-insensitive; retain the strict
        # exactly-one no-store requirement without assuming ASGI casing.
        assert [value for name, value in headers if name.lower() == b"cache-control"] == [b"no-store"]
        self.started = json.loads(raw)
        cookies = [value.decode() for name, value in headers if name.lower() == b"set-cookie"]
        assert len(cookies) == 1 and all(word in cookies[0].lower() for word in ("secure", "httponly", "samesite=lax"))
        parsed = SimpleCookie(cookies[0])
        name = self.oauth.browser_cookie_name(self.started["state"])
        assert set(parsed) == {name}
        self.cookie = name + "=" + parsed[name].value
        self.browser_nonce = parsed[name].value
        authorization = urlsplit(self.started["authorizationUrl"])
        assert authorization.scheme == "https" and authorization.netloc == "accounts.google.com"
        assert authorization.path == "/o/oauth2/v2/auth"
        query = parse_qs(authorization.query, strict_parsing=True)
        assert query["state"] == [self.started["state"]]
        assert query["client_id"] == [self.profile.client_id]
        assert query["redirect_uri"] == [self.profile.redirect_uri]
        assert query["scope"] == [" ".join(self.profile.scopes)]
        assert query["code_challenge_method"] == ["S256"] and query["access_type"] == ["offline"]
        self.challenge = query["code_challenge"][0]
        stored = self.oauth._read_states()["states"][self.started["state"]]
        assert stored["operator_catalog_intent_id"] == self.started["operatorGoogleIntent"]["id"]
        assert stored["browser_nonce_sha256"] == "sha256:" + hashlib.sha256(self.browser_nonce.encode()).hexdigest()
        assert self.oauth._code_challenge(stored["code_verifier"]) == self.challenge
        assert not self.calls
        return self.started

    def transport(self, request, **options):
        assert options["require_https"] is True and 0 < options["timeout"] <= 20
        assert 0 < options["max_bytes"] <= 256 * 1024
        url, method = request.full_url, request.get_method()
        self.calls.append((method, url))
        if url == "https://oauth2.googleapis.com/token":
            assert method == "POST"
            form = parse_qs(request.data.decode(), strict_parsing=True)
            assert form["client_id"] == [self.profile.client_id]
            assert form["client_secret"] == [google_tests.CLIENT_SECRET]
            if form["grant_type"] == ["authorization_code"]:
                assert set(form) == {"grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier"}
                assert form["code"] == [CODE] and form["redirect_uri"] == [self.profile.redirect_uri]
                assert self.oauth._code_challenge(form["code_verifier"][0]) == self.challenge
                assert self.started["state"] not in self.oauth._read_states()["states"]
                intent = json.loads(self.rows("operator_catalog_oauth_intents")[-1]["metadata_json"])
                assert intent["status"] == "exchanging", "provider was contacted before durable claim"
                payload = {"access_token": ACCESS, "refresh_token": REFRESH,
                    "token_type": "Bearer", "expires_in": 3600, "scope": self.scope_string, **self.token_changes}
                if self.omit_initial_scope:
                    payload.pop("scope")
            else:
                assert set(form) == {"grant_type", "refresh_token", "client_id", "client_secret"}
                assert form["grant_type"] == ["refresh_token"] and form["refresh_token"] == [REFRESH]
                payload = {"access_token": REFRESHED, "token_type": "Bearer", "expires_in": 3600,
                    "scope": self.refresh_scope_string or self.scope_string, **self.token_changes}
                if self.omit_refresh_scope:
                    payload.pop("scope")
        elif url == "https://openidconnect.googleapis.com/v1/userinfo":
            assert method == "GET" and request.data is None
            assert request.get_header("Authorization") == "Bearer " + ACCESS
            payload = {"sub": "synthetic-google-subject-" + str(self.account_number),
                "email": "fixture@example.com", "email_verified": True, **self.identity_changes}
        elif url == "https://oauth2.googleapis.com/revoke":
            assert method == "POST"
            form = parse_qs(request.data.decode(), strict_parsing=True)
            assert form["token"][0] in {ACCESS, REFRESH, REFRESHED}
            assert set(form) == {"token", "token_type_hint"}
            return SimpleNamespace(status=200, body=b"", headers={})
        else:
            raise AssertionError("provider transport attempted an unapproved endpoint")
        return SimpleNamespace(status=200, body=json.dumps(payload).encode(),
            headers={"content-type": "application/json"},
            raw_headers=(("Content-Type", "application/json"),))

    def callback(self, **changes):
        query = {"code": CODE, "state": self.started["state"], **changes}
        return self.request("GET", CALLBACK + "?" + urlencode(query), auth=False, origin=False)

    def exchange(self):
        return self.oauth.exchange_authorization_code(provider_id="google", code=CODE,
            state=self.started["state"], browser_nonce=self.browser_nonce)

    def connected(self):
        records = self.rows("operator_catalog_credentials")
        assert records and len(records) == len(self.rows("credentials"))
        catalog = workspace.catalog(self.db, self.schema)
        record = catalog["credentials"][-1]
        core = self.db.get_credential(record["id"], include_secret=True)
        assert core["metadata"]["scopes"] == list(self.profile.scopes)
        assert core["metadata"]["oauth_intent_id"] == self.started["operatorGoogleIntent"]["id"]
        assert core["metadata"]["oauth_profile_binding_digest"] == self.profile.binding_digest
        assert core["metadata"]["provider_subject"] == "synthetic-google-subject-" + str(self.account_number)
        assert core["metadata"]["provider_account"] == "fixture@example.com"
        secret = json.loads(core["secret"])
        assert secret["access_token"] == ACCESS and secret["refresh_token"] == REFRESH
        assert secret["scope"] == self.scope_string
        assert catalog["applications"] == catalog["access_rules"] == []
        assert not self.rows("oauth_revocation_work")
        code, raw, _ = self.request("GET", INTENTS)
        assert code == 200
        intent = json.loads(raw)["intents"][-1]
        assert intent["status"] == "connected" and intent["credential_id"] == core["id"]
        assert "state_digest" not in intent and "actor_id" not in intent
        self.assert_redacted()
        assert self.db.verify_audit_chain()["ok"]
        return core


def success(scope_mode):
    f = Fixture()
    values = list(f.profile.scopes)
    if scope_mode == "reordered":
        values.reverse()
    elif scope_mode == "alias":
        values = [ALIAS if value == "email" else value for value in values]
    elif scope_mode == "alias-pair":
        values.append(ALIAS)
    f.scope_string = " ".join(values)
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        code, body, _ = f.callback()
        assert code == 200 and b"No application access has been granted" in body
        f.connected()
        before = f.snapshot()
        code, _, _ = f.callback()
        assert code == 400 and len(f.calls) == 2 and f.snapshot() == before
    return {"scope_mode": scope_mode, "connected": True, "replay_contacts": 0}


def browser_and_denial():
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        original = f.cookie
        for cookie in (None, original.split("=", 1)[0] + "=" + "z" * 43):
            f.cookie = cookie
            code, _, _ = f.callback()
            assert code == 400 and not f.calls
            assert f.started["state"] in f.oauth._read_states()["states"]
        f.cookie = original
        code, _, _ = f.callback(code="", error="access_denied")
        assert code == 400 and not f.calls
        assert f.started["state"] not in f.oauth._read_states()["states"]
        intent = json.loads(f.rows("operator_catalog_oauth_intents")[0]["metadata_json"])
        assert intent["status"] == "failed" and intent["reason"] == "consent_denied"
        assert not f.rows("credentials") and not f.rows("oauth_revocation_work")
    return {"wrong_browser_controls": 2, "denial_contacts": 0}


def before_contact(change):
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        if change in {"actor", "missing-intent"}:
            with f.oauth._oauth_state_lock():
                states = f.oauth._read_states()
                record = states["states"][f.started["state"]]
                if change == "actor":
                    record["actor_id"] = "different-synthetic-actor"
                else:
                    record.pop("operator_catalog_intent_id")
                f.oauth._write_states(states)
        elif change in {"revision", "profile-pin"}:
            with closing(f.db.connect()) as conn, conn:
                if change == "revision":
                    conn.execute("UPDATE operator_catalog_state SET revision=revision+1")
                else:
                    conn.execute("UPDATE operator_catalog_oauth_profile SET binding_digest=?", ("sha256:" + "0" * 64,))
        environment = {"SERVERWARE_GOOGLE_OAUTH_CLIENT_ID": "456-drift.apps.googleusercontent.com"} if change == "profile" else {}
        with patch.dict(os.environ, environment):
            # Direct exchange proves the after-consumption hook even when HTTP
            # admission itself would reject a changed cold profile earlier.
            refused(f.exchange, f.oauth.OAuthError)
        assert f.started["state"] not in f.oauth._read_states()["states"]
        assert not f.calls and not f.rows("credentials") and not f.rows("oauth_revocation_work")
    return {"change": change, "consumed": True, "contacts": 0}


def rollback(target):
    f = Fixture()
    from serverware import operator_google_cleanup as cleanup, operator_google_cleanup_store as cleanup_store
    targets = {"core": ("INSERT", "credentials", ""),
        "catalog": ("INSERT", "operator_catalog_credentials", ""),
        "revision": ("UPDATE", "operator_catalog_state", ""),
        "intent": ("UPDATE", "operator_catalog_oauth_intents", ""),
        "audit": ("INSERT", "audit_events", " WHEN NEW.event_type='operator_catalog.oauth.account_connected'")}
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        exchanged = f.exchange()
        before = f.snapshot()
        operation, table, condition = targets[target]
        with closing(f.db.connect()) as conn, conn:
            conn.execute("CREATE TRIGGER consent_abort BEFORE " + operation + " ON " + table + condition
                + " BEGIN SELECT RAISE(ABORT, 'synthetic registration rollback'); END")
        try:
            f.consent.register_active(exchanged, exchanged["metadata"])
        except cleanup.CleanupDisposition as error:
            outcome = error.outcome
        else:
            raise AssertionError("registration fault did not return its cleanup disposition")
        after = f.snapshot()
        # An empty family cannot authorize asynchronous revocation: a later
        # consent could adopt the same identity after a read-only permit check.
        assert outcome.status == "deferred" and outcome.receipt is None
        assert after == before, "registration/fence failure left partial state"
        work = f.rows("oauth_revocation_work")
        assert len(work) == 1 and work[0]["secret_ciphertext"]
        retained = cleanup_store.get_work(work[0]["id"])
        assert retained["fence"] == outcome.receipt
        assert work[0]["status"] == "held"
        assert not f.rows("credentials") and not f.rows("operator_catalog_credentials")
        assert len(f.calls) == 2
        f.assert_redacted()
    return {"target": target, "atomic_rollback": True, "encrypted_cleanup_retained": True}


def callback_cleanup():
    f = Fixture()
    from serverware import operator_google_cleanup_store as cleanup_store
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        with closing(f.db.connect()) as conn, conn:
            conn.execute("CREATE TRIGGER consent_abort BEFORE INSERT ON operator_catalog_credentials "
                "BEGIN SELECT RAISE(ABORT, 'synthetic catalog refusal'); END")
        code, raw, _ = f.callback()
        assert code == 409 and b"synthetic catalog refusal" not in raw
        disposition = json.loads(raw)["operator_google_cleanup"]
        assert disposition["status"] == "deferred" and "fence" not in disposition
        assert not f.rows("credentials") and not f.rows("operator_catalog_credentials")
        assert not any(url.endswith("/revoke") for _method, url in f.calls)
        work = f.rows("oauth_revocation_work")
        assert len(work) == 1 and work[0]["status"] == "held" and work[0]["secret_ciphertext"]
        assert cleanup_store.get_work(work[0]["id"])["fence"] is None
        f.app._reconcile_oauth_revocations(limit=8)
        assert not any(url.endswith("/revoke") for _method, url in f.calls)
        value = json.loads(f.rows("operator_catalog_oauth_intents")[0]["metadata_json"])
        assert value["status"] == "exchanging" and value["credential_id"] is None
        f.assert_redacted()
    return {"provider_cleanup": False, "cleanup_deferred": True, "half_registration": False}


def invalid_grant(change):
    f = Fixture()
    if change == "missing":
        f.scope_string = "openid email"
    elif change == "broader":
        f.scope_string += " https://www.googleapis.com/auth/gmail.modify"
    elif change == "duplicate":
        f.scope_string += " email"
    elif change == "identity":
        f.identity_changes = {"sub": None}
    elif change == "omitted":
        f.omit_initial_scope = True
    else:
        raise AssertionError("unknown fixture")
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        code, raw, _ = f.callback()
        assert code == 409 and not f.rows("credentials") and not f.rows("operator_catalog_credentials")
        disposition = json.loads(raw)["operator_google_cleanup"]
        work = f.rows("oauth_revocation_work")
        assert disposition["status"] == "deferred" and "fence" not in disposition
        assert len(work) == 1 and work[0]["secret_ciphertext"] and work[0]["status"] == "held"
        assert not any(url.endswith("/revoke") for _method, url in f.calls)
        value = json.loads(f.rows("operator_catalog_oauth_intents")[0]["metadata_json"])
        assert value["status"] == "failed" and value["reason"] == "exchange_failed"
        f.assert_redacted()
    return {"invalid_grant": change, "cleanup_deferred": True, "encrypted_cleanup_retained": True}


def scope_schema_contract():
    """Validate the actual shared schema; no compiler/provider success is inferred."""
    from jsonschema import Draft202012Validator
    schema = json.loads((ROOT / "schemas/adapters/generic.rest.schema.json").read_text())
    validator = Draft202012Validator(schema["$defs"]["credentialBinding"])
    scopes = ["email", "https://www.googleapis.com/auth/gmail.readonly", "openid"]
    binding = {"credentialType": "oauth2", "provider": "google", "subjects": ["synthetic-subject"],
        "clientIds": ["synthetic-client.apps.googleusercontent.com"], "requiredScopes": scopes}
    validator.validate(binding)
    validator.validate({**binding, "requiredScopes": [scopes[1]]})
    validator.validate({**binding, "provider": "x", "requiredScopes": ["tweet.read"]})
    refused_values = [
        {**binding, "provider": "x"},
        {**binding, "requiredScopes": scopes[:2]},
        {**binding, "requiredScopes": list(reversed(scopes))},
        {**binding, "requiredScopes": [*scopes, "extra"]},
        {**binding, "requiredScopes": [scopes[0], scopes[0], scopes[2]]},
        {**binding, "requiredScopes": [scopes[0], "https://www.googleapis.com/auth/gmail.modify", scopes[2]]},
        {**binding, "requiredScopes": [ALIAS, *scopes[1:]]},
        {**binding, "clientIds": [*binding["clientIds"], "another-client"]},
        {**binding, "subjects": [*binding["subjects"], "another-subject"]},
    ]
    for value in refused_values:
        assert not validator.is_valid(value), "generic binding unexpectedly widened"
    return {"exact_google_three_scope_schema": True, "legacy_singleton_preserved": True,
        "negative_controls": len(refused_values), "runtime_verified": False}


def expired_refresh(*, omit_scope=False):
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        assert f.callback()[0] == 200
        core = f.connected()
        secret = {**json.loads(core["secret"]), "expires_at_epoch_ms": 1}
        expired, changed = f.db.update_credential_secret_if_version(core["id"],
            expected_version=core["credential_version"], secret=json.dumps(secret),
            metadata={**core["metadata"], "expires_at_epoch_ms": 1})
        assert changed and expired["credential_version"] == core["credential_version"] + 1
        f.app.runtime.invalidate_secret_leases(core["id"])
        f.refresh_scope_string = " ".join([*reversed(f.profile.scopes), ALIAS])
        f.omit_refresh_scope = omit_scope
        refreshed = f.app._credential_for_lease(core["id"])
        assert refreshed["credential_version"] == expired["credential_version"] + 1
        actual = f.db.get_credential(core["id"], include_secret=True)
        assert json.loads(actual["secret"])["access_token"] == REFRESHED
        assert json.loads(actual["secret"])["scope"] == (f.scope_string if omit_scope else f.refresh_scope_string)
        assert actual["metadata"]["scopes"] == list(f.profile.scopes)
        assert actual["metadata"]["oauth_intent_id"] == core["metadata"]["oauth_intent_id"]
        assert f.calls == [("POST", "https://oauth2.googleapis.com/token"),
            ("GET", "https://openidconnect.googleapis.com/v1/userinfo"),
            ("POST", "https://oauth2.googleapis.com/token")]
        assert f.app._credential_for_lease(core["id"])["credential_version"] == actual["credential_version"]
        assert len(f.calls) == 3 and not f.rows("oauth_revocation_work")
        f.assert_redacted()
    return {"automatic_refresh": True, "second_consent": False, "generation_advanced": True}


def refresh_failure_guidance():
    """Exercise the real refresh catch without diagnosing an uncertain outcome."""
    f = Fixture()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        f.begin()
        assert f.callback()[0] == 200
        core = f.connected()
        secret = {**json.loads(core["secret"]), "expires_at_epoch_ms": 1}
        expired, changed = f.db.update_credential_secret_if_version(core["id"],
            expected_version=core["credential_version"], secret=json.dumps(secret),
            metadata={**core["metadata"], "expires_at_epoch_ms": 1})
        assert changed and expired["credential_version"] == core["credential_version"] + 1
        f.app.runtime.invalidate_secret_leases(core["id"])
        before = f.db.get_credential(core["id"], include_secret=True)
        catalog_before = workspace.catalog(f.db, f.schema)
        calls_before = list(f.calls)

        def timeout(request, **options):
            assert request.full_url == "https://oauth2.googleapis.com/token"
            assert request.get_method() == "POST" and options["require_https"] is True
            form = parse_qs(request.data.decode(), strict_parsing=True)
            assert form["grant_type"] == ["refresh_token"] and form["refresh_token"] == [REFRESH]
            f.calls.append(("POST", request.full_url))
            raise TimeoutError("synthetic uncertain provider outcome " + REFRESH)

        with patch.object(f.oauth, "request_bytes", side_effect=timeout):
            try:
                f.app._credential_for_lease(core["id"])
            except f.app.HTTPException as exc:
                assert exc.status_code == 503
                assert exc.detail == ("OAuth access token could not be refreshed; "
                    "check account status and audit logs before taking action")
                assert "reconnect" not in exc.detail.lower() and REFRESH not in exc.detail
            else:
                raise AssertionError("uncertain OAuth refresh unexpectedly issued a credential")
        assert f.calls == calls_before + [("POST", "https://oauth2.googleapis.com/token")]
        assert f.db.get_credential(core["id"], include_secret=True) == before
        assert workspace.catalog(f.db, f.schema) == catalog_before
        work = f.rows("oauth_revocation_work")
        assert len(work) == 1 and work[0]["status"] == "issuance_uncertain_unreported"
        from serverware import operator_google_cleanup_store
        retained = operator_google_cleanup_store.get_work(work[0]["id"])
        assert retained["fence"] is None and retained["material_sha256"] is None
        failed = [row for row in f.rows("audit_events")
            if row["event_type"] == "credential.oauth_refresh_failed"]
        assert len(failed) == 1
        assert json.loads(failed[0]["event_json"]) == {"credential_id": core["id"],
            "provider": "google", "credential_version": before["credential_version"], "reason": "OAuthError"}
        assert f.db.verify_audit_chain()["ok"]
        f.assert_redacted()
    return {"status": 503, "reconnection_required_claimed": False,
        "refresh_attempts": 1, "provider_revocations": 0, "uncertainty_retained": True}


def state_durability(failure=None):
    f = Fixture()
    f.begin()
    events = []
    real_sync, real_replace = os.fsync, os.replace

    def sync(descriptor):
        path = Path(os.readlink("/proc/self/fd/" + str(descriptor)))
        mode = os.fstat(descriptor).st_mode
        if path.parent == f.oauth.OAUTH_STATE_PATH.parent and path.name.startswith(".oauth-state-"):
            assert stat.S_ISREG(mode) and stat.S_IMODE(mode) == 0o600
            assert f.started["state"] not in json.loads(path.read_text())["states"]
            events.append("file")
            if failure == "file":
                raise OSError("synthetic state file synchronization failure")
        elif path == f.oauth.OAUTH_STATE_PATH.parent and stat.S_ISDIR(mode):
            assert f.started["state"] not in f.oauth._read_states()["states"]
            events.append("directory")
            if failure == "directory":
                raise OSError("synthetic state directory synchronization failure")
        return real_sync(descriptor)

    def replace(source, destination, **options):
        if Path(destination) == f.oauth.OAUTH_STATE_PATH:
            assert events == ["file"]
            events.append("replace")
        return real_replace(source, destination, **options)

    with patch.object(f.oauth.os, "fsync", side_effect=sync), patch.object(f.oauth.os, "replace", side_effect=replace), \
            patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        if failure:
            refused(f.exchange, f.oauth.OAuthError)
        else:
            f.oauth.consume_state(provider_id="google", state=f.started["state"], browser_nonce=f.browser_nonce)
    assert events == (["file"] if failure == "file" else ["file", "replace", "directory"])
    assert (f.started["state"] in f.oauth._read_states()["states"]) == (failure == "file")
    assert not f.calls and not f.rows("credentials") and not f.rows("oauth_revocation_work")
    assert not list(f.oauth.OAUTH_STATE_PATH.parent.glob(".oauth-state-*"))
    return {"failure": failure, "events": events, "provider_contacts": 0}


def http_guards():
    f = Fixture()
    payload = {**f.review(), "name": "Synthetic Google account"}
    before = f.snapshot()
    with patch.object(f.oauth, "request_bytes", side_effect=f.transport):
        for options, body, expected in (({"auth": False}, payload, 401),
                ({"origin": False}, payload, 403),
                ({}, {**payload, "scopes": ["email"]}, 422),
                ({}, {**payload, "metadata": {"oauth_intent_id": "caller-owned"}}, 422),
                ({}, {**payload, "permission_preset": "gmail_modify"}, 422),
                ({}, {**payload, "expected_revision": True}, 422),
                ({}, b" " * 2049, 413)):
            assert f.request("POST", START, body=body, **options)[0] == expected
            assert f.snapshot() == before and not f.calls
        assert f.request("POST", "/api/oauth/start", body={"provider": "google"})[0] == 403
        assert f.request("GET", INTENTS, auth=False)[0] == 401
    return {"bounded_http_refusals": 9, "contacts": 0}


OPERATIONS = {"browser-denial": browser_and_denial, "callback-cleanup": callback_cleanup,
    "scope-schema": scope_schema_contract,
    "expired-refresh": expired_refresh, "refresh-omitted-scope": lambda: expired_refresh(omit_scope=True),
    "refresh-failure-guidance": refresh_failure_guidance,
    "http-guards": http_guards, "state-durability": state_durability,
    "state-file-sync-failure": lambda: state_durability("file"),
    "state-directory-sync-failure": lambda: state_durability("directory")}
for _mode in ("canonical", "reordered", "alias", "alias-pair"):
    OPERATIONS["success-" + _mode] = lambda mode=_mode: success(mode)
for _change in ("actor", "missing-intent", "revision", "profile", "profile-pin"):
    OPERATIONS["precontact-" + _change] = lambda change=_change: before_contact(change)
for _target in ("core", "catalog", "revision", "intent", "audit"):
    OPERATIONS["rollback-" + _target] = lambda target=_target: rollback(target)
for _change in ("missing", "broader", "duplicate", "identity", "omitted"):
    OPERATIONS["invalid-" + _change] = lambda change=_change: invalid_grant(change)


class OperatorGoogleConsentTests(unittest.TestCase):
    def setUp(self):
        google_tests.OperatorCatalogGoogleTests.setUp(self)
        self.environment["SERVERWARE_ADMIN_TOKEN"] = ADMIN

    def worker(self, operation):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        return json.loads(result.stdout)


def _test(operation):
    def check(self):
        self.worker(operation)
    return check


for _operation in OPERATIONS:
    setattr(OperatorGoogleConsentTests, "test_" + _operation.replace("-", "_"), _test(_operation))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        print(json.dumps(OPERATIONS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
