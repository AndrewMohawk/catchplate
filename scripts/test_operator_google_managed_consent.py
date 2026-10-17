#!/usr/bin/env python3
"""Connected managed consent admission, with synthetic health/provider transport.

Real cold startup, ASGI administrator/origin admission, SQLite/CAS/publication
locks, OAuth state/cookies, PKCE, encrypted custody and callbacks run unchanged.
Only HTTPConnection and the established fixed provider request_bytes seam are
synthetic. No provider, live gate, browser or external socket is contacted.
Run only in the bounded network-none, read-only-source dependency harness.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs
import uuid

import test_operator_google_consent as consent_tests
import test_operator_google_managed_config as managed_tests
import test_operator_google_managed_readiness_connected as health_tests
import test_operator_google_reauthorization as reauth_tests
import test_operator_publication as coordination
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]


class Fixture(reauth_tests.Fixture):
    def __init__(self):
        # Use the actual managed runner/startup fixture, not the legacy
        # constructor that initializes an externally configured Google profile.
        runtime = managed_tests.Fixture()
        self.__dict__.update(vars(runtime))
        from catchplate import operator_catalog_oauth, operator_google_reauthorization
        from catchplate import operator_google_reauthorization_store, operator_google_cleanup_store
        from catchplate import operator_google_managed_readiness
        self.consent, self.lifecycle = operator_catalog_oauth, operator_google_reauthorization
        self.durable, self.cleanup_store = operator_google_reauthorization_store, operator_google_cleanup_store
        self.readiness = operator_google_managed_readiness
        self.profile = self.profiles.require_profile()
        self.policy = self.config.POLICY_BUNDLE_PATH.read_bytes()
        self.calls, self.history, self.provider_checks, self.client_tokens = [], [], [], []
        self.cookie = self.started = self.subject = None
        self.account_number, self.phase = 0, "initial"
        self.scope_string = " ".join(self.profile.scopes)
        assert self.config.GOOGLE_OAUTH_CLIENT_SECRET == managed_tests.SECRET

    def request(self, *args, **kwargs):
        result = super().request(*args, **kwargs)
        public = result[1] + b"\n".join(name + b":" + value for name, value in result[2])
        assert managed_tests.SECRET.encode() not in public
        return result

    def provider(self, request, **options):
        """Fixed synthetic responses; validate real claimed custody and PKCE."""
        url, method = request.full_url, request.get_method()
        self.calls.append((method, url))
        self.history.append((method, url))
        index = len(self.provider_checks)
        self.provider_checks.append(False)  # A swallowed assertion is a failure.
        assert options["require_https"] is True and 0 < options["timeout"] <= 20
        assert 0 < options["max_bytes"] <= 256 * 1024
        self.store.operator_publication.assert_not_held()
        assert coordination.shared_probe(self.config.DATA_DIR / self.store.operator_publication.LOCK_NAME)
        with closing(self.db.connect()) as conn:
            conn.execute("PRAGMA busy_timeout=0")
            conn.execute("BEGIN IMMEDIATE")
            conn.rollback()
        if url == "https://oauth2.googleapis.com/token":
            assert method == "POST"
            form = parse_qs(request.data.decode(), strict_parsing=True)
            assert set(form) == {"grant_type", "code", "redirect_uri", "client_id", "client_secret", "code_verifier"}
            assert form["grant_type"] == ["authorization_code"] and form["code"] == [consent_tests.CODE]
            assert form["client_id"] == [self.profile.client_id]
            assert form["client_secret"] == [managed_tests.SECRET]
            assert form["redirect_uri"] == [self.profile.redirect_uri]
            assert self.oauth._code_challenge(form["code_verifier"][0]) == self.challenge
            assert self.started["state"] not in self.oauth._read_states()["states"]
            work = [row for row in self.rows("oauth_revocation_work") if row["status"] == "exchange_in_flight"]
            assert len(work) == 1
            retained = self.cleanup_store.get_work(work[0]["id"])
            assert retained["fence"] is None
            assert retained["association"]["profile_binding_digest"] == self.profile.binding_digest
            assert retained["association"]["oauth_client_id"] == self.profile.client_id
            if self.phase == "initial":
                assert work[0]["source"] == "operator_google_initial_v1"
                intent = json.loads(self.rows("operator_catalog_oauth_intents")[-1]["metadata_json"])
                assert intent["status"] == "exchanging"
                access, refresh = consent_tests.ACCESS, consent_tests.REFRESH
            else:
                assert self.phase == "reauthorize" and work[0]["source"] == reauth_tests.SOURCE
                assert self.public(self.start_payload["operation_id"])["status"] == "exchanging"
                access, refresh = reauth_tests.NEW_ACCESS, reauth_tests.NEW_REFRESH
            payload = {"access_token": access, "refresh_token": refresh, "token_type": "Bearer",
                "expires_in": 3600, "scope": self.scope_string}
        elif url == "https://openidconnect.googleapis.com/v1/userinfo":
            assert method == "GET" and request.data is None
            access = consent_tests.ACCESS if self.phase == "initial" else reauth_tests.NEW_ACCESS
            assert request.get_header("Authorization") == "Bearer " + access
            payload = {"sub": self.subject or "synthetic-google-subject-1",
                "email": "fixture@example.com", "email_verified": True}
        else:
            raise AssertionError("unapproved synthetic provider endpoint")
        self.provider_checks[index] = True
        return SimpleNamespace(status=200, body=json.dumps(payload).encode(),
            headers={"content-type": "application/json"}, raw_headers=(("Content-Type", "application/json"),))

    def connected_account(self):
        core = self.connect()
        self.subject = core["metadata"]["provider_subject"]
        assert self.subject == "synthetic-google-subject-1"
        assert json.loads(core["secret"])["refresh_token"] == consent_tests.REFRESH
        assert all(self.provider_checks) and len(self.provider_checks) == 2
        return core

    def actor(self):
        return json.loads(self.rows("operator_catalog_oauth_intents")[0]["metadata_json"])["actor_id"]


def snapshot(f):
    path = f.oauth.OAUTH_STATE_PATH
    lock = path.with_suffix(path.suffix + ".lock")
    return managed_tests.raw_snapshot(), (path.read_bytes() if path.exists() else None, lock.exists())


def initial_payload(f):
    return {**f.review(), "name": "Managed consent admission fixture", "permission_preset": "gmail_readonly"}


def rejected_response(f, path, payload):
    code, raw, headers = f.request("POST", path, body=payload)
    assert code == 409, (code, raw)
    assert set(json.loads(raw)) == {"detail"}
    expected = ("Google consent changed or unavailable; inspect saved status before starting again"
        if path == consent_tests.START else
        "Google account or reviewed access changed; check saved reauthorization status")
    assert json.loads(raw)["detail"] == expected
    assert [value for name, value in headers if name.lower() == b"cache-control"] == [b"no-store"]
    assert not [value for name, value in headers if name.lower() == b"set-cookie"]


@contextmanager
def real_join_observer(f):
    calls, original = [], f.readiness.require_start

    def require(conn, observation):
        f.store.operator_publication.assert_held()
        assert conn.in_transaction and conn.total_changes == 0
        assert conn.execute("PRAGMA query_only").fetchone()[0] == 0
        assert not coordination.shared_probe(f.config.DATA_DIR / f.store.operator_publication.LOCK_NAME)
        calls.append(observation)
        return original(conn, observation)

    with patch.object(f.readiness, "require_start", side_effect=require):
        yield calls


def mismatch_controls(document):
    changes = (
        lambda value: value.update(data_plane_binary_digest="sha256:" + "8" * 64),
        lambda value: value["policy_shadow"]["managed_google"]["operation"].update(operation_id=str(uuid.uuid4())),
        lambda value: value["policy_shadow"]["managed_google"].update(profile_binding_digest="sha256:" + "0" * 64),
        lambda value: value["policy_shadow"]["managed_google"].update(effective_settings_digest="sha256:" + "0" * 64),
        lambda value: value["policy_shadow"].update(managed_google={
            **value["policy_shadow"]["managed_google"], "operation": None, "profile_binding_digest": None}),
        lambda value: value["policy_shadow"].pop("managed_google"),
        lambda value: value.update(ok=False),
    )
    for change in changes:
        changed = deepcopy(document)
        change(changed)
        yield changed


def admission_controls(request):
    f = Fixture()
    transport = health_tests.HealthTransport(f, health_tests.health(f))
    with patch.object(f.store.http.client, "HTTPConnection", side_effect=transport.connect), \
            patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        reauth = request["reauthorization"]
        core = f.connected_account() if reauth else None
        path = reauth_tests.PATH if reauth else consent_tests.START
        payload = f.payload(core, []) if reauth else initial_payload(f)
        expected, before, contacts = health_tests.health(f), snapshot(f), list(f.history)
        transport.complete()
        transport.connections.clear()
        for document in mismatch_controls(expected):
            transport.document = document
            rejected_response(f, path, payload)
            assert snapshot(f) == before and f.history == contacts
        transport.complete(expected=7)
        transport.connections.clear()
        failed_connections = []

        def unavailable(host, port, *, timeout):
            assert (host, port, timeout) == ("127.0.0.1", 9091, 1)
            f.store.operator_publication.assert_not_held()
            failed_connections.append(True)
            raise ConnectionError("synthetic unavailable gate transport")

        with patch.object(f.store.http.client, "HTTPConnection", side_effect=unavailable):
            rejected_response(f, path, payload)
        assert failed_connections == [True] and snapshot(f) == before and f.history == contacts
        transport.document = expected
        # The API executes on a worker thread. Test caller-owned EX directly
        # on the owning thread, so there is no artificial cross-thread deadlock.
        with f.store.operator_publication.exclusive():
            if reauth:
                function = lambda: f.lifecycle.start(payload, f.actor(), "n" * 43)
            else:
                function = lambda: f.consent.begin(f.consent.GoogleStartInput(**payload), managed_tests.ACTOR)
            consent_tests.refused(function, f.schema.CatalogConflict)
            assert transport.connections == []
        assert snapshot(f) == before and f.history == contacts
        with real_join_observer(f) as joins:
            if reauth:
                f.begin_reauthorization(core, [])
            else:
                f.begin()
            assert len(joins) == 1 and joins[0]["ready"] is True
        assert f.started["state"] in f.oauth._read_states()["states"]
        assert f.history == contacts and len(transport.connections) == 1
    transport.complete()
    return {"reauthorization": reauth, "same_policy_refusals": 7,
        "connection_failure_refused_without_writes": True,
        "outer_EX_no_HTTP_or_writes": True, "real_ASGI_state_and_cookie": True}


def capture_to_cas_drift(request):
    f = Fixture()
    transport = health_tests.HealthTransport(f, health_tests.health(f))
    with patch.object(f.store.http.client, "HTTPConnection", side_effect=transport.connect), \
            patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        reauth = request["reauthorization"]
        core = f.connected_account() if reauth else None
        path = reauth_tests.PATH if reauth else consent_tests.START
        payload = f.payload(core, []) if reauth else initial_payload(f)
        original, after_mutation = f.readiness.capture_start, []

        def capture_then_mutate():
            observation = original()  # No fabricated successful observation.
            assert observation["ready"] is True
            f.store.operator_publication.assert_not_held()
            workspace.create_credential(f.db, f.store, f.schema, f.inputs, f.mutations,
                "Concurrent reviewed-revision change")
            assert f.review()["expected_revision"] == payload["expected_revision"] + 1
            after_mutation.append(snapshot(f))
            return observation

        contacts = list(f.history)
        with patch.object(f.readiness, "capture_start", side_effect=capture_then_mutate):
            rejected_response(f, path, payload)
        assert len(after_mutation) == 1 and snapshot(f) == after_mutation[0]
        assert f.history == contacts
    transport.complete()
    return {"reauthorization": reauth, "real_revision_change_after_observation": True,
        "no_additional_consent_state_audit_cookie": True}


def durable_omitted_and_stale_observation(_request):
    f = Fixture()
    transport = health_tests.HealthTransport(f, health_tests.health(f))
    with patch.object(f.store.http.client, "HTTPConnection", side_effect=transport.connect), \
            patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        core = f.connected_account()
        observation = f.readiness.capture_start()
        application = workspace.create_application(f.db, f.store, f.schema, f.inputs, f.mutations)["application"]
        rule = f.mutations.create_rule(f.inputs.RuleInput(**f.review(), name="Actual signed Gmail assignment",
            application_id=application["id"], credential_id=core["id"],
            upstream_url="https://gmail.googleapis.com/gmail/v1/users/me/messages",
            methods=["GET"], response_fields=["id"]), managed_tests.ACTOR)["access_rule"]
        payload = f.lifecycle.ReauthorizeInput(**f.payload(core, [rule]))
        assert payload.expected_policy_hash != observation["policy_hash"]
        before, contacts, count = snapshot(f), list(f.history), len(transport.connections)
        for supplied in (None, observation):
            with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn:
                conn.execute("BEGIN IMMEDIATE")
                consent_tests.refused(lambda: f.durable.begin(conn, payload, f.actor(),
                    managed_readiness=supplied), f.schema.CatalogConflict)
                assert conn.total_changes == 0
                conn.rollback()
            assert snapshot(f) == before and f.history == contacts and len(transport.connections) == count
    transport.complete()
    workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    return {"current_CAS_with_omitted_observation_refused": True,
        "current_CAS_with_old_real_policy_observation_refused": True, "writer_guard_no_HTTP": True}


def callbacks_and_recovery(_request):
    f = Fixture()
    transport = health_tests.HealthTransport(f, health_tests.health(f))
    with patch.object(f.store.http.client, "HTTPConnection", side_effect=transport.connect), \
            patch.object(f.oauth, "request_bytes", side_effect=f.provider), real_join_observer(f) as joins:
        f.begin()
        assert len(joins) == 1
        transport.document = {"ok": False}
        count = len(transport.connections)
        status, raw, _ = f.request("GET", consent_tests.INTENTS)
        assert status == 200 and json.loads(raw)["intents"][0]["id"] == f.started["operatorGoogleIntent"]["id"]
        assert f.consent.status("different-synthetic-actor")["intents"] == []
        assert len(transport.connections) == count
        code, _, _ = f.callback()
        assert code == 200 and len(joins) == 1
        core = f.connected()
        f.subject = core["metadata"]["provider_subject"]
        transport.document = health_tests.health(f)
        f.begin_reauthorization(core, [])
        assert len(joins) == 2
        operation = f.started["operatorGoogleReauthorization"]
        transport.document = {"ok": False}
        count, retained = len(transport.connections), snapshot(f)
        assert f.public(operation["operation_id"]) == operation
        assert f.lifecycle.status(operation["operation_id"], "different-synthetic-actor") is None
        assert snapshot(f) == retained and len(transport.connections) == count
        code, _, _ = f.callback()
        assert code == 200 and len(joins) == 2
        receipt = f.public(operation["operation_id"])
        assert receipt["status"] == "adopted"
        current = f.db.get_credential(core["id"], include_secret=True)
        assert current["credential_version"] == core["credential_version"] + 1
        assert json.loads(current["secret"])["refresh_token"] == reauth_tests.NEW_REFRESH
        assert current["metadata"]["provider_subject"] == core["metadata"]["provider_subject"]
        assert receipt["receipt"]["affected_rule_ids"] == []
        assert f.config.POLICY_BUNDLE_PATH.read_bytes() == f.policy
        assert len(f.provider_checks) == 4 and all(f.provider_checks)
        count, retained = len(f.history), snapshot(f)
        code, _, _ = f.callback()
        assert code == 400 and snapshot(f) == retained and len(f.history) == count
        assert f.public(operation["operation_id"]) == receipt and len(joins) == 2
    transport.complete()
    assert f.db.verify_audit_chain()["ok"] and not f.rows("oauth_revocation_work")
    return {"real_initial_and_reauthorization_callbacks": True,
        "gate_unavailable_does_not_strand_actor_owned_recovery": True, "callback_not_regated": True}


def legacy_off(_request):
    f = reauth_tests.Fixture()
    attempts = []

    def forbidden(*_args, **_kwargs):
        attempts.append(True)
        raise AssertionError("legacy start acquired a new managed health dependency")

    with patch.object(f.oauth, "request_bytes", side_effect=f.provider):
        with patch.object(f.store.http.client, "HTTPConnection", side_effect=forbidden):
            f.begin()
        # Existing optional catalog observations during callback are not new
        # consent admission. Keep them unavailable without opening any socket.
        with patch.object(f.store.http.client, "HTTPConnection", side_effect=ConnectionError("synthetic gate down")):
            assert f.callback()[0] == 200
        core = f.connected()
        f.subject = core["metadata"]["provider_subject"]
        with patch.object(f.store.http.client, "HTTPConnection", side_effect=forbidden):
            f.begin_reauthorization(core, [])
        assert f.started["operatorGoogleReauthorization"]["status"] == "awaiting_consent"
    assert attempts == [] and all(f.transport_checks)
    return {"legacy_initial_and_reauthorization_starts_unchanged": True, "new_health_requests": 0}


class ManagedConsentTests(unittest.TestCase):
    def setUp(self):
        managed_tests.ManagedGoogleConfigurationTests.setUp(self)
        self.environment.update({"CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST": health_tests.BINARY,
            "CATCHPLATE_DECISION_GATE_BASE": "http://127.0.0.1:9091", "CATCHPLATE_ADMIN_TOKEN": consent_tests.ADMIN})
        prepared = self.worker("prepare")
        self.worker("activate", prepared)

    def worker(self, name, request=None):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            input=json.dumps(request or {}), cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        self.assertNotIn(managed_tests.SECRET, result.stdout)
        return json.loads(result.stdout)

    def test_initial_consent_health_refusals_outer_EX_and_exact_ASGI_cookie(self):
        self.worker("admission_controls", {"reauthorization": False})

    def test_reauthorization_health_refusals_outer_EX_and_exact_ASGI_cookie(self):
        self.worker("admission_controls", {"reauthorization": True})

    def test_initial_and_reauthorization_local_CAS_drift_after_real_observation(self):
        self.worker("capture_to_cas_drift", {"reauthorization": False})
        self.worker("capture_to_cas_drift", {"reauthorization": True})

    def test_durable_reauthorization_current_CAS_cannot_omit_or_reuse_old_policy_observation(self):
        self.worker("durable_omitted_and_stale_observation")

    def test_callbacks_and_actor_owned_recovery_survive_gate_unavailability(self):
        self.worker("callbacks_and_recovery")


class LegacyConsentTests(unittest.TestCase):
    def setUp(self):
        consent_tests.OperatorGoogleConsentTests.setUp(self)
        self.environment.update({managed_tests.FLAG: "0", "CATCHPLATE_DECISION_GATE_BASE": "http://127.0.0.1:9091"})

    worker = ManagedConsentTests.worker

    def test_flag_off_initial_and_reauthorization_starts_need_no_health_HTTP(self):
        self.worker("legacy_off")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(managed_tests.no_network)
        actions = {function.__name__: function for function in (managed_tests.prepare, managed_tests.activate,
            admission_controls, capture_to_cas_drift, durable_omitted_and_stale_observation,
            callbacks_and_recovery, legacy_off)}
        result = actions[sys.argv[2]](json.loads(sys.stdin.read(131072)))
        assert managed_tests.NETWORK_ATTEMPTS == []
        print(json.dumps(result, sort_keys=True))
    else:
        unittest.main(verbosity=2)
