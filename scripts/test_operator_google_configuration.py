#!/usr/bin/env python3
"""Real managed configuration API, custody and cold-start discovery.

Execute only in the bounded network-none dependency harness. The full ASGI
app, admin/Origin/parser admission, publication locks, SQLite, provider key,
encrypted preparation and startup activation are real. Only gate HTTP transport
is synthetic; provider contact is forbidden. This is not live Google proof.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import uuid

import test_operator_google_consent as consent_tests
import test_operator_google_managed_config as managed_tests
import test_operator_google_managed_readiness_connected as health_tests
import test_operator_google_setup as legacy_tests
import test_operator_publication as coordination
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
PATH = "/api/operator-demo/oauth/google/configuration/v2"
SCHEMA = "catchplate.operatorGoogleConfiguration/v2"
FIELDS = {"schema", "state", "revision", "policy_hash", "effective_settings", "effective_settings_digest",
    "public_url", "redirect_uri", "permission_preset", "scopes", "review", "operation", "readiness", "blocked_reason"}
UNKNOWN = "synthetic-private-error-detail-must-not-be-public"


class Fixture(managed_tests.Fixture):
    def __init__(self):
        super().__init__()
        self.health_attempts = []
        self.health = self.unavailable

    def unavailable(self, host, port, *, timeout):
        self.health_attempts.append(True)
        assert (host, port, timeout) == ("127.0.0.1", 9091, 1)
        self.store.operator_publication.assert_not_held()
        raise ConnectionError("synthetic gate unavailable")

    def call(self, method, path=PATH, *, expected=200, **options):
        with patch.object(self.store.http.client, "HTTPConnection", side_effect=self.health), \
                patch.object(self.oauth, "request_bytes", side_effect=self.provider):
            code, raw, headers = self.request(method, path, **options)
        assert code == expected, (code, expected, raw)
        assert [value for name, value in headers if name.lower() == b"cache-control"] == [b"no-store"]
        assert not [value for name, value in headers if name.lower() == b"set-cookie"]
        public = raw + b"\n".join(name + b":" + value for name, value in headers)
        for secret in (managed_tests.SECRET, consent_tests.ADMIN, UNKNOWN):
            assert secret.encode() not in public
        assert not self.provider_calls
        value = json.loads(raw)
        assert type(value) is dict
        return value

    def payload(self, **changes):
        discovery = self.call("GET")
        review = discovery["review"]
        assert discovery["state"] == "unconfigured" and review["eligible"] is True
        return {key: review[key] for key in (
            "expected_revision", "expected_policy_hash", "expected_settings_digest")} | {
                "operation_id": str(uuid.uuid4()), "client_id": managed_tests.CLIENT,
                "client_secret": managed_tests.SECRET} | changes


def snapshot(f):
    path = f.oauth.OAUTH_STATE_PATH
    return managed_tests.raw_snapshot(), path.read_bytes() if path.exists() else None


def rejected(f, method, path=PATH, *, expected, **options):
    before = snapshot(f)
    value = f.call(method, path, expected=expected, **options)
    assert set(value) == {"detail"} and snapshot(f) == before
    return value


@contextmanager
def no_new_custody_reads(f):
    """Existing admitted key-pin checks remain real and are explicitly allowed."""
    attempts = []

    def forbidden(*_args, **_kwargs):
        attempts.append(True)
        raise AssertionError("public configuration initialized or decrypted custody")

    with patch.object(f.keys, "initialize_first", side_effect=forbidden), \
            patch.object(f.keys, "read_existing_pinned", side_effect=forbidden), \
            patch.object(f.custody, "read_secret", side_effect=forbidden), \
            patch.object(f.custody, "open_secret", side_effect=forbidden):
        yield
    assert attempts == []


def validate_discovery(f, value, state):
    assert set(value) == FIELDS and value["schema"] == SCHEMA and value["state"] == state
    assert value["public_url"] == f.config.PUBLIC_URL
    assert value["redirect_uri"] == f.config.PUBLIC_URL + f.profiles.CALLBACK_PATH
    assert value["permission_preset"] == f.profiles.PERMISSION_PRESET and value["scopes"] == list(f.profiles.SCOPES)
    assert value["revision"] == f.review()["expected_revision"]
    assert value["policy_hash"] == f.store.get_policy_high_water()["policy_hash"]
    assert value["effective_settings"] == {key: f.demo.settings()[key] for key in ("allowed_upstreams", "fixture_cidrs")}
    assert value["effective_settings_digest"] == f.setup._digest(value["effective_settings"])
    assert set(value["readiness"]) == {"pair_ready", "consent_ready", "loaded_policy_hash"}
    assert all(type(value["readiness"][key]) is bool for key in ("pair_ready", "consent_ready"))


def decrypt_exact(f, operation, secret):
    reference = operation["custody_ref"]
    owner = f.setup._admit_managed_owner(reference["owner_id"])
    admission = f.keys.admit_directory(os.environ[managed_tests.KEY_DIRECTORY], data_directory=f.config.DATA_DIR)
    pin = f.keys.read_existing_pinned(admission, owner.owner_id)
    try:
        binding = f.custody.bind_google(owner, config_version=reference["config_version"],
            public_profile=operation["profile_binding"])
        with closing(f.db.connect()) as conn:
            conn.execute("PRAGMA query_only=ON")
            conn.execute("BEGIN")
            assert f.custody.read_secret(conn, owner, binding, key=pin.material).secret == secret
            assert secret not in "\n".join(conn.iterdump())
    finally:
        f.keys.close_pin(pin)


def prepare_api(f, payload=None, *, padded=False):
    payload = f.payload() if payload is None else payload
    authority, settings, inserts = f.authority(), f.rows("operator_demo_settings"), []
    original = f.custody.insert_secret

    def insert(conn, owner, binding, **options):
        f.store.operator_publication.assert_held()
        assert conn.in_transaction
        assert not coordination.shared_probe(f.config.DATA_DIR / f.store.operator_publication.LOCK_NAME)
        original(conn, owner, binding, **options)
        inserts.append((owner.owner_id, binding.config_version))

    body = payload
    if padded:
        raw = json.dumps(payload).encode()
        assert len(raw) < 8192
        body = raw + b" " * (8192 - len(raw))
    with patch.object(f.custody, "insert_secret", side_effect=insert):
        operation = f.call("POST", body=body, expected=201)
    assert operation["schema"] == f.setup.MANAGED_PUBLIC_V2
    assert operation["setup_contract"] == f.setup.MANAGED_BINDING_V2
    assert operation["custody_ref"]["key_source"] == "operator-provider-key-v1"
    assert inserts == [(operation["custody_ref"]["owner_id"], operation["custody_ref"]["config_version"])]
    assert operation["operation_id"] == payload["operation_id"] and operation["status"] == "pending"
    assert operation["revision"] == operation["staged_revision"] == payload["expected_revision"] + 1
    assert operation["activation_receipt"] is None and operation["secret_present"] is True
    assert f.authority() == authority and f.rows("operator_demo_settings") == settings
    assert f.selected() == operation and not f.profiles.selected()
    assert f.config.GOOGLE_OAUTH_CLIENT_ID == f.config.GOOGLE_OAUTH_CLIENT_SECRET == ""
    assert not (f.config.DATA_DIR / "master.key").exists()
    decrypt_exact(f, operation, payload["client_secret"])
    before = snapshot(f)
    with no_new_custody_reads(f):
        assert f.call("GET", PATH + "/" + payload["operation_id"]) == operation
        discovery = f.call("GET")
    validate_discovery(f, discovery, "pending")
    assert discovery["operation"] == operation and discovery["review"] is None
    assert discovery["blocked_reason"] == "pending_configuration" and not discovery["readiness"]["consent_ready"]
    assert snapshot(f) == before
    return operation


def empty_and_admission(_request):
    f = Fixture()
    before = snapshot(f)
    with no_new_custody_reads(f):
        value = f.call("GET", origin=False)
        validate_discovery(f, value, "unconfigured")
        assert value["operation"] is None and value["blocked_reason"] is None and value["review"]["eligible"]
        assert not value["readiness"]["consent_ready"]
    assert snapshot(f) == before and managed_tests.key_evidence() == {}
    with closing(f.db.connect()) as conn:
        assert not conn.execute("SELECT name FROM sqlite_master WHERE name IN (?,?,?,?)", (
            f.setup.TABLE, f.selection.TABLE, f.custody.TABLE, f.custody.META)).fetchall()
    payload = f.payload()
    failures = (
        (payload, {"auth": False}, 401), (payload, {"origin": False}, 403),
        (payload, {"headers": (("Origin", "https://different.example.com"),)}, 403),
        ({**payload, "unexpected": UNKNOWN}, {}, 422),
        ({**payload, "client_secret": 123}, {}, 422),
        ({**payload, "client_secret": "x" * 4097}, {}, 422),
        ({**payload, "expected_revision": True}, {}, 422),
        ({**payload, "client_id": "invalid"}, {}, 422),
        ({**payload, "operation_id": "10000000-0000-4000-8000-00000000000A"}, {}, 422),
        (b'{"client_secret":"first","client_secret":"second"}', {}, 422),
        (b"[]", {}, 422), (b"{" + UNKNOWN.encode(), {}, 422), (b" " * 8193, {}, 413),
        (payload, {"headers": (("Content-Encoding", "identity"),)}, 415),
        (payload, {"headers": (("Content-Type", "application/json"),)}, 415),
        # Full application's framing middleware rejects this before the router.
        (payload, {"headers": (("Content-Length", "0"),)}, 400),
    )
    for body, options, expected in failures:
        rejected(f, "POST", body=body, expected=expected, **options)
    for path, options, expected in (
            (PATH, {"auth": False}, 401), (PATH + "?unexpected=1", {}, 422),
            (PATH, {"body": {}}, 400), (PATH + "/not-a-uuid", {}, 422),
            (PATH + "/" + str(uuid.uuid4()), {}, 404)):
        rejected(f, "GET", path, expected=expected, **options)
    actual_app = f.app
    for declared in (None, b"0"):
        async def request_without_length(scope, receive, send):
            headers = [(name, value) for name, value in scope["headers"] if name.lower() != b"content-length"]
            if declared is not None:
                headers.append((b"content-length", declared))
            await actual_app.app({**scope, "headers": headers}, receive, send)

        # Test client transport only: exact application and body bytes remain.
        f.app = SimpleNamespace(app=request_without_length)
        try:
            rejected(f, "GET", body=b"{}", expected=400)
        finally:
            f.app = actual_app
    assert managed_tests.key_evidence() == {} and snapshot(f) == before
    return {"empty_discovery_no_key_or_schema_creation": True, "strict_ASGI_refusals": len(failures) + 7,
        "pre_router_no_store": True, "secret_safe_errors": True}


def prepare_cancel_reprepare(_request):
    f = Fixture()
    operation = prepare_api(f, padded=True)
    key = managed_tests.key_evidence()
    with no_new_custody_reads(f):
        cancelled = f.call("POST", PATH + "/cancel", body={**f.review(), "operation_id": operation["operation_id"]})
        assert cancelled["status"] == "cancelled" and f.selected() is None
        assert f.call("GET", PATH + "/" + operation["operation_id"]) == cancelled
        discovery = f.call("GET")
    validate_discovery(f, discovery, "unconfigured")
    assert discovery["operation"] is None and discovery["review"]["eligible"]
    second = prepare_api(f, f.payload(client_secret=managed_tests.SECRET + "-second"))
    assert second["custody_ref"] == {**operation["custody_ref"], "config_version": 2}
    assert managed_tests.key_evidence() == key
    return {"operation": second, "secret_suffix": "-second"}


def cas_and_replay(_request):
    f = Fixture()
    payload = f.payload()
    for changes in ({"expected_revision": payload["expected_revision"] + 1},
            {"expected_policy_hash": "sha256:" + "0" * 64}, {"expected_settings_digest": "sha256:" + "0" * 64}):
        rejected(f, "POST", body={**payload, **changes}, expected=409)
    operation = prepare_api(f, payload)
    rejected(f, "POST", body=payload, expected=409)
    rejected(f, "POST", body={**payload, **f.review(), "operation_id": str(uuid.uuid4())}, expected=409)
    cancel = {**f.review(), "operation_id": operation["operation_id"]}
    for changes, options, expected in (({}, {"auth": False}, 401), ({}, {"origin": False}, 403),
            ({"expected_revision": cancel["expected_revision"] - 1}, {}, 409),
            ({"client_secret": managed_tests.SECRET}, {}, 422)):
        rejected(f, "POST", PATH + "/cancel", body={**cancel, **changes}, expected=expected, **options)
    rejected(f, "POST", PATH + "/cancel", body=b" " * 2049, expected=413)
    f.call("POST", PATH + "/cancel", body=cancel)
    rejected(f, "POST", body={**f.payload(), "operation_id": operation["operation_id"]}, expected=409)
    rejected(f, "POST", PATH + "/cancel", body={**f.review(), "operation_id": operation["operation_id"]}, expected=409)
    return {"stale_review_and_UUID_replay_refused": True, "cancel_admission_checked": True}


def audit_rollback(_request):
    f = Fixture()
    payload = f.payload()
    with closing(f.db.connect()) as conn, conn:
        conn.execute("CREATE TRIGGER configuration_api_abort BEFORE INSERT ON audit_events "
            "WHEN NEW.event_type='operator_catalog.google_setup.prepared' "
            "BEGIN SELECT RAISE(ABORT,'synthetic-private-error-detail-must-not-be-public'); END")
    before = f.snapshot()
    value = f.call("POST", body=payload, expected=503)
    assert set(value) == {"detail"} and f.snapshot() == before and f.selected() is None
    orphan = managed_tests.key_evidence()
    assert set(orphan) == {f.keys.FILENAME}
    with closing(f.db.connect()) as conn, conn:
        assert not conn.execute("SELECT name FROM sqlite_master WHERE name IN (?,?,?,?)", (
            f.setup.TABLE, f.selection.TABLE, f.custody.TABLE, f.custody.META)).fetchall()
        conn.execute("DROP TRIGGER configuration_api_abort")
    operation = prepare_api(f)  # Explicit new operation after proven rollback.
    assert managed_tests.key_evidence() == orphan
    return {"actual_audit_rollback": True, "explicit_new_prepare_reuses_owned_orphan": True,
        "operation": operation}


def lost_ack(_request):
    f = Fixture()
    payload = f.payload()
    authority, original, committed = f.authority(), sqlite3.connect, []
    event = "operator-google-setup:" + payload["operation_id"] + ":prepared"

    class LostAcknowledgement(sqlite3.Connection):
        def commit(self):
            found = self.in_transaction and self.execute("SELECT id FROM audit_events WHERE id=?", (event,)).fetchone()
            if found and not committed:
                super().commit()
                committed.append(True)
                raise OSError(UNKNOWN)
            return super().commit()

    def connect(*args, **kwargs):
        assert "factory" not in kwargs
        return original(*args, factory=LostAcknowledgement, **kwargs)

    with patch.object(sqlite3, "connect", side_effect=connect):
        f.call("POST", body=payload, expected=503)
    assert committed == [True] and f.authority() == authority
    before = snapshot(f)
    with no_new_custody_reads(f):
        operation = f.call("GET", PATH + "/" + payload["operation_id"])
        assert f.call("GET", PATH + "/" + payload["operation_id"]) == operation
    assert operation["status"] == "pending" and operation == f.selected() and snapshot(f) == before
    decrypt_exact(f, operation, managed_tests.SECRET)
    rejected(f, "POST", body=payload, expected=409)
    with closing(f.db.connect()) as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_events WHERE id=?", (event,)).fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM " + f.setup.TABLE).fetchone()[0] == 1
    return {"actual_commit_lost_ack_HTTP503": True, "exact_UUID_GET_without_replay": True}


def receipt_isolation(request):
    f = Fixture()
    payload = f.payload()
    if request["legacy"]:
        # A real legacy owner writes its own v1 receipt in this unselected
        # runtime. The new routes must not expose or cancel that namespace.
        actor = f.auth.require_admin(SimpleNamespace(headers={}, cookies={}), consent_tests.ADMIN).user_id
        operation = f.setup.prepare({key: value for key, value in payload.items() if key != "client_secret"}, actor)
        assert operation["schema"] == "catchplate.operatorGoogleSetup/v1"
    else:
        operation = f.setup.prepare_configuration(payload, "different-synthetic-administrator")
        with no_new_custody_reads(f):
            discovery = f.call("GET")
        validate_discovery(f, discovery, "pending")
        assert discovery["operation"] is None and operation["operation_id"] not in json.dumps(discovery)
    with no_new_custody_reads(f):
        rejected(f, "GET", PATH + "/" + operation["operation_id"], expected=404)
        rejected(f, "POST", PATH + "/cancel", body={**f.review(), "operation_id": operation["operation_id"]}, expected=404)
    return {"legacy_v1": request["legacy"], "lookup_and_cancel_refused_without_writes": True}


def prepare_single(_request):
    f = Fixture()
    return {"operation": prepare_api(f)}


def activated_discovery(request):
    f = Fixture()  # Actual fresh bootstrap and activation, no profile guard patch.
    expected = request["operation"]
    assert f.profiles.require_profile().client_id == expected["client_id"]
    assert f.config.GOOGLE_OAUTH_CLIENT_SECRET == managed_tests.SECRET + request.get("secret_suffix", "")
    operation = f.call("GET", PATH + "/" + expected["operation_id"])
    assert operation["status"] == "activated" and f.selected() == operation
    assert operation["activation_receipt"]["operation_id"] == expected["operation_id"]
    transport = health_tests.HealthTransport(f, health_tests.health(f))
    f.health = transport.connect
    before = snapshot(f)
    with no_new_custody_reads(f):
        discovery = f.call("GET")
        validate_discovery(f, discovery, "activated")
        assert discovery["operation"] == operation and discovery["review"] is None
        assert discovery["blocked_reason"] == "already_configured"
        assert discovery["readiness"] == {"pair_ready": True, "consent_ready": True,
            "loaded_policy_hash": discovery["policy_hash"]}
        exact = deepcopy(transport.document)
        for field in ("operation", "binary", "settings"):
            transport.document = deepcopy(exact)
            if field == "operation":
                transport.document["policy_shadow"]["managed_google"]["operation"]["operation_id"] = str(uuid.uuid4())
            elif field == "binary":
                transport.document["data_plane_binary_digest"] = "sha256:" + "8" * 64
            else:
                transport.document["policy_shadow"]["managed_google"]["effective_settings_digest"] = "sha256:" + "0" * 64
            refused = f.call("GET")
            assert refused["operation"] == operation and refused["state"] == "activated"
            assert not refused["readiness"]["pair_ready"] and not refused["readiness"]["consent_ready"]
        transport.document = {"ok": False}
        assert f.call("GET")["readiness"] == {"pair_ready": False, "consent_ready": False, "loaded_policy_hash": None}
    transport.complete(expected=5)
    assert snapshot(f) == before
    workspace.verify_signed(f.config, f.db, f.store, f.bundles)
    return {"operation": operation, "discovery": discovery, "authority": f.retained(), "audit": f.rows("audit_events")}


def external_off(_request):
    runtime = legacy_tests.Fixture()  # Real externally configured legacy startup.
    assert runtime.profiles.selected()
    # Reuse only the request assertions, not a managed constructor/admission.
    f = Fixture.__new__(Fixture)
    f.__dict__.update(vars(runtime))
    f.health_attempts, f.health = [], f.unavailable
    before = runtime.snapshot()
    identifier = str(uuid.uuid4())
    for method, path, body in (("GET", PATH, None), ("GET", PATH + "/" + identifier, None),
            ("POST", PATH, {}), ("POST", PATH + "/cancel", {})):
        f.call(method, path, body=body, expected=404)
        assert runtime.snapshot() == before
    assert f.health_attempts == [] and not f.provider_calls
    return {"flag_off_external_profile_preserved": True, "no_new_storage_or_health_requests": True}


class GoogleConfigurationTests(unittest.TestCase):
    def setUp(self):
        managed_tests.ManagedGoogleConfigurationTests.setUp(self)
        self.environment.update({"CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST": health_tests.BINARY,
            "CATCHPLATE_DECISION_GATE_BASE": "http://127.0.0.1:9091"})

    def worker(self, name, request=None, *, changes=None):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            input=json.dumps(request or {}), cwd=ROOT, env={**self.environment, **(changes or {})},
            capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-45:]))
        self.assertNotIn(managed_tests.SECRET, result.stdout)
        return json.loads(result.stdout)

    def test_empty_discovery_and_full_ASGI_admission_are_inert_and_secret_safe(self):
        self.worker("empty_and_admission")

    def test_real_encrypted_prepare_cancel_reprepare_and_cold_activation(self):
        prepared = self.worker("prepare_cancel_reprepare")
        self.worker("activated_discovery", prepared)

    def test_stale_CAS_replay_and_cancel_admission_preserve_retained_state(self):
        self.worker("cas_and_replay")

    def test_actual_audit_failure_rolls_back_SQL_and_retains_reusable_owned_key(self):
        self.worker("audit_rollback")

    def test_lost_POST_ack_after_real_commit_recovers_exact_UUID_by_GET(self):
        self.worker("lost_ack")

    def test_foreign_actor_and_real_legacy_v1_receipt_are_not_exposed_or_cancelled(self):
        self.worker("receipt_isolation", {"legacy": False})
        data, provider = Path(self.scratch.name) / "legacy-data", Path(self.scratch.name) / "legacy-provider"
        data.mkdir(mode=0o700)
        provider.mkdir(mode=0o700)
        self.worker("receipt_isolation", {"legacy": True}, changes={"CATCHPLATE_DATA_DIR": str(data),
            managed_tests.KEY_DIRECTORY: str(provider)})

    def test_activated_discovery_exact_pair_and_stale_health_survive_second_restart(self):
        prepared = self.worker("prepare_single")
        first = self.worker("activated_discovery", prepared)
        self.assertEqual(self.worker("activated_discovery", prepared), first)


class ExternalGoogleConfigurationTests(unittest.TestCase):
    def setUp(self):
        consent_tests.OperatorGoogleConsentTests.setUp(self)
        self.environment.update({managed_tests.FLAG: "0", "CATCHPLATE_DECISION_GATE_BASE": "http://127.0.0.1:9091"})

    worker = GoogleConfigurationTests.worker

    def test_flag_off_external_profile_has_no_configuration_API_storage_side_effects(self):
        self.worker("external_off")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(managed_tests.no_network)
        actions = {function.__name__: function for function in (empty_and_admission, prepare_cancel_reprepare,
            cas_and_replay, audit_rollback, lost_ack, receipt_isolation, prepare_single, activated_discovery, external_off)}
        result = actions[sys.argv[2]](json.loads(sys.stdin.read(131072)))
        assert managed_tests.NETWORK_ATTEMPTS == []
        print(json.dumps(result, sort_keys=True))
    else:
        unittest.main(verbosity=2)
