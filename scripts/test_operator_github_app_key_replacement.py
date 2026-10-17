#!/usr/bin/env python3
"""Connected GitHub App replacement controls; no live GitHub/proxy acceptance.

Cold workers use real operator admission, SQLite ownership, envelope encryption,
signed policy and (one story) the complete ASGI application. Only fixed GitHub
HTTP transport is synthetic; both App JWT keys are genuinely generated RSA and
every JWT is verified by that transport. Failure injection never grants access.
"""
from __future__ import annotations

import asyncio
import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "scripts")]
import test_operator_catalog_github_app as existing

workspace = existing.workspace
require, refused = existing.require, existing.refused
ACTOR, ADMIN, ORIGIN = existing.ACTOR, existing.ADMIN, existing.ORIGIN
PATH = "/api/operator-demo/credentials/github-app/replace-key"
EVENT = "operator_catalog.credential.github_app_key_replaced"
MAX_SAFE = 9_007_199_254_740_991


class Fixture(existing.Fixture):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        self.next_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.next_pem = self.next_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode("ascii")
        self.next_provider = existing.Provider(self.next_key)
        # Distinct token strings make accidental reuse visible, not just two
        # successful signatures over keys that happen to share a token value.
        self.next_provider.tokens.extend(("synthetic-unused-next-provider-token-1",
            "synthetic-unused-next-provider-token-2"))
        self.identifier = None

    def install(self, *, shared=False):
        with self.transport():
            credential = self.create()["credential"]
        self.identifier = credential["id"]
        self.routes = []
        if shared:
            for bundle in (existing.legacy.READ, existing.legacy.WRITE):
                app = self.application()
                self.routes.append(self.rule(app, credential, bundle=bundle)["access_rule"])
        return credential

    def next_transport(self):
        from catchplate import github_app
        return patch.object(github_app.http_client, "request_bytes", self.next_provider)

    def core(self, connection=None):
        if connection is None:
            with closing(self.db.connect()) as conn:
                return self.core(conn)
        return dict(connection.execute("SELECT * FROM credentials WHERE id=?", (self.identifier,)).fetchone())

    def fields_replace(self, **changes):
        return {**self.review(), "id": self.identifier,
            "expected_credential_generation": self.core()["credential_version"],
            "private_key_pem": self.next_pem, **changes}

    def replace(self, payload=None):
        value = payload if payload is not None else self.fields_replace()
        return self.mutations.replace_github_app_key(self.inputs.ReplaceGithubAppKeyInput(**value), ACTOR)

    def secret_is(self, pem):
        current = self.db.get_credential(self.identifier, include_secret=True)
        private = json.loads(current["secret"])
        require(private["private_key_pem"] == pem, "retained encrypted App key differs")

    def clean(self, value):
        super().clean(value)
        if not hasattr(self, "next_pem"):
            return
        raw = value if type(value) is bytes else json.dumps(value, sort_keys=True).encode()
        sensitive = [self.next_pem, *self.next_pem.splitlines()[1:-1],
            *self.next_provider.tokens, *self.next_provider.jwts]
        require(all(secret.encode() not in raw for secret in sensitive), "replacement private material disclosed")

    def runtime(self):
        compiled = self.bundles.compile_policy_bundle(self.signed(), verify_signature=True, validate_schema=True)
        return (next(item for item in compiled.routes if item.id == self.routes[0]["route_id"]),
            compiled.credentials[self.identifier])


def replacement_success():
    from catchplate import operator_github_app as owner
    f = Fixture()
    f.install(shared=True)
    before, core, catalog = f.snapshot(), f.core(), f.catalog()
    prior_events = workspace.rows(f.db, "audit_events")
    real = f.db.replace_operator_github_app_credential_if_version
    calls = []

    def observe(conn, identifier, **arguments):
        require(type(conn) is sqlite3.Connection and conn.in_transaction, "replacement lacks actual transaction")
        f.store.operator_publication.assert_held()
        calls.append(identifier)
        return real(conn, identifier, **arguments)

    with f.next_transport(), patch.object(f.db, "replace_operator_github_app_credential_if_version", observe), \
            patch.object(f.db, "decrypt_secret_envelope", side_effect=AssertionError("old key decrypt attempted")):
        result = f.replace()
    current, retained, after = f.core(), f.catalog(), f.snapshot()
    require(calls == [f.identifier] and current["credential_version"] == 2, "actual helper/generation")
    for key in ("id", "name", "kind", "metadata", "created_at", "lifecycle_status"):
        require(current[key] == core[key], "credential identity changed")
    require(current["secret_ciphertext"] != core["secret_ciphertext"]
        and current["secret_nonce"] != core["secret_nonce"], "replacement was not freshly encrypted")
    require(retained["revision"] == catalog["revision"] + 1
        and retained["applications"] == catalog["applications"]
        and retained["access_rules"] == catalog["access_rules"], "replacement changed assignments")
    old, new = catalog["credentials"][0], retained["credentials"][0]
    require(new["version"] == old["version"] + 1 and new["key_replaced_at"]
        and {k: v for k, v in new.items() if k not in {"version", "key_replaced_at"}} ==
            {k: v for k, v in old.items() if k not in {"version", "key_replaced_at"}}, "public binding drift")
    require(after[1:] == before[1:] and after[0]["operator_demo_policy"] == before[0]["operator_demo_policy"],
        "replacement changed signed policy or high water")
    require(result["key_replacement"] == {"previous_credential_generation": 1, "credential_generation": 2,
        "cache_invalidation": "local_completed", "in_flight_requests": "not_recalled"}, "replacement receipt")
    events = workspace.rows(f.db, "audit_events")[len(prior_events):]
    require(len(events) == 1 and events[0]["event_type"] == EVENT and events[0]["actor_id"] == ACTOR,
        "one actual replacement audit")
    event = json.loads(events[0]["event_json"])
    require(event["resource_id"] == f.identifier and event["credential_generation"] == 2
        and event["previous_credential_generation"] == 1, "audit generation binding")
    floor = next(row for row in workspace.rows(f.db, "credential_generations") if row["credential_id"] == f.identifier)
    require(floor["last_version"] == 2, "durable monotonic generation floor")
    require(f.next_provider.calls == ["installation", "mint-id", "repositories"], "replacement lost numeric pins")
    f.secret_is(f.next_pem)
    route, policy = f.runtime()
    with f.next_transport():
        public = f.db.get_credential(f.identifier, include_secret=False)
        owner.prepare_dispatch_token(public, route, policy)
        with f.db.credential_generation_snapshot(f.identifier) as locked:
            token = owner.cached_dispatch_token(locked, route, policy)
    require(token == f.next_provider.tokens[-1] and token != f.provider.tokens[-1]
        and len(f.next_provider.calls) == 3, "postcommit cache did not use the verified replacement token")
    f.clean(result)
    f.storage_clean()
    return {"two_assignments_preserved": True, "real_rsa_keys": 2, "no_old_decrypt": True, "generation": 2}


def admission_controls():
    from pydantic import ValidationError
    f = Fixture()
    f.install()
    stale = f.fields_replace()
    f.application()
    before = f.snapshot()
    with f.next_transport():
        refused(lambda: f.replace(stale), f.schema.CatalogConflict)
        for change in ({"expected_credential_generation": 2}, {"expected_policy_hash": "sha256:" + "0" * 64}):
            refused(lambda: f.replace(f.fields_replace(**change)), f.schema.CatalogConflict)
        refused(lambda: f.replace(f.fields_replace(id=str(uuid.uuid4()))), f.mutations.CatalogNotFound)
        for generation in (True, 0, -1, 1.0, "1", MAX_SAFE):
            refused(lambda: f.replace(f.fields_replace(expected_credential_generation=generation)), ValidationError)
        refused(lambda: f.replace(f.fields_replace(private_key_pem="not-a-private-key")), (ValidationError, ValueError))
    require(f.snapshot() == before and not f.next_provider.calls, "preflight refusal contacted provider or wrote state")
    static = f.mutations.create_github_credential(f.inputs.GithubTokenInput(**f.review(),
        name="Retained PAT", secret=existing.legacy.TOKEN), ACTOR)["credential"]
    with f.next_transport():
        refused(lambda: f.replace(f.fields_replace(id=static["id"])), f.schema.CatalogConflict)
        f.mutations.revoke_credential(f.target(f.identifier), ACTOR)
        retained = f.snapshot()
        payload = {**f.review(), "id": f.identifier, "expected_credential_generation": 1,
            "private_key_pem": f.next_pem}
        refused(lambda: f.replace(payload), f.schema.CatalogConflict)
    require(f.snapshot() == retained and not f.next_provider.calls, "wrong-kind/revoked input reached provider")
    return {"pre_provider_refusals": True, "strict_generation": True, "wrong_kind_and_revoked": True}


def provider_and_audit_rollback():
    from catchplate import operator_github_app as owner
    f = Fixture()
    f.install(shared=True)
    before = f.snapshot()
    # The old provider genuinely verifies with the old RSA public key. A
    # candidate signed with the new key cannot pass this cryptographic oracle.
    with f.transport():
        refused(f.replace, owner.GitHubAppUnavailable)
    require(f.snapshot() == before, "rejected App JWT changed retained state")
    f.next_provider.installation_changes = {"app_id": existing.APP_ID + 1}
    with f.next_transport():
        refused(f.replace, owner.GitHubAppUnavailable)
    require(f.snapshot() == before and f.next_provider.calls == ["installation"], "binding refusal changed state")
    f.next_provider.installation_changes = {}
    with closing(f.db.connect()) as conn, conn:
        conn.execute("CREATE TRIGGER app_key_audit_abort BEFORE INSERT ON audit_events WHEN NEW.event_type='" +
            EVENT + "' BEGIN SELECT RAISE(ABORT,'synthetic App key audit refusal'); END")
    before = f.snapshot()
    with f.next_transport(), patch.object(owner, "seed_committed", side_effect=AssertionError("precommit seed")) as seed:
        refused(f.replace, sqlite3.IntegrityError)
    require(seed.call_count == 0 and f.snapshot() == before and f.core()["credential_version"] == 1,
        "failed audit did not roll back ciphertext/catalog/generation")
    f.secret_is(f.pem)
    f.storage_clean()
    return {"wrong_binding_refused": True, "audit_failure_atomic": True}


def final_cas_race():
    f = Fixture()
    f.install()
    core = f.core()
    intervened = []

    def intervening_writer():
        f.store.operator_publication.assert_not_held()
        f.application()
        intervened.append(f.snapshot())

    f.next_provider.before_listing = intervening_writer
    with f.next_transport():
        refused(f.replace, f.schema.CatalogConflict)
    require(len(intervened) == 1 and f.snapshot() == intervened[0] and f.core() == core,
        "final CAS discarded or overwrote concurrent application")
    require(f.next_provider.calls == ["installation", "mint-id", "repositories"], "candidate validation sequence")
    f.secret_is(f.pem)
    f.storage_clean()
    return {"provider_outside_lock": True, "candidate_discarded_after_cas": True}


def generation_guards():
    from catchplate import operator_github_app as owner
    f = Fixture()
    credential = f.install()
    with f.next_transport():
        prepared = owner.verify_replacement(credential["github_app"], f.next_pem)
    helper = f.db.replace_operator_github_app_credential_if_version
    before = f.snapshot()
    for statement, arguments in (
            ("UPDATE credential_generations SET last_version=2 WHERE credential_id=?", (f.identifier,)),
            ("DELETE FROM credential_generations WHERE credential_id=?", (f.identifier,)),
            ("UPDATE credentials SET credential_version=? WHERE id=?", (MAX_SAFE, f.identifier))):
        with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(statement, arguments)
            changes = conn.total_changes
            refused(lambda: helper(conn, f.identifier, expected_version=1, secret=prepared.secret), f.db.MetadataStoreError)
            require(conn.total_changes == changes, "refused ledger check wrote rows")
            conn.rollback()
        require(f.snapshot() == before, "rolled back corruption control changed retained state")
    with closing(f.db.connect()) as conn:
        conn.execute("BEGIN IMMEDIATE")
        refused(lambda: helper(conn, f.identifier, expected_version=1, secret=prepared.secret),
            f.store.operator_publication.PublicationError)
        conn.rollback()
    with f.store.operator_publication.exclusive(), closing(f.db.connect()) as conn:
        refused(lambda: helper(conn, f.identifier, expected_version=1, secret=prepared.secret), f.db.MetadataStoreError)
    require(f.snapshot() == before, "ownership refusal changed retained state")
    return {"floor_missing_drift_overflow": 3, "ownership_refusals": 2}


def postcommit_failure():
    from catchplate import operator_github_app as owner, runtime
    f = Fixture()
    f.install(shared=True)
    before = f.snapshot()
    with f.next_transport(), patch.object(owner, "seed_committed", side_effect=RuntimeError("synthetic seed refusal")), \
            patch.object(runtime, "invalidate_secret_leases", side_effect=RuntimeError("synthetic eviction refusal")):
        result = f.replace()
    require(f.core()["credential_version"] == 2 and result["credential"]["credential_generation"] == 2
        and result["key_replacement"]["cache_invalidation"] == "local_unconfirmed", "committed failure hidden as rollback")
    require(len(f.snapshot()[0]["audit_events"]) == len(before[0]["audit_events"]) + 1
        and f.snapshot()[1:] == before[1:], "postcommit failure changed durable replacement semantics")
    f.secret_is(f.next_pem)
    f.clean(result)
    # Independent new App-cache failure: the standard runtime eviction really
    # succeeds. Replacing with the same valid key still advances generation.
    invalidations = []
    real_invalidate = runtime.invalidate_secret_leases

    def invalidated(identifier):
        real_invalidate(identifier)
        invalidations.append(identifier)

    with f.next_transport(), patch.object(runtime, "invalidate_secret_leases", side_effect=invalidated), \
            patch.object(owner, "forget", side_effect=RuntimeError("synthetic App cache refusal")):
        second = f.replace()
    require(invalidations == [f.identifier] and f.core()["credential_version"] == 3
        and second["key_replacement"] == {"previous_credential_generation": 2, "credential_generation": 3,
            "cache_invalidation": "local_unconfirmed", "in_flight_requests": "not_recalled"},
        "App forget failure misreported committed replacement")
    require(len(f.snapshot()[0]["audit_events"]) == len(before[0]["audit_events"]) + 2
        and f.snapshot()[1:] == before[1:], "App cache failure changed durable policy or audit")
    f.secret_is(f.next_pem)
    f.clean(second)
    f.storage_clean()
    return {"committed_despite_cache_fault": True, "receipt_unconfirmed": True, "independent_app_cache_fault": True}


def stale_refresh_and_reopen():
    from catchplate import operator_github_app as owner
    f = Fixture()
    f.install(shared=True)
    route, policy = f.runtime()
    old = f.db.get_credential(f.identifier, include_secret=False)
    owner.forget(f.identifier)
    replacements = []

    def replace_during_old_refresh():
        with f.next_transport():
            replacements.append(f.replace())

    f.provider.before_listing = replace_during_old_refresh
    with f.transport():
        refused(lambda: owner.prepare_dispatch_token(old, route, policy), owner.GitHubAppUnavailable)
    require(len(replacements) == 1 and f.core()["credential_version"] == 2, "old refresh raced no genuine replacement")
    refused(lambda: owner.cached_dispatch_token(old, route, policy), owner.GitHubAppUnavailable)
    with f.db.credential_generation_snapshot(f.identifier) as locked:
        token = owner.cached_dispatch_token(locked, route, policy)
    require(token == f.next_provider.tokens[-1] and token not in f.provider.tokens, "stale refresh escaped generation fence")
    before = f.snapshot()
    environment = dict(os.environ, REPLACEMENT_ID=f.identifier,
        REPLACEMENT_PEM_SHA256=hashlib.sha256(f.next_pem.encode()).hexdigest())
    restarted = subprocess.run([sys.executable, "-B", __file__, "--worker", "reopen"],
        cwd=ROOT, env=environment, capture_output=True, text=True, timeout=30)
    require(restarted.returncode == 0 and restarted.stdout.strip() == '{"reopened_generation": 2}',
        "fresh process did not reopen actual encrypted replacement")
    require(f.snapshot() == before, "fresh reader changed durable records")
    f.storage_clean()
    return {"stale_refresh_refused": True, "fresh_process_retained_generation": 2}


def reopen_worker():
    config, db, store, bundles, schema, inputs, mutations = workspace.workspace()
    credential = db.get_credential(os.environ["REPLACEMENT_ID"], include_secret=True)
    require(credential["credential_version"] == 2
        and hashlib.sha256(json.loads(credential["secret"])["private_key_pem"].encode()).hexdigest()
            == os.environ["REPLACEMENT_PEM_SHA256"], "fresh process encrypted key retention")
    workspace.verify_signed(config, db, store, bundles)
    require(not existing.NETWORK_ATTEMPTS, "fresh process contacted network")
    return {"reopened_generation": 2}


async def api_story():
    from test_operator_catalog_body_routing import BodyTransport
    f = Fixture(full_startup=True)
    from catchplate import app as application
    from catchplate import operator_catalog_api as api
    app = BodyTransport(application.app, ADMIN)

    async def call(method, path, body=None, *, status=200, authenticate=True, origin=ORIGIN, media="application/json"):
        raw = b"" if body is None else body if type(body) is bytes else json.dumps(body).encode()
        headers = [] if body is None else [("origin", origin), ("content-type", media), ("content-length", str(len(raw)))]
        result = await app.request(method, path, headers, raw, authenticate=authenticate)
        require(result["status"] == status, "full ASGI replacement status")
        require({key.lower(): value for key, value in result["headers"]}.get("cache-control") == "no-store",
            "replacement response cache contract")
        public = base64.b64decode(result["body_b64"], validate=True)
        f.clean(public)
        return json.loads(public)

    await app.start()
    try:
        with f.transport():
            saved = await call("POST", existing.PATH, f.fields(), status=201)
        f.identifier = saved["credential"]["id"]
        before = f.snapshot()
        catalog = await call("GET", "/api/operator-demo/catalog")
        require(catalog["capabilities"]["github_app_key_replacement"] == {
            "schema": "catchplate.operatorGithubAppKeyReplacement/v1", "path": PATH},
            "dedicated replacement capability")
        with f.next_transport():
            with patch.object(api, "_payload", wraps=api._payload) as parser:
                for options, expected in (({"authenticate": False}, 401),
                        ({"origin": "https://foreign.example.com"}, 403)):
                    status, public, delivered = await app.post(path=PATH, stall=True, **options)
                    require(status == expected and delivered == 0 and parser.await_count == 0,
                        "authentication/origin did not precede body parser")
                    f.clean(public)
            await call("POST", PATH, f.fields_replace(), media="text/plain", status=415)
            await call("POST", PATH, f.fields_replace(private_key_pem="not-key"), status=422)
            await call("POST", PATH, b"x" * 32769, status=413)
            await call("POST", PATH, f.fields_replace(expected_credential_generation=2), status=409)
            require(not f.next_provider.calls and f.snapshot() == before, "API admission touched provider or state")
            f.next_provider.installation_changes = {"app_id": existing.APP_ID + 1}
            await call("POST", PATH, f.fields_replace(), status=503)
            require(f.snapshot() == before, "provider error changed retained key")
            f.next_provider.installation_changes = {}
            original = f.fields_replace()
            result = await call("POST", PATH, original)
            require(result["credential"]["id"] == f.identifier
                and result["credential"]["credential_generation"] == 2, "API replacement receipt binding")
            committed, provider_count = f.snapshot(), len(f.next_provider.calls)
            await call("POST", PATH, original, status=409)
            await call("GET", "/api/operator-demo/catalog")
            require(f.snapshot() == committed and len(f.next_provider.calls) == provider_count,
                "replayed API operation or GET contacted provider")
        f.secret_is(f.next_pem)
        f.storage_clean()
        return {"full_asgi": True, "redacted_errors": True, "admission_statuses": [401, 403, 415, 422, 413, 409, 503]}
    finally:
        await app.stop()


OPERATIONS = {"success": replacement_success, "admission": admission_controls,
    "rollback": provider_and_audit_rollback, "cas": final_cas_race, "generation": generation_guards,
    "postcommit": postcommit_failure, "stale": stale_refresh_and_reopen, "api": lambda: asyncio.run(api_story()),
    "reopen": reopen_worker}


class GithubAppKeyReplacementTests(unittest.TestCase):
    setUp = existing.OperatorCatalogGithubAppTests.setUp

    def worker(self, name):
        result = subprocess.run([sys.executable, "-B", __file__, "--worker", name], cwd=ROOT,
            env=self.environment, capture_output=True, text=True, timeout=120)
        if result.returncode:
            self.fail("isolated App replacement worker failed: " + existing.legacy.worker_failure_summary(result))
        value = json.loads(result.stdout)
        self.assertIs(type(value), dict)
        self.assertTrue(value)
        return value

    def test_replacement_preserves_two_assignments_and_encrypts_without_old_decrypt(self):
        self.assertEqual(self.worker("success"), {"two_assignments_preserved": True,
            "real_rsa_keys": 2, "no_old_decrypt": True, "generation": 2})

    def test_pre_provider_cas_and_wrong_kind_revoked_strict_input_refusals(self):
        self.assertEqual(self.worker("admission"), {"pre_provider_refusals": True,
            "strict_generation": True, "wrong_kind_and_revoked": True})

    def test_provider_binding_and_audit_failure_roll_back(self):
        self.assertEqual(self.worker("rollback"), {"wrong_binding_refused": True, "audit_failure_atomic": True})

    def test_real_post_provider_writer_wins_without_candidate_commit(self):
        self.assertEqual(self.worker("cas"), {"provider_outside_lock": True, "candidate_discarded_after_cas": True})

    def test_actual_sqlite_generation_floor_overflow_and_owner_checks(self):
        self.assertEqual(self.worker("generation"), {"floor_missing_drift_overflow": 3, "ownership_refusals": 2})

    def test_cache_fault_after_commit_does_not_report_rollback(self):
        self.assertEqual(self.worker("postcommit"), {"committed_despite_cache_fault": True,
            "receipt_unconfirmed": True, "independent_app_cache_fault": True})

    def test_old_generation_refresh_cannot_serve_and_fresh_process_retains_replacement(self):
        self.assertEqual(self.worker("stale"), {"stale_refresh_refused": True, "fresh_process_retained_generation": 2})

    def test_actual_full_asgi_auth_framing_cas_redacted_error_and_success(self):
        self.assertEqual(self.worker("api"), {"full_asgi": True, "redacted_errors": True,
            "admission_statuses": [401, 403, 415, 422, 413, 409, 503]})


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker" and sys.argv[2] in OPERATIONS:
        os.umask(0o077)
        signal.alarm(110)
        sys.addaudithook(existing.no_network)
        try:
            outcome = OPERATIONS[sys.argv[2]]()
        except BaseException as error:
            print(json.dumps(existing.legacy.safe_worker_failure(error), sort_keys=True), flush=True)
            raise SystemExit(1) from None
        print(json.dumps(outcome, sort_keys=True), flush=True)
    else:
        unittest.main(verbosity=2)
