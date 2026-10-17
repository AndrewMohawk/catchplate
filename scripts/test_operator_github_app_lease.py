#!/usr/bin/env python3
"""Synthetic ordinary-app lease integration; no GitHub/native/gate acceptance.

Cold workers use real SQLite, encrypted App storage, catalog signing, ASGI
request parsing/authentication, nonce reservation and X25519 lease encryption.
Only GitHub HTTP responses and gate observation are synthetic. Final-snapshot
faults are explicitly injected; no admission or cryptographic verdict is mocked.
"""
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

import test_operator_catalog_github as catalog

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "synthetic_github_app_lease_token"
DATA_PLANE_TOKEN = "synthetic_github_app_data_plane"
BINARY = "sha256:" + "7" * 64


def no_network(event, args):
    # asyncio's local self-pipe is allowed; provider/DNS/listener I/O is not.
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"} or event.startswith("subprocess."):
        raise AssertionError("external I/O is forbidden in the synthetic worker")


class Fixture(catalog.Fixture):
    def __init__(self):
        super().__init__()
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from catchplate import github_app, operator_github_app, http_client
        self.service, self.protocol = operator_github_app, github_app
        self.http_calls, self.mints = [], 0
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.pem = key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
        actual_mint = github_app.mint_installation_token

        def mint(config, signing_key):
            self.mints += 1
            expiry = datetime.fromtimestamp(int(time.time()) + 3600, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            owner, name = config.owner, config.repository
            bodies = [(200, {"id": 456, "app_id": 123,
                "account": {"id": 700, "login": owner, "type": "Organization"},
                "target_id": 700, "target_type": "Organization", "suspended_at": None,
                "suspended_by": None, "permissions": {"issues": "write", "metadata": "read"}}),
                (201, {"token": TOKEN, "expires_at": expiry,
                    "permissions": {"issues": config.issues, "metadata": "read"},
                    "repository_selection": "selected"}),
                (200, {"total_count": 1, "repositories": [{"id": 900, "name": name,
                    "full_name": owner + "/" + name, "owner": {"id": 700, "login": owner}}]})]

            def transport(request, **kwargs):
                # A second writer really can acquire SQLite here: provider
                # work is outside the catalog/final credential mutation lock.
                with self.db.metadata_connection() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    conn.rollback()
                self.http_calls.append(request)
                assert bodies, "unexpected provider request"
                status, value = bodies.pop(0)
                raw = json.dumps(value, separators=(",", ":")).encode()
                headers = (("Content-Type", "application/json"), ("Content-Length", str(len(raw))))
                return http_client.HttpResponse(status, dict(headers), headers, raw)

            result = actual_mint(config, signing_key, transport=transport)
            assert not bodies
            return result

        self.minter = patch.object(github_app, "mint_installation_token", side_effect=mint)
        self.minter.start()
        try:
            result = self.call(self.mutations.create_github_app_credential,
                self.inputs.GithubAppInput(**self.review(), name="Synthetic App",
                    app_id="123", installation_id="456", private_key_pem=self.pem,
                    repository=catalog.REPOSITORY, issues_permission="write"), catalog.ACTOR)
            self.credential_record = result["credential"]
            self.application_record = self.application()
            self.rule_record = self.rule(self.application_record, self.credential_record, catalog.WRITE)["access_rule"]
            self.signed()
            from catchplate import app
            import test_credential_lease_delivery as lease
            self.app, self.lease = app, lease
            self.core = self.db.get_credential(self.credential_record["id"], include_secret=False)
            self.policy_snapshot = self.bundles.get_policy_snapshot()
            self.route = app._active_route_by_id(self.rule_record["route_id"], snapshot=self.policy_snapshot)
            self.policy = self.policy_snapshot.credentials[self.core["id"]]
            app._assert_route_credential_binding(self.route, self.core, self.policy)
        except BaseException:
            self.close()
            raise

    def close(self):
        self.minter.stop()

    def request(self, purpose="dispatchSecret", **changes):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        key = X25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        nonce = os.urandom(32)
        metadata = self.app._credential_lease_public_metadata(self.core)
        payload = {"apiVersion": "catchplate.credentialLeaseRequest/v3", "purpose": purpose,
            "principalId": self.application_record["principal_id"], "routeId": self.route.id,
            "credentialId": self.core["id"], "expectedCredentialVersion": None,
            "expectedMetadataSha256": None, "recipientPublicKey": self.lease.b64e(public),
            "recipientKeyId": "sha256:" + hashlib.sha256(public).hexdigest(),
            "recipientNonce": self.lease.b64e(nonce), "policyHash": self.policy_snapshot.hash,
            "dataPlaneBinaryDigest": BINARY, "maxTtlSeconds": 5, "recipientAttestation": None}
        if purpose == "dispatchSecret":
            payload.update(expectedCredentialVersion=self.core["credential_version"],
                expectedMetadataSha256=self.app._credential_lease_metadata_sha256(metadata))
        payload.update(changes)
        response = self.lease.app_request(self.app.app, "POST", self.lease.LEASE_PATH,
            payload=payload, headers={"X-Catchplate-Data-Plane-Token": DATA_PLANE_TOKEN})
        return response, payload, key, nonce

    def plaintext(self, result):
        response, payload, key, nonce = result
        assert response.status_code == 200, "lease was refused: " + str(response.status_code)
        assert response.headers.get("cache-control") == "no-store"
        return self.lease.decrypt_lease(response.json(), recipient_private_key=key,
            recipient_nonce_raw=nonce, request_payload=payload)


def success(f):
    from catchplate import runtime
    f.service.forget(f.core["id"])
    calls = f.mints
    actual_get, actual_snapshot = f.db.get_credential, f.db.credential_generation_snapshot
    held, secret_reads, snapshots = False, [], []

    def get(identifier, **kwargs):
        if kwargs.get("include_secret"):
            assert not held, "App private key opened inside final snapshot"
            secret_reads.append(identifier)
        return actual_get(identifier, **kwargs)

    @contextmanager
    def snapshot(identifier):
        nonlocal held
        with actual_snapshot(identifier) as current:
            held = True
            snapshots.append(identifier)
            try:
                assert "secret" not in current and "encryptedCredential" not in current
                yield current
            finally:
                held = False

    with patch.object(f.db, "get_credential", side_effect=get), \
            patch.object(f.db, "credential_generation_snapshot", side_effect=snapshot), \
            patch.object(f.db, "credential_lease_snapshot", side_effect=AssertionError("raw secret snapshot forbidden")), \
            patch.object(runtime, "get_control_plane_credential", side_effect=AssertionError("generic secret lookup forbidden")):
        metadata = f.plaintext(f.request("generationMetadata"))
        assert "secret" not in metadata["credentials"][0] and f.mints == calls
        first = f.plaintext(f.request())
        second = f.plaintext(f.request())
    assert f.mints == calls + 1 and secret_reads == [f.core["id"]] and len(snapshots) == 3
    for plaintext in (first, second):
        entry = plaintext["credentials"][0]
        assert entry["secret"] == TOKEN and entry["credentialVersion"] == f.core["credential_version"]
        encoded = json.dumps(plaintext)
        assert f.pem not in encoded and "PRIVATE KEY" not in encoded and "private_key_pem" not in encoded
        assert f.service.SECRET_SCHEMA not in encoded and "github_app" not in entry["metadata"]
    current = f.db.get_credential(f.core["id"], include_secret=False)
    assert current["credential_version"] == f.core["credential_version"]
    assert f.db.verify_audit_chain()["ok"]
    return {"actual_envelopes": 3, "dispatch_tokens": 2, "private_opens": 1, "generation_unchanged": True}


def stale_preparation(f):
    f.service.forget(f.core["id"])
    calls = f.mints
    with patch.object(f.service, "prepare_dispatch_token", wraps=f.service.prepare_dispatch_token) as prepare:
        response, *_ = f.request(expectedCredentialVersion=f.core["credential_version"] + 1)
        assert response.status_code == 409 and prepare.call_count == 0
        response, *_ = f.request(expectedMetadataSha256="sha256:" + "0" * 64)
        assert response.status_code == 409 and prepare.call_count == 0
    assert f.mints == calls
    return {"stale_requests_rejected_before_mint": 2}


def final_fence(f, fault):
    original = f.service.prepare_dispatch_token
    f.service.forget(f.core["id"])

    def prepare(*args):
        original(*args)
        if fault == "expiry":
            # Synthetic elapsed monotonic time, checked by the real cache.
            identity = f.service._identity(f.core)
            with f.service._lock:
                entry = f.service._cache[identity]
                f.service._cache[identity] = replace(entry, monotonic=entry.monotonic - 4000)
        else:
            # Actual disposable SQL mutation between preparation and the final
            # snapshot; not a production writer or an authorized key rotation.
            with f.db.metadata_connection() as conn:
                conn.execute("UPDATE credentials SET credential_version=credential_version+1 WHERE id=?", (f.core["id"],))
                conn.commit()

    with patch.object(f.service, "prepare_dispatch_token", side_effect=prepare), \
            patch.object(f.app, "encrypt_credential_lease_envelope", wraps=f.app.encrypt_credential_lease_envelope) as encrypt:
        response, *_ = f.request()
        assert response.status_code == (503 if fault == "expiry" else 409)
        assert encrypt.call_count == 0 and "ciphertext" not in response.json()
    return {"no_envelope_after_" + fault: True}


def boundaries(f):
    from fastapi import HTTPException
    from catchplate import runtime, control_plane_credential_currentness as currentness
    calls = f.mints
    with patch.object(runtime, "get_control_plane_credential", side_effect=AssertionError("generic fallback")):
        catalog.refused(lambda: f.app._credential_for_lease(f.core["id"]), HTTPException)
        catalog.refused(lambda: f.app._broker_credential_for_lease(f.core["id"]), HTTPException)
        assert "secret" not in f.app._credential_for_lease(f.core["id"], allow_github_app=True)
    for attribute, value in (("operationBundle", "generic"), ("githubRepository", {"owner": "different", "name": "repository"})):
        adapter = deepcopy(f.route.adapter_config)
        adapter[attribute] = value
        bad = replace(f.route, adapter_config=adapter)
        catalog.refused(lambda: f.app._assert_route_credential_binding(bad, f.core, f.policy), HTTPException)
    bad = replace(f.route, credential_header={"mode": "insert"})
    catalog.refused(lambda: f.app._assert_route_credential_binding(bad, f.core, f.policy), HTTPException)
    for version in ("catchplate.nativeCredentialLeaseRequest/v1", "catchplate.policyAwareCredentialLeaseRequest/v1",
            "catchplate.nativeBrokerCredentialLeaseRequest/v1"):
        response, *_ = f.request(apiVersion=version, recipientAttestation={"synthetic": True})
        assert response.status_code in (403, 503), "nonordinary profile unexpectedly admitted"
    with patch.object(currentness, "selected", return_value=True):
        response, *_ = f.request()
        assert response.status_code == 503
    with patch.object(f.config, "KEY_RELEASE_REQUIRED", True):
        catalog.refused(lambda: f.app._credential_for_lease(f.core["id"], allow_github_app=True), HTTPException)
    assert f.mints == calls
    # Existing ordinary bearer projection remains unchanged.
    assert f.app._credential_secret_for_lease({"kind": "bearer", "secret": "synthetic_pat", "metadata": {}}, f.policy) == "synthetic_pat"
    # Local revocation uses the real catalog/DB writers, not a mock missing row.
    f.call(f.mutations.revoke_application, f.target(f.application_record["id"]), catalog.ACTOR)
    f.call(f.mutations.revoke_credential, f.target(f.core["id"]), catalog.ACTOR)
    assert f.db.get_credential(f.core["id"], include_secret=False) is None
    with patch.object(f.app, "encrypt_credential_lease_envelope", wraps=f.app.encrypt_credential_lease_envelope) as encrypt:
        response, *_ = f.request()
        assert response.status_code == 409 and encrypt.call_count == 0 and f.mints == calls
    return {"ordinary_only_and_named_repository": True, "local_revocation_refused": True}


OPERATIONS = {"success": success, "stale": stale_preparation, "boundaries": boundaries,
    "expiry": lambda f: final_fence(f, "expiry"), "generation": lambda f: final_fence(f, "generation")}


class GithubAppLeaseTests(unittest.TestCase):
    def setUp(self):
        if not __debug__ or os.getenv("PYTHONOPTIMIZE") not in (None, "", "0"):
            self.fail("assertions must be enabled")
        catalog.OperatorCatalogGithubTests.setUp(self)
        self.environment.update(CATCHPLATE_DATA_PLANE_CREDENTIAL_LEASE_TOKEN=DATA_PLANE_TOKEN,
            CATCHPLATE_DATA_PLANE_INSTANCE_ID="spiffe://test.catchplate/github-app-lease",
            CATCHPLATE_EXPECTED_DATA_PLANE_BINARY_DIGEST=BINARY,
            CATCHPLATE_DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED="0",
            CATCHPLATE_SECRET_LEASE_TTL_SECONDS="5")

    def run_worker(self, name):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=90)
        if result.returncode:
            self.fail("synthetic lease worker failed: " + catalog.worker_failure_summary(result))
        return json.loads(result.stdout)

    def test_actual_asgi_metadata_and_token_only_envelopes(self):
        self.assertEqual(self.run_worker("success")["dispatch_tokens"], 2)

    def test_stale_generation_and_metadata_do_not_mint(self):
        self.assertEqual(self.run_worker("stale")["stale_requests_rejected_before_mint"], 2)

    def test_exact_named_scope_and_nonordinary_refusals(self):
        self.assertTrue(self.run_worker("boundaries")["ordinary_only_and_named_repository"])

    def test_final_cached_expiry_cannot_reopen_or_emit(self):
        self.assertTrue(self.run_worker("expiry")["no_envelope_after_expiry"])

    def test_final_sql_generation_drift_cannot_emit(self):
        self.assertTrue(self.run_worker("generation")["no_envelope_after_generation"])


if __name__ == "__main__":
    if not __debug__ or os.getenv("PYTHONOPTIMIZE") not in (None, "", "0"):
        raise SystemExit("assertions must be enabled")
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(no_network)
        fixture = None
        try:
            fixture = Fixture()
            outcome = OPERATIONS[sys.argv[2]](fixture)
        except Exception as error:
            print(json.dumps(catalog.safe_worker_failure(error), sort_keys=True))
            raise SystemExit(1) from None
        finally:
            if fixture is not None:
                fixture.close()
        print(json.dumps(outcome, sort_keys=True))
    else:
        unittest.main(verbosity=2)
