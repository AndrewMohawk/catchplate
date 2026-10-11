#!/usr/bin/env python3
"""Imported AWS release refusals over real cold encrypted catalog records.

Run in the existing bounded network-none full dependency image with read-only source and
private TMPDIR. Only gate observation and background-worker startup are absent.
The catalog, SQLite, encryption and imported release/injection guards are real.
Decrypt/claim tripwires prove refusal ordering; the ordinary bearer control
uses real decryption. Deliberately contradictory rows are restored afterwards.

The native-helper test supplies a synthetic owner/channel and a sentinel KEK.
It proves only metadata refusal before unwrap, NOT native/enclave acceptance,
request authority, signing, SDK/provider compatibility or deployed readiness.
"""
from __future__ import annotations

from contextlib import closing, contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

if sys.flags.optimize:
    raise RuntimeError("AWS release tests require enabled assertions")

import test_operator_catalog_github as shared
import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
ACTOR = "operator-aws-release-boundary-test"
KIND = "aws_sigv4_v1"
ACCESS = "AKIA" + "F" * 16
SECRET = "G" * 40
BEARER = "synthetic-aws-release-normal-bearer"
NETWORK_ATTEMPTS = []


def no_network(event, _args):
    if event in {"socket.connect", "socket.bind", "socket.getaddrinfo"}:
        NETWORK_ATTEMPTS.append(event)
        raise AssertionError("AWS release fixture forbids network")


def refused(callback, exception, message):
    try:
        callback()
    except exception as caught:
        assert str(caught) == message
        return caught
    raise AssertionError("AWS release boundary admitted a stored tuple")


class Fixture:
    def __init__(self):
        (self.config, self.db, self.store, self.bundles, self.schema,
            self.inputs, self.mutations) = workspace.workspace()
        from serverware import app, policy_engine, runtime
        self.app, self.engine, self.runtime = app, policy_engine, runtime
        self.expected_tuple = {"schema": "serverware.awsSigV4Credentials/v1",
            "credential_kind": "long_term", "access_key_id": ACCESS,
            "secret_access_key": SECRET, "session_token": None, "expires_at": None}
        result = self.call(self.mutations.create_aws_credential,
            self.inputs.AwsSigV4CredentialInput(**self.review(), name="Stored AWS tuple",
                **{key: value for key, value in self.expected_tuple.items() if key != "schema"}), ACTOR)
        self.aws_id = result["credential"]["id"]
        result = self.call(self.mutations.create_credential,
            self.inputs.CredentialInput(**self.review(), name="Ordinary bearer control",
                auth_type="bearer", secret=BEARER), ACTOR)
        self.bearer_id = result["credential"]["id"]
        # Storage control: this is a real encrypted tuple, not a fabricated
        # get_credential response. Generic release paths below must not open it.
        self.aws = self.db.get_credential(self.aws_id, include_secret=True)
        assert self.aws["kind"] == KIND
        assert json.loads(self.aws["secret"]) == self.expected_tuple
        assert self.aws["secret"] == json.dumps(self.expected_tuple,
            sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        self.bearer = self.db.get_credential(self.bearer_id, include_secret=True)
        assert self.bearer["secret"] == BEARER
        with closing(self.db.connect()) as connection:
            self.aws_row = dict(connection.execute("SELECT * FROM credentials WHERE id=?",
                (self.aws_id,)).fetchone())
            persisted = "\n".join(connection.iterdump())
        assert self.aws_row["encrypted_secret"] == "envelope:v2"
        assert all(self.aws_row[key] for key in
            ("encrypted_dek", "secret_nonce", "secret_ciphertext", "secret_kek_id"))
        assert all(value not in persisted for value in (ACCESS, SECRET, BEARER))
        self.before = self.snapshot()

    def review(self):
        return workspace.review(self.db, self.store, self.schema)

    def call(self, function, *args):
        with patch.object(self.store, "loaded_policy_hash", return_value=None), \
                patch.object(self.store, "loaded_gate_status", return_value=None):
            return function(*args)

    def snapshot(self):
        return (workspace.snapshot(self.db, catalog=True), self.config.POLICY_BUNDLE_PATH.read_bytes(),
            self.store.get_policy_high_water())

    def unchanged(self):
        assert self.snapshot() == self.before, "release checks changed durable catalog or authority"
        workspace.catalog(self.db, self.schema)
        workspace.verify_signed(self.config, self.db, self.store, self.bundles)
        assert not NETWORK_ATTEMPTS

    def policy(self):
        return self.bundles.CredentialPolicy(id=self.bearer_id, kind="static",
            provider="operator-demo", provider_subject=self.bearer["metadata"]["provider_subject"],
            scopes=(), injection={"type": "bearer", "header": "Authorization"})

    def variants(self):
        ordinary = {"provider_id": "operator-demo",
            "provider_subject": self.aws["metadata"]["provider_subject"], "secret_class": "bearerToken"}
        return (
            ("retained-tuple", KIND, deepcopy(self.aws["metadata"])),
            ("kind-only", KIND, ordinary),
            ("bearer-connection-marker", "bearer", {**ordinary, "connection_type": KIND}),
            ("bearer-secret-class-marker", "bearer", {**ordinary, "secret_class": "awsSigV4"}),
        )

    @contextmanager
    def marked_row(self, kind, metadata):
        # Deliberate retained-row corruption, not an admitted catalog mutation.
        with closing(self.db.connect()) as connection, connection:
            connection.execute("UPDATE credentials SET kind=?,metadata=? WHERE id=?",
                (kind, json.dumps(metadata), self.aws_id))
        try:
            yield self.db.get_credential(self.aws_id, include_secret=False)
        finally:
            with closing(self.db.connect()) as connection, connection:
                connection.execute("UPDATE credentials SET kind=?,metadata=? WHERE id=?",
                    (self.aws_row["kind"], self.aws_row["metadata"], self.aws_id))


def runtime_refusals():
    f = Fixture()
    runtime = f.runtime
    contexts = ({"request_authority": {}}, {"release_authorization": {}},
        {"expected_release_identity": object()}, {"jit_policy": {}},
        {"request_authority": {}, "expected_release_identity": object()})
    callbacks = [lambda: runtime.get_control_plane_credential(f.aws_id),
        lambda: runtime.get_credential(f.aws_id), lambda: runtime.get_bound_credential_lease(f.aws_id)]
    callbacks.extend(lambda context=context: runtime.get_credential(f.aws_id, **context)
        for context in contexts)
    callbacks.extend(lambda context=context: runtime.get_bound_credential_lease(f.aws_id, **context)
        for context in contexts)
    getter = f.db.get_credential
    for _label, kind, metadata in f.variants():
        with f.marked_row(kind, metadata), \
                patch.object(f.db, "decrypt_secret_envelope", side_effect=AssertionError("unexpected tuple decrypt")) as decrypt, \
                patch.object(runtime, "_claim_release_controlled_credential", side_effect=AssertionError("unexpected release claim")) as claim, \
                patch.object(runtime, "start_runtime_workers", return_value=None), \
                patch.object(f.db, "get_credential", wraps=getter) as reads:
            for index, callback in enumerate(callbacks):
                runtime.invalidate_secret_leases()
                poisoned = {**deepcopy(f.aws), "kind": kind, "metadata": deepcopy(metadata)}
                with runtime._credential_lock:
                    for version in (f.aws["credential_version"], f.aws["credential_version"] + 1):
                        runtime._credential_cache[(f.aws_id, version)] = (time.monotonic() + 60, deepcopy(poisoned))
                    keep = (f.bearer_id, f.bearer["credential_version"])
                    runtime._credential_cache[keep] = (time.monotonic() + 60, deepcopy(f.bearer))
                reads.reset_mock()
                assert callback() is None
                assert reads.call_count == 1
                call = reads.call_args
                assert call.args == (f.aws_id,) and not call.kwargs.get("include_secret", False)
                decrypt.assert_not_called()
                claim.assert_not_called()
                with runtime._credential_lock:
                    # The control-plane refresh read rejects without consulting
                    # its data-plane cache. Both data-plane retrieval paths evict.
                    if index != 0:
                        assert all(key[0] != f.aws_id for key in runtime._credential_cache)
                    assert keep in runtime._credential_cache
    runtime.invalidate_secret_leases()
    f.unchanged()
    return {"ok": True}


def app_and_injection_refusals():
    from fastapi import HTTPException
    from mitmproxy import http
    f = Fixture()
    policy = f.policy()
    for _label, kind, metadata in f.variants():
        with f.marked_row(kind, metadata) as public, \
                patch.object(f.db, "decrypt_secret_envelope", side_effect=AssertionError("unexpected tuple decrypt")) as decrypt:
            callbacks = (lambda: f.app._broker_credential_for_lease(f.aws_id),
                lambda: f.app._assert_credential_policy_binding(public, policy),
                lambda: f.app._assert_credential_injection_binding(public, policy),
                lambda: f.app._credential_secret_for_lease({**public, "secret": f.aws["secret"]}, policy))
            for callback in callbacks:
                try:
                    callback()
                except HTTPException as caught:
                    assert caught.status_code == 409 and caught.detail == "AWS credential dispatch is unavailable"
                else:
                    raise AssertionError("app lease helper admitted an AWS tuple")
            flow = SimpleNamespace(request=http.Request.make("GET", "https://api.example.com/v1/items",
                headers={"Authorization": "Bearer synthetic-placeholder"}), metadata={})
            before = flow.request.headers.fields
            refused(lambda: f.engine._inject_credential(flow, policy,
                {**public, "secret": f.aws["secret"]}), ValueError,
                "AWS credentials cannot use generic secret injection")
            assert flow.request.headers.fields == before and flow.metadata == {}
            assert f.engine._take_response_credential_guard(flow) is None
            assert f.runtime._project_credential_for_data_plane({**public, "secret": f.aws["secret"]}) is None
            decrypt.assert_not_called()
    f.unchanged()
    return {"ok": True}


def normal_bearer_control():
    from mitmproxy import http
    f = Fixture()
    runtime, policy = f.runtime, f.policy()
    runtime.invalidate_secret_leases()
    with patch.object(f.db, "decrypt_secret_envelope", wraps=f.db.decrypt_secret_envelope) as decrypt, \
            patch.object(runtime, "start_runtime_workers", return_value=None):
        assert runtime.get_control_plane_credential(f.bearer_id)["secret"] == BEARER
        assert decrypt.call_count == 1
        decrypt.reset_mock()
        credential = runtime.get_credential(f.bearer_id)
        assert credential["secret"] == BEARER and decrypt.call_count == 1
        assert runtime.get_credential(f.bearer_id) == credential and decrypt.call_count == 1
        lease = runtime.get_bound_credential_lease(f.bearer_id)
        assert lease is not None and lease.credential == credential and decrypt.call_count == 1
        assert lease.binding.secret_fingerprint == "sha256:" + hashlib.sha256(BEARER.encode()).hexdigest()
        public = f.app._broker_credential_for_lease(f.bearer_id)
        assert public["id"] == f.bearer_id and "secret" not in public
        f.app._assert_credential_policy_binding(public, policy)
        f.app._assert_credential_injection_binding(public, policy)
        assert f.app._credential_secret_for_lease(credential, policy) == BEARER
        assert runtime._project_credential_for_data_plane(credential) == credential
        flow = SimpleNamespace(request=http.Request.make("GET", "https://api.example.com/v1/items"), metadata={})
        assert f.engine._inject_credential(flow, policy, credential) == "injected bearer into Authorization"
        assert flow.request.headers["Authorization"] == "Bearer " + BEARER
        guard = f.engine._take_response_credential_guard(flow)
        assert guard is not None and guard.detects(BEARER.encode())
        guard.clear()
        # Exact sentinel identity proves the claim tripwire can be reached by
        # an ordinary record; no synthetic authority is claimed as authorized.
        reached = RuntimeError("synthetic claim boundary reached")
        with patch.object(runtime, "_claim_release_controlled_credential", side_effect=reached) as claim:
            try:
                runtime.get_credential(f.bearer_id, request_authority={}, expected_release_identity=object())
            except RuntimeError as caught:
                assert caught is reached
            else:
                raise AssertionError("ordinary claim tripwire was not reached")
            claim.assert_called_once()
        assert decrypt.call_count == 1
    runtime.invalidate_secret_leases()
    f.unchanged()
    return {"ok": True}


def normal_oauth_projection_control():
    """Real projection functions, synthetic tokens; no OAuth/provider lifecycle."""
    f = Fixture()
    policy = SimpleNamespace(injection={"type": "bearer", "header": "Authorization",
        "field": "access_token", "prefix": "Bearer "})
    for provider in ("google", "x"):
        access, refresh = "synthetic-" + provider + "-access", "synthetic-" + provider + "-refresh"
        credential = {"id": "synthetic-oauth-projection", "kind": "oauth2",
            "metadata": {"provider_id": provider},
            "secret": json.dumps({"access_token": access, "refresh_token": refresh, "token_type": "Bearer"})}
        before = deepcopy(credential)
        expected = json.dumps({"access_token": access}, sort_keys=True, separators=(",", ":"))
        leased = f.app._credential_secret_for_lease(credential, policy)
        projected = f.runtime._project_credential_for_data_plane(credential)
        assert leased == expected and projected is not None and projected["secret"] == expected
        assert refresh not in leased and refresh not in projected["secret"]
        assert credential == before
        for raw in ('{"access_token":', '{"refresh_token":"synthetic-refresh-only"}',
                '{"access_token":"first","access_token":"second"}'):
            malformed = {**credential, "secret": raw}
            assert f.runtime._project_credential_for_data_plane(malformed) is None
            try:
                f.app._credential_secret_for_lease(malformed, policy)
            except f.app.HTTPException as caught:
                assert caught.status_code == 503 and raw not in str(caught.detail)
            else:
                raise AssertionError("malformed OAuth projection accepted")
    f.unchanged()
    assert NETWORK_ATTEMPTS == []
    return {"ok": True}


def native_pre_unwrap_refusals():
    f = Fixture()
    from serverware import credential_ciphertext, native_secret_broker_helper as native
    row = credential_ciphertext.row_projection(f.aws_row)
    ordinary = {"provider_id": "operator-demo", "provider_subject": f.aws["metadata"]["provider_subject"],
        "secret_class": "bearerToken"}
    cases = [(False, ordinary, ordinary), (True, f.aws["metadata"], f.aws["metadata"])]
    for marker in ({"connection_type": KIND}, {"secret_class": "awsSigV4"}):
        cases.extend(((True, {**ordinary, **marker}, ordinary), (True, ordinary, {**ordinary, **marker})))
    for index, (blocked, metadata, storage) in enumerate(cases):
        now = time.time_ns() // 1_000_000
        deadline = time.clock_gettime_ns(time.CLOCK_BOOTTIME) + 30_000_000_000
        binding = {"requestBindingSha256": "sha256:" + "1" * 64, "policyHash": "sha256:" + "2" * 64,
            "dataPlaneBinaryDigest": "sha256:" + "3" * 64, "principalId": "synthetic-release-test",
            "routeId": "synthetic-route", "credentialId": f.aws_id,
            "credentialVersion": f.aws["credential_version"], "metadataSha256": native._sha(native._canonical(metadata)),
            "issuedAtEpochMs": now - 1000, "expiresAtEpochMs": now + 30000,
            "requestAuthoritySha256": None, "releaseAuthorizationSha256": None}
        value = {"apiVersion": native._WORK, "operationId": "aws-release-test-" + str(index),
            "gateRecipientPublicKey": native._encoded(b"1" * 32), "gateRecipientNonce": native._encoded(b"2" * 32),
            "deadlineBoottimeNs": deadline, "leaseBinding": binding, "encryptedCredential": deepcopy(row),
            "metadata": deepcopy(metadata), "storageMetadata": json.dumps(storage, sort_keys=True)}
        reached = RuntimeError("synthetic unwrap boundary reached")
        owner = native._Broker.__new__(native._Broker)
        owner.kek, owner.rsa, owner.operations = SimpleNamespace(decrypt=Mock(side_effect=reached)), None, set()
        owner.key_id, owner.channel = row["secretKekId"], SimpleNamespace(check=Mock())
        if blocked:
            refused(lambda: owner.open_credential(value), ValueError, "native broker owner unavailable")
            owner.kek.decrypt.assert_not_called()
        else:
            try:
                owner.open_credential(value)
            except RuntimeError as caught:
                assert caught is reached
            else:
                raise AssertionError("valid synthetic pre-unwrap binding did not reach sentinel KEK")
            owner.kek.decrypt.assert_called_once()
        owner.channel.check.assert_called_once_with(deadline)
        assert owner.operations == {value["operationId"]}
    f.unchanged()
    return {"ok": True}


class OperatorAwsReleaseBoundaryTests(unittest.TestCase):
    def setUp(self):
        workspace.common.OperatorDemoPersistenceTests.setUp(self)
        self.environment.pop("PYTHONOPTIMIZE", None)

    def worker(self, name):
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", name],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=90)
        if result.returncode != 0:
            self.fail("isolated AWS release worker refused: " + shared.worker_failure_summary(result))
        self.assertLessEqual(len(result.stdout), 8192)
        self.assertEqual(json.loads(result.stdout), {"ok": True})

    def test_runtime_refuses_before_decrypt_claim_cache_and_bound_lease(self): self.worker("runtime")
    def test_imported_app_helpers_and_engine_refuse_all_aws_markers(self): self.worker("app")
    def test_ordinary_bearer_release_cache_and_injection_are_unchanged(self): self.worker("bearer")
    def test_ordinary_oauth_projection_remains_access_token_only(self): self.worker("oauth")
    def test_native_helper_refuses_each_metadata_marker_before_unwrap(self): self.worker("native")

    def test_optimized_worker_is_explicitly_refused(self):
        result = subprocess.run([sys.executable, "-O", "-B", str(Path(__file__).resolve()), "--worker", "runtime"],
            cwd=ROOT, env=self.environment, capture_output=True, text=True, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("AWS release tests require enabled assertions", result.stderr)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        os.umask(0o077)
        sys.addaudithook(no_network)
        try:
            operation = {"runtime": runtime_refusals, "app": app_and_injection_refusals,
                "bearer": normal_bearer_control, "oauth": normal_oauth_projection_control,
                "native": native_pre_unwrap_refusals}[sys.argv[2]]
            print(json.dumps(operation(), sort_keys=True))
        except Exception as error:
            print(json.dumps(shared.safe_worker_failure(error), sort_keys=True))
            raise SystemExit(1) from None
    else:
        unittest.main()
