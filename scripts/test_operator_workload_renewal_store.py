#!/usr/bin/env python3
"""Prepared ordinary renewal-store controls; run only in the isolated harness.

Each scenario starts a fresh subprocess with the existing workspace fixture:
real SQLite, Ed25519 proof/signature checks, catalog/publication ownership,
signed policy and audit. Only the gate HTTP observation and renewal clock are
synthetic. An os.replace fault exercises real postcommit file uncertainty.
This is not HTTP, Rust CONNECT, native, provider or deployment acceptance.
"""
from __future__ import annotations

import base64
from contextlib import closing, contextmanager, ExitStack
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
import uuid

import test_operator_workspace_store as workspace

ROOT = Path(__file__).resolve().parents[1]
ACTOR = workspace.common._ACTOR
RECEIPT_KEYS = {
    "operation_id", "request_sha256", "application_id", "enrollment_id",
    "previous_generation", "token_generation", "token_sha256",
    "issued_at_epoch_ms", "rotated_at_epoch_ms", "expires_at_epoch_ms",
    "previous_accept_until_epoch_ms",
}
RENEWAL_KEYS = {
    "version", "enrollment_id", "public_key", "enrolled_at_epoch_ms",
    "expires_at_epoch_ms", "token_lifetime_seconds", "overlap_seconds",
    "previous_token", "last_operation",
}


class Fixture:
    """No owner import until the subprocess's explicit environment is selected."""

    def __init__(self, *, application_lifetime=90 * 86400):
        self.config, self.db, self.demo, self.bundles, self.schema, self.inputs, self.mutations = workspace.workspace()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        from serverware import operator_workload_renewal as wire
        from serverware import operator_workload_renewal_store as renewal
        self.wire, self.renewal = wire, renewal
        # Test-only private material; never printed, stored in SQLite or returned.
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        self.other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
        self.public_key = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.other_public_key = self.other_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        credential = workspace.create_credential(self.db, self.demo, self.schema, self.inputs, self.mutations)
        self.credential_id = credential["credential"]["id"]
        created = self.mutations.create_application(self.inputs.ApplicationInput(
            **self.review(), name="Finite workload renewal fixture",
            token_lifetime_seconds=application_lifetime,
            proxy_authentication="basic_and_bearer_v1"), ACTOR)
        self.application_id = created["application"]["id"]
        self.tokens = [created["client_token"]]
        rule = workspace.create_rule(self.db, self.demo, self.schema, self.inputs,
            self.mutations, self.application_id, self.credential_id)
        self.rule_id = rule["access_rule"]["id"]
        self.now = time.time_ns() // 1_000_000 + 1000
        self.gate_hook = None
        self.gate_transform = lambda value: value
        self.gate_calls = 0
        self.sequence = 0

    @contextmanager
    def observed(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(self.renewal, "_now", side_effect=lambda: self.now))
            stack.enter_context(patch.object(self.demo, "loaded_gate_status", side_effect=self.gate))
            yield self

    def gate(self):
        self.demo.operator_publication.assert_not_held()
        self.gate_calls += 1
        signed = json.loads(self.config.POLICY_BUNDLE_PATH.read_bytes())
        compiled = self.bundles.compile_policy_bundle(signed, verify_signature=True, validate_schema=True)
        result = {"ok": True, "policy_hash": compiled.hash,
            "operator_workload_renewal": self.wire.gate_descriptor()}
        hook, self.gate_hook = self.gate_hook, None
        if hook is not None:
            hook()
        return self.gate_transform(result)

    def review(self):
        return workspace.review(self.db, self.demo, self.schema)

    def target(self):
        return self.inputs.TargetInput(**self.review(), id=self.application_id)

    def catalog(self):
        return workspace.catalog(self.db, self.schema)

    def application(self):
        return next(row for row in self.catalog()["applications"] if row["id"] == self.application_id)

    def snapshot(self):
        with closing(self.db.connect()) as conn:
            rows = tuple(conn.iterdump())
        return rows, self.config.POLICY_BUNDLE_PATH.read_bytes()

    def audit(self):
        return workspace.rows(self.db, "audit_events")

    def preserved(self):
        catalog = self.catalog()
        return (workspace.rows(self.db, "credentials"), workspace.rows(self.db, "credential_generations"),
            catalog["credentials"], catalog["access_rules"])

    def signed(self):
        return workspace.verify_signed(self.config, self.db, self.demo, self.bundles)

    def principal(self):
        principal_id = self.application()["principal_id"]
        return next(row for row in self.signed()["principals"] if row["id"] == principal_id)

    def assert_no_secrets(self, result):
        text = json.dumps(result, sort_keys=True)
        with closing(self.db.connect()) as conn:
            retained = "\n".join(conn.iterdump())
        for secret in (*self.tokens, workspace.common._PROVIDER_SECRET,
                bytes(range(32)).hex(), bytes(range(32, 64)).hex()):
            assert secret not in text and secret not in retained, "private material escaped fixture boundary"

    def enroll(self, **changes):
        return self.renewal.enroll(self.wire.EnrollmentInput(**self.review(), id=self.application_id,
            **({"public_key": self.public_key, "enrollment_lifetime_seconds": 86400,
                "token_lifetime_seconds": 3600} | changes)), ACTOR)

    def request(self, *, key=None, **changes):
        record = self.application()
        enrollment = record["client_renewal"]
        self.sequence += 1
        token = base64.urlsafe_b64encode(hashlib.sha256(
            ("synthetic-workload-token-" + str(self.sequence)).encode()).digest()).rstrip(b"=").decode()
        self.tokens.append(token)
        issued = changes.get("issued_at_epoch_ms", self.now - 1000)
        fields = {"schema": self.wire.SCHEMA,
            "audience": "https://proxy.example.com" + self.wire.PUBLIC_PATH,
            "application_id": self.application_id, "enrollment_id": enrollment["enrollment_id"],
            "expected_token_generation": record["token_version"], "operation_id": str(uuid.uuid4()),
            "issued_at_epoch_ms": issued, "expires_at_epoch_ms": issued + 60_000,
            "token_sha256": "sha256:" + hashlib.sha256(token.encode()).hexdigest(),
            "token_expires_at_epoch_ms": min(issued + enrollment["token_lifetime_seconds"] * 1000,
                enrollment["expires_at_epoch_ms"])} | changes
        unsigned = self.wire.RenewalRequest(**fields, signature="00" * 64)
        return unsigned.model_copy(update={"signature": (key or self.key).sign(unsigned.signing_bytes()).hex()})

    def resign(self, request, *, key=None, **changes):
        fields = request.model_dump(exclude={"signature"}) | changes
        unsigned = self.wire.RenewalRequest(**fields, signature="00" * 64)
        return unsigned.model_copy(update={"signature": (key or self.key).sign(unsigned.signing_bytes()).hex()})

    def refused(self, operation, exceptions):
        before = self.snapshot()
        try:
            operation()
        except exceptions:
            pass
        else:
            raise AssertionError("operation unexpectedly accepted")
        assert self.snapshot() == before, "refusal changed persisted state or policy bytes"


def enrollment():
    f = Fixture()
    with f.observed():
        old, preserved, audit = f.application(), f.preserved(), f.audit()
        assert f.renewal.validate(old) is None
        assert f.renewal.public_fields(old, f.now) == {"client_renewal": None}
        result = f.enroll()
        current = f.application()
        enrollment = current["client_renewal"]
        assert set(enrollment) == RENEWAL_KEYS
        assert enrollment["version"] == 1 and enrollment["public_key"] == f.public_key
        assert str(uuid.UUID(enrollment["enrollment_id"])) == enrollment["enrollment_id"]
        assert enrollment["enrolled_at_epoch_ms"] == f.now
        assert enrollment["expires_at_epoch_ms"] == f.now + 86400_000
        assert enrollment["token_lifetime_seconds"] == 3600 and enrollment["overlap_seconds"] == 300
        assert enrollment["previous_token"] is enrollment["last_operation"] is None
        assert current["token_sha256"] == old["token_sha256"]
        assert current["token_version"] == old["token_version"]
        assert current["token_expires_at_epoch_ms"] == enrollment["expires_at_epoch_ms"] < old["token_expires_at_epoch_ms"]
        assert f.preserved() == preserved and len(f.audit()) == len(audit) + 1
        assert result["application"]["id"] == old["id"] and "client_token" not in result
        assert result["application"]["client_renewal"] is not None
        assert f.renewal.validate(current) is None
        assert f.principal()["proxyAuthorization"]["expiresAtEpochMs"] == current["token_expires_at_epoch_ms"]
        f.assert_no_secrets(result)
    return {"enrollment_clips_without_issuance": True}


def short_or_expired_enrollment(expired=False):
    f = Fixture(application_lifetime=3600)
    with f.observed():
        old = f.application()
        if expired:
            f.now = old["token_expires_at_epoch_ms"] + 1
        f.enroll()
        current = f.application()
        assert current["token_sha256"] == old["token_sha256"]
        assert current["token_expires_at_epoch_ms"] == old["token_expires_at_epoch_ms"]
        assert current["token_version"] == old["token_version"]
        if expired:
            result = f.renewal.renew(f.request())
            assert result["operation"]["token_generation"] == old["token_version"] + 1
            assert f.application()["token_expires_at_epoch_ms"] > f.now
        f.signed()
    return {"old_expiry_preserved": True, "expired": expired}


def committed_renewal(f):
    old, preserved, before, audit = f.application(), f.preserved(), f.review(), f.audit()
    request = f.request()
    result = f.renewal.renew(request)
    current = f.application()
    operation = result["operation"]
    cutoff = min(old["token_expires_at_epoch_ms"], f.now + 300_000)
    assert set(result) == {"operation", "application", "revision", "policy"}
    assert operation == {"operation_id": request.operation_id, "request_sha256": request.request_digest(),
        "application_id": old["id"], "enrollment_id": old["client_renewal"]["enrollment_id"],
        "previous_generation": old["token_version"], "token_generation": old["token_version"] + 1,
        "token_sha256": request.token_sha256, "issued_at_epoch_ms": request.issued_at_epoch_ms,
        "rotated_at_epoch_ms": f.now, "expires_at_epoch_ms": request.token_expires_at_epoch_ms,
        "previous_accept_until_epoch_ms": cutoff}
    assert set(operation) == RECEIPT_KEYS
    assert current["token_sha256"] == request.token_sha256 and current["token_version"] == old["token_version"] + 1
    assert current["token_expires_at_epoch_ms"] == request.token_expires_at_epoch_ms
    assert current["client_renewal"]["last_operation"] == operation
    assert current["client_renewal"]["previous_token"] == {"token_sha256": old["token_sha256"],
        "token_generation": old["token_version"], "original_expires_at_epoch_ms": old["token_expires_at_epoch_ms"],
        "accept_until_epoch_ms": cutoff}
    assert current["client_renewal"]["expires_at_epoch_ms"] == old["client_renewal"]["expires_at_epoch_ms"]
    assert result["revision"] == before["expected_revision"] + 1 and f.preserved() == preserved
    assert len(f.audit()) == len(audit) + 1
    assert f.audit()[-1]["event_type"] == "operator_catalog.application.token_renewed"
    assert f.audit()[-1]["actor_type"] == "agent" and f.audit()[-1]["actor_id"] == old["principal_id"]
    assert result["policy"]["policy_hash"] != before["expected_policy_hash"]
    assert result["application"]["token_generation"] == current["token_version"]
    public = json.dumps(result["application"], sort_keys=True)
    assert current["token_sha256"] not in public and old["token_sha256"] not in public
    proxy = f.principal()["proxyAuthorization"]
    assert proxy["tokenSha256"] == request.token_sha256 and proxy["expiresAtEpochMs"] == request.token_expires_at_epoch_ms
    assert proxy["managedRenewal"] == {"schema": f.wire.POLICY_SCHEMA,
        "enrollmentId": old["client_renewal"]["enrollment_id"],
        "enrollmentExpiresAtEpochMs": old["client_renewal"]["expires_at_epoch_ms"],
        "rotatedAtEpochMs": f.now,
        "previousToken": {"tokenSha256": old["token_sha256"],
            "originalExpiresAtEpochMs": old["token_expires_at_epoch_ms"], "expiresAtEpochMs": cutoff}}
    f.assert_no_secrets(result)
    return request, result


def renew_and_replay():
    f = Fixture()
    with f.observed():
        f.enroll()
        request, result = committed_renewal(f)
        before = f.snapshot()
        for now in (f.now, request.expires_at_epoch_ms + 1):
            f.now = now
            recovered = f.renewal.renew(request)
            assert recovered["operation"] == result["operation"]
            assert recovered["revision"] == result["revision"]
            assert recovered["policy"]["activation"] == "active"
            assert f.snapshot() == before, "exact recovery rewrote authority or materialized policy"
        f.refused(lambda: f.renewal.renew(f.resign(request, key=f.other_key)), ValueError)
        f.refused(lambda: f.renewal.renew(f.resign(request,
            expected_token_generation=request.expected_token_generation + 1)), f.schema.CatalogConflict)
        f.refused(lambda: f.renewal.renew(f.resign(request, token_sha256="sha256:" + "f" * 64)), f.schema.CatalogConflict)
        f.refused(lambda: f.renewal.renew(f.resign(request, operation_id=str(uuid.uuid4()))),
            (f.schema.CatalogConflict, ValueError))
        f.now = result["operation"]["previous_accept_until_epoch_ms"] + 1
        stale_generation = f.request(expected_token_generation=request.expected_token_generation)
        f.refused(lambda: f.renewal.renew(stale_generation), f.schema.CatalogConflict)
    return {"one_issuance_fresh_and_expired_recovery_read_only": True}


def proof_and_deadlines():
    f = Fixture()
    with f.observed():
        f.enroll()
        requests = [f.request(key=f.other_key), f.request(audience="https://other.example.com" + f.wire.PUBLIC_PATH),
            f.request(issued_at_epoch_ms=f.now + f.wire.CLOCK_SKEW_MS + 1),
            f.request(issued_at_epoch_ms=f.now - 70_000, expires_at_epoch_ms=f.now - 10_000)]
        for request in requests:
            f.refused(lambda request=request: f.renewal.renew(request), ValueError)
        request = f.request()
        missing = f.resign(request, application_id=str(uuid.uuid4()))
        f.refused(lambda: f.renewal.renew(missing), f.mutations.CatalogNotFound)
        different_enrollment = f.resign(request, enrollment_id=str(uuid.uuid4()))
        f.refused(lambda: f.renewal.renew(different_enrollment), f.schema.CatalogConflict)
        for expiry in (request.token_expires_at_epoch_ms - 1, request.token_expires_at_epoch_ms + 1):
            candidate = f.resign(request, token_expires_at_epoch_ms=expiry)
            f.refused(lambda candidate=candidate: f.renewal.renew(candidate), (ValueError, f.schema.CatalogConflict))
        f.refused(lambda: f.renewal.renew(f.request(expected_token_generation=True)), ValueError)
        deadline = f.application()["client_renewal"]["expires_at_epoch_ms"]
        f.now = deadline - 30_000
        request, result = committed_renewal(f)
        assert request.token_expires_at_epoch_ms == deadline
        assert result["operation"]["previous_accept_until_epoch_ms"] == deadline
        f.now = deadline
        f.refused(lambda: f.renewal.renew(request), f.schema.CatalogConflict)
    return {"proof_deadlines_and_exact_expiry_refused": True}


def overlap_and_old_operation():
    f = Fixture()
    with f.observed():
        f.enroll()
        first, result = committed_renewal(f)
        candidate = f.request()
        f.refused(lambda: f.renewal.renew(candidate), f.schema.CatalogConflict)
        f.now = result["operation"]["previous_accept_until_epoch_ms"]
        second, next_result = committed_renewal(f)
        assert second.operation_id != first.operation_id
        assert next_result["operation"]["token_generation"] == result["operation"]["token_generation"] + 1
        f.refused(lambda: f.renewal.renew(first), f.schema.CatalogConflict)
    return {"one_overlap_owner_and_old_operation_refused": True}


def replacement():
    f = Fixture()
    with f.observed():
        f.enroll()
        old_request, _ = committed_renewal(f)
        old = f.application()
        result = f.enroll(public_key=f.other_public_key)
        current = f.application()
        assert current["client_renewal"]["enrollment_id"] != old["client_renewal"]["enrollment_id"]
        assert current["client_renewal"]["public_key"] == f.other_public_key
        assert current["client_renewal"]["previous_token"] is current["client_renewal"]["last_operation"] is None
        assert current["token_sha256"] == old["token_sha256"] and current["token_version"] == old["token_version"]
        assert current["token_expires_at_epoch_ms"] <= old["token_expires_at_epoch_ms"]
        f.refused(lambda: f.renewal.renew(old_request), f.schema.CatalogConflict)
        f.refused(lambda: f.renewal.renew(f.request()), ValueError)
        assert f.renewal.renew(f.request(key=f.other_key))["operation"]["token_generation"] == current["token_version"] + 1
        f.assert_no_secrets(result)
    return {"replacement_invalidates_old_enrollment_and_overlap": True}


def cancel():
    f = Fixture()
    with f.observed():
        f.refused(lambda: f.renewal.cancel(f.target(), ACTOR), f.schema.CatalogConflict)
        f.enroll()
        request, _ = committed_renewal(f)
        old, original = f.application(), f.target()
        for update in ({"expected_revision": original.expected_revision - 1},
                {"expected_policy_hash": "sha256:" + "0" * 64}):
            stale = original.model_copy(update=update)
            f.refused(lambda stale=stale: f.renewal.cancel(stale, ACTOR), f.schema.CatalogConflict)
        result = f.renewal.cancel(original, ACTOR)
        current = f.application()
        assert "client_renewal" not in current and result["application"]["client_renewal"] is None
        assert current["client_renewal_cancelled_at_epoch_ms"] == f.now
        assert result["application"]["client_renewal_cancelled_at_epoch_ms"] == f.now
        assert f.public_key not in json.dumps(current)
        assert (current["token_sha256"], current["token_version"], current["token_expires_at_epoch_ms"]) == (
            old["token_sha256"], old["token_version"], old["token_expires_at_epoch_ms"])
        assert "managedRenewal" not in f.principal()["proxyAuthorization"]
        f.refused(lambda: f.renewal.cancel(original, ACTOR), f.schema.CatalogConflict)
        f.refused(lambda: f.renewal.cancel(f.target(), ACTOR), f.schema.CatalogConflict)
        f.refused(lambda: f.renewal.renew(request), f.schema.CatalogConflict)
    return {"cancel_cas_manual_only_and_repeat_guards": True}


def manual_change(revoke=False):
    f = Fixture()
    with f.observed():
        f.enroll()
        request, _ = committed_renewal(f)
        old, core = f.application(), workspace.rows(f.db, "credentials")
        if revoke:
            result = f.mutations.revoke_application(f.target(), ACTOR)
        else:
            result = f.mutations.rotate_application_token(f.inputs.RotateApplicationInput(
                **f.review(), id=f.application_id, token_lifetime_seconds=3600), ACTOR)
            f.tokens.append(result["client_token"])
        current = f.application()
        assert "client_renewal" not in current
        assert type(current["client_renewal_cancelled_at_epoch_ms"]) is int
        assert f.public_key not in json.dumps(current)
        assert workspace.rows(f.db, "credentials") == core
        if revoke:
            assert current["status"] == "revoked" and current["token_sha256"] == old["token_sha256"]
            assert current["principal_id"] not in {row["id"] for row in f.signed()["principals"]}
        else:
            assert current["token_version"] == old["token_version"] + 1
            assert "managedRenewal" not in f.principal()["proxyAuthorization"]
        f.refused(lambda: f.renewal.renew(request), f.schema.CatalogConflict)
        f.assert_no_secrets({key: value for key, value in result.items() if key != "client_token"})
    return {"manual_action_cancels_enrollment": True, "revoked": revoke}


def materialization_uncertainty():
    f = Fixture()
    with f.observed():
        f.enroll()
        old_file, old_audit = f.config.POLICY_BUNDLE_PATH.read_bytes(), f.audit()
        request, replace = f.request(), os.replace

        def refuse_policy(source, destination, *args, **kwargs):
            if Path(destination) == f.config.POLICY_BUNDLE_PATH:
                raise OSError("synthetic workload policy materialization failure")
            return replace(source, destination, *args, **kwargs)

        with patch.object(os, "replace", refuse_policy):
            result = f.renewal.renew(request)
        assert result["policy"]["activation"] == "pending"
        assert f.application()["client_renewal"]["last_operation"] == result["operation"]
        assert len(f.audit()) == len(old_audit) + 1 and f.config.POLICY_BUNDLE_PATH.read_bytes() == old_file
        assert f.bundles.get_policy_snapshot() is None, "stale materialized policy remained usable"
        committed = f.snapshot()
        f.now = request.expires_at_epoch_ms + 1
        recovered = f.renewal.renew(request)
        assert recovered["operation"] == result["operation"] and recovered["policy"]["activation"] == "pending"
        assert f.snapshot() == committed, "unknown-outcome recovery retried issuance or file publication"
        f.demo.materialize()
        materialized = f.snapshot()
        recovered = f.renewal.renew(request)
        assert recovered["operation"] == result["operation"] and recovered["policy"]["activation"] == "active"
        assert f.snapshot() == materialized
        f.signed()
    return {"postcommit_unknown_recovers_exactly_without_reissuance": True}


def observation_drift(resource=False):
    f = Fixture()
    with f.observed():
        f.enroll()
        request, result = committed_renewal(f)
        captured = {}

        def change():
            if resource:
                f.renewal.cancel(f.target(), ACTOR)
            else:
                f.mutations.revoke_rule(f.inputs.TargetInput(**f.review(), id=f.rule_id), ACTOR)
            captured["state"] = f.snapshot()

        f.gate_hook = change
        try:
            recovered = f.renewal.renew(request)
        except f.schema.CatalogConflict:
            pass
        else:
            assert recovered["operation"] == result["operation"]
            assert recovered["policy"]["activation"] == "pending", "stale observation asserted activation"
        assert "state" in captured, "recovery never made the fresh gate observation"
        assert f.snapshot() == captured["state"], "recovery changed authority after the independent mutation"
        if resource:
            assert "client_renewal" not in f.application()
        f.signed()
    return {"resource_drift" if resource else "policy_drift": "no_false_activation_or_renewal_write"}


def gate_refusal():
    f = Fixture()
    with f.observed():
        before = f.snapshot()
        descriptor = {"schema": f.wire.SCHEMA, "enroll_path": f.wire.ENROLL_PATH,
            "cancel_path": f.wire.CANCEL_PATH, "path": f.wire.PUBLIC_PATH,
            "audience": "https://proxy.example.com" + f.wire.PUBLIC_PATH,
            "overlap_seconds": f.wire.OVERLAP_SECONDS,
            "token_lifetime_seconds": {"min": f.wire.MIN_TOKEN_LIFETIME_SECONDS,
                "max": f.wire.MAX_TOKEN_LIFETIME_SECONDS, "default": f.wire.DEFAULT_TOKEN_LIFETIME_SECONDS},
            "enrollment_lifetime_seconds": {"min": f.wire.MIN_ENROLLMENT_LIFETIME_SECONDS,
                "max": f.wire.MAX_ENROLLMENT_LIFETIME_SECONDS,
                "default": f.wire.DEFAULT_ENROLLMENT_LIFETIME_SECONDS}, "single_writer": True}
        assert f.renewal.capability() == descriptor
        for transform in (lambda value: {**value, "operator_workload_renewal": None},
                lambda value: {**value, "operator_workload_renewal": {**f.wire.gate_descriptor(), "overlap_seconds": 301}},
                lambda value: {**value, "policy_hash": "sha256:" + "0" * 64}):
            f.gate_transform = transform
            assert f.renewal.capability() == descriptor, "static descriptor became a readiness claim"
            assert f.renewal.observe()["ready"] is False
            f.refused(f.enroll, f.schema.CatalogConflict)
        assert f.snapshot() == before
        f.gate_transform = lambda value: value
        assert f.renewal.observe()["ready"] is True
        f.enroll()
        request = f.request()
        f.gate_transform = lambda value: {**value, "operator_workload_renewal": None}
        f.refused(lambda: f.renewal.renew(request), f.schema.CatalogConflict)
    return {"gate_capability_and_policy_must_match": True}


def before_first_observation():
    f = Fixture()
    with f.observed():
        f.enroll()
        request, result = committed_renewal(f)
        original = f.renewal._result
        captured = {}

        def changed(identifier, operation):
            rotated = f.mutations.rotate_application_token(f.inputs.RotateApplicationInput(
                **f.review(), id=f.application_id, token_lifetime_seconds=3600), ACTOR)
            f.tokens.append(rotated["client_token"])
            captured["state"] = f.snapshot()
            return original(identifier, operation)

        with patch.object(f.renewal, "_result", side_effect=changed):
            recovered = f.renewal.renew(request)
        assert recovered["operation"] == result["operation"]
        assert recovered["application"]["token_generation"] == result["operation"]["token_generation"] + 1
        assert recovered["application"]["client_renewal"] is None
        assert recovered["policy"]["activation"] == "pending"
        assert f.snapshot() == captured["state"]
        f.assert_no_secrets(recovered)
    return {"pre_observation_rotation_cannot_activate_historical_operation": True}


def acknowledgement_failure():
    f = Fixture()
    with f.observed():
        f.enroll()
        request, audit = f.request(), f.audit()
        with patch.object(f.renewal, "_result", side_effect=ValueError("synthetic postcommit projection failure")):
            try:
                f.renewal.renew(request)
            except RuntimeError as error:
                assert str(error) == "workload renewal outcome observation unavailable"
            else:
                raise AssertionError("postcommit failure did not remain an unknown outcome")
        operation = f.application()["client_renewal"]["last_operation"]
        assert operation["operation_id"] == request.operation_id
        assert len(f.audit()) == len(audit) + 1
        committed = f.snapshot()
        recovered = f.renewal.renew(request)
        assert recovered["operation"] == operation
        assert f.snapshot() == committed
    return {"postcommit_parser_failure_is_unknown_not_proof_rejection": True}


def unassigned_renewal():
    f = Fixture()
    with f.observed():
        f.mutations.revoke_rule(f.inputs.TargetInput(**f.review(), id=f.rule_id), ACTOR)
        f.enroll()
        before_rules = deepcopy(f.catalog()["access_rules"])
        before_audit = len(f.audit())
        request = f.request()
        result = f.renewal.renew(request)
        operation = result["operation"]
        assert result["policy"]["activation"] == "pending"
        assert result["application"]["active_rule_count"] == 0
        assert result["application"]["access_status"] == "unassigned"
        assert f.catalog()["access_rules"] == before_rules
        assert len(f.audit()) == before_audit + 1
        principal_id = f.application()["principal_id"]
        assert principal_id not in {row["id"] for row in f.signed()["principals"]}
        committed = f.snapshot()
        recovered = f.renewal.renew(request)
        assert recovered["operation"] == operation and recovered["policy"]["activation"] == "pending"
        assert f.snapshot() == committed
        # Only this explicit administrator action grants a permission. The
        # original signed renewal then recovers without issuing another token.
        workspace.create_rule(f.db, f.demo, f.schema, f.inputs, f.mutations,
            f.application_id, f.credential_id, name="Explicit permission after renewal")
        assigned = f.snapshot()
        recovered = f.renewal.renew(request)
        assert recovered["operation"] == operation
        assert recovered["policy"]["activation"] == "active"
        assert recovered["application"]["active_rule_count"] == 1
        assert recovered["application"]["access_status"] == "active"
        assert f.snapshot() == assigned
    return {"unassigned_issuance_grants_nothing_and_recovers_after_explicit_permission": True}


def malformed_metadata():
    f = Fixture()
    with f.observed():
        f.enroll()
        committed_renewal(f)
        valid = f.application()
        malformed = [{**valid, "client_renewal": None},
            {**valid, "client_renewal_cancelled_at_epoch_ms": f.now},
            {**valid, "client_renewal_cancelled_at_epoch_ms": True}]

        def altered(path, value=None, *, remove=False):
            record = deepcopy(valid)
            selected = record["client_renewal"]
            for key in path[:-1]:
                selected = selected[key]
            if remove:
                del selected[path[-1]]
            else:
                selected[path[-1]] = value
            malformed.append(record)

        for path, value in ((["unexpected"], 1), (["version"], True), (["version"], 2),
                (["enrollment_id"], "not-a-uuid"), (["public_key"], "G" * 64),
                (["enrolled_at_epoch_ms"], True), (["expires_at_epoch_ms"], valid["client_renewal"]["enrolled_at_epoch_ms"]),
                (["token_lifetime_seconds"], 3599), (["overlap_seconds"], 301),
                (["previous_token"], {}), (["previous_token", "unexpected"], 1),
                (["previous_token", "token_generation"], True),
                (["previous_token", "token_sha256"], valid["token_sha256"]),
                (["previous_token", "accept_until_epoch_ms"], valid["client_renewal"]["last_operation"]["rotated_at_epoch_ms"] + 300_001),
                (["last_operation"], {}), (["last_operation", "unexpected"], 1),
                (["last_operation", "token_generation"], valid["token_version"] + 1),
                (["last_operation", "application_id"], str(uuid.uuid4())),
                (["last_operation", "token_sha256"], "sha256:" + "f" * 64)):
            altered(path, value)
        for key in RENEWAL_KEYS:
            altered([key], remove=True)
        for key in RECEIPT_KEYS:
            altered(["last_operation", key], remove=True)
        before = f.snapshot()
        for record in malformed:
            try:
                f.renewal.validate(record)
            except f.schema.CatalogIntegrityError:
                pass
            else:
                raise AssertionError("malformed retained renewal metadata accepted")
        assert f.snapshot() == before
        # A real retained malformed row must fail the catalog startup validator,
        # not only a direct unit call of the new validator.
        record = {key: value for key, value in valid.items() if key not in {"id", "ordinal"}}
        record["client_renewal"] = None
        with closing(f.db.connect()) as conn, conn:
            conn.execute("UPDATE operator_catalog_applications SET data_json=? WHERE id=?",
                (json.dumps(record, sort_keys=True, separators=(",", ":")), f.application_id))
        f.refused(lambda: f.catalog(), f.schema.CatalogIntegrityError)
    return {"malformed_metadata_controls": len(malformed), "catalog_rejects_explicit_null": True}


SCENARIOS = {
    "enrollment": enrollment,
    "short-enrollment": short_or_expired_enrollment,
    "expired-enrollment": lambda: short_or_expired_enrollment(True),
    "renew-replay": renew_and_replay,
    "proof-deadlines": proof_and_deadlines,
    "overlap": overlap_and_old_operation,
    "replacement": replacement,
    "cancel": cancel,
    "manual-rotation": manual_change,
    "revocation": lambda: manual_change(True),
    "materialization": materialization_uncertainty,
    "policy-drift": observation_drift,
    "resource-drift": lambda: observation_drift(True),
    "gate-refusal": gate_refusal,
    "before-observation": before_first_observation,
    "acknowledgement-failure": acknowledgement_failure,
    "unassigned": unassigned_renewal,
    "malformed-metadata": malformed_metadata,
}


class OperatorWorkloadRenewalStoreTests(unittest.TestCase):
    setUp = workspace.common.OperatorDemoPersistenceTests.setUp

    def run_worker(self, operation):
        environment = dict(self.environment, SERVERWARE_DECISION_GATE_BASE="")
        result = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()), "--worker", operation],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, "\n".join(result.stderr.splitlines()[-50:]))
        return json.loads(result.stdout)

    def test_explicit_enrollment_clips_expiry_without_issuing_or_disclosing_token(self):
        self.assertTrue(self.run_worker("enrollment")["enrollment_clips_without_issuance"])

    def test_enrollment_never_extends_a_short_existing_token(self):
        self.assertTrue(self.run_worker("short-enrollment")["old_expiry_preserved"])

    def test_expired_active_client_can_enroll_without_resurrecting_old_token(self):
        self.assertTrue(self.run_worker("expired-enrollment")["old_expiry_preserved"])

    def test_one_atomic_renewal_and_exact_fresh_or_expired_recovery(self):
        self.assertTrue(self.run_worker("renew-replay")["one_issuance_fresh_and_expired_recovery_read_only"])

    def test_proof_audience_deadlines_and_exact_expiry_are_required(self):
        self.assertTrue(self.run_worker("proof-deadlines")["proof_deadlines_and_exact_expiry_refused"])

    def test_active_overlap_blocks_next_rotation_and_old_operations_cannot_replay(self):
        self.assertTrue(self.run_worker("overlap")["one_overlap_owner_and_old_operation_refused"])

    def test_replacement_enrollment_invalidates_old_key_receipt_and_overlap(self):
        self.assertTrue(self.run_worker("replacement")["replacement_invalidates_old_enrollment_and_overlap"])

    def test_cancellation_preserves_current_token_and_refuses_stale_or_repeat_actions(self):
        self.assertTrue(self.run_worker("cancel")["cancel_cas_manual_only_and_repeat_guards"])

    def test_manual_rotation_cancels_enrollment_and_overlap(self):
        self.assertTrue(self.run_worker("manual-rotation")["manual_action_cancels_enrollment"])

    def test_revocation_cancels_enrollment_without_touching_provider_secret(self):
        self.assertTrue(self.run_worker("revocation")["manual_action_cancels_enrollment"])

    def test_postcommit_materialization_failure_recovers_without_new_issuance(self):
        self.assertTrue(self.run_worker("materialization")["postcommit_unknown_recovers_exactly_without_reissuance"])

    def test_policy_observation_drift_never_reports_old_operation_active(self):
        self.assertEqual(self.run_worker("policy-drift")["policy_drift"], "no_false_activation_or_renewal_write")

    def test_resource_observation_drift_never_reports_cancelled_operation_active(self):
        self.assertEqual(self.run_worker("resource-drift")["resource_drift"], "no_false_activation_or_renewal_write")

    def test_gate_descriptor_and_current_policy_are_required_for_new_authority(self):
        self.assertTrue(self.run_worker("gate-refusal")["gate_capability_and_policy_must_match"])

    def test_rotation_before_first_observation_cannot_activate_historical_operation(self):
        self.assertTrue(self.run_worker("before-observation")["pre_observation_rotation_cannot_activate_historical_operation"])

    def test_postcommit_projection_failure_is_unknown_and_recovers_exactly(self):
        self.assertTrue(self.run_worker("acknowledgement-failure")["postcommit_parser_failure_is_unknown_not_proof_rejection"])

    def test_unassigned_renewal_grants_nothing_and_recovers_after_explicit_permission(self):
        self.assertTrue(self.run_worker("unassigned")["unassigned_issuance_grants_nothing_and_recovers_after_explicit_permission"])

    def test_strict_retained_metadata_and_catalog_validation(self):
        self.assertGreater(self.run_worker("malformed-metadata")["malformed_metadata_controls"], 30)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        if not __debug__:
            raise RuntimeError("renewal fixture requires active assertions")
        os.umask(0o077)

        def no_network(event, _args):
            if event.startswith("socket."):
                raise AssertionError("renewal store fixture attempted network access")

        sys.addaudithook(no_network)
        print(json.dumps(SCENARIOS[sys.argv[2]](), sort_keys=True))
    else:
        unittest.main(verbosity=2)
