#!/usr/bin/env python3
"""JIT ingress/kernel components: no custody, durable insertion or admission.

The installed DB facade is intercepted at its dispatch boundary by a terminal
sentinel, never a successful writer response. Normalization, business-intent
and authorization digests, and the actual query/transition kernel are real.
The local signature tests immutable bytes, not a trusted authority envelope.
Expiry controls additionally execute the real kernel over explicitly synthetic
admitted selected rows. Their receipt digests and retained originals exercise
the actual opaque/evidence/aggregate consumers, not custody or root admission.
No database, transport, provider, native pilot or durable receipt is created.
"""
from __future__ import annotations

import copy
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def no_network(event, _args):
    if event.startswith("socket."):
        raise AssertionError("JIT ingress component tests forbid sockets and DNS")


if __name__ == "__main__":
    sys.addaudithook(no_network)
    # Offline import-only validator mode, never application startup. Importing
    # these fixture helpers must preserve the caller suite's selected mode.
    os.environ["SERVERWARE_PROCESS_MODE"] = "metadata-bootstrap"
    os.environ["SERVERWARE_RELEASE_CHANNEL"] = "dev"

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from serverware import authority_contract as contract
from serverware import authority_jit_request as ingress
from serverware import authority_service as service
from serverware import authority_transition_core as core
from serverware import authority_transition_quota as quota
from serverware import db
from serverware.authority_store import authority_dispatch

NOW = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)
PUBLIC_FIELDS = frozenset({"route_id", "method", "url", "principal_id",
    "credential_id", "credential_version", "policy_hash", "request_digest",
    "operation_digest", "canonical_request", "redacted_display",
    "pending_ttl_seconds", "grant_ttl_seconds", "grant_max_uses",
    "required_approver_roles", "allowed_approver_ids", "require_approver_webauthn",
    "approval_threshold", "approver_credential_policy"})


def canonical(value):
    return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def framed(domain, value):
    raw = canonical(value)
    return sha(domain.encode("ascii") + b"\0" + len(raw).to_bytes(8, "big") + raw)


def identity(request_digest, purpose):
    raw = hashlib.sha256(canonical({
        "schema": "serverware.policyAuthorityDeterministicIdentity/v1",
        "operation": "jit.request", "requestDigest": request_digest,
        "purpose": purpose})).digest()
    return str(uuid.UUID(bytes=raw[:16], version=5))


def policy():
    return {"schema": "serverware.jitApproverPolicy/v1",
        "requiredRoles": ["approver"], "roleMatch": "any",
        "allowedApproverIds": ["oidc:alpha", "oidc:beta"],
        "allowAnyApproverId": False, "requireWebAuthn": True, "threshold": 2,
        "credentialPolicy": {
            "allowedCredentialRecordIds": [],
            "allowedAuthenticatorClasses": ["hardware", "yubikey"],
            "allowedAaguids": [], "requireAttestationTrusted": True,
            "requiredTrustBundleDigest": None, "minimumTrustBundleSequence": None,
            "rpId": "synthetic.invalid", "origins": ["https://synthetic.invalid"],
            "requireUserPresence": True, "requireUserVerification": True,
            "counterPolicy": "strict-or-zero", "maxAssertionAgeSeconds": 30}}


def public_arguments():
    # The actual production route helper fills the explicit RP/origin fields.
    # Only its local configuration inputs are synthetic; no trust is admitted.
    with patch.object(db, "WEBAUTHN_RP_ID", "synthetic.invalid"), \
            patch.object(db, "WEBAUTHN_ORIGIN", "https://synthetic.invalid"):
        approvers = db.jit_approver_policy_arguments({"approvers": {
            "users": ["oidc:beta", "oidc:alpha"], "quorum": 2,
            "authn": {"maxAssertionAgeSeconds": 30}}})
    return {"route_id": "route:synthetic", "method": "PUT",
        "url": "https://registry.npmjs.org/@fixture%2fpackage",
        "principal_id": "agent:synthetic", "credential_id": "credential:synthetic",
        "credential_version": 7, "policy_hash": "sha256:" + "1" * 64,
        "request_digest": "sha256:" + "2" * 64,
        "operation_digest": "sha256:" + "3" * 64,
        "canonical_request": {"request": {"method": "PUT", "body_sha256": "sha256:" + "4" * 64},
            "operation": {"packageName": "@fixture/package", "packageVersion": "1.0.0"}},
        "redacted_display": {"package": "@fixture/package", "label": "caf\u00e9", "nested": {
            "$authorityType": "bytes", "base64Url": "literal-json-not-a-typed-argument"}},
        "pending_ttl_seconds": 300, "grant_ttl_seconds": 30, "grant_max_uses": 1,
        **approvers}


class DispatchReached(Exception):
    pass


def dispatch_input(values):
    captured = []

    def stop(operation, document):
        captured.append((operation, copy.deepcopy(document)))
        raise DispatchReached

    with patch.object(db, "dispatch_policy_authority_operation", side_effect=stop), \
            patch.object(db, "connect", side_effect=AssertionError("unexpected database access")):
        try:
            db.ensure_jit_approval_request(**values)
        except DispatchReached:
            pass
        else:
            raise AssertionError("installed facade did not reach the dispatch boundary")
    if len(captured) != 1:
        raise AssertionError("dispatch count changed")
    return captured[0]


def arguments():
    # Preserve the original raw projection as a component oracle, not as an
    # admitted durable request. The installed facade now uses private ingress.
    raw = authority_dispatch._authority_marshal_value(public_arguments())
    return raw, service._synthesize_business_arguments("jit.request", raw), \
        service._controlled_writer_request_digest("jit.request", raw)


def kernel_arguments(values=None):
    _operation, document = dispatch_input(public_arguments() if values is None else values)
    raw, explicit, _private = service._extract_v9_runtime_input(
        "jit.request", "ensure_jit_approval_request", document)
    assert explicit is None
    return raw, service._synthesize_business_arguments("jit.request", raw), \
        service._controlled_writer_request_digest("jit.request", raw)


class JitRequestIngressTests(unittest.TestCase):
    def normalize(self, value, digest):
        return ingress.normalize(value, request_digest=digest)

    def refused(self, value, digest):
        with self.assertRaises(core.TransitionKernelError):
            self.normalize(value, digest)

    def test_installed_facade_signature_marshaling_and_default_fields(self):
        values = public_arguments()
        before = copy.deepcopy(values)
        operation, document = dispatch_input(values)
        self.assertEqual(operation, "jit.request")
        self.assertEqual(set(document), {"schema", "handler", "operationManifestDigest", "arguments", "privateDocuments"})
        self.assertEqual(document["schema"], "serverware.policyAuthorityPrivateJitWriterInput/v2")
        self.assertEqual(document["handler"], "ensure_jit_approval_request")
        self.assertEqual(document["operationManifestDigest"], contract.OPERATION_MANIFEST_DIGEST)
        self.assertEqual(set(inspect.signature(db.ensure_jit_approval_request).parameters), PUBLIC_FIELDS)
        self.assertEqual(document["arguments"]["schema"], "serverware.jitRequestCommitments/v2")
        self.assertEqual(set(document["privateDocuments"]), {"url", "canonical_request", "redacted_display"})
        raw = {key: copy.deepcopy(value) for key, value in document["arguments"].items()
            if key in PUBLIC_FIELDS}
        raw.update(document["privateDocuments"])
        self.assertEqual(set(raw), PUBLIC_FIELDS)
        self.assertEqual(raw["required_approver_roles"], {"$authorityType": "set", "items": ["approver"]})
        self.assertEqual(raw["allowed_approver_ids"], {"$authorityType": "set", "items": ["oidc:alpha", "oidc:beta"]})
        for key in PUBLIC_FIELDS - {"required_approver_roles", "allowed_approver_ids"}:
            self.assertEqual(raw[key], values[key])
        self.assertEqual(values, before)
        for key in ("required_approver_roles", "allowed_approver_ids", "require_approver_webauthn",
                "approval_threshold", "approver_credential_policy"):
            values.pop(key)
        with patch.object(db, "dispatch_policy_authority_operation") as send:
            with self.assertRaises(db.MetadataStoreError):
                db.ensure_jit_approval_request(**values)
            send.assert_not_called()
        for extra in ({"businessIntent": {}}, {"_connection": object()}, {"url_commitment": "sha256:" + "5" * 64}):
            with self.subTest(extra=tuple(extra)), patch.object(db, "dispatch_policy_authority_operation") as send:
                with self.assertRaises(db.MetadataStoreError):
                    db.ensure_jit_approval_request(**public_arguments(), **extra)
                send.assert_not_called()

    def test_actual_route_policy_parity_and_independent_commitment_projection(self):
        raw, value, digest = arguments()
        expected_policy = policy()
        public = public_arguments()
        with patch.object(db, "WEBAUTHN_RP_ID", "synthetic.invalid"), \
                patch.object(db, "WEBAUTHN_ORIGIN", "https://synthetic.invalid"):
            self.assertEqual(db._normalize_jit_approver_policy(
                required_roles=public["required_approver_roles"], allowed_approver_ids=public["allowed_approver_ids"],
                require_webauthn=True, threshold=2, credential_policy=public["approver_credential_policy"]), expected_policy)
        projected = self.normalize(value, digest)
        removed = {"url", "canonical_request", "redacted_display", "required_approver_roles",
            "allowed_approver_ids", "require_approver_webauthn", "approval_threshold", "approver_credential_policy"}
        expected = {key: copy.deepcopy(item) for key, item in value.items() if key not in removed}
        expected.update(url_commitment=sha(raw["url"].encode("utf-8")),
            canonical_request_digest=sha(canonical(raw["canonical_request"])),
            redacted_display_digest=sha(canonical(raw["redacted_display"])),
            canonical_request_opaque_id=identity(digest, "jit-canonical-request"),
            redacted_display_opaque_id=identity(digest, "jit-redacted-display"),
            approver_policy=expected_policy, approver_policy_digest=framed("serverware.jitApproverPolicy/v1", expected_policy))
        self.assertEqual(projected, expected)
        self.assertNotEqual(projected["canonical_request_opaque_id"], projected["redacted_display_opaque_id"])
        changed_raw = copy.deepcopy(raw)
        changed_raw["approver_credential_policy"]["requireAttestationTrusted"] = False
        changed = self.normalize(service._synthesize_business_arguments("jit.request", changed_raw), digest)
        self.assertEqual(changed["approver_policy"], {**expected_policy, "credentialPolicy": {
            **expected_policy["credentialPolicy"], "requireAttestationTrusted": False}})
        with patch.object(db, "WEBAUTHN_RP_ID", "synthetic.invalid"), \
                patch.object(db, "WEBAUTHN_ORIGIN", "https://synthetic.invalid"):
            self.assertEqual(changed["approver_policy"], db._normalize_jit_approver_policy(
                required_roles=public["required_approver_roles"], allowed_approver_ids=public["allowed_approver_ids"],
                require_webauthn=True, threshold=2, credential_policy=changed_raw["approver_credential_policy"]))

    def test_original_authorization_bytes_and_intent_are_not_rewritten(self):
        raw, value, digest = arguments()
        original = copy.deepcopy(value)
        envelope = {"schema": "serverware.policyAuthorityV9Authorization/v1", "operation": "jit.request",
            "handler": "ensure_jit_approval_request", "operationManifestDigest": contract.OPERATION_MANIFEST_DIGEST,
            "arguments": value}
        self.assertEqual(digest, framed("serverware.policyAuthorityV9Request/v1", envelope))
        signer = Ed25519PrivateKey.generate()
        signature = signer.sign(canonical(envelope))
        projected = self.normalize(value, digest)
        self.assertEqual(value, original)
        self.assertEqual(projected["businessIntent"], original["businessIntent"])
        self.assertEqual(projected["businessIntent"]["arguments"], raw)
        signer.public_key().verify(signature, canonical(envelope))
        with self.assertRaises(InvalidSignature):
            signer.public_key().verify(signature, canonical({**envelope, "arguments": projected}))
        for key, replacement in (("url", raw["url"] + "?changed=1"),
                ("canonical_request", {"changed": True}), ("redacted_display", {"changed": True}),
                ("grant_max_uses", 2)):
            changed = copy.deepcopy(value)
            changed[key] = replacement
            self.refused(changed, digest)
        changed = copy.deepcopy(value)
        changed["businessIntent"]["arguments"]["method"] = "GET"
        self.refused(changed, digest)

    def test_deterministic_ids_follow_original_envelope_not_inner_request_digest(self):
        raw, value, digest = arguments()
        first = self.normalize(value, digest)
        self.assertEqual(first, self.normalize(dict(reversed(list(value.items()))), digest))
        alternate_digest = "sha256:" + "a" * 64
        second = self.normalize(value, alternate_digest)
        changed_fields = {key for key in first if first[key] != second[key]}
        self.assertEqual(changed_fields, {"canonical_request_opaque_id", "redacted_display_opaque_id"})
        self.assertEqual(second["canonical_request_opaque_id"], identity(alternate_digest, "jit-canonical-request"))
        self.assertNotEqual(first["canonical_request_opaque_id"], identity(raw["request_digest"], "jit-canonical-request"))
        changed_raw = {**raw, "url": raw["url"] + "?changed=1"}
        changed_digest = service._controlled_writer_request_digest("jit.request", changed_raw)
        self.assertNotEqual(changed_digest, digest)
        changed = self.normalize(service._synthesize_business_arguments("jit.request", changed_raw), changed_digest)
        self.assertNotEqual(first["canonical_request_opaque_id"], changed["canonical_request_opaque_id"])

    def test_closed_fields_and_exact_scalar_types_refuse(self):
        raw, value, digest = arguments()
        for key in value:
            changed = copy.deepcopy(value)
            changed.pop(key)
            with self.subTest(missing=key):
                self.refused(changed, digest)
        for key in ("canonical_request_opaque_id", "url_commitment", "approver_policy", "extra"):
            with self.subTest(extra=key):
                self.refused({**value, key: "caller-selected"}, digest)
        bad = (("method", "put"), ("route_id", ""), ("credential_version", True),
            ("credential_version", -1), ("pending_ttl_seconds", 0), ("pending_ttl_seconds", 3601),
            ("grant_ttl_seconds", 1.0), ("grant_ttl_seconds", 3601), ("grant_max_uses", True),
            ("grant_max_uses", 1_000_001), ("approval_threshold", True), ("approval_threshold", 3),
            ("require_approver_webauthn", 1), ("policy_hash", "sha256:" + "A" * 64),
            ("canonical_request", []), ("redacted_display", None), ("url", ""))
        for key, replacement in bad:
            changed = {**raw, key: replacement}
            with self.subTest(field=key, value=replacement):
                self.refused(service._synthesize_business_arguments("jit.request", changed), digest)
        for malformed in (None, True, "0" * 64, "sha256:" + "A" * 64):
            with self.subTest(digest=malformed):
                self.refused(value, malformed)

    def test_policy_marshaling_explicit_identity_and_document_bounds(self):
        raw, _value, digest = arguments()
        changes = []
        for field in ("rpId", "origins"):
            changed = copy.deepcopy(raw)
            changed["approver_credential_policy"].pop(field)
            changes.append(changed)
        for field, invalid in (("rpId", ""), ("origins", []), ("maxAssertionAgeSeconds", 31),
                ("requireUserVerification", False), ("requireAttestationTrusted", 1), ("unknown", True)):
            changed = copy.deepcopy(raw)
            changed["approver_credential_policy"][field] = invalid
            changes.append(changed)
        for field, invalid in (("required_approver_roles", ["approver"]),
                ("required_approver_roles", {"$authorityType": "set", "items": ["approver", "approver"]}),
                ("allowed_approver_ids", {"$authorityType": "set", "items": ["oidc:beta", "oidc:alpha"]}),
                ("allowed_approver_ids", {"$authorityType": "tuple", "items": ["oidc:alpha", "oidc:beta"]})):
            changes.append({**raw, field: invalid})
        changes.append({**raw, "redacted_display": {"oversized": "x" * (64 * 1024)}})
        changes.append({**raw, "canonical_request": {"padding": "x" * (33 * 1024)},
            "redacted_display": {"padding": "y" * (33 * 1024)}})
        deep = {"leaf": "value"}
        for _ in range(18):
            deep = {"nested": deep}
        changes.append({**raw, "canonical_request": deep})
        for number, changed in enumerate(changes):
            with self.subTest(control=number):
                self.refused(service._synthesize_business_arguments("jit.request", changed), digest)
        below = {**raw, "canonical_request": {"padding": "x" * (15 * 1024)},
            "redacted_display": {"padding": "y" * (15 * 1024)}}
        self.normalize(service._synthesize_business_arguments("jit.request", below), digest)
        self.assertEqual(ingress.MAX_PAYLOAD_BYTES, 65536)
        boundary = {**raw, "redacted_display": {"padding": ""}}
        base_size = sum(len((boundary[key] or "").encode("utf-8")) for key in (
            "route_id", "method", "url", "principal_id", "credential_id", "policy_hash",
            "request_digest", "operation_digest")) + len(canonical(boundary["canonical_request"])) \
            + len(canonical(boundary["redacted_display"])) + len(canonical(policy()))
        boundary["redacted_display"]["padding"] = "x" * (65536 - base_size)
        self.normalize(service._synthesize_business_arguments("jit.request", boundary), digest)
        boundary["redacted_display"]["padding"] += "x"
        self.refused(service._synthesize_business_arguments("jit.request", boundary), digest)

    def test_real_query_plan_is_deterministic_and_binds_derived_custody_ids(self):
        _raw, value, digest = kernel_arguments()
        before = copy.deepcopy(value)
        kernel = quota.KERNELS["jit.request"]
        first = kernel.queries(arguments=value, database_now=NOW, request_digest=digest)
        self.assertEqual(first, kernel.queries(arguments=value, database_now=NOW, request_digest=digest))
        self.assertEqual(value, before)
        self.assertEqual([query.table for query in first], ["approval_requests", "routes",
            "policy_authority_opaque_values", "policy_authority_external_evidence_receipts",
            "policy_authority_opaque_values", "policy_authority_external_evidence_receipts",
            "policy_authority_bounded_aggregate_states", "metadata_audit_outbox"])
        self.assertEqual(first[0].absent_key, {"id": identity(digest, "jit-approval-request")})
        self.assertEqual(first[1].absent_key, {"id": "route:synthetic"})
        self.assertEqual(first[2].absent_key, {"opaque_id": identity(digest, "jit-canonical-request")})
        self.assertEqual(first[4].absent_key, {"opaque_id": identity(digest, "jit-redacted-display")})
        self.assertTrue(all(query.maximum_rows == 1 for query in first))
        self.assertLessEqual({query.table for query in first}, set(contract.operation_spec("jit.request")["reads"]))
        self.assertIn("key-custody-seal/v1", contract.operation_spec("jit.request")["externalEvidenceTypes"])

    def test_valid_public_input_still_refuses_missing_custody_without_mutations(self):
        _raw, value, digest = kernel_arguments()
        before = copy.deepcopy(value)
        context = core.KernelContext(operation="jit.request", arguments=value, selected_rows=(),
            database_now=NOW, request_digest=digest)
        with patch.object(core, "mutation", side_effect=AssertionError("mutation preceded custody")) as mutation:
            with self.assertRaisesRegex(core.TransitionKernelError,
                    "^authority transition exact row is absent or ambiguous$"):
                quota.KERNELS["jit.request"].transition(context)
            mutation.assert_not_called()
        self.assertEqual(context.arguments, before)
        self.assertEqual(context.selected_rows, ())


class HeldRequestRows:
    """Synthetic admitted originals, real kernel consumers; no crypto verdict.

    The kernel trusts prior row admission. Fixed ciphertext/signature bytes below
    are NOT a seal, signature verification, native attestation or custody proof.
    They are held unchanged across delayed planning and replay controls.
    """
    EPOCH_NS = 1_791_720_000_000_000_000  # 2026-10-11T12:00:00Z, literal oracle.
    OPAQUE = "policy_authority_opaque_values"
    EVIDENCE = "policy_authority_external_evidence_receipts"
    AGGREGATE = "policy_authority_bounded_aggregate_states"

    def __init__(self, canonical_expiry, display_expiry, *, pending_ttl=300):
        self.kernel = quota.KERNELS["jit.request"]
        _raw, self.arguments, self.digest = kernel_arguments({**public_arguments(),
            "pending_ttl_seconds": pending_ttl})
        normalized = ingress.normalize(self.arguments, request_digest=self.digest)
        self.item = identity(self.digest, "jit-approval-request")
        self.rows = []
        self.originals = []
        for purpose, kind, field, expiry in (
            ("jit-canonical-request", "approval-secret-json/v1", "canonical_request_digest", canonical_expiry),
            ("jit-redacted-display", "approval-review-json/v1", "redacted_display_digest", display_expiry),
        ):
            binding = framed("serverware.policyAuthorityJitOpaqueValueBinding/v1", {
                "schema": "serverware.policyAuthorityJitOpaqueValueBinding/v1", "valueKind": kind,
                "approvalRequestId": self.item, "requestDigest": normalized["request_digest"],
                "plaintextDigest": normalized[field]})
            # The statement's explicit fixture label avoids inventing native
            # evidence. The actual consumer checks all retained row digests.
            statement = {"fixture": "synthetic admitted row, not verifier execution", "bindingDigest": binding}
            signature = base64.urlsafe_b64encode(b"synthetic-not-verified-signature" * 2).decode().rstrip("=")
            signature_digest = core.framed_digest("serverware.policyAuthorityExternalEvidenceSignature/v1",
                b"Ed25519", signature.encode())
            receipt_material = {
                "schema": "serverware.policyAuthorityExternalEvidenceReceipt/v1",
                "bindingDigest": binding, "evidenceType": "key-custody-seal/v1",
                "expiresAtEpochNs": self.EPOCH_NS + 3600 * 1_000_000_000,
                "signatureAlgorithm": "Ed25519", "signatureDigest": signature_digest,
                "sourceRevision": contract.SOURCE_REVISION,
                "statementDigest": framed("serverware.policyAuthorityExternalEvidenceStatement/v1", statement),
                "verifiedAtEpochNs": self.EPOCH_NS,
                "verifierAttestationReceiptDigest": sha(b"synthetic unattested selection"),
                "verifierIdentityDigest": sha(b"synthetic verifier identity"),
                "verifierMeasurementDigest": sha(b"synthetic verifier measurement"),
            }
            evidence_digest = framed("serverware.policyAuthorityExternalEvidenceReceipt/v1", receipt_material)
            evidence = {
                "evidence_digest": evidence_digest, "evidence_type": "key-custody-seal/v1",
                "binding_digest": binding, "statement_json": canonical(statement).decode(),
                "statement_digest": receipt_material["statementDigest"], "signature_algorithm": "Ed25519",
                "signature_base64url": signature, "signature_digest": signature_digest,
                "verified_at_epoch_ns": self.EPOCH_NS,
                "expires_at_epoch_ns": receipt_material["expiresAtEpochNs"],
                "verifier_identity_digest": receipt_material["verifierIdentityDigest"],
                "verifier_measurement_digest": receipt_material["verifierMeasurementDigest"],
                "verifier_attestation_receipt_digest": receipt_material["verifierAttestationReceiptDigest"],
                "status": "verified", "consumed_operation_id": None, "consumed_at_epoch_ns": None,
                "source_revision": contract.SOURCE_REVISION,
            }
            ciphertext = base64.urlsafe_b64encode(("synthetic-not-sealed:" + purpose).encode()).decode().rstrip("=")
            opaque = {
                "opaque_id": identity(self.digest, purpose), "value_kind": kind, "binding_digest": binding,
                "algorithm": "synthetic-no-custody", "key_id": "synthetic-unadmitted-key",
                "ciphertext_base64url": ciphertext,
                "ciphertext_digest": core.framed_digest("serverware.policyAuthorityOpaqueCiphertext/v1",
                    b"synthetic-no-custody", b"synthetic-unadmitted-key", ciphertext.encode()),
                "producer_evidence_digest": evidence_digest, "created_at_epoch_ns": self.EPOCH_NS,
                "expires_at_epoch_ns": expiry, "status": "active", "consumed_at_epoch_ns": None,
                "source_revision": contract.SOURCE_REVISION,
            }
            self.add(self.OPAQUE, {"opaque_id": opaque["opaque_id"]}, opaque)
            self.add(self.EVIDENCE, {"evidence_digest": evidence_digest}, evidence)
            self.originals.append(copy.deepcopy(opaque))
        aggregate_id, partition = quota._aggregate_key("jit-pending-approvals", "global")
        aggregate = {"aggregate_id": aggregate_id, "aggregate_kind": "jit-pending-approvals",
            "partition_digest": partition, "revision": 1, "live_count": 0, "active_count": 0,
            "capacity_limit": 100, "reserved_units_json": "{}", "committed_units_json": "{}",
            "next_sequence": 0, "minimum_expiry_epoch_ns": None,
            "expiry_index_root_digest": sha(b"synthetic admitted empty expiry index"), "work_page_id": None,
            "updated_at_epoch_ns": self.EPOCH_NS, "source_revision": contract.SOURCE_REVISION}
        state = core._aggregate_state_material(aggregate, reserved_units={}, committed_units={})
        aggregate.update(state_json=canonical(state).decode(), state_digest=framed(
            "serverware.policyAuthorityAggregateState/v1", state))
        self.add(self.AGGREGATE, {"aggregate_id": aggregate_id}, aggregate)
        self.add("approval_requests", {"id": self.item}, None)
        self.add("routes", {"id": normalized["route_id"]}, None)
        self.add("metadata_audit_outbox", {"id": identity(self.digest, "metadata-audit-outbox")}, None)

    def add(self, table, key, row):
        self.rows.append({"table": table, "key": key, "keyDigest": core.framed_digest(
            "serverware.policyAuthorityBusinessKey/v1", table.encode(), canonical(key)),
            "present": row is not None, "row": row, "contractSelector": None})

    def context(self, now=NOW):
        return core.KernelContext(operation="jit.request", arguments=copy.deepcopy(self.arguments),
            selected_rows=tuple(copy.deepcopy(self.rows)), database_now=now, request_digest=self.digest)

    def transition(self, now=NOW):
        context = self.context(now)
        before = copy.deepcopy(context.selected_rows)
        result = self.kernel.transition(context)
        if context.selected_rows != before:
            raise AssertionError("kernel changed the retained originals")
        return result

    def apply_model(self, transition):
        """Retain exact emitted rows for replay, not a database commit claim."""
        for mutation in transition.mutations:
            selected = next(item for item in self.rows if item["table"] == mutation["table"]
                and item["key"] == mutation["key"])
            if selected["row"] != mutation["expectedRow"]:
                raise AssertionError("model CAS does not match the original")
            selected.update(present=True, row=copy.deepcopy(mutation["row"]))


class JitPendingProjectionTests(unittest.TestCase):
    """Pure projection and real kernel parity, not row/custody admission."""

    def project(self, fixture, now=NOW):
        return quota.jit_pending_projection(
            ingress.normalize(fixture.arguments, request_digest=fixture.digest),
            approval_id=fixture.item, canonical_value=fixture.originals[0],
            display_value=fixture.originals[1], database_now=now)

    def expected_immutable(self, fixture):
        # Independent old row/key grammar: no production projection or key
        # helper supplies the expected bytes.
        raw = public_arguments()
        policy_digest = framed("serverware.jitApproverPolicy/v1", policy())
        pending_key = framed("serverware.jitPendingApproval/v2", {
            "routeId": raw["route_id"], "method": "PUT",
            "urlCommitment": sha(raw["url"].encode("utf-8")),
            "principalId": raw["principal_id"], "credentialId": raw["credential_id"],
            "credentialVersion": 7, "policyHash": raw["policy_hash"],
            "requestDigest": raw["request_digest"], "operationDigest": raw["operation_digest"],
            "grantTtlSeconds": 30, "grantMaxUses": 1, "approverPolicyDigest": policy_digest})
        return {"route_id": raw["route_id"], "method": "PUT",
            "url": sha(raw["url"].encode("utf-8")), "principal_id": raw["principal_id"],
            "credential_id": raw["credential_id"], "credential_version": 7,
            "policy_hash": raw["policy_hash"], "request_digest": raw["request_digest"],
            "operation_digest": raw["operation_digest"],
            "canonical_request": fixture.originals[0]["ciphertext_base64url"],
            "redacted_display": fixture.originals[1]["ciphertext_base64url"],
            "grant_ttl_seconds": 30, "grant_max_uses": 1, "pending_key": pending_key,
            "approver_policy_json": canonical(policy()).decode("ascii"),
            "approver_policy_digest": policy_digest}

    def test_complete_row_pending_key_bytes_and_kernel_mutation_identity_match(self):
        fixture = HeldRequestRows(HeldRequestRows.EPOCH_NS + 12_345_678_999,
            HeldRequestRows.EPOCH_NS + 20_000_000_000)
        now = NOW + timedelta(seconds=3, microseconds=1000)
        before = copy.deepcopy((fixture.arguments, fixture.originals, fixture.rows))
        projection = self.project(fixture, now)
        immutable = self.expected_immutable(fixture)
        expected = {"id": identity(fixture.digest, "jit-approval-request"), **immutable,
            "status": "pending", "requested_at": "2026-10-11T12:00:03.001000+00:00",
            "expires_at": "2026-10-11T12:00:12.345678+00:00", "approved_until": None,
            "decision_note": None, "approved_by": None, "approval_authn": None,
            "approver_webauthn_credential_id": None, "verified_assertion_receipt_digest": None,
            "approval_challenge_id": None}
        self.assertEqual(canonical(dict(projection.immutable)), canonical(immutable))
        self.assertEqual(canonical(dict(projection.row)), canonical(expected))
        transition = fixture.transition(now)
        self.assertEqual([(item["table"], item["operation"]) for item in transition.mutations], [
            ("routes", "INSERT"), ("approval_requests", "INSERT"),
            (fixture.AGGREGATE, "UPDATE"), ("metadata_audit_outbox", "INSERT")])
        approval = transition.mutations[1]
        self.assertEqual(approval["key"], {"id": expected["id"]})
        self.assertIsNone(approval["expectedRow"])
        self.assertEqual(canonical(approval["row"]), canonical(expected))
        self.assertEqual(transition.mutations[0]["key"], {"id": "route:synthetic"})
        self.assertEqual(transition.mutations[3]["key"], {
            "id": identity(fixture.digest, "metadata-audit-outbox")})
        self.assertEqual(transition.work_units, 44)
        self.assertEqual((fixture.arguments, fixture.originals, fixture.rows), before)
        for mapping in (projection.immutable, projection.row):
            with self.assertRaises(TypeError):
                mapping["method"] = "GET"
        retained_bytes = canonical(dict(projection.row))
        fixture.originals[0]["ciphertext_base64url"] = "changed-after-projection"
        self.assertEqual(canonical(dict(projection.row)), retained_bytes)

    def test_projection_original_expiry_minimum_and_integer_microsecond_floor(self):
        epoch = HeldRequestRows.EPOCH_NS
        for first, second, delay_us, ttl in (
            (12_345_678_999, 20_000_000_000, 3_001_000, 300),
            (20_000_000_000, 12_345_678_999, 3_001_000, 300),
            (3_500_000_000_000, 3_600_000_000_000, 1000, 300),
            (1000, 1999, 0, 300),
        ):
            with self.subTest(bounds=(first, second), delay_us=delay_us):
                fixture = HeldRequestRows(epoch + first, epoch + second, pending_ttl=ttl)
                projected = self.project(fixture, NOW + timedelta(microseconds=delay_us))
                expected_ns = min(epoch + delay_us * 1000 + ttl * 1_000_000_000,
                    epoch + first, epoch + second) // 1000 * 1000
                self.assertIs(type(projected.expiry_epoch_ns), int)
                self.assertEqual(projected.document_expiry_epoch_ns, epoch + min(first, second))
                self.assertEqual(projected.expiry_epoch_ns, expected_ns)
                self.assertEqual(projected.row["expires_at"], (NOW + timedelta(
                    microseconds=(expected_ns - epoch) // 1000)).isoformat())

    def test_projection_rejects_each_expired_or_unusable_original_without_mutation(self):
        epoch = HeldRequestRows.EPOCH_NS
        for index in range(2):
            for bad in (None, True, 0, -1, epoch - 1, epoch, epoch + 999,
                    float(epoch + 60_000_000_000), str(epoch), 2**63):
                with self.subTest(document=index, bound=bad):
                    bounds = [epoch + 60_000_000_000] * 2
                    bounds[index] = bad
                    fixture = HeldRequestRows(*bounds)
                    before = copy.deepcopy((fixture.arguments, fixture.originals, fixture.rows))
                    with self.assertRaises(core.TransitionKernelError):
                        self.project(fixture)
                    self.assertEqual((fixture.arguments, fixture.originals, fixture.rows), before)

    def test_real_replay_refuses_each_changed_immutable_identity_field(self):
        end = HeldRequestRows.EPOCH_NS + 60_000_000_000
        fixture = HeldRequestRows(end, end)
        fixture.apply_model(fixture.transition())
        retained = copy.deepcopy(fixture.rows)
        for field in self.expected_immutable(fixture):
            with self.subTest(field=field):
                fixture.rows = copy.deepcopy(retained)
                approval = next(item["row"] for item in fixture.rows
                    if item["table"] == "approval_requests")
                value = approval[field]
                approval[field] = value + 1 if type(value) is int else value + ":changed"
                before = copy.deepcopy(fixture.rows)
                with self.assertRaisesRegex(core.TransitionKernelError,
                        "^JIT request identity was rebound$"):
                    fixture.transition(NOW + timedelta(seconds=1))
                self.assertEqual(fixture.rows, before)


class JitRequestExpiryTests(unittest.TestCase):
    def assert_expiry(self, fixture, transition, expected_text, expected_ns):
        self.assertEqual([(item["table"], item["operation"]) for item in transition.mutations], [
            ("routes", "INSERT"), ("approval_requests", "INSERT"),
            (fixture.AGGREGATE, "UPDATE"), ("metadata_audit_outbox", "INSERT")])
        approval = transition.mutations[1]["row"]
        aggregate = transition.mutations[2]["row"]
        event = json.loads(transition.mutations[3]["row"]["event_json"])
        self.assertEqual(approval["expires_at"], expected_text)
        self.assertEqual(transition.result["expires_at"], expected_text)
        self.assertEqual(event["expiresAt"], expected_text)
        self.assertEqual(aggregate["minimum_expiry_epoch_ns"], expected_ns)
        self.assertEqual(json.loads(aggregate["state_json"])["minimumExpiryEpochNs"], expected_ns)
        self.assertEqual((aggregate["live_count"], aggregate["active_count"], aggregate["next_sequence"]), (1, 1, 1))
        for field, original in zip(("canonical_request", "redacted_display"), fixture.originals):
            self.assertEqual(approval[field], original["ciphertext_base64url"])
            self.assertLessEqual(expected_ns, original["expires_at_epoch_ns"])
        self.assertIs(transition.result["approval_created"], True)
        self.assertIs(transition.result["idempotent_replay"], False)

    def test_both_original_expiries_independently_cap_and_floor_exact_microseconds(self):
        short = HeldRequestRows.EPOCH_NS + 12_345_678_999
        long = HeldRequestRows.EPOCH_NS + 20_000_000_000
        for first, second in ((short, long), (long, short), (short, short)):
            with self.subTest(canonical_is_short=first == short, display_is_short=second == short):
                fixture = HeldRequestRows(first, second)
                result = fixture.transition(NOW + timedelta(seconds=3, microseconds=1000))
                self.assert_expiry(fixture, result, "2026-10-11T12:00:12.345678+00:00",
                    HeldRequestRows.EPOCH_NS + 12_345_678_000)

    def test_pending_ttl_remains_upper_bound_and_aggregate_does_not_use_float(self):
        fixture = HeldRequestRows(HeldRequestRows.EPOCH_NS + 3500_000_000_000,
            HeldRequestRows.EPOCH_NS + 3600_000_000_000)
        result = fixture.transition(NOW + timedelta(microseconds=1000))
        self.assert_expiry(fixture, result, "2026-10-11T12:05:00.001000+00:00",
            HeldRequestRows.EPOCH_NS + 300_001_000_000)

    def test_delayed_admission_uses_held_originals_not_a_restarted_document_ttl(self):
        end = HeldRequestRows.EPOCH_NS + 300_000_000_000
        fixture = HeldRequestRows(end, end)
        originals = copy.deepcopy(fixture.rows)
        initial = fixture.transition()
        delayed = fixture.transition(NOW + timedelta(seconds=37))
        self.assert_expiry(fixture, delayed, "2026-10-11T12:05:00+00:00", end)
        self.assertEqual(delayed.result["expires_at"], initial.result["expires_at"])
        self.assertNotEqual(delayed.result["requested_at"], initial.result["requested_at"])
        self.assertEqual(fixture.rows, originals)

    def test_original_bounds_must_be_finite_current_exact_and_have_usable_microsecond(self):
        end = HeldRequestRows.EPOCH_NS + 60_000_000_000
        for index in range(2):
            for bad in (None, True, float(end), str(end), 0, HeldRequestRows.EPOCH_NS,
                        HeldRequestRows.EPOCH_NS + 999, 2**63):
                with self.subTest(document=index, invalid_type=type(bad).__name__, value=bad):
                    bounds = [end, end]
                    bounds[index] = bad
                    fixture = HeldRequestRows(*bounds)
                    before = copy.deepcopy(fixture.rows)
                    with self.assertRaises(core.TransitionKernelError):
                        fixture.transition()
                    self.assertEqual(fixture.rows, before)

    def test_exact_replay_never_renews_ttl_or_changes_rows_audit_or_capacity(self):
        end = HeldRequestRows.EPOCH_NS + 300_000_000_000
        fixture = HeldRequestRows(end, end, pending_ttl=1)
        first = fixture.transition()
        self.assert_expiry(fixture, first, "2026-10-11T12:00:01+00:00",
            HeldRequestRows.EPOCH_NS + 1_000_000_000)
        fixture.apply_model(first)
        retained = copy.deepcopy(fixture.rows)
        for delay in (timedelta(microseconds=1), timedelta(seconds=2)):
            replay = fixture.transition(NOW + delay)
            self.assertEqual(replay.mutations, ())
            self.assertEqual(replay.result, {**first.result, "approval_created": False, "idempotent_replay": True})
            self.assertEqual(fixture.rows, retained)
        # Elapsed business expiry may be reported as retained read-only replay;
        # neither private document nor producer evidence validity is renewed.
        with self.assertRaises(core.TransitionKernelError):
            fixture.transition(NOW + timedelta(seconds=300))

    def test_retained_replay_cannot_escape_original_document_expiry(self):
        end = HeldRequestRows.EPOCH_NS + 60_000_000_000
        for bad in (None, "invalid", "2026-10-11T12:00:30", "1970-01-01T00:00:00+00:00",
                    "2026-10-11T12:01:00.000001+00:00"):
            with self.subTest(retained_expiry=bad):
                fixture = HeldRequestRows(end, end)
                fixture.apply_model(fixture.transition())
                approval = next(item["row"] for item in fixture.rows if item["table"] == "approval_requests")
                audit = next(item["row"] for item in fixture.rows if item["table"] == "metadata_audit_outbox")
                approval["expires_at"] = bad
                # Keep the actual retained audit replay binding coherent, so
                # its mismatch cannot masquerade as an expiry refusal.
                event = json.loads(audit["event_json"])
                event["expiresAt"] = bad
                audit.update(event_json=canonical(event).decode(), event_digest=framed(
                    "serverware.metadataAuditOutboxEvent/v1", event))
                before = copy.deepcopy(fixture.rows)
                with self.assertRaises(core.TransitionKernelError):
                    fixture.transition(NOW + timedelta(seconds=1))
                self.assertEqual(fixture.rows, before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
