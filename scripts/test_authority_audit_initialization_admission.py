#!/usr/bin/env python3
"""Real Ed25519 and pure initialization admission components.

The keys and accepted root descriptors are explicit local fixtures, not an
authority service, measured signer, physical writer fence, currentness check
or one-use installer. No database, registry replacement or clock is supplied.
Independent signing hashes use length-prefixed domains; preparation/inventory
hashes intentionally use the distinct core NUL-terminated-domain convention.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
import unittest
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catchplate import authority_audit_initialization as initialization
from catchplate import authority_audit_initialization_admission as admission
from catchplate import authority_audit_initialization_signatures as signatures
from catchplate import authority_contract
import test_authority_audit_initialization as initialization_fixture
from test_authority_audit_initialization import (
    AGGREGATE, KEY, OUTBOX, aggregate_tree, absence,
)
from test_authority_audit_inventory import InventoryTree, outbox_row, wire_digest, wire_json


ROLES = {
    "checkpoint": {
        "schema": "catchplate.metadataAuditInitializationCheckpoint/v1",
        "payload": "catchplate.metadataAuditInitializationCheckpointPayload/v1",
        "purpose": "metadata-audit-initialization-checkpoint",
        "signature": "catchplate.metadataAuditInitializationCheckpointSignature/v1",
        "envelope": "catchplate.metadataAuditInitializationCheckpointEnvelope/v1",
    },
    "authorization": {
        "schema": "catchplate.metadataAuditInitializationAuthorization/v1",
        "payload": "catchplate.metadataAuditInitializationAuthorizationPayload/v1",
        "purpose": "metadata-audit-initialization-authorization",
        "signature": "catchplate.metadataAuditInitializationAuthorizationSignature/v1",
        "envelope": "catchplate.metadataAuditInitializationAuthorizationEnvelope/v1",
    },
}
MAX_INTEGER = 2**63 - 1


def label_digest(label):
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def signed_digest(domain, *frames):
    encoded = domain.encode("ascii")
    value = hashlib.sha256(len(encoded).to_bytes(8, "big") + encoded)
    for frame in frames:
        value.update(len(frame).to_bytes(8, "big"))
        value.update(frame)
    return "sha256:" + value.hexdigest()


def spki(key):
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                       serialization.PublicFormat.SubjectPublicKeyInfo)


def bypassed_dataclass(value, **changes):
    """Create caller-controlled data without invoking its normal constructor."""
    result = object.__new__(type(value))
    for field in fields(value):
        object.__setattr__(result, field.name,
                           changes[field.name] if field.name in changes else copy.deepcopy(getattr(value, field.name)))
    return result


class SigningFixture:
    def __init__(self):
        self.keys = {
            "checkpoint": ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32))),
            "authorization": ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64))),
        }
        self.pins = {role: signatures.InitializationSignerPin(
            role, spki(key), label_digest(role + "-identity"),
            label_digest(role + "-measurement"), label_digest(role + "-attestation"))
            for role, key in self.keys.items()}

    def payload(self, role):
        pin = self.pins[role]
        return {
            "schema": ROLES[role]["payload"], "purpose": ROLES[role]["purpose"],
            "authorityIdentityDigest": pin.authority_identity_digest,
            "authorityMeasurementDigest": pin.measurement_digest,
            "authorityAttestationDigest": pin.attestation_receipt_digest,
        }

    def sign(self, role, payload=None, *, key=None, message=None):
        payload = self.payload(role) if payload is None else copy.deepcopy(payload)
        if message is None:
            message = signed_digest(ROLES[role]["signature"], wire_json(payload)).encode("ascii")
        signature = (self.keys[role] if key is None else key).sign(message)
        return wire_json({"schema": ROLES[role]["schema"], "payload": payload,
            "signerKeyId": "sha256:" + hashlib.sha256(spki(self.keys[role])).hexdigest(),
            "algorithm": "Ed25519",
            "signatureBase64Url": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")})


class InitializationSignatureTests(unittest.TestCase):
    def setUp(self):
        self.fixture = SigningFixture()

    def verify(self, expected_role, raw, **changes):
        arguments = {"role": expected_role, "pin": self.fixture.pins[expected_role]}
        arguments.update(changes)
        return signatures.verify_initialization_envelope(raw, **arguments)

    def test_both_roles_verify_real_signatures_and_independent_envelope_hashes(self):
        for role in ROLES:
            with self.subTest(role=role):
                raw = self.fixture.sign(role)
                self.assertEqual(self.verify(role, raw), json.loads(raw))
                self.assertEqual(signatures.envelope_digest(raw, role=role),
                                 signed_digest(ROLES[role]["envelope"], raw))
                self.assertEqual(self.fixture.pins[role].key_id,
                                 "sha256:" + hashlib.sha256(spki(self.fixture.keys[role])).hexdigest())

    def test_pin_requires_exact_bounded_canonical_ed25519_spki_and_digest_strings(self):
        original = self.fixture.pins["checkpoint"]
        wrong_algorithm = spki(ec.derive_private_key(1, ec.SECP256R1()))
        for value in (None, bytearray(original.public_key_der), b"", b"x" * 1025,
                      original.public_key_der + b"\x00", wrong_algorithm):
            with self.subTest(key=repr(value)), self.assertRaises(signatures.AuditInitializationSignatureError):
                replace(original, public_key_der=value)
        for field in ("authority_identity_digest", "measurement_digest", "attestation_receipt_digest"):
            for value in (None, True, "sha256:" + "A" * 64, "sha256:" + "0" * 63):
                with self.subTest(field=field, value=value), self.assertRaises(signatures.AuditInitializationSignatureError):
                    replace(original, **{field: value})
        with self.assertRaises(FrozenInstanceError):
            original.role = "authorization"

    def test_role_key_and_all_authority_pins_are_independent_admission_inputs(self):
        for role in ROLES:
            raw, pin = self.fixture.sign(role), self.fixture.pins[role]
            other = "authorization" if role == "checkpoint" else "checkpoint"
            changes = [None, {}, self.fixture.pins[other],
                       replace(pin, public_key_der=spki(self.fixture.keys[other]))]
            changes.extend(replace(pin, **{field: label_digest("other-" + field)}) for field in
                           ("authority_identity_digest", "measurement_digest", "attestation_receipt_digest"))
            for changed in changes:
                with self.subTest(role=role, pin=changed), self.assertRaises(signatures.AuditInitializationSignatureError):
                    self.verify(role, raw, pin=changed)
            for changed in (None, "other", True):
                with self.subTest(role=role, role_value=changed), self.assertRaises(signatures.AuditInitializationSignatureError):
                    self.verify(role, raw, role=changed)

    def test_authentic_but_wrong_purpose_schema_or_pins_are_rejected_for_both_roles(self):
        for role in ROLES:
            for field in ("schema", "purpose", "authorityIdentityDigest", "authorityMeasurementDigest", "authorityAttestationDigest"):
                payload = self.fixture.payload(role)
                payload[field] += ".other"
                with self.subTest(role=role, field=field), self.assertRaises(signatures.AuditInitializationSignatureError):
                    self.verify(role, self.fixture.sign(role, payload))
            raw = json.loads(self.fixture.sign(role))
            for field, value in (("schema", ROLES[role]["schema"] + ".other"),
                                 ("algorithm", "other"), ("extra", None)):
                changed = {**raw, field: value}
                with self.subTest(role=role, field=field), self.assertRaises(signatures.AuditInitializationSignatureError):
                    self.verify(role, wire_json(changed))

    def test_invalid_real_signatures_and_wrong_signing_preimages_are_rejected(self):
        for role in ROLES:
            other = "authorization" if role == "checkpoint" else "checkpoint"
            payload = self.fixture.payload(role)
            bad = [self.fixture.sign(role, key=self.fixture.keys[other]),
                   self.fixture.sign(role, message=wire_json(payload)),
                   self.fixture.sign(role, message=wire_digest(ROLES[role]["signature"], wire_json(payload)).encode("ascii"))]
            changed = json.loads(self.fixture.sign(role))
            changed["payload"]["unsignedChange"] = True
            bad.append(wire_json(changed))
            for raw in bad:
                with self.subTest(role=role), self.assertRaises(signatures.AuditInitializationSignatureError):
                    self.verify(role, raw)
            for signature in (None, "A" * 85, "A" * 87, "/" * 86, "A" * 86):
                changed = json.loads(self.fixture.sign(role))
                changed["signatureBase64Url"] = signature
                with self.subTest(role=role, signature=signature), self.assertRaises(signatures.AuditInitializationSignatureError):
                    self.verify(role, wire_json(changed))

    def test_only_exact_canonical_ascii_envelope_bytes_are_accepted(self):
        for role in ROLES:
            raw = self.fixture.sign(role)
            payload = self.fixture.payload(role)
            payload["unicodeControl"] = "é😀"
            escaped = self.fixture.sign(role, payload)
            self.assertEqual(self.verify(role, escaped)["payload"]["unicodeControl"], "é😀")
            for value in (None, bytearray(raw), raw.decode("ascii"), b"", b"x" * 65537,
                    raw + b"\n", b" " + raw, b"\xef\xbb\xbf" + raw,
                    b'{"algorithm":"Ed25519",' + raw[1:],
                    escaped.replace(b"\\u00e9", "é".encode("utf-8")),
                    escaped.replace(b"\\u00e9", b"\\u00E9")):
                with self.subTest(role=role, kind=type(value).__name__), self.assertRaises(signatures.AuditInitializationSignatureError):
                    self.verify(role, value)

    def test_integer_lexemes_graph_limits_and_forbidden_string_scalars_reject(self):
        for role in ROLES:
            payload = self.fixture.payload(role)
            for value in (-(2**63), 2**63 - 1):
                payload["componentInteger"] = value
                self.assertEqual(self.verify(role, self.fixture.sign(role, payload))["payload"]["componentInteger"], value)
            payload["componentInteger"] = 1
            raw = self.fixture.sign(role, payload)
            for token in (b"-0", b"1.0", b"1e0", b"NaN", b"Infinity", b"9223372036854775808", b"9" * 20):
                changed = raw.replace(b'"componentInteger":1', b'"componentInteger":' + token)
                with self.subTest(role=role, token=token), self.assertRaises(signatures.AuditInitializationSignatureError):
                    self.verify(role, changed)
            for value in (1.0, -(2**63) - 1, 2**63):
                payload["componentInteger"] = value
                with self.subTest(role=role, signed_number=value), self.assertRaises(signatures.AuditInitializationSignatureError):
                    self.verify(role, self.fixture.sign(role, payload))
            payload["componentInteger"] = 0
            signed_zero = self.fixture.sign(role, payload)
            with self.assertRaises(signatures.AuditInitializationSignatureError):
                self.verify(role, signed_zero.replace(b'"componentInteger":0', b'"componentInteger":-0'))
            nested = None
            for _ in range(17):
                nested = [nested]
            for value in ("\x00", "\ud800", nested, [None] * 4096):
                payload["componentGraph"] = value
                with self.subTest(role=role, value_type=type(value).__name__), self.assertRaises(signatures.AuditInitializationSignatureError):
                    self.verify(role, self.fixture.sign(role, payload))

    def test_returned_graph_is_owned_and_digest_only_is_not_signature_admission(self):
        for role in ROLES:
            raw = self.fixture.sign(role)
            result = self.verify(role, raw)
            result["payload"].clear()
            self.assertEqual(self.verify(role, raw), json.loads(raw))
            arbitrary = b"unverified local bytes"
            self.assertEqual(signatures.envelope_digest(arbitrary, role=role),
                             signed_digest(ROLES[role]["envelope"], arbitrary))
            with self.assertRaises(signatures.AuditInitializationSignatureError):
                self.verify(role, arbitrary)


class InitializationAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.signing = SigningFixture()
        self.outbox = InventoryTree([outbox_row("one"), outbox_row("two", "claimed"),
                                    outbox_row("three", "audited")], revision=17)
        self.aggregate = aggregate_tree([{"aggregate_id": "other-a", "opaque": 1},
                                         {"aggregate_id": "other-z", "opaque": None}], revision=23)
        self.records = self.outbox.records()
        self.missing = absence(self.aggregate)
        self.now = 30_000_000_000
        self.trust = admission.AuditInitializationTrust(
            checkpoint_signer=self.signing.pins["checkpoint"],
            authorization_signer=self.signing.pins["authorization"],
            policy_digest=label_digest("trust-policy"), not_before_epoch_ns=0,
            not_after_epoch_ns=200_000_000_000, maximum_lifetime_ns=120_000_000_000)
        self.expectation = admission.AuditInitializationExpectation(
            database_identity_digest=label_digest("database"),
            database_generation_digest=label_digest("database-generation"),
            source_contract_digest=label_digest("source-contract"),
            schema_contract_digest=label_digest("schema-contract"),
            initializer_measurement_digest=label_digest("initializer-measurement"),
            operation_id=label_digest("initialization-operation"),
            nonce_digest=label_digest("initialization-nonce"), fence_id=label_digest("fence"),
            writer_inventory_digest=label_digest("writer-inventory"),
            fence_evidence_digest=label_digest("fence-evidence"),
            initialization_ancestry_digest=label_digest("initialization-ancestry"),
            fence_generation=7, checkpoint_sequence=1, checkpoint_predecessor_digest=None,
            initialized_at_epoch_ns=1_000_000_000)
        # This builder independently rebuilds both small trees, state/row and
        # framed digests. It calls no production preparation or admission.
        self.prepared_document = initialization_fixture.AuditCapacityInitializationTests.expected(self)
        self.checkpoint_payload, self.authorization_payload = self.payloads()
        self.checkpoint, self.authorization = self.signed_pair()

    def binding(self):
        expected = self.expectation
        return {
            "databaseIdentityDigest": expected.database_identity_digest,
            "databaseGenerationDigest": expected.database_generation_digest,
            "sourceContractDigest": expected.source_contract_digest,
            "schemaContractDigest": expected.schema_contract_digest,
            "initializerMeasurementDigest": expected.initializer_measurement_digest,
            "operationId": expected.operation_id, "nonceDigest": expected.nonce_digest,
            "fenceId": expected.fence_id, "writerInventoryDigest": expected.writer_inventory_digest,
            "fenceEvidenceDigest": expected.fence_evidence_digest,
            "initializationAncestryDigest": expected.initialization_ancestry_digest,
            "fenceGeneration": expected.fence_generation,
            "checkpointSequence": expected.checkpoint_sequence,
            "checkpointPredecessorDigest": expected.checkpoint_predecessor_digest,
            "initializedAtEpochNs": expected.initialized_at_epoch_ns,
        }

    def payloads(self):
        common = {
            "sourceRevision": authority_contract.SOURCE_REVISION,
            "preparationProfile": "catchplate.metadataAuditCapacityInitializationProfile/v1",
            "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
            "trustPolicyDigest": self.trust.policy_digest, "binding": self.binding(),
            "expiresAtEpochNs": 100_000_000_000,
        }
        checkpoint = {**self.signing.payload("checkpoint"), **copy.deepcopy(common),
            "issuedAtEpochNs": 10_000_000_000,
            "beforeRoots": copy.deepcopy(self.prepared_document["beforeRoots"]),
            "tableKeyContracts": {OUTBOX: ["id"], AGGREGATE: ["aggregate_id"]},
            "initializationDisposition": "initial-install-only"}
        authorization = {**self.signing.payload("authorization"), **copy.deepcopy(common),
            "issuedAtEpochNs": 20_000_000_000, "checkpointEnvelopeDigest": label_digest("replaced-when-signing"),
            "preparationDigest": wire_digest("catchplate.metadataAuditCapacityInitializationPreparation/v1",
                                            wire_json(self.prepared_document)),
            "counterRowDigest": self.prepared_document["counterRowDigest"],
            "afterRoots": copy.deepcopy(self.prepared_document["afterRoots"])}
        return checkpoint, authorization

    def signed_pair(self, *, checkpoint_payload=None, authorization_payload=None):
        checkpoint_payload = self.checkpoint_payload if checkpoint_payload is None else checkpoint_payload
        authorization_payload = copy.deepcopy(self.authorization_payload if authorization_payload is None else authorization_payload)
        checkpoint = self.signing.sign("checkpoint", checkpoint_payload)
        authorization_payload["checkpointEnvelopeDigest"] = signed_digest(ROLES["checkpoint"]["envelope"], checkpoint)
        return checkpoint, self.signing.sign("authorization", authorization_payload)

    def verify(self, checkpoint=None, authorization=None, **changes):
        arguments = {
            "trust": self.trust, "expectation": self.expectation, "now_epoch_ns": self.now,
            "outbox_root": self.outbox.root, "outbox_records": self.records,
            "aggregate_root": self.aggregate.root, "aggregate_absence": self.missing,
        }
        arguments.update(changes)
        return admission.verify_audit_initialization_evidence(
            self.checkpoint if checkpoint is None else checkpoint,
            self.authorization if authorization is None else authorization, **arguments)

    def preflight(self, checkpoint=None, authorization=None, **changes):
        arguments = {
            "trust": self.trust, "expectation": self.expectation, "now_epoch_ns": self.now,
            "outbox_root": self.outbox.root, "aggregate_root": self.aggregate.root,
        }
        arguments.update(changes)
        return admission.validate_audit_initialization_intent(
            self.checkpoint if checkpoint is None else checkpoint,
            self.authorization if authorization is None else authorization, **arguments)

    def reject_before_stream(self, checkpoint=None, authorization=None, **changes):
        def records():
            raise AssertionError("envelope admission must precede outbox iteration")
            yield

        with self.assertRaises(admission.AuditInitializationAdmissionError):
            self.verify(checkpoint, authorization, outbox_records=records(), **changes)

    def test_real_signed_pair_recomputes_exact_independent_preparation(self):
        evidence = self.verify()
        expected = {
            "schema": "catchplate.metadataAuditInitializationEvidence/v1",
            "checkpoint": json.loads(self.checkpoint),
            "checkpointEnvelopeDigest": signed_digest(ROLES["checkpoint"]["envelope"], self.checkpoint),
            "authorization": json.loads(self.authorization),
            "authorizationEnvelopeDigest": signed_digest(ROLES["authorization"]["envelope"], self.authorization),
            "preparation": self.prepared_document,
            "preparationDigest": wire_digest("catchplate.metadataAuditCapacityInitializationPreparation/v1",
                                            wire_json(self.prepared_document)),
            "verifiedAtEpochNs": self.now,
            "verificationBoundary": "pinned-signatures-and-local-recomputation",
            "installationPermitted": False,
        }
        self.assertEqual(evidence.json_projection(), expected)
        self.assertEqual(evidence.canonical_bytes, wire_json(expected))
        self.assertEqual(evidence.digest,
                         wire_digest("catchplate.metadataAuditInitializationEvidence/v1", wire_json(expected)))
        self.assertEqual(evidence.preparation.canonical_bytes, wire_json(self.prepared_document))
        self.assertEqual(evidence.checkpoint_bytes, self.checkpoint)
        self.assertEqual(evidence.authorization_bytes, self.authorization)
        self.assertEqual(evidence.verified_at_epoch_ns, self.now)

    def test_intent_preflight_returns_none_and_preserves_full_evidence_bytes(self):
        expected = self.verify().canonical_bytes
        for now in (20_000_000_000, self.now, 99_999_999_999):
            with self.subTest(now=now):
                self.assertIsNone(self.preflight(now_epoch_ns=now))
        self.assertIsNone(self.preflight())
        self.assertEqual(self.verify().canonical_bytes, expected)

    def test_intent_preflight_checks_both_real_signatures_without_caching_success(self):
        self.assertIsNone(self.preflight())
        for role in ROLES:
            other_role = "authorization" if role == "checkpoint" else "checkpoint"
            payload = json.loads(self.checkpoint if role == "checkpoint" else self.authorization)["payload"]
            changed = self.signing.sign(role, payload, key=self.signing.keys[other_role])
            pair = (changed, self.authorization) if role == "checkpoint" else (self.checkpoint, changed)
            with self.subTest(role=role):
                with self.assertRaisesRegex(admission.AuditInitializationAdmissionError,
                                            "^audit initialization signed evidence is invalid$"):
                    self.preflight(*pair)
                # A previously valid preflight cannot replace the full
                # verifier's own signature checks or open its proof iterator.
                self.reject_before_stream(*pair)

    def test_intent_preflight_rechecks_explicit_time_binding_and_root_inputs(self):
        cases = (
            ({"now_epoch_ns": 19_999_999_999}, "audit initialization envelope is outside its validity interval"),
            ({"now_epoch_ns": 100_000_000_000}, "audit initialization envelope is outside its validity interval"),
            ({"now_epoch_ns": True}, "audit initialization integer is outside its exact bound"),
            ({"expectation": replace(self.expectation, nonce_digest=label_digest("other-intent"))},
             "audit initialization payload fields or bindings differ"),
            ({"trust": replace(self.trust, policy_digest=label_digest("other-policy"))},
             "audit initialization payload fields or bindings differ"),
            ({"outbox_root": replace(self.outbox.root, root_revision=self.outbox.root.root_revision + 1)},
             "audit initialization checkpoint or authorization linkage differs"),
            ({"aggregate_root": self.outbox.root}, "audit initialization root has the wrong table"),
        )
        for changes, message in cases:
            with self.subTest(argument=next(iter(changes))):
                with self.assertRaises(admission.AuditInitializationAdmissionError) as raised:
                    self.preflight(**changes)
                self.assertEqual(str(raised.exception), message)

    def test_intent_preflight_preserves_closed_payload_and_digest_syntax_guards(self):
        for role in ROLES:
            baseline = self.checkpoint_payload if role == "checkpoint" else self.authorization_payload
            for changed in ({**baseline, "extra": None},
                            {key: value for key, value in baseline.items() if key != "sourceRevision"}):
                with self.subTest(role=role, fields=tuple(changed)), self.assertRaisesRegex(
                    admission.AuditInitializationAdmissionError,
                    "^audit initialization payload fields or bindings differ$",
                ):
                    self.preflight(*self.signed_pair(**{role + "_payload": changed}))
        for field in ("preparationDigest", "counterRowDigest"):
            changed = {**self.authorization_payload, field: "not-a-digest"}
            with self.subTest(field=field), self.assertRaisesRegex(
                admission.AuditInitializationAdmissionError,
                "^audit initialization expected digest is invalid$",
            ):
                self.preflight(*self.signed_pair(authorization_payload=changed))

    def test_each_role_signature_failure_and_cross_role_bytes_precede_stream(self):
        for role in ROLES:
            raw = json.loads(self.checkpoint if role == "checkpoint" else self.authorization)
            raw["signatureBase64Url"] = "A" * 86
            if role == "checkpoint":
                self.reject_before_stream(checkpoint=wire_json(raw))
                self.reject_before_stream(checkpoint=self.authorization)
            else:
                self.reject_before_stream(authorization=wire_json(raw))
                self.reject_before_stream(authorization=self.checkpoint)

    def test_trust_requires_distinct_roles_keys_identities_and_exact_bounded_time(self):
        checkpoint_pin, authorization_pin = self.signing.pins["checkpoint"], self.signing.pins["authorization"]
        changes = [
            {"checkpoint_signer": authorization_pin},
            {"authorization_signer": replace(authorization_pin, public_key_der=checkpoint_pin.public_key_der)},
            {"authorization_signer": replace(authorization_pin, authority_identity_digest=checkpoint_pin.authority_identity_digest)},
            {"checkpoint_signer": {}}, {"policy_digest": "sha256:" + "A" * 64},
            {"not_before_epoch_ns": True}, {"not_before_epoch_ns": -1},
            {"not_after_epoch_ns": 0}, {"not_after_epoch_ns": MAX_INTEGER + 1},
            {"maximum_lifetime_ns": 0}, {"maximum_lifetime_ns": True},
            {"maximum_lifetime_ns": 300_000_000_001},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(admission.AuditInitializationAdmissionError):
                replace(self.trust, **change)
        for value in (None, False, -1, MAX_INTEGER + 1, 30.0, "30"):
            with self.subTest(now=value):
                self.reject_before_stream(now_epoch_ns=value)
        self.reject_before_stream(trust={})
        self.reject_before_stream(expectation={})

    def test_expectation_requires_exact_digests_integers_and_checkpoint_ancestry(self):
        for field in ("database_identity_digest", "database_generation_digest", "source_contract_digest",
                "schema_contract_digest", "initializer_measurement_digest", "operation_id", "nonce_digest",
                "fence_id", "writer_inventory_digest", "fence_evidence_digest", "initialization_ancestry_digest"):
            with self.subTest(field=field), self.assertRaises(admission.AuditInitializationAdmissionError):
                replace(self.expectation, **{field: "not-a-digest"})
        for field in ("fence_generation", "checkpoint_sequence", "initialized_at_epoch_ns"):
            for value in (False, True, -1, MAX_INTEGER + 1, 1.0, "1"):
                with self.subTest(field=field, value=value), self.assertRaises(admission.AuditInitializationAdmissionError):
                    replace(self.expectation, **{field: value})
        for change in ({"fence_generation": 0}, {"checkpoint_sequence": 0},
                       {"checkpoint_sequence": 2}, {"checkpoint_predecessor_digest": label_digest("predecessor")}):
            with self.subTest(change=change), self.assertRaises(admission.AuditInitializationAdmissionError):
                replace(self.expectation, **change)
        later = replace(self.expectation, checkpoint_sequence=2,
                        checkpoint_predecessor_digest=label_digest("predecessor"))
        self.assertEqual(later.checkpoint_sequence, 2)
        self.expectation = later
        checkpoint, authorization = self.payloads()
        accepted = self.verify(*self.signed_pair(checkpoint_payload=checkpoint, authorization_payload=authorization))
        self.assertEqual(accepted.json_projection()["checkpoint"]["payload"]["binding"]["checkpointSequence"], 2)

    def test_public_context_snapshot_owns_nested_pins_without_verifying_authority(self):
        # Representation/ownership only: this API consumes no signed envelope.
        caller_trust, caller_expectation = copy.deepcopy(self.trust), replace(self.expectation)
        snapshots = admission.snapshot_audit_initialization_context(caller_trust, caller_expectation)
        self.assertIs(type(snapshots), tuple)
        self.assertEqual(snapshots, (self.trust, self.expectation))
        owned_trust, owned_expectation = snapshots
        for original, owned in ((caller_trust, owned_trust), (caller_expectation, owned_expectation),
                (caller_trust.checkpoint_signer, owned_trust.checkpoint_signer),
                (caller_trust.authorization_signer, owned_trust.authorization_signer)):
            self.assertIsNot(original, owned)
            self.assertIs(type(owned), type(original))
        for target, field in ((caller_trust, "policy_digest"), (caller_expectation, "nonce_digest"),
                (caller_trust.checkpoint_signer, "measurement_digest"),
                (caller_trust.authorization_signer, "attestation_receipt_digest")):
            changed = label_digest("changed-caller-" + field)
            object.__setattr__(target, field, changed)
            self.assertEqual(getattr(target, field), changed)
        self.assertEqual(snapshots, (self.trust, self.expectation))
        self.assertNotEqual(caller_trust, owned_trust)
        self.assertNotEqual(caller_expectation, owned_expectation)
        invalid = (
            (bypassed_dataclass(self.trust, maximum_lifetime_ns=True), self.expectation),
            (self.trust, bypassed_dataclass(self.expectation, checkpoint_sequence=True)),
            (bypassed_dataclass(self.trust, checkpoint_signer=bypassed_dataclass(
                self.trust.checkpoint_signer, measurement_digest=None)), self.expectation),
        )
        for index, (trust, expectation) in enumerate(invalid):
            with self.subTest(case=index), self.assertRaises(admission.AuditInitializationAdmissionError):
                admission.snapshot_audit_initialization_context(trust, expectation)

    def test_context_and_root_snapshots_revalidate_incomplete_or_bypassed_dataclasses(self):
        cases = []
        for argument, value in (("trust", self.trust), ("expectation", self.expectation),
                                ("outbox_root", self.outbox.root), ("aggregate_root", self.aggregate.root)):
            cases.append({argument: object.__new__(type(value))})
        for field, value in (("policy_digest", True), ("maximum_lifetime_ns", True)):
            cases.append({"trust": bypassed_dataclass(self.trust, **{field: value})})
        cases.extend((
            {"expectation": bypassed_dataclass(self.expectation, checkpoint_sequence=True)},
            {"expectation": bypassed_dataclass(self.expectation, initialized_at_epoch_ns=-1)},
            {"outbox_root": bypassed_dataclass(self.outbox.root, leaf_count=True)},
            {"aggregate_root": bypassed_dataclass(self.aggregate.root, root_revision=False)},
        ))
        for pin in (object.__new__(signatures.InitializationSignerPin),
                    bypassed_dataclass(self.trust.checkpoint_signer, measurement_digest=None),
                    bypassed_dataclass(self.trust.checkpoint_signer,
                                       public_key_der=bytearray(self.trust.checkpoint_signer.public_key_der))):
            cases.append({"trust": bypassed_dataclass(self.trust, checkpoint_signer=pin)})
        for index, changes in enumerate(cases):
            # Do not repr deliberately incomplete dataclasses in subTest:
            # their generated repr itself expects the missing fields.
            with self.subTest(case=index, argument=next(iter(changes))):
                self.reject_before_stream(**changes)

    def test_authentic_common_claims_and_closed_payloads_reject_before_stream(self):
        for role in ROLES:
            baseline = self.checkpoint_payload if role == "checkpoint" else self.authorization_payload
            for field, value in (("sourceRevision", authority_contract.SOURCE_REVISION + ".other"),
                    ("preparationProfile", "other-profile"), ("operationManifestDigest", label_digest("other-manifest")),
                    ("trustPolicyDigest", label_digest("other-trust-policy")), ("extra", None)):
                changed = {**copy.deepcopy(baseline), field: value}
                pair = self.signed_pair(**{role + "_payload": changed})
                with self.subTest(role=role, field=field):
                    self.reject_before_stream(*pair)
            changed = copy.deepcopy(baseline)
            del changed["sourceRevision"]
            with self.subTest(role=role, missing="sourceRevision"):
                self.reject_before_stream(*self.signed_pair(**{role + "_payload": changed}))

    def test_every_expected_binding_is_compared_for_both_authentic_roles(self):
        for role in ROLES:
            baseline = self.checkpoint_payload if role == "checkpoint" else self.authorization_payload
            for field, original in self.binding().items():
                changed = copy.deepcopy(baseline)
                changed["binding"][field] = original + 1 if type(original) is int else label_digest("crossed-" + field)
                with self.subTest(role=role, binding=field):
                    self.reject_before_stream(*self.signed_pair(**{role + "_payload": changed}))
            for field, value in (("checkpointSequence", True), ("initializedAtEpochNs", 1_000_000_000.0),
                                 ("extra", None)):
                changed = copy.deepcopy(baseline)
                changed["binding"][field] = value
                with self.subTest(role=role, type_or_extra=field):
                    self.reject_before_stream(*self.signed_pair(**{role + "_payload": changed}))
            changed = copy.deepcopy(baseline)
            del changed["binding"]["nonceDigest"]
            self.reject_before_stream(*self.signed_pair(**{role + "_payload": changed}))

    def test_checkpoint_root_descriptors_key_contract_and_disposition_precede_stream(self):
        variants = []
        for index in (0, 1):
            for field, value in (("rootRevision", 100), ("leafCount", 100),
                                 ("rootDigest", label_digest("crossed-root")), ("table", "unlisted_table")):
                changed = copy.deepcopy(self.checkpoint_payload)
                changed["beforeRoots"][index][field] = value
                variants.append(changed)
        for roots in (list(reversed(self.prepared_document["beforeRoots"])),
                      self.prepared_document["beforeRoots"][:1], self.prepared_document["beforeRoots"] * 2):
            variants.append({**self.checkpoint_payload, "beforeRoots": roots})
        variants.extend((
            {**self.checkpoint_payload, "tableKeyContracts": {OUTBOX: ["id"]}},
            {**self.checkpoint_payload, "tableKeyContracts": {OUTBOX: ["other"], AGGREGATE: ["aggregate_id"]}},
            {**self.checkpoint_payload, "initializationDisposition": "reset-deleted-counter"},
        ))
        for changed in variants:
            with self.subTest(changed=changed), self.assertRaises(admission.AuditInitializationAdmissionError):
                def records():
                    raise AssertionError("checkpoint descriptor rejection must precede inventory")
                    yield
                self.verify(*self.signed_pair(checkpoint_payload=changed), outbox_records=records())

    def test_before_root_zero_counters_do_not_accept_equal_python_boolean_aliases(self):
        aggregate = aggregate_tree(revision=0)
        missing = absence(aggregate)
        prepared = initialization_fixture.AuditCapacityInitializationTests.expected(self, aggregate=aggregate)
        checkpoint = {**self.checkpoint_payload, "beforeRoots": prepared["beforeRoots"]}
        authorization = {**self.authorization_payload,
            "preparationDigest": wire_digest("catchplate.metadataAuditCapacityInitializationPreparation/v1",
                                            wire_json(prepared)),
            "counterRowDigest": prepared["counterRowDigest"], "afterRoots": prepared["afterRoots"]}
        valid = self.signed_pair(checkpoint_payload=checkpoint, authorization_payload=authorization)
        self.assertEqual(self.verify(*valid, aggregate_root=aggregate.root,
                                    aggregate_absence=missing).preparation.json_projection(), prepared)
        for field in ("rootRevision", "leafCount"):
            changed = copy.deepcopy(checkpoint)
            changed["beforeRoots"][1][field] = False
            self.assertEqual(changed["beforeRoots"], checkpoint["beforeRoots"])
            self.assertNotEqual(wire_json(changed["beforeRoots"]), wire_json(checkpoint["beforeRoots"]))
            with self.subTest(field=field):
                self.reject_before_stream(*self.signed_pair(checkpoint_payload=changed,
                    authorization_payload=authorization), aggregate_root=aggregate.root, aggregate_absence=missing)

    def test_crossed_genuinely_signed_checkpoint_is_not_authorized(self):
        changed = {**self.checkpoint_payload, "issuedAtEpochNs": 11_000_000_000}
        crossed = self.signing.sign("checkpoint", changed)
        signatures.verify_initialization_envelope(crossed, role="checkpoint", pin=self.signing.pins["checkpoint"])
        signatures.verify_initialization_envelope(self.authorization, role="authorization", pin=self.signing.pins["authorization"])
        self.assertNotEqual(signed_digest(ROLES["checkpoint"]["envelope"], crossed),
                            json.loads(self.authorization)["payload"]["checkpointEnvelopeDigest"])
        self.reject_before_stream(checkpoint=crossed)

    def test_explicit_validity_endpoints_lifetime_and_role_window_ordering(self):
        for now in (20_000_000_000, 99_999_999_999):
            self.assertEqual(self.verify(now_epoch_ns=now).verified_at_epoch_ns, now)
        for now in (19_999_999_999, 100_000_000_000):
            self.reject_before_stream(now_epoch_ns=now)
        variants = [
            ("checkpoint", "issuedAtEpochNs", 21_000_000_000),
            ("checkpoint", "issuedAtEpochNs", -1),
            ("checkpoint", "expiresAtEpochNs", 99_000_000_000),
            ("checkpoint", "expiresAtEpochNs", 200_000_000_001),
            ("authorization", "issuedAtEpochNs", 9_000_000_000),
            ("authorization", "issuedAtEpochNs", self.now + 1),
            ("authorization", "expiresAtEpochNs", 101_000_000_000),
            ("authorization", "expiresAtEpochNs", 20_000_000_000),
            ("authorization", "issuedAtEpochNs", True),
            ("authorization", "expiresAtEpochNs", 100_000_000_000.0),
        ]
        for role, field, value in variants:
            baseline = self.checkpoint_payload if role == "checkpoint" else self.authorization_payload
            changed = {**baseline, field: value}
            with self.subTest(role=role, field=field, value=value):
                self.reject_before_stream(*self.signed_pair(**{role + "_payload": changed}))
        self.reject_before_stream(trust=replace(self.trust, maximum_lifetime_ns=89_999_999_999))

    def test_authentic_wrong_preparation_row_and_after_root_fail_after_recomputation(self):
        variants = []
        for field in ("preparationDigest", "counterRowDigest"):
            variants.append({**self.authorization_payload, field: label_digest("crossed-" + field)})
        for field, value in (("rootRevision", 100), ("leafCount", 100),
                             ("rootDigest", label_digest("crossed-after-root"))):
            changed = copy.deepcopy(self.authorization_payload)
            changed["afterRoots"][1][field] = value
            variants.append(changed)
        for changed in variants:
            consumed = []
            def records():
                for record in self.records:
                    consumed.append(record["selectedRow"]["key"]["id"])
                    yield record
            pair = self.signed_pair(authorization_payload=changed)
            # Genuine signatures on false preparation commitments pass only
            # intent syntax/binding checks, never the complete verifier.
            self.assertIsNone(self.preflight(*pair))
            with self.subTest(changed=changed), self.assertRaisesRegex(
                admission.AuditInitializationAdmissionError,
                "^audit initialization authorization differs from recomputation$",
            ):
                self.verify(*pair, outbox_records=records())
            self.assertEqual(len(consumed), 3)

    def test_changed_missing_outbox_and_forged_preparation_cannot_replace_proof_stream(self):
        changed = copy.deepcopy(self.records)
        changed[0]["selectedRow"]["row"]["attempts"] += 1
        forged = copy.deepcopy(self.prepared_document)
        forged["inventory"]["outstandingCount"] = 0
        forged["counterRow"]["live_count"] = 999
        constructed = initialization.AuditCapacityInitializationPreparation(wire_json(forged))
        # Direct evidence construction is also representation-only. Its type
        # cannot stand in for either signature verification or the proof stream.
        constructed_evidence = admission.AuditInitializationEvidence(constructed, b"{}", b"{}", self.now)
        self.assertEqual(constructed_evidence.preparation.json_projection()["counterRow"]["live_count"], 999)
        self.reject_before_stream(checkpoint=constructed_evidence.checkpoint_bytes,
                                  authorization=constructed_evidence.authorization_bytes)
        for records in (changed, self.records[:1], constructed, self.prepared_document):
            with self.subTest(kind=type(records).__name__), self.assertRaises(admission.AuditInitializationAdmissionError):
                self.verify(outbox_records=records)
        invalid_absence = copy.deepcopy(self.missing)
        invalid_absence["proof"]["proofDigest"] = label_digest("wrong-absence-proof")
        with self.assertRaises(admission.AuditInitializationAdmissionError):
            self.verify(aggregate_absence=invalid_absence)

    def test_owned_inputs_frozen_output_and_stream_failure_boundary(self):
        original = copy.deepcopy((self.records, self.missing))
        evidence = self.verify()
        self.assertEqual((self.records, self.missing), original)
        changed = evidence.json_projection()
        changed["checkpoint"]["payload"].clear()
        changed["preparation"]["counterRow"].clear()
        self.assertEqual(evidence.json_projection()["preparation"], self.prepared_document)
        with self.assertRaises(FrozenInstanceError):
            evidence.verified_at_epoch_ns = 0
        missing = copy.deepcopy(self.missing)
        def records():
            missing.clear()
            yield from self.records
        self.assertEqual(self.verify(outbox_records=records(), aggregate_absence=missing).canonical_bytes,
                         evidence.canonical_bytes)
        def interrupted():
            yield self.records[0]
            raise RuntimeError("component producer interrupted")
        with self.assertRaisesRegex(RuntimeError, "^component producer interrupted$"):
            self.verify(outbox_records=interrupted())

    def test_success_is_not_a_one_use_fence_or_installer_authorization(self):
        # Pure verification is intentionally repeatable. Trusted context and
        # signed fence/currentness claims are inputs, not observed DB effects.
        first, repeated = self.verify(), self.verify()
        self.assertEqual(first.canonical_bytes, repeated.canonical_bytes)
        self.assertIs(first.json_projection()["installationPermitted"], False)
        self.assertIs(first.preparation.json_projection()["installationPermitted"], False)

    def test_generator_mutation_cannot_rebind_owned_context_or_root_snapshots(self):
        expected = self.verify().canonical_bytes
        local_trust = copy.deepcopy(self.trust)
        local_expectation = replace(self.expectation)
        local_outbox, local_aggregate = replace(self.outbox.root), replace(self.aggregate.root)
        original = (self.trust.policy_digest, self.trust.checkpoint_signer.measurement_digest,
                    self.expectation.initialized_at_epoch_ns, self.outbox.root, self.aggregate.root)

        def records():
            object.__setattr__(local_expectation, "initialized_at_epoch_ns", 9_000_000_000)
            object.__setattr__(local_expectation, "nonce_digest", label_digest("mutated-nonce"))
            object.__setattr__(local_trust, "policy_digest", label_digest("mutated-policy"))
            object.__setattr__(local_trust.checkpoint_signer, "measurement_digest", label_digest("mutated-measurement"))
            for root in (local_outbox, local_aggregate):
                object.__setattr__(root, "root_revision", 999)
                object.__setattr__(root, "leaf_count", 999)
                object.__setattr__(root, "root_digest", label_digest("mutated-root"))
            yield from self.records

        evidence = self.verify(trust=local_trust, expectation=local_expectation,
            outbox_root=local_outbox, aggregate_root=local_aggregate, outbox_records=records())
        self.assertEqual(evidence.canonical_bytes, expected)
        self.assertEqual(local_expectation.initialized_at_epoch_ns, 9_000_000_000)
        self.assertEqual((local_outbox.root_revision, local_aggregate.leaf_count), (999, 999))
        self.assertEqual((self.trust.policy_digest, self.trust.checkpoint_signer.measurement_digest,
                          self.expectation.initialized_at_epoch_ns, self.outbox.root, self.aggregate.root), original)


if __name__ == "__main__":
    unittest.main()
