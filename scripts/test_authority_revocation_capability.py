#!/usr/bin/env python3
"""Real signed capability bytes over independently authored retained evidence.

All four Ed25519 identities are deterministic local fixture keys. The initial
witness reservation is genuinely signed, but no witness process, journal,
generation enrollment, current roots or post-plan witness event is invented.
The authenticator bytes remain the existing signed-verifier fixture evidence,
not a claim that a physical authenticator was exercised. No registry is replaced.
"""
from __future__ import annotations

import copy
from dataclasses import FrozenInstanceError
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from serverware import authority_contract
from serverware import authority_query_read_work as accounting
from serverware import authority_revocation_capability as capability
from serverware import authority_revocation_retention as retention
import test_authority_revocation_plan as oracle
import test_authority_revocation_retention as record_oracle
import test_authority_revocation_reservation as reservation_oracle
import test_authority_revocation_wire as wire_oracle


CAPABILITY_SCHEMA = "serverware.policyAuthorityDatabaseCapability/v4"
SIGNED_SCHEMA = "serverware.signedPolicyAuthorityDatabaseCapability/v4"
RECORD_SCHEMA = "serverware.policyAuthorityRevocationRetainedCapability/v1"
REQUEST_SCHEMA = "serverware.policyAuthorityReplayWitnessRequest/v2"
RECEIPT_SCHEMA = "serverware.policyAuthorityReplayWitnessReceipt/v2"
HEAD_DOMAIN = "serverware.policyAuthorityReplayWitnessHead/v2"
WITNESS_ENVELOPE_DOMAIN = "serverware.policyAuthorityReplayWitnessEnvelope/v2"
WEBAUTHN_SCHEMA = "serverware.policyAuthorityWebAuthnReceipt/v1"
CREDENTIAL_DOMAIN = "serverware.policyAuthorityWebAuthnCredentialBinding/v1"
PAYLOAD_FIELDS = frozenset({
    "schema", "capabilityId", "envelopeId", "plannerTransactionId",
    "authorizationProjectionDigest", "selectedBusinessRowsDigest", "mutationPlanDigest",
    "expectedResultDigest", "operation", "operationId", "handlerName", "requestDigest",
    "operationManifestDigest", "queryManifestDigest", "authorityRootSetDigest",
    "authoritySnapshotDigest", "approverPolicyDigest", "webauthnReceipt", "webauthnReceiptDigest",
    "webauthnTrustHighWaterDigest", "witnessReservation", "witnessReservationDigest",
    "witnessSequence", "witnessHeadDigest", "witnessPredecessorHeadDigest", "deadlineMonotonicNs",
    "deadlineEpochNs", "fence", "issuedMonotonicNs", "issuedAtEpochNs", "expiresAtEpochNs",
    "issuerSessionIdentityDigest", "planProtocol", "retainedRecordDigest", "rootTransitionDigest",
    "exactRequestBytesDigest",
})
ENVELOPE_FIELDS = frozenset({"schema", "sourceRevision", "signerIdentity", "payload", "signatureBase64Url"})
REQUEST_FIELDS = frozenset({"schema", "envelopeId", "parentEnvelopeId", "phase", "operation",
    "requestDigest", "capabilityId", "resultDigest", "predecessorReceiptDigest", "deadlineMonotonicNs",
    "configurationDigest", "operationManifestDigest", "generationSequence", "generationDigest",
    "issuedAtEpochNs", "signature"})
RECEIPT_FIELDS = frozenset({"schema", "envelopeId", "parentEnvelopeId", "phase", "operation",
    "requestDigest", "capabilityId", "resultDigest", "witnessIdentityDigest", "sequence", "fence",
    "headDigest", "predecessorHeadDigest", "predecessorReceiptDigest", "logPredecessorHeadDigest",
    "deadlineMonotonicNs", "issuedAtEpochNs", "generationSequence", "generationDigest",
    "canonicalRequestDigest", "signature"})
HEADER_FIELDS = frozenset({"schema", "sourceRevision", "capabilityProtocol", "capabilityId",
    "plannerTransactionId", "executionEnvelopeId", "retainedRecordDigest", "rootTransitionDigest",
    "authoritySnapshotDigest", "exactRequestBytesDigest", "capabilityDigest", "signerKeyDigest",
    "witnessKeyDigest", "envelopeDigest", "envelopeByteCount", "witnessRequestBytesDigest",
    "witnessRequestByteCount"})
WEBAUTHN_COPY_FIELDS = ("operationId", "challengeDigest", "challengeId", "credentialRecordId",
    "credentialId", "credentialPolicyDigest", "trustHighWaterDigest", "clientDataJSONDigest",
    "authenticatorDataDigest", "signatureDigest", "flags", "priorCounter", "counter",
    "userPresent", "userVerified", "verifiedAtEpochNs")
CREDENTIAL_FIELDS = ("id", "credential_id", "user_id", "public_key_cose", "sign_count", "aaguid",
    "authenticator_class", "attestation_trusted", "attestation_leaf_sha256", "attestation_root_sha256",
    "attestation_trust_bundle_digest", "attestation_trust_bundle_sequence", "revoked_at")


def length_domain_digest(domain, *frames):
    """The legacy credential binding length-prefixes the domain itself."""
    encoded = domain.encode("ascii")
    material = len(encoded).to_bytes(8, "big") + encoded
    for frame in frames:
        material += len(frame).to_bytes(8, "big") + frame
    return oracle.sha(material)


def original_rows(fixture):
    evidence = fixture.plan.payload["webauthnEvidence"]
    rows = fixture.plan.payload["selectedBusinessRows"]
    challenge = next(item["row"] for item in rows
        if item["table"] == "webauthn_challenges" and item["key"] == {"id": evidence["challengeId"]})
    credential = next(item["row"] for item in rows
        if item["table"] == "webauthn_credentials" and item["key"] == {"id": evidence["credentialRecordId"]})
    return challenge, {name: credential[name] for name in CREDENTIAL_FIELDS}


def webauthn_receipt(fixture):
    challenge, credential = original_rows(fixture)
    return {"schema": WEBAUTHN_SCHEMA,
        **{name: fixture.plan.payload["webauthnEvidence"][name] for name in WEBAUTHN_COPY_FIELDS},
        "challengeRowDigest": oracle.framed("serverware.policyAuthorityWebAuthnChallengeRow/v1",
            oracle.wire(challenge)),
        "credentialBindingDigest": length_domain_digest(CREDENTIAL_DOMAIN, oracle.wire(credential))}


class CapabilityFixture:
    """Independent raw documents; no production verifier builds expected data."""
    def __init__(self):
        self.plan = oracle.PlanFixture(approval=False, include_audit=False)
        self.key = Ed25519PrivateKey.from_private_bytes(bytes(range(128, 160)))
        self.witness_key = Ed25519PrivateKey.from_private_bytes(bytes(range(160, 192)))
        self.other_key = Ed25519PrivateKey.from_private_bytes(bytes(range(192, 224)))
        self.signer_identity = {name: oracle.sha(("capability signer " + name).encode("ascii"))
            for name in ("sessionIdentityDigest", "measurementDigest", "attestationReceiptDigest")}
        self.issuer_identity = oracle.sha(b"independently admitted issuer session")
        self.witness_identity = oracle.sha(b"independently admitted preliminary witness")
        self.configuration_digest = oracle.sha(b"independently admitted authority configuration")
        self.generation_sequence = 3
        self.generation_digest = oracle.sha(b"independently admitted historical generation")
        self.execution_envelope_id = oracle.framed("serverware.policyAuthorityExecutionEnvelope/v1",
            self.plan.semantic.receipt.capability_id.encode("ascii"), self.plan.planner_transaction_id.encode("ascii"))
        self.witness_request = {"schema": REQUEST_SCHEMA, "parentEnvelopeId": None, "phase": "reserve",
            "operation": "webauthn.credential.revoke", "requestDigest": self.plan.semantic.request_digest,
            "capabilityId": self.plan.semantic.receipt.capability_id, "resultDigest": None,
            "predecessorReceiptDigest": None, "deadlineMonotonicNs": self.plan.deadline_monotonic_ns,
            "configurationDigest": self.configuration_digest,
            "operationManifestDigest": authority_contract.OPERATION_MANIFEST_DIGEST,
            "generationSequence": self.generation_sequence, "generationDigest": self.generation_digest,
            "issuedAtEpochNs": self.plan.reserved_at_epoch_ns}
        material = {name: self.witness_request[name] for name in ("phase", "operation", "requestDigest",
            "capabilityId", "resultDigest", "predecessorReceiptDigest", "generationSequence", "generationDigest")}
        self.witness_request["envelopeId"] = oracle.framed(WITNESS_ENVELOPE_DOMAIN, oracle.wire(material))
        self.sign_request()
        self.witness_receipt = {"schema": RECEIPT_SCHEMA,
            **{name: self.witness_request[name] for name in ("envelopeId", "parentEnvelopeId", "phase",
                "operation", "requestDigest", "capabilityId", "resultDigest", "deadlineMonotonicNs",
                "generationSequence", "generationDigest")},
            "witnessIdentityDigest": self.witness_identity, "sequence": 11, "fence": self.plan.fence,
            "headDigest": None, "predecessorHeadDigest": None, "predecessorReceiptDigest": None,
            "logPredecessorHeadDigest": oracle.sha(b"historical witness log predecessor"),
            "issuedAtEpochNs": self.plan.reserved_at_epoch_ns,
            "canonicalRequestDigest": oracle.framed(REQUEST_SCHEMA, oracle.wire(self.witness_request))}
        self.sign_receipt()
        self.rebuild()

    def sign_request(self, *, key=None):
        unsigned = {name: value for name, value in self.witness_request.items() if name != "signature"}
        self.witness_request = {**unsigned, "signature": oracle.encoded(
            (self.key if key is None else key).sign(oracle.framed(REQUEST_SCHEMA, oracle.wire(unsigned)).encode("ascii")))}

    def sign_receipt(self, *, key=None, update_head=True):
        unsigned = {name: value for name, value in self.witness_receipt.items() if name != "signature"}
        if update_head:
            unsigned["headDigest"] = oracle.framed(HEAD_DOMAIN, oracle.wire({**unsigned, "headDigest": None}))
        self.witness_receipt = {**unsigned, "signature": oracle.encoded(
            (self.witness_key if key is None else key).sign(
                oracle.framed(RECEIPT_SCHEMA, oracle.wire(unsigned)).encode("ascii")))}
        self.witness_receipt_digest = oracle.framed(RECEIPT_SCHEMA, oracle.wire(self.witness_receipt))

    def rebuild(self):
        plan, measured = self.plan, self.plan.payload["measuredPlan"]
        self.retained_bytes = oracle.wire(plan.envelope)
        self.context_bytes = oracle.wire(record_oracle.record_context(plan))
        self.retained_digest = oracle.framed(record_oracle.RECORD_SCHEMA,
            oracle.wire(record_oracle.record_header(plan, self.retained_bytes, self.context_bytes)))
        self.execution_request = reservation_oracle.expected_request(plan)
        self.execution_bytes = oracle.wire(self.execution_request)
        receipt = webauthn_receipt(self)
        self.payload = {"schema": CAPABILITY_SCHEMA,
            **{name: measured[name] for name in ("capabilityId", "plannerTransactionId",
                "authorizationProjectionDigest", "selectedBusinessRowsDigest", "mutationPlanDigest",
                "operation", "operationId", "requestDigest", "operationManifestDigest", "queryManifestDigest",
                "authoritySnapshotDigest", "deadlineMonotonicNs", "deadlineEpochNs", "fence", "rootTransitionDigest")},
            "envelopeId": self.execution_envelope_id, "expectedResultDigest": plan.payload["expectedResultDigest"],
            "handlerName": "revoke_webauthn_credential", "authorityRootSetDigest": measured["authorityRootSetBeforeDigest"],
            "approverPolicyDigest": plan.approver_policy_digest, "webauthnReceipt": receipt,
            "webauthnReceiptDigest": oracle.framed(WEBAUTHN_SCHEMA, oracle.wire(receipt)),
            "webauthnTrustHighWaterDigest": receipt["trustHighWaterDigest"],
            "witnessReservation": copy.deepcopy(self.witness_receipt),
            "witnessReservationDigest": self.witness_receipt_digest,
            "witnessSequence": self.witness_receipt["sequence"], "witnessHeadDigest": self.witness_receipt["headDigest"],
            "witnessPredecessorHeadDigest": self.witness_receipt["predecessorHeadDigest"],
            "issuedMonotonicNs": plan.deadline_monotonic_ns - (plan.deadline_epoch_ns - plan.reserved_at_epoch_ns),
            "issuedAtEpochNs": plan.reserved_at_epoch_ns, "expiresAtEpochNs": plan.deadline_epoch_ns,
            "issuerSessionIdentityDigest": self.issuer_identity, "planProtocol": "revocation-v4",
            "retainedRecordDigest": self.retained_digest, "exactRequestBytesDigest": oracle.sha(self.execution_bytes)}
        self.resign()

    def resign(self, *, key=None):
        unsigned = {"schema": SIGNED_SCHEMA, "sourceRevision": authority_contract.SOURCE_REVISION,
            "signerIdentity": copy.deepcopy(self.signer_identity), "payload": copy.deepcopy(self.payload)}
        self.envelope = {**unsigned, "signatureBase64Url": oracle.encoded(
            (self.key if key is None else key).sign(oracle.framed(SIGNED_SCHEMA, oracle.wire(unsigned)).encode("ascii")))}
        self.raw = oracle.wire(self.envelope)

    def arguments(self):
        return {"envelope_bytes": self.raw, "retained_envelope_bytes": self.retained_bytes,
            "evaluation_context_bytes": self.context_bytes, "execution_request_bytes": self.execution_bytes,
            "witness_request_bytes": oracle.wire(self.witness_request), "signer_public_key": self.key.public_key(),
            "witness_public_key": self.witness_key.public_key(), "expected_signer_identity": copy.deepcopy(self.signer_identity),
            "expected_issuer_session_identity_digest": self.issuer_identity,
            "expected_execution_envelope_id": self.execution_envelope_id,
            "expected_witness_receipt_digest": self.witness_receipt_digest,
            "expected_witness_identity_digest": self.witness_identity,
            "expected_configuration_digest": self.configuration_digest,
            "expected_generation_sequence": self.generation_sequence,
            "expected_generation_digest": self.generation_digest,
            "retention_expectations": wire_oracle.expectations(self.plan)}


def expected_header(fixture):
    payload, raw_request = fixture.payload, oracle.wire(fixture.witness_request)
    return {"schema": RECORD_SCHEMA, "sourceRevision": authority_contract.SOURCE_REVISION,
        "capabilityProtocol": "revocation-v4", "capabilityId": payload["capabilityId"],
        "plannerTransactionId": payload["plannerTransactionId"], "executionEnvelopeId": payload["envelopeId"],
        "retainedRecordDigest": fixture.retained_digest, "rootTransitionDigest": payload["rootTransitionDigest"],
        "authoritySnapshotDigest": payload["authoritySnapshotDigest"], "exactRequestBytesDigest": oracle.sha(fixture.execution_bytes),
        "capabilityDigest": oracle.framed(CAPABILITY_SCHEMA, oracle.wire(payload)),
        "signerKeyDigest": oracle.sha(fixture.key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
        "witnessKeyDigest": oracle.sha(fixture.witness_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)),
        "envelopeDigest": oracle.sha(fixture.raw), "envelopeByteCount": len(fixture.raw),
        "witnessRequestBytesDigest": oracle.sha(raw_request), "witnessRequestByteCount": len(raw_request)}


PHASES = ("capture", "transport", "capability_authentication", "witness_verification",
          "retained_verification", "bindings", "record")


def capture_graph(fixture):
    supplied = fixture.arguments()
    return {"retention": {name: value for name, value in supplied["retention_expectations"].items()
                if name not in {"planner_public_key", "verifier_public_key", "database_now"}},
        "expectedSignerIdentity": supplied["expected_signer_identity"],
        "expectedIssuerSessionIdentityDigest": supplied["expected_issuer_session_identity_digest"],
        "expectedExecutionEnvelopeId": supplied["expected_execution_envelope_id"],
        "expectedWitnessReceiptDigest": supplied["expected_witness_receipt_digest"],
        "expectedWitnessIdentityDigest": supplied["expected_witness_identity_digest"],
        "expectedConfigurationDigest": supplied["expected_configuration_digest"],
        "expectedGenerationSequence": supplied["expected_generation_sequence"],
        "expectedGenerationDigest": supplied["expected_generation_digest"]}


def signature_work(domain, unsigned):
    # Independent codec reservation: padding, ASCII conversion, URL translation
    # and decoder input88 each, plus exact decoded64. The actual Ed25519 work
    # is an attempt counter, not a claim to meter its cryptographic internals.
    return oracle.add((0, 4 * 88 + 64, 0), oracle.frame_cost(domain, (oracle.wire(unsigned),)),
                      (0, 2 * 71, 2))


def independent_capability_work(fixture):
    """Closed successful passes, with the genuine retained hold peak shifted.

    No production accounting helper, observed counter or verifier result is
    consulted. Only the existing independent retained proof oracle is reused.
    """
    add, graph = oracle.add, oracle.graph_cost
    same = lambda value: oracle.canonical_comparison(value, value)
    request, receipt = fixture.witness_request, fixture.witness_receipt
    unsigned_capability = {name: value for name, value in fixture.envelope.items() if name != "signatureBase64Url"}
    unsigned_request = {name: value for name, value in request.items() if name != "signature"}
    unsigned_receipt = {name: value for name, value in receipt.items() if name != "signature"}
    head = {**unsigned_receipt, "headDigest": None}
    material = {name: request[name] for name in ("phase", "operation", "requestDigest", "capabilityId",
        "resultDigest", "predecessorReceiptDigest", "generationSequence", "generationDigest")}
    phases = {"capture": graph(capture_graph(fixture), 1, 1)}
    phases["transport"] = add(*(add(wire_oracle.decoder_units(raw, value), graph(value), (0, 2 * len(raw), 0))
        for raw, value in ((fixture.raw, fixture.envelope), (oracle.wire(request), request),
                           (fixture.execution_bytes, fixture.execution_request))), graph(fixture.payload))
    phases["capability_authentication"] = add(same(fixture.signer_identity), graph(fixture.envelope),
        graph(unsigned_capability), signature_work(SIGNED_SCHEMA, unsigned_capability))
    request_fields = ("configurationDigest", "operationManifestDigest", "generationSequence", "generationDigest",
                      "capabilityId", "requestDigest", "deadlineMonotonicNs")
    joined_fields = ("envelopeId", "parentEnvelopeId", "phase", "operation", "requestDigest", "capabilityId",
        "resultDigest", "predecessorReceiptDigest", "deadlineMonotonicNs", "generationSequence", "generationDigest")
    phases["witness_verification"] = add(
        *(same(request[name]) for name in request_fields),
        oracle.json_digest_cost(WITNESS_ENVELOPE_DOMAIN, material), same(request["envelopeId"]),
        graph(request), graph(unsigned_request), signature_work(REQUEST_SCHEMA, unsigned_request),
        *(same(request[name]) for name in joined_fields),
        oracle.json_digest_cost(REQUEST_SCHEMA, request),
        *(same(receipt[name]) for name in ("witnessIdentityDigest", "fence", "canonicalRequestDigest")),
        graph(receipt), graph(unsigned_receipt), oracle.json_digest_cost(HEAD_DOMAIN, head), same(receipt["headDigest"]),
        graph(unsigned_receipt), signature_work(RECEIPT_SCHEMA, unsigned_receipt),
        oracle.json_digest_cost(RECEIPT_SCHEMA, receipt), same(fixture.witness_receipt_digest))
    replay = record_oracle.independent_record_metrics(fixture.plan)
    phases["retained_verification"] = replay["total"]
    challenge, credential = original_rows(fixture)
    evidence = fixture.plan.payload["webauthnEvidence"]
    service_receipt = webauthn_receipt(fixture)
    phases["bindings"] = add(same(fixture.execution_request), (1, len(fixture.execution_bytes), 0),
        graph(fixture.plan.payload["mutationPlan"], 4, 4),
        graph(evidence["challengeId"]), graph(evidence["credentialRecordId"]),
        oracle.json_digest_cost("serverware.policyAuthorityWebAuthnChallengeRow/v1", challenge),
        graph(credential), oracle.utf8_cost(CREDENTIAL_DOMAIN), (1, 16 + len(oracle.wire(credential)), 0),
        oracle.json_digest_cost(WEBAUTHN_SCHEMA, service_receipt), same(fixture.payload))
    phases["record"] = add(oracle.frame_cost(CAPABILITY_SCHEMA, (oracle.wire(fixture.payload),)),
        (4, 128 + len(fixture.raw) + len(oracle.wire(request)), 0),
        oracle.json_digest_cost(RECORD_SCHEMA, expected_header(fixture)))
    total = add(*(phases[name] for name in PHASES))
    prefix = add(*(phases[name] for name in PHASES[:4]))
    peak = add(prefix, replay["admission"])
    return {**phases, "total": total, "before_replay": prefix,
        "admission": tuple(max(left, right) for left, right in zip(total, peak))}


def json_depth(value):
    if type(value) is dict:
        return max((1, *(1 + json_depth(child) for child in value.values())))
    if type(value) is list:
        return max((0, *(1 + json_depth(child) for child in value)))
    return 0


class RevocationCapabilityTests(unittest.TestCase):
    def verify(self, fixture, *, work=None, **changes):
        supplied = fixture.arguments()
        supplied.update(changes)
        return capability._verify_signed_capability_on_work(
            work=accounting._ValidationWork(accounting.QueryReadValidationLimits()) if work is None else work,
            **supplied)

    def test_genuine_signatures_retained_replay_and_original_header_are_independent(self):
        fixture = CapabilityFixture()
        expected = independent_capability_work(fixture)
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof, \
                patch.object(retention.plan.semantics, "_derive_revocation_effects",
                    wraps=retention.plan.semantics._derive_revocation_effects) as effects:
            actual = self.verify(fixture, work=work)
        self.assertEqual((replay.call_count, proof.call_count, effects.call_count), (1, 1, 1))
        self.assertIs(replay.call_args.kwargs["work"], work)
        self.assertIs(replay.call_args.kwargs["envelope_bytes"], fixture.retained_bytes)
        self.assertIs(replay.call_args.kwargs["evaluation_context_bytes"], fixture.context_bytes)
        self.assertIs(actual.envelope_bytes, fixture.raw)
        self.assertIs(actual.execution_request_bytes, fixture.execution_bytes)
        self.assertEqual(actual.witness_request_bytes, oracle.wire(fixture.witness_request))
        self.assertEqual(actual.payload_bytes, oracle.wire(fixture.payload))
        self.assertEqual(actual.payload, fixture.payload)
        self.assertEqual(actual.retained_record.record_digest, fixture.retained_digest)
        self.assertEqual(actual.retained_record.verification.semantics.mutations, fixture.plan.semantic.final_mutations)
        header = expected_header(fixture)
        self.assertEqual(actual.header, header)
        self.assertEqual(actual.record_digest, oracle.framed(RECORD_SCHEMA, oracle.wire(header)))
        for name in ("capability_digest", "signer_key_digest", "witness_key_digest", "envelope_digest",
                     "witness_request_bytes_digest"):
            header_field = {"capability_digest": "capabilityDigest", "signer_key_digest": "signerKeyDigest",
                "witness_key_digest": "witnessKeyDigest", "envelope_digest": "envelopeDigest",
                "witness_request_bytes_digest": "witnessRequestBytesDigest"}[name]
            self.assertEqual(getattr(actual, name), header[header_field])
        self.assertEqual(actual.witness_receipt_digest, fixture.witness_receipt_digest)
        self.assertEqual((actual.metrics.capability_signature_attempts, actual.metrics.request_signature_attempts,
                          actual.metrics.witness_signature_attempts), (1, 1, 1))
        self.assertEqual((actual.metrics.total_hashes, actual.metrics.total_input_bytes,
                          actual.metrics.total_json_nodes), oracle.units(work.metrics))
        self.assertEqual(oracle.units(work.metrics), expected["total"])
        for name in PHASES:
            self.assertEqual(oracle.units(getattr(actual.metrics, name)), expected[name], name)
        self.assertEqual(expected["total"][0] - expected["retained_verification"][0], 17)
        with self.assertRaises(FrozenInstanceError):
            actual.record_digest = oracle.sha(b"caller success replacement")

    def test_all_legacy_semantics_and_four_successor_bindings_remain_closed(self):
        fixture = CapabilityFixture()
        actual = self.verify(fixture)
        self.assertEqual(set(actual.payload), PAYLOAD_FIELDS)
        self.assertEqual(set(fixture.envelope), ENVELOPE_FIELDS)
        self.assertEqual(set(fixture.witness_request), REQUEST_FIELDS)
        self.assertEqual(set(fixture.witness_receipt), RECEIPT_FIELDS)
        self.assertEqual(set(actual.header), HEADER_FIELDS)
        self.assertEqual(tuple(map(len, (PAYLOAD_FIELDS, ENVELOPE_FIELDS, REQUEST_FIELDS,
                                        RECEIPT_FIELDS, HEADER_FIELDS))), (36, 5, 16, 21, 17))
        receipt = actual.payload["webauthnReceipt"]
        self.assertEqual(len(receipt), 19)
        challenge, credential = original_rows(fixture)
        self.assertEqual(len(credential), 13)
        self.assertEqual(receipt, webauthn_receipt(fixture))
        self.assertEqual(receipt["challengeRowDigest"], oracle.framed(
            "serverware.policyAuthorityWebAuthnChallengeRow/v1", oracle.wire(challenge)))
        self.assertEqual(receipt["credentialBindingDigest"], length_domain_digest(CREDENTIAL_DOMAIN, oracle.wire(credential)))
        self.assertNotEqual(receipt["credentialBindingDigest"], oracle.framed(CREDENTIAL_DOMAIN, oracle.wire(credential)))
        self.assertNotEqual(set(receipt), set(fixture.plan.payload["webauthnEvidence"]))
        self.assertEqual(actual.payload["exactRequestBytesDigest"], oracle.sha(fixture.execution_bytes))

    def test_real_capability_request_and_witness_keys_cannot_be_substituted(self):
        for phase in ("capability", "request", "witness", "signer_pin", "witness_pin"):
            fixture = CapabilityFixture()
            changes = {}
            if phase == "capability":
                fixture.resign(key=fixture.other_key)
            elif phase == "request":
                fixture.sign_request(key=fixture.other_key)
                fixture.witness_receipt["canonicalRequestDigest"] = oracle.framed(
                    REQUEST_SCHEMA, oracle.wire(fixture.witness_request))
                fixture.sign_receipt()
                fixture.rebuild()
            elif phase == "witness":
                fixture.sign_receipt(key=fixture.other_key)
                fixture.rebuild()
            else:
                changes["signer_public_key" if phase == "signer_pin" else "witness_public_key"] = fixture.other_key.public_key()
            with self.subTest(phase=phase), self.assertRaises(capability.RevocationCapabilityError):
                self.verify(fixture, **changes)

    def test_every_plan_commitment_and_wrapper_binding_denies_even_when_resigned(self):
        fields = ("capabilityId", "envelopeId", "plannerTransactionId", "authorizationProjectionDigest",
            "selectedBusinessRowsDigest", "mutationPlanDigest", "expectedResultDigest", "operationId",
            "requestDigest", "operationManifestDigest", "queryManifestDigest", "authorityRootSetDigest",
            "authoritySnapshotDigest", "issuerSessionIdentityDigest", "retainedRecordDigest",
            "rootTransitionDigest", "exactRequestBytesDigest", "webauthnReceiptDigest", "webauthnTrustHighWaterDigest")
        for field in fields:
            fixture = CapabilityFixture()
            fixture.payload[field] = oracle.sha(("different " + field).encode("ascii"))
            fixture.resign()
            with self.subTest(field=field), self.assertRaises(capability.RevocationCapabilityError):
                self.verify(fixture)
        for field, value in (("planProtocol", "v3"), ("schema", authority_contract.CAPABILITY_SCHEMA),
                             ("operation", "webauthn.credential.register"), ("handlerName", "other_handler"),
                             ("approverPolicyDigest", oracle.sha(b"unadmitted approver"))):
            fixture = CapabilityFixture()
            fixture.payload[field] = value
            fixture.resign()
            with self.subTest(field=field), self.assertRaises(capability.RevocationCapabilityError):
                self.verify(fixture)

    def test_service_receipt_is_reconstructed_from_proved_original_rows_and_evidence(self):
        for field in ("challengeRowDigest", "credentialBindingDigest", "credentialPolicyDigest", "challengeDigest",
                      "credentialRecordId", "credentialId", "priorCounter", "counter", "verifiedAtEpochNs"):
            fixture = CapabilityFixture()
            receipt = fixture.payload["webauthnReceipt"]
            receipt[field] = receipt[field] + 1 if type(receipt[field]) is int else (
                oracle.sha(b"false WebAuthn binding") if field.endswith("Digest") else "different")
            fixture.payload["webauthnReceiptDigest"] = oracle.framed(WEBAUTHN_SCHEMA, oracle.wire(receipt))
            fixture.resign()
            with self.subTest(field=field), self.assertRaises(capability.RevocationCapabilityError):
                self.verify(fixture)
        fixture = CapabilityFixture()
        fixture.payload["webauthnReceipt"] = copy.deepcopy(fixture.plan.payload["webauthnEvidence"])
        fixture.payload["webauthnReceiptDigest"] = oracle.framed(WEBAUTHN_SCHEMA,
            oracle.wire(fixture.payload["webauthnReceipt"]))
        fixture.resign()
        with self.assertRaises(capability.RevocationCapabilityError):
            self.verify(fixture)

    def test_independent_configuration_identity_generation_and_receipt_pins_are_not_enrolled(self):
        fixture = CapabilityFixture()
        changes = [
            {"expected_signer_identity": {**fixture.signer_identity, "measurementDigest": oracle.sha(b"other signer")}},
            {"expected_generation_sequence": fixture.generation_sequence + 1},
        ]
        changes.extend({field: oracle.sha(field.encode("ascii"))} for field in (
            "expected_issuer_session_identity_digest", "expected_execution_envelope_id", "expected_witness_receipt_digest",
            "expected_witness_identity_digest", "expected_configuration_digest", "expected_generation_digest"))
        for change in changes:
            with self.subTest(field=next(iter(change))), self.assertRaises(capability.RevocationCapabilityError):
                self.verify(fixture, **change)
        for field, value in (("expected_generation_sequence", True), ("expected_generation_sequence", 3.0),
                             ("expected_signer_identity", {"callerAuthority": True})):
            with self.subTest(field=field, value=value), self.assertRaises(capability.RevocationCapabilityError):
                self.verify(fixture, **{field: value})

    def test_preliminary_witness_request_receipt_and_head_join_even_when_re_signed(self):
        for field, value in (("phase", "commit"), ("operation", "webauthn.credential.register"),
                ("capabilityId", oracle.sha(b"other capability")), ("requestDigest", oracle.sha(b"other request")),
                ("resultDigest", oracle.sha(b"not preliminary")), ("parentEnvelopeId", oracle.sha(b"parent")),
                ("predecessorHeadDigest", oracle.sha(b"predecessor")),
                ("predecessorReceiptDigest", oracle.sha(b"predecessor receipt")),
                ("canonicalRequestDigest", oracle.sha(b"not the signed request")),
                ("generationSequence", 4), ("generationDigest", oracle.sha(b"other generation")),
                ("deadlineMonotonicNs", 1), ("fence", 8), ("witnessIdentityDigest", oracle.sha(b"other witness"))):
            fixture = CapabilityFixture()
            fixture.witness_receipt[field] = value
            fixture.sign_receipt()
            fixture.rebuild()
            with self.subTest(field=field), self.assertRaises(capability.RevocationCapabilityError):
                self.verify(fixture)
        fixture = CapabilityFixture()
        fixture.witness_receipt["headDigest"] = oracle.sha(b"false head with a genuine signature")
        fixture.sign_receipt(update_head=False)
        fixture.rebuild()
        with self.assertRaises(capability.RevocationCapabilityError):
            self.verify(fixture)
        for field, value in (("configurationDigest", oracle.sha(b"other configuration")),
                ("envelopeId", oracle.sha(b"not the source-derived envelope")),
                ("operationManifestDigest", oracle.sha(b"other source manifest"))):
            fixture = CapabilityFixture()
            fixture.witness_request[field] = value
            fixture.sign_request()
            fixture.witness_receipt["canonicalRequestDigest"] = oracle.framed(REQUEST_SCHEMA, oracle.wire(fixture.witness_request))
            fixture.sign_receipt()
            fixture.rebuild()
            with self.subTest(request_field=field), self.assertRaises(capability.RevocationCapabilityError):
                self.verify(fixture)

    def test_historical_times_are_exact_and_do_not_create_post_plan_witness_authority(self):
        fixture = CapabilityFixture()
        actual = self.verify(fixture)
        self.assertEqual(actual.payload["witnessReservation"]["phase"], "reserve")
        self.assertIsNone(actual.payload["witnessReservation"]["resultDigest"])
        self.assertNotIn("retainedRecordDigest", actual.payload["witnessReservation"])
        self.assertNotIn("rootTransitionDigest", fixture.witness_request)
        self.assertEqual(actual.payload["issuedAtEpochNs"], fixture.plan.reserved_at_epoch_ns)
        for field in ("issuedAtEpochNs", "issuedMonotonicNs", "expiresAtEpochNs", "deadlineEpochNs", "deadlineMonotonicNs"):
            changed = CapabilityFixture()
            changed.payload[field] += 1
            changed.resign()
            with self.subTest(field=field), self.assertRaises(capability.RevocationCapabilityError):
                self.verify(changed)
        for part in ("request", "receipt"):
            for instant in (fixture.plan.reserved_at_epoch_ns - fixture.plan.maximum_clock_skew_ns - 1,
                            fixture.plan.now_epoch_ns + fixture.plan.maximum_clock_skew_ns + 1):
                changed = CapabilityFixture()
                if part == "request":
                    changed.witness_request["issuedAtEpochNs"] = instant
                    changed.sign_request()
                    changed.witness_receipt["canonicalRequestDigest"] = oracle.framed(REQUEST_SCHEMA, oracle.wire(changed.witness_request))
                else:
                    changed.witness_receipt["issuedAtEpochNs"] = instant
                changed.sign_receipt()
                changed.rebuild()
                with self.subTest(part=part, instant=instant), self.assertRaises(capability.RevocationCapabilityError):
                    self.verify(changed)

    def test_original_transport_aliases_are_not_normalized_into_accepted_bytes(self):
        fixture = CapabilityFixture()
        supplied = fixture.arguments()
        for field in ("envelope_bytes", "retained_envelope_bytes", "evaluation_context_bytes",
                      "execution_request_bytes", "witness_request_bytes"):
            raw = supplied[field]
            aliases = (b" " + raw, raw.replace(b'"schema":', b'"schema" :', 1),
                       raw[:-1] + b',"schema":"duplicate"}')
            for alias in aliases:
                with self.subTest(field=field, alias=alias[:24]), self.assertRaises(capability.RevocationCapabilityError):
                    self.verify(fixture, **{field: alias})
        aliases = (fixture.raw.replace(b'"fence":7', b'"fence":7.0', 1),
                   fixture.raw.replace(b'"fence":7', b'"fence":7e0', 1),
                   fixture.raw.replace(b'"phase":"reserve"', b'"phase":"\\u0072eserve"', 1))
        for alias in aliases:
            self.assertNotEqual(alias, fixture.raw)
            with self.subTest(alias=alias[:24]), self.assertRaises(capability.RevocationCapabilityError):
                self.verify(fixture, envelope_bytes=alias)

    def test_closed_shapes_and_exact_scalar_aliases_cannot_be_signed_into_authority(self):
        for part in ("envelope", "payload", "signerIdentity", "webauthnReceipt", "witnessReservation"):
            for change in ("extra", "missing"):
                fixture = CapabilityFixture()
                value = (fixture.envelope if part == "envelope" else fixture.payload if part == "payload"
                    else fixture.signer_identity if part == "signerIdentity" else fixture.payload[part])
                if change == "extra":
                    value["callerAuthority"] = True
                else:
                    value.pop(next(iter(value)))
                if part != "envelope":
                    fixture.resign()
                else:
                    fixture.raw = oracle.wire(fixture.envelope)
                with self.subTest(part=part, change=change), self.assertRaises(capability.RevocationCapabilityError):
                    self.verify(fixture)
        for field in ("fence", "issuedAtEpochNs", "issuedMonotonicNs", "expiresAtEpochNs", "witnessSequence"):
            for value in (True, None, "7", 2**63):
                fixture = CapabilityFixture()
                fixture.payload[field] = value
                fixture.resign()
                with self.subTest(field=field, value=value), self.assertRaises(capability.RevocationCapabilityError):
                    self.verify(fixture)

    def test_all_mutable_external_graphs_are_owned_before_real_signer_callbacks(self):
        fixture = CapabilityFixture()
        supplied = fixture.arguments()
        original = copy.deepcopy(fixture.payload)
        events = []
        def change():
            events.append("real signature verified")
            supplied["expected_signer_identity"]["measurementDigest"] = oracle.sha(b"late signer")
            supplied["retention_expectations"]["expected_request"]["arguments"]["actor_id"] = "late actor"
            supplied["retention_expectations"]["expected_planner_identity"]["measurementDigest"] = oracle.sha(b"late planner")
            supplied["retention_expectations"]["expected_before"]["indexBeforeHeads"][0]["rootDigest"] = oracle.sha(b"late root")
        key = oracle._CallbackPublicKey(fixture.key.public_key(), change)
        supplied["signer_public_key"] = key
        actual = capability._verify_signed_capability_on_work(
            work=accounting._ValidationWork(accounting.QueryReadValidationLimits()), **supplied)
        self.assertEqual(key.calls, 2)
        self.assertEqual(events, ["real signature verified"] * 2)
        self.assertEqual(actual.payload, original)
        self.assertEqual(actual.retained_record.payload, fixture.plan.payload)
        self.assertEqual(actual.retained_record.context, record_oracle.record_context(fixture.plan))

    def test_missing_extra_or_result_token_inputs_never_replace_real_replay(self):
        fixture = CapabilityFixture()
        for change in ("missing", "extra", "result"):
            supplied = fixture.arguments()
            if change == "missing":
                supplied["retention_expectations"].pop("expected_before")
            elif change == "extra":
                supplied["retention_expectations"]["verified_result"] = {"success": True}
            else:
                supplied["retention_expectations"] = {"record_digest": fixture.retained_digest, "success": True}
            with self.subTest(change=change), patch.object(retention, "_verify_record_on_work",
                    wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(capability.RevocationCapabilityError):
                    capability._verify_signed_capability_on_work(
                        work=accounting._ValidationWork(accounting.QueryReadValidationLimits()), **supplied)
            self.assertEqual(replay.call_count, 0)
        for name in ("verified_record", "witness_verified", "limits"):
            with self.subTest(name=name), self.assertRaises(TypeError):
                self.verify(fixture, **{name: True})

    def test_genuine_retained_proof_and_kernel_reject_coherently_resigned_false_claims(self):
        for changed in ("proof", "result"):
            fixture = CapabilityFixture()
            if changed == "proof":
                bundle = fixture.plan.payload["revocationProofBundle"]
                bundle["inputs"]["beforeProofs"][0]["rootDigest"] = oracle.sha(b"false raw primary proof")
                fixture.plan.payload["rootTransition"]["proofBundleDigest"] = oracle.framed(
                    "serverware.policyAuthorityRevocationProofBundle/v1", oracle.wire(bundle))
            else:
                fixture.plan.payload["expectedResult"] = {"false": "all outer signatures are genuine"}
            fixture.plan.rehash()
            fixture.rebuild()
            with self.subTest(changed=changed), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                    patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof, \
                    patch.object(retention.plan.semantics, "_derive_revocation_effects",
                        wraps=retention.plan.semantics._derive_revocation_effects) as effects:
                with self.assertRaises(capability.RevocationCapabilityError):
                    self.verify(fixture)
            self.assertEqual((replay.call_count, proof.call_count), (1, 1))
            self.assertEqual(effects.call_count, 0 if changed == "proof" else 1)

    def test_exact_original_bytes_and_work_types_deny_before_retained_replay(self):
        fixture = CapabilityFixture()
        for field in ("envelope_bytes", "retained_envelope_bytes", "evaluation_context_bytes",
                      "execution_request_bytes", "witness_request_bytes"):
            raw = fixture.arguments()[field]
            for value in (raw.decode("ascii"), bytearray(raw), memoryview(raw), {"bytes": raw}, b""):
                with self.subTest(field=field, kind=type(value).__name__), \
                        patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                    with self.assertRaises(capability.RevocationCapabilityError):
                        self.verify(fixture, **{field: value})
                self.assertEqual(replay.call_count, 0)
        for value in (None, object(), accounting.QueryReadValidationLimits()):
            with self.subTest(work=type(value).__name__), \
                    patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                with self.assertRaises(capability.RevocationCapabilityError):
                    capability._verify_signed_capability_on_work(work=value, **fixture.arguments())
            self.assertEqual(replay.call_count, 0)

    def test_real_signature_callbacks_cannot_spend_refund_or_retype_shared_work(self):
        for phase in ("capability", "request", "witness"):
            for change in ("spend", "refund", "float", "limits"):
                fixture = CapabilityFixture()
                work = accounting._ValidationWork(accounting.QueryReadValidationLimits())
                work.charge(hashes=2, input_bytes=13, json_nodes=3)
                callbacks, changed = [], []
                def callback():
                    callbacks.append(work.metrics)
                    if phase == "request" and len(callbacks) == 1:
                        return
                    if change == "spend":
                        work.charge(hashes=1)
                    elif change == "refund":
                        work.hash_work -= 1
                    elif change == "float":
                        work.hash_work = float(work.hash_work)
                    else:
                        work.limits = accounting.QueryReadValidationLimits()
                    changed.append((work.hash_work, work.input_bytes, work.json_nodes, work.limits))
                key = oracle._CallbackPublicKey(
                    (fixture.witness_key if phase == "witness" else fixture.key).public_key(), callback)
                kwargs = {"witness_public_key" if phase == "witness" else "signer_public_key": key}
                with self.subTest(phase=phase, change=change), \
                        patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                    with self.assertRaises(capability.RevocationCapabilityError):
                        self.verify(fixture, work=work, **kwargs)
                self.assertEqual(key.calls, 2 if phase == "request" else 1)
                self.assertEqual(len(changed), 1)
                self.assertEqual(replay.call_count, 0)
                # Failure does not pretend that a hostile callback's mutation
                # was refunded or repaired into a reusable successful meter.
                observed = changed[0]
                self.assertEqual((work.hash_work, work.input_bytes, work.json_nodes), observed[:3])
                self.assertIs(type(work.hash_work), float if change == "float" else int)
                self.assertIs(work.limits, observed[3])

    def test_exact_and_preconsumed_peak_each_minus_one_share_the_original_allowance(self):
        fixture = CapabilityFixture()
        expected = independent_capability_work(fixture)
        for prior in ((0, 0, 0), (3, 31, 7)):
            for dimension in (None, 0, 1, 2):
                ceilings = list(oracle.add(prior, expected["admission"]))
                if dimension is not None:
                    ceilings[dimension] -= 1
                work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*ceilings))
                work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
                entering = work.limits
                # Genuine retained replay attaches to this work. Its internal
                # generation worker remains real; only a new packaging outer
                # allowance is forbidden, exactly as in retained-plan tests.
                with self.subTest(prior=prior, dimension=dimension), \
                        patch.object(retention.plan.retained._PackagingLedger, "__init__",
                            side_effect=AssertionError("replacement outer allowance")):
                    if dimension is None:
                        result = self.verify(fixture, work=work)
                        self.assertEqual(oracle.units(work.metrics), oracle.add(prior, expected["total"]))
                        self.assertEqual((result.metrics.total_hashes, result.metrics.total_input_bytes,
                            result.metrics.total_json_nodes), oracle.units(work.metrics))
                        for name in PHASES:
                            self.assertEqual(oracle.units(getattr(result.metrics, name)), expected[name])
                    else:
                        with self.assertRaises(capability.RevocationCapabilityError):
                            self.verify(fixture, work=work)
                        self.assertTrue(all(start <= spent <= maximum for start, spent, maximum
                            in zip(prior, oracle.units(work.metrics), ceilings)))
                self.assertIs(work.limits, entering)
                self.assertFalse(hasattr(work, "_revocation_packaging_owner"))

    def test_repeated_verification_replays_raw_proofs_and_retains_cumulative_costs(self):
        fixture, prior = CapabilityFixture(), (2, 17, 5)
        expected = independent_capability_work(fixture)
        ceilings = oracle.add(prior, expected["total"], expected["admission"])
        work = accounting._ValidationWork(accounting.QueryReadValidationLimits(*ceilings))
        work.charge(hashes=prior[0], input_bytes=prior[1], json_nodes=prior[2])
        entering, results = work.limits, []
        with patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay, \
                patch.object(retention.plan.mixed, "_verify", wraps=retention.plan.mixed._verify) as proof:
            for count in (1, 2):
                result = self.verify(fixture, work=work)
                results.append(result)
                self.assertEqual(oracle.units(work.metrics), oracle.add(prior, tuple(count * item for item in expected["total"])))
                for name in PHASES:
                    self.assertEqual(oracle.units(getattr(result.metrics, name)), expected[name])
                self.assertIs(work.limits, entering)
        self.assertEqual((replay.call_count, proof.call_count), (2, 2))
        self.assertTrue(all(call.kwargs["work"] is work for call in replay.call_args_list))
        self.assertIsNot(results[0].retained_record, results[1].retained_record)
        self.assertEqual(results[0].envelope_bytes, results[1].envelope_bytes)
        results[0].payload["capabilityId"] = oracle.sha(b"mutable observation is not authority")
        results[0].header.clear()
        self.assertEqual(results[0].envelope_bytes, fixture.raw)
        self.assertEqual(results[1].payload, fixture.payload)

    def test_local_original_byte_node_and_depth_ceilings_precede_signature_or_replay(self):
        fixture = CapabilityFixture()
        self.assertEqual((capability.MAX_CAPABILITY_BYTES, capability.MAX_WITNESS_REQUEST_BYTES,
            capability.MAX_JSON_NODES, capability.MAX_JSON_DEPTH), (4 * 1024 * 1024, 64 * 1024, 4096, 16))
        boundaries = (("MAX_CAPABILITY_BYTES", len(fixture.raw)),
            ("MAX_WITNESS_REQUEST_BYTES", len(oracle.wire(fixture.witness_request))),
            ("MAX_JSON_NODES", wire_oracle.counts(fixture.envelope)[0]),
            ("MAX_JSON_DEPTH", json_depth(fixture.envelope)))
        for constant, exact in boundaries:
            for difference in (0, 1):
                key = oracle._CallbackPublicKey(fixture.key.public_key(), lambda: None)
                with self.subTest(constant=constant, difference=difference), \
                        patch.object(capability, constant, exact - difference), \
                        patch.object(retention, "_verify_record_on_work", wraps=retention._verify_record_on_work) as replay:
                    if difference:
                        with self.assertRaises(capability.RevocationCapabilityError):
                            self.verify(fixture, signer_public_key=key)
                    else:
                        self.verify(fixture, signer_public_key=key)
                self.assertEqual(key.calls, 0 if difference else 2)
                self.assertEqual(replay.call_count, 0 if difference else 1)
        too_many = oracle.wire({"values": [None] * 4096})
        nested = None
        for _ in range(17):
            nested = [nested]
        too_deep = oracle.wire({"value": nested})
        for raw, message in ((too_many, "remaining node work"), (too_deep, "source depth")):
            for field, parses in (("envelope_bytes", 0), ("witness_request_bytes", 1)):
                with self.subTest(field=field, message=message), \
                        patch.object(retention.wire.json, "loads", wraps=retention.wire.json.loads) as loads:
                    with self.assertRaises(capability.RevocationCapabilityError) as raised:
                        self.verify(fixture, **{field: raw})
                self.assertIn(message, str(raised.exception.__cause__))
                self.assertEqual(loads.call_count, parses)


if __name__ == "__main__":
    unittest.main()
