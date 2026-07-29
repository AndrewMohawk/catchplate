#!/usr/bin/env python3
"""Static source fixtures for the production Nitro public verifier.

This file intentionally uses real canonical encodings and signatures. It does
not mock a verifier decision or replace the AWS evidence that production
verification requires. The source-only implementation pass does not execute it.
"""
from __future__ import annotations

import base64
import copy
from datetime import datetime, timedelta, timezone
import inspect
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography import x509
from cryptography.x509.oid import NameOID
from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry, Resource

import verify_nitro_tee as verifier
import verify_release_completion as release_completion
import test_production_attestation_bridge as bridge_fixture
import test_run_production_readiness as readiness_fixture
import attestation_verifier_state_service as verifier_state_service
import attestation_nonce_service as nonce_service
import production_attestation_producer_issuer as producer_issuer
import generate_production_launch_manifest as launch_manifest_generator


def b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def public_schema_validator(filename: str) -> Draft202012Validator:
    schema_directory = Path(__file__).parents[1] / "schemas"
    dependency_names = (
        "attestation-verifier-state-service.v1.schema.json",
        "live-witness-head.v1.schema.json",
        "protected-live-witness-state.v2.schema.json",
        "public-attestation-bundle.v3.schema.json",
        "public-attestation-config.v2.schema.json",
        "public-attestation-producer-descriptor.v2.schema.json",
        "public-attestation-producer-request.v2.schema.json",
        "public-release-graph.v1.schema.json",
        "release-identity.v1.schema.json",
        "signed-attestation-nonce-consumption-receipt.v2.schema.json",
    )
    documents = {
        name: json.loads(
            (schema_directory / name).read_text(encoding="utf-8")
        )
        for name in dependency_names
    }
    for document in documents.values():
        Draft202012Validator.check_schema(document)
    registry = Registry().with_resources(
        (
            document["$id"],
            Resource.from_contents(document),
        )
        for document in documents.values()
    )
    return Draft202012Validator(
        documents[filename],
        registry=registry,
    )


def standard_envelope(
    private_key: Ed25519PrivateKey,
    *,
    api_version: str,
    domain: bytes,
    payload: dict,
) -> dict:
    public_key = private_key.public_key()
    key_id = verifier.sha256(
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    payload_sha256 = verifier.sha256_json(payload)
    signed = domain + verifier.canonical_json_bytes(
        {"payload": payload, "payloadSha256": payload_sha256}
    )
    return {
        "apiVersion": api_version,
        "payload": payload,
        "payloadSha256": payload_sha256,
        "signature": b64u(private_key.sign(signed)),
        "signingKeyId": key_id,
    }


def trust_key_record(private_key: Ed25519PrivateKey) -> dict:
    public_key = private_key.public_key()
    key_file = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return {
        "fileBase64url": b64u(key_file),
        "keyFileSha256": verifier.sha256(key_file),
        "keyId": verifier.sha256(der),
        "rawKeySha256": verifier.sha256(raw),
    }


def completion_identity() -> dict:
    return verifier.reconstruct_completion_identity(
        core_digests={
            name: verifier.sha256(name.encode("ascii"))
            for name in verifier.COMPLETION_CORE_DIGEST_FIELDS
        },
        challenge_nonce_sha256=verifier.sha256(b"challenge"),
        release_generation=7,
        rollback_epoch=3,
    )


def stable_release_identity(
    response_signing_key_id: str,
    *,
    release_signing_key_id: str | None = None,
    witness_signing_key_id: str | None = None,
    witness_store_signing_key_id: str | None = None,
) -> dict:
    image_sha384 = verifier.sha384(b"fixture-eif")
    builders = sorted(
        [
            verifier.sha256(b"builder-a"),
            verifier.sha256(b"builder-b"),
        ]
    )
    return {
        "apiVersion": verifier.RELEASE_IDENTITY_VERSION,
        "build": {
            "builderCoreSha256s": builders,
            "buildWatchdogReceiptSha256":
            verifier.sha256(b"watchdog"),
            "candidateManifestFileSha256":
            verifier.sha256(b"candidate-file"),
            "candidateManifestPayloadSha256":
            verifier.sha256(b"candidate-payload"),
            "dependencyClosureSha256":
            verifier.sha256(b"dependency-closure"),
            "eifBuildCoreSha256": verifier.sha256(b"eif-build-core"),
            "importedImageMappingsSha256":
            verifier.sha256(b"image-mappings"),
            "promotedManifestSha256":
            verifier.sha256(b"promoted-manifest"),
            "promotionReceiptSha256":
            verifier.sha256(b"promotion-receipt"),
            "releaseCoreSha256": verifier.sha256(b"release-core"),
        },
        "configuration": {
            "caSpkiSha256": verifier.sha256(b"ca-spki"),
            "publicAttestation": {
                "nonceStoreIdentitySha256":
                verifier.sha256(b"nonce-store-identity"),
                "nonceStoreKeySpkiSha256":
                verifier.sha256(b"nonce-store-key-spki"),
                "producerDescriptorSha256":
                verifier.sha256(b"producer-descriptor"),
                "producerExecutableSha256":
                verifier.sha256(b"producer-executable"),
                "producerRequestSchemaSha256":
                verifier.sha256(b"producer-request-schema"),
                "sandboxDescriptorSha256":
                verifier.sha256(b"sandbox-descriptor"),
                "sandboxLauncherSha256":
                verifier.sha256(b"sandbox-launcher"),
                "witnessStoreIdentitySha256":
                verifier.sha256(b"witness-store-identity"),
                "witnessStoreKeySpkiSha256": (
                    verifier.sha256(b"witness-store-key-spki")
                    if witness_store_signing_key_id is None
                    else witness_store_signing_key_id
                ),
            },
            "releaseKeySpkiSha256": (
                verifier.sha256(b"release-key-spki")
                if release_signing_key_id is None
                else release_signing_key_id
            ),
            "responseKeySpkiSha256": response_signing_key_id,
            "tlsScopeSigningKeySpkiSha256":
            verifier.sha256(b"tls-scope-key-spki"),
            "trustRootBundleSha256":
            verifier.sha256(b"trust-root-bundle"),
            "witnessKeySpkiSha256": (
                verifier.sha256(b"witness-key-spki")
                if witness_signing_key_id is None
                else witness_signing_key_id
            ),
        },
        "eif": {
            "imageSha384": image_sha384,
            "pcrs": {
                "PCR0": image_sha384,
                "PCR1": verifier.sha384(b"fixture-pcr1"),
                "PCR2": verifier.sha384(b"fixture-pcr2"),
            },
        },
        "monotonicRelease": {
            "releaseGeneration": 7,
            "rollbackEpoch": 3,
        },
        "pipeline": verifier.PIPELINE,
        "policy": {
            "hash": verifier.sha256(b"policy"),
            "sequence": 11,
        },
        "source": {
            "sourceClosureSha256":
            verifier.sha256(b"source-closure"),
            "sourceInputApprovalSha256":
            verifier.sha256(b"source-approval"),
            "sourceInputManifestFileSha256":
            verifier.sha256(b"source-manifest-file"),
            "sourceInputManifestPayloadSha256":
            verifier.sha256(b"source-manifest-payload"),
        },
    }


def stable_attestation_statement_pins(
    release_identity: dict,
) -> dict:
    components = release_identity["configuration"][
        "publicAttestation"
    ]
    return {
        "descriptorSha256": verifier.sha256(b"producer-descriptor"),
        "executableSha256":
        components["producerExecutableSha256"],
        "immutableConfigSha256":
        verifier.sha256(b"immutable-attestation-config"),
        "nonceStoreIdentitySha256":
        components["nonceStoreIdentitySha256"],
        "nonceStoreKeySpkiSha256":
        components["nonceStoreKeySpkiSha256"],
        "producerRequestSchemaSha256":
        components["producerRequestSchemaSha256"],
        "sandboxDescriptorSha256":
        verifier.sha256(b"sandbox-descriptor"),
        "sandboxLauncherSha256":
        components["sandboxLauncherSha256"],
        "trustRootsSha256":
        release_identity["configuration"]["trustRootBundleSha256"],
        "witnessStoreIdentitySha256":
        components["witnessStoreIdentitySha256"],
        "witnessStoreKeySpkiSha256":
        components["witnessStoreKeySpkiSha256"],
    }


def live_tls_binding() -> dict:
    core = {
        "apiVersion": verifier.TLS_SCOPE_VERSION,
        "connectionId": "connection-0001",
        "connectionNonceSha256":
        verifier.sha256(b"connection-nonce"),
        "enclaveBootId": "enclave-boot-0001",
        "enclaveInstanceId": "enclave-instance-0001",
        "expiresAtUnix": 1_060,
        "exporterLabel": "EXPORTER-Serverware-Attestation-v1",
        "exporterSha256": verifier.sha256(b"tls-exporter"),
        "issuedAtUnix": 1_000,
        "leafCertificateSha256":
        verifier.sha256(b"leaf-certificate"),
        "leafSpkiSha256": verifier.sha256(b"leaf-spki"),
        "peerCertificateSha256":
        verifier.sha256(b"peer-certificate"),
        "peerIdentity": "peer-0001",
        "peerSpkiSha256": verifier.sha256(b"peer-spki"),
        "provider": "enclave-nitro-tls",
        "tlsKeyGeneration": 7,
        "tlsScopeEnvelopeSha256":
        verifier.sha256(b"tls-scope-envelope"),
        "tlsScopeKeyGeneration": 8,
        "tlsScopeKeySpkiSha256":
        verifier.sha256(b"tls-scope-key-spki"),
        "tlsStackMeasurementSha256":
        verifier.sha256(b"tls-stack"),
    }
    return {**core, "bindingSha256": verifier.sha256_json(core)}


def signed_live_session_fixture(
    private_key: Ed25519PrivateKey,
    *,
    caller_nonce: bytes = b"n" * 32,
    evidence_body: bytes | None = None,
    request_body: bytes | None = None,
    tls_binding: dict | None = None,
    release_signing_key_id: str | None = None,
    witness_signing_key_id: str | None = None,
) -> dict:
    key_record = trust_key_record(private_key)
    release_identity = stable_release_identity(
        key_record["keyId"],
        release_signing_key_id=release_signing_key_id,
        witness_signing_key_id=witness_signing_key_id,
    )
    selected_request = (
        b'{"apiVersion":"serverware.publicAttestationRequest/v1",'
        b'"callerNonceBase64url":"bm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm4"}'
        if request_body is None
        else request_body
    )
    selected_body = (
        verifier.canonical_json_bytes(
            {
                "apiVersion":
                "serverware.publicAttestationEvidenceBody/v1",
                "releaseIdentity": release_identity,
            }
        )
        + b"\n"
        if evidence_body is None
        else evidence_body
    )
    selected_tls = (
        live_tls_binding() if tls_binding is None else tls_binding
    )
    proof = {
        "apiVersion": verifier.LIVE_SESSION_PROOF_VERSION,
        "callerNonceSha256": verifier.sha256(caller_nonce),
        "evidenceBodySha256": verifier.sha256(selected_body),
        "expiresAtUnix": 1_030,
        "producedAtUnix": 1_010,
        "releaseIdentity": release_identity,
        "releaseIdentitySha256":
        verifier.sha256_json(release_identity),
        "request": {
            "bodySha256": verifier.sha256(selected_request),
            "method": "POST",
            "path": "/attestation/public-evidence",
        },
        "responseSigningKeyId": key_record["keyId"],
        "tlsBinding": selected_tls,
        "tlsBindingSha256": selected_tls["bindingSha256"],
        "witness": {
            "generation": 7,
            "headSha256": verifier.sha256(b"current-witness-head"),
            "rollbackEpoch": 3,
            "sequence": 19,
            "treeSize": 23,
        },
    }
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    return {
        "callerNonce": caller_nonce,
        "evidenceBody": selected_body,
        "proof": proof,
        "protectedWitnessState": {
            "apiVersion":
            verifier.PROTECTED_LIVE_WITNESS_STATE_VERSION,
            "releaseIdentitySha256":
            verifier.sha256_json(release_identity),
            "witness": proof["witness"],
        },
        "releaseIdentity": release_identity,
        "requestBody": selected_request,
        "responseSigningPublicKeyPem": public_key_pem,
        "signature": "ed25519:"
        + b64u(private_key.sign(verifier.canonical_json_bytes(proof))),
        "tlsBinding": selected_tls,
    }


def pending_state_commit_result() -> dict:
    identity = completion_identity()
    old_state = verifier.sha256(b"old")
    new_state = verifier.sha256(b"new")
    transition = {
        "oldStateSha256": old_state,
        "newStateSha256": new_state,
    }
    transition["transitionSha256"] = verifier.sha256_json(transition)
    return {
        "apiVersion": verifier.RESULT_VERSION,
        "challengeConsumptionSha256": verifier.sha256(b"challenge-consumption"),
        "completionIdentity": identity,
        "completionIdentitySha256": verifier.sha256_json(identity),
        "completionProofFileSha256": verifier.sha256(b"completion-proof"),
        "okForAction": False,
        "pipeline": verifier.PIPELINE,
        "requestSha256": verifier.sha256(b"request"),
        "responseBytesSha256": verifier.sha256(b"response"),
        "stateTransition": transition,
        "status": "pending-state-commit",
    }


def cas_payload(pending: dict, *, roots: str) -> dict:
    transition = pending["stateTransition"]
    return {
        "commitId": "commit-1",
        "committedAtUnix": 100,
        "compareAndSwap": True,
        "expiresAtUnix": 200,
        "newRedemptionSequence": 1,
        "newStateSha256": transition["newStateSha256"],
        "newStoreGeneration": 1,
        "oldHeadSha256": verifier.sha256(b"prior-head"),
        "oldRedemptionSequence": 1,
        "oldStateSha256": transition["oldStateSha256"],
        "oldStoreGeneration": 0,
        "storeId": "external-store-1",
        "transitionSha256": transition["transitionSha256"],
        "trustRootBundleSha256": roots,
    }


def current_head_authorization_payload(
    post_cas: dict,
    *,
    verifier_nonce: bytes,
    roots: str,
) -> dict:
    transition = post_cas["stateTransition"]
    current_head = {
        "apiVersion": verifier.STATE_STORE_HEAD_VERSION,
        "challengeConsumptionSha256": post_cas[
            "challengeConsumptionSha256"
        ],
        "commitId": post_cas["stateCommitId"],
        "generation": post_cas["stateStoreGeneration"],
        "redemptionSequence": post_cas[
            "stateStoreRedemptionSequence"
        ],
        "stateCommitReceiptSha256": post_cas[
            "stateCommitReceiptSha256"
        ],
        "stateSha256": transition["newStateSha256"],
        "storeId": post_cas["stateStoreId"],
    }
    current_head_sha256 = verifier.sha256_json(current_head)
    nonce_consumption = {
        "consumedAtUnix": 140,
        "consumptionId": "nonce-consumption-1",
        "expiresAtUnix": 170,
        "oneUse": True,
        "status": "consumed",
        "verifierNonceSha256": verifier.sha256(verifier_nonce),
    }
    completion_result_sha256 = verifier.sha256_json(post_cas)
    receipt_identity_sha256 = verifier.sha256_json(
        post_cas["stateCommitReceiptIdentity"]
    )
    return {
        "authorizationId": "authorization-1",
        "canonicalProfile": verifier.CANONICAL_PROFILE,
        "challengeConsumptionSha256": post_cas[
            "challengeConsumptionSha256"
        ],
        "committedNewStateSha256": transition["newStateSha256"],
        "completionIdentitySha256": post_cas[
            "completionIdentitySha256"
        ],
        "completionResultSha256": completion_result_sha256,
        "currentHead": current_head,
        "currentHeadSha256": current_head_sha256,
        "expectedOldStateSha256": transition["oldStateSha256"],
        "expiresAtUnix": 170,
        "headReservation": {
            "apiVersion": verifier.CURRENT_HEAD_RESERVATION_IDENTITY_VERSION,
            "authorizationId": "authorization-1",
            "challengeConsumptionSha256": post_cas[
                "challengeConsumptionSha256"
            ],
            "completionResultSha256": completion_result_sha256,
            "currentRedemptionSequence": post_cas[
                "stateStoreRedemptionSequence"
            ],
            "expectedFinalGeneration": (
                post_cas["stateStoreGeneration"] + 1
            ),
            "expectedOneUseSequence": (
                post_cas["stateStoreRedemptionSequence"] + 1
            ),
            "expiresAtUnix": 170,
            "generation": post_cas["stateStoreGeneration"],
            "headSha256": current_head_sha256,
            "oneUse": True,
            "receiptIdentitySha256": receipt_identity_sha256,
            "reservationId": "reservation-1",
            "status": "reserved",
            "storeId": post_cas["stateStoreId"],
            "verifierNonceConsumptionSha256": verifier.sha256_json(
                nonce_consumption
            ),
        },
        "issuedAtUnix": 145,
        "oneUse": True,
        "preAuthorizationResultCoreSha256": post_cas[
            "preAuthorizationResultCoreSha256"
        ],
        "stateCommitReceiptIdentity": post_cas[
            "stateCommitReceiptIdentity"
        ],
        "status": "active",
        "storeGeneration": post_cas["stateStoreGeneration"],
        "storeId": post_cas["stateStoreId"],
        "transitionSha256": transition["transitionSha256"],
        "trustRootBundleSha256": roots,
        "verifierNonceConsumption": nonce_consumption,
    }


def current_head_redemption_payload(
    authorized: dict,
    *,
    verifier_nonce: bytes,
    roots: str,
) -> dict:
    transition = authorized["stateTransition"]
    pre_head = authorized["currentHead"]
    redemption_id = "redemption-1"
    nonce_consumption = {
        "consumedAtUnix": 151,
        "consumptionId": "redemption-nonce-consumption-1",
        "expiresAtUnix": 165,
        "oneUse": True,
        "status": "consumed",
        "verifierNonceSha256": verifier.sha256(verifier_nonce),
    }
    final_head = {
        "apiVersion": verifier.STATE_STORE_FINAL_HEAD_VERSION,
        "authorizationId": authorized[
            "currentHeadAuthorizationId"
        ],
        "challengeConsumptionSha256": authorized[
            "challengeConsumptionSha256"
        ],
        "commitId": authorized["stateCommitId"],
        "completionResultSha256": authorized[
            "currentHeadReservationIdentity"
        ]["completionResultSha256"],
        "generation": authorized["currentHeadExpectedFinalGeneration"],
        "previousHeadSha256": authorized["currentHeadSha256"],
        "redemptionId": redemption_id,
        "redemptionSequence": authorized[
            "currentHeadExpectedOneUseSequence"
        ],
        "redemptionVerifierNonceSha256": verifier.sha256(verifier_nonce),
        "reservationId": authorized["currentHeadReservationId"],
        "stateCommitReceiptSha256": authorized[
            "stateCommitReceiptSha256"
        ],
        "stateSha256": transition["newStateSha256"],
        "storeId": authorized["stateStoreId"],
    }
    return {
        "authorizationIdentity": authorized[
            "currentHeadAuthorizationIdentity"
        ],
        "authorizationIdentitySha256": authorized[
            "currentHeadAuthorizationIdentitySha256"
        ],
        "authorizationVerifierNonceSha256": authorized[
            "currentHeadVerifierNonceSha256"
        ],
        "challengeConsumptionSha256": authorized[
            "challengeConsumptionSha256"
        ],
        "committedNewStateSha256": transition["newStateSha256"],
        "completionIdentitySha256": authorized[
            "completionIdentitySha256"
        ],
        "completionResultSha256": authorized[
            "currentHeadReservationIdentity"
        ]["completionResultSha256"],
        "currentRedemptionSequence": authorized[
            "stateStoreRedemptionSequence"
        ],
        "currentStoreGeneration": authorized["stateStoreGeneration"],
        "expectedOldStateSha256": transition["oldStateSha256"],
        "expiresAtUnix": 165,
        "finalHead": final_head,
        "finalHeadSha256": verifier.sha256_json(final_head),
        "finalStoreGeneration": authorized[
            "currentHeadExpectedFinalGeneration"
        ],
        "issuedAtUnix": 153,
        "oneUse": True,
        "oneUseSequence": authorized[
            "currentHeadExpectedOneUseSequence"
        ],
        "operation": {
            "authorizationConsumed": True,
            "compareCurrentHead": True,
            "finalHeadCommitted": True,
            "reservationConsumed": True,
        },
        "preRedemptionHead": pre_head,
        "preRedemptionHeadSha256": authorized["currentHeadSha256"],
        "preRedemptionResultSha256": verifier.sha256_json(authorized),
        "redeemedAtUnix": 152,
        "redemptionId": redemption_id,
        "redemptionVerifierNonceConsumption": nonce_consumption,
        "reservationIdentity": authorized[
            "currentHeadReservationIdentity"
        ],
        "reservationIdentitySha256": authorized[
            "currentHeadReservationIdentitySha256"
        ],
        "stateCommitReceiptIdentity": authorized[
            "stateCommitReceiptIdentity"
        ],
        "stateCommitReceiptIdentitySha256": verifier.sha256_json(
            authorized["stateCommitReceiptIdentity"]
        ),
        "status": "redeemed",
        "storeId": authorized["stateStoreId"],
        "transitionSha256": transition["transitionSha256"],
        "trustRootBundleSha256": roots,
    }


class CanonicalProfileFixtures(unittest.TestCase):
    def test_positive_current_profile(self) -> None:
        value = {"apiVersion": verifier.BUNDLE_VERSION, "count": (1 << 63) - 1}
        self.assertEqual(
            verifier.canonical_json_bytes(value),
            b'{"apiVersion":"serverware.publicNitroVerificationBundle/v2","count":9223372036854775807}',
        )

    def test_float_is_rejected(self) -> None:
        with self.assertRaises(verifier.VerificationError):
            verifier.canonical_json_bytes({"value": 1.25})

    def test_signed_and_u64_integer_boundaries_are_closed(self) -> None:
        self.assertEqual(
            verifier.canonical_json_bytes({"value": verifier.MAX_U64}),
            (
                b'{"value":18446744073709551615}'
            ),
        )
        self.assertEqual(
            verifier.canonical_json_bytes({"value": -(1 << 63)}),
            b'{"value":-9223372036854775808}',
        )
        with self.assertRaises(verifier.VerificationError):
            verifier.canonical_json_bytes({"value": verifier.MAX_U64 + 1})
        with self.assertRaises(verifier.VerificationError):
            verifier.canonical_json_bytes({"value": -(1 << 63) - 1})

    def test_non_nfc_text_is_rejected(self) -> None:
        with self.assertRaises(verifier.VerificationError):
            verifier.canonical_json_bytes({"value": "e\u0301"})

    def test_surrogate_text_is_rejected(self) -> None:
        with self.assertRaises(verifier.VerificationError):
            verifier.canonical_json_bytes({"value": "\ud800"})


class TrustRootIdentityFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.record = trust_key_record(self.private_key)

    def test_positive_file_spki_and_raw_identities_are_distinct(self) -> None:
        key, key_id, file_sha256, raw_sha256 = verifier.load_ed25519_key_file(
            self.record, "fixture key"
        )
        self.assertEqual(key_id, self.record["keyId"])
        self.assertEqual(file_sha256, self.record["keyFileSha256"])
        self.assertEqual(raw_sha256, self.record["rawKeySha256"])
        self.assertNotEqual(file_sha256, key_id)
        self.assertEqual(verifier.ed25519_raw_key_id(key), raw_sha256)

    def test_spki_id_in_key_file_field_is_rejected(self) -> None:
        changed = copy.deepcopy(self.record)
        changed["keyFileSha256"] = changed["keyId"]
        with self.assertRaises(verifier.VerificationError):
            verifier.load_ed25519_key_file(changed, "fixture key")

    def test_unknown_key_field_is_rejected(self) -> None:
        changed = copy.deepcopy(self.record)
        changed["trusted"] = True
        with self.assertRaises(verifier.VerificationError):
            verifier.load_ed25519_key_file(changed, "fixture key")


class ClosedVersionFixtures(unittest.TestCase):
    def test_exact_pipeline_literal(self) -> None:
        self.assertEqual(
            verifier.PIPELINE, "manifest-v6-promoted-oci-nitro-eif"
        )
        self.assertNotEqual(verifier.PIPELINE, "manifest-v6-nitro-eif")

    def test_current_versions_are_closed(self) -> None:
        self.assertEqual(
            {
                verifier.BUNDLE_VERSION,
                verifier.EXPECTATIONS_VERSION,
                verifier.TRUST_ROOTS_VERSION,
                verifier.SOURCE_INPUT_VERSION,
                verifier.GIT_INVENTORY_VERSION,
                verifier.UNTRACKED_APPROVAL_VERSION,
                verifier.BUILD_WATCHDOG_VERSION,
                verifier.PROMOTION_VERSION,
                verifier.RUNTIME_CUSTODY_VERSION,
                verifier.TLS_SCOPE_VERSION,
                verifier.TLS_SCOPE_ENVELOPE_VERSION,
                verifier.RESPONSE_STATEMENT_VERSION,
                verifier.RELEASE_IDENTITY_VERSION,
                verifier.LIVE_SESSION_PROOF_VERSION,
                verifier.LIVE_WITNESS_HEAD_VERSION,
                verifier.PROTECTED_LIVE_WITNESS_STATE_VERSION,
                verifier.PUBLIC_ATTESTATION_BUNDLE_VERSION,
                verifier.PUBLIC_ATTESTATION_CONFIG_VERSION,
                verifier.PUBLIC_RELEASE_GRAPH_VERSION,
                verifier.STABLE_RELEASE_STATEMENT_VERSION,
            },
            {
                "serverware.publicNitroVerificationBundle/v2",
                "serverware.publicNitroExpectations/v2",
                "serverware.publicNitroTrustRoots/v4",
                "serverware.sourceInputManifest/v3",
                "serverware.gitSourceInventory/v3",
                "serverware.untrackedSourceApproval/v2",
                "serverware.ociBuildWatchdogReceipt/v4",
                "serverware.verificationPromotionReceipt/v4",
                "serverware.enclaveKeyCustody/v3",
                "serverware.enclaveTlsScope/v2",
                "serverware.enclaveTlsScopeEnvelope/v2",
                "serverware.attestationResponse/v2",
                "serverware.releaseIdentity/v1",
                "serverware.liveSessionProof/v1",
                "serverware.liveWitnessHead/v1",
                "serverware.protectedLiveWitnessState/v2",
                "serverware.publicAttestationBundle/v3",
                "serverware.publicAttestationConfig/v2",
                "serverware.publicReleaseGraph/v1",
                "serverware.stableReleaseStatement/v1",
            },
        )

    def test_legacy_versions_do_not_cross_accept(self) -> None:
        rejected = {
            "serverware.publicNitroVerificationBundle/v1",
            "serverware.sourceInputManifest/v2",
            "serverware.ociBuildWatchdogReceipt/v3",
            "serverware.verificationPromotionReceipt/v3",
            "serverware.enclaveKeyCustody/v2",
            "serverware.enclaveTlsScope/v1",
            "serverware.attestationResponse/v1",
            "manifest-v6-nitro-eif",
            "legacy-docker-dev-nsm",
        }
        current = {
            verifier.BUNDLE_VERSION,
            verifier.SOURCE_INPUT_VERSION,
            verifier.BUILD_WATCHDOG_VERSION,
            verifier.PROMOTION_VERSION,
            verifier.RUNTIME_CUSTODY_VERSION,
            verifier.TLS_SCOPE_VERSION,
            verifier.RESPONSE_STATEMENT_VERSION,
            verifier.PIPELINE,
        }
        self.assertTrue(rejected.isdisjoint(current))


class ReleaseIdentityAndLiveSessionFixtures(unittest.TestCase):
    def verify_live(self, fixture: dict, *, now: int = 1_015) -> dict:
        return verifier.verify_live_session_proof(
            fixture["proof"],
            signature=fixture["signature"],
            response_signing_public_key_pem=fixture[
                "responseSigningPublicKeyPem"
            ],
            evidence_body=fixture["evidenceBody"],
            caller_nonce=fixture["callerNonce"],
            request_body=fixture["requestBody"],
            expected_tls_binding=fixture["tlsBinding"],
            expected_release_identity=fixture["releaseIdentity"],
            expected_witness=fixture["proof"]["witness"],
            now=now,
        )

    def test_positive_release_then_live_verifier_is_real_and_byte_exact(
        self,
    ) -> None:
        fixture_case = bridge_fixture.PublicEvidenceTests(
            methodName="test_public_v3_uses_real_stable_and_live_verifiers"
        )
        try:
            fixture = fixture_case.public_v3_fixture()
            if fixture.prior_protected_witness_state is None:
                raise AssertionError(
                    "exact fixture did not retain its prior witness state"
                )
            result = verifier.verify_public_v3_response(
                evidence_body=fixture.body,
                live_session_proof=fixture.live_session_proof,
                live_session_signature=fixture.live_session_signature,
                response_signing_public_key_pem=(
                    fixture.response_public_key_pem
                ),
                caller_nonce=fixture.caller_nonce,
                request_body=fixture.raw_request,
                expected_tls_binding=fixture.scope.binding_document(),
                delivery_rebind=fixture.delivery_rebind,
                trust=fixture.trust,
                expected_release_config_sha256=verifier.sha256(
                    fixture.immutable_config_raw
                ),
                expected_nonce_authority_assurance_sha256=(
                    fixture.nonce_authority_assurance_sha256
                ),
                expected_nonce_authority_assurance_issuer_spki_sha256=(
                    fixture
                    .nonce_authority_assurance_evidence_key_id
                ),
                expected_attestation_pins=(
                    fixture.expected_attestation_pins
                ),
                protected_witness_state=(
                    fixture.protected_witness_state
                ),
                protected_witness_state_raw=(
                    verifier.canonical_json_bytes(
                        fixture.protected_witness_state
                    )
                    + b"\n"
                ),
                prior_protected_witness_state=(
                    fixture.prior_protected_witness_state
                ),
                nonce_consumption_receipt=(
                    fixture.nonce_consumption_receipt
                ),
                nonce_authority_assurance_evidence=(
                    fixture.nonce_authority_assurance_evidence
                ),
                prior_nonce_authority_verifier_state=(
                    fixture.prior_nonce_authority_verifier_state
                ),
                nonce_authority_state_authorization=(
                    fixture.nonce_authority_state_authorization
                ),
                nonce_authority_state_commit_receipt=(
                    fixture.nonce_authority_state_commit_receipt
                ),
                nonce_authority_verifier_challenge=(
                    fixture.nonce_authority_verifier_challenge
                ),
                witness_verifier_challenge=(
                    fixture.witness_verifier_challenge
                ),
                now=fixture.live_session_proof["producedAtUnix"],
            )
        finally:
            fixture_case.doCleanups()
        self.assertEqual(
            set(result),
            {
                "actionAuthorization",
                "apiVersion",
                "committedNonceAuthorityVerifierState",
                "evidence",
                "finalCompletionVerified",
                "okForAction",
                "verificationOk",
            },
        )
        self.assertIs(result["verificationOk"], True)
        self.assertIs(result["finalCompletionVerified"], True)
        self.assertIsNone(result["actionAuthorization"])
        self.assertIs(result["okForAction"], False)
        self.assertEqual(
            verifier.validate_non_actionable_live_result(result),
            result,
        )
        result_schema = json.loads(
            (
                Path(__file__).parents[1]
                / "schemas"
                / "live-attestation-verification-result.v1.schema.json"
            ).read_text(encoding="utf-8")
        )
        schema_validator = Draft202012Validator(result_schema)
        schema_validator.validate(result)
        shape_cases = {
            "obsolete-final-completion": {
                **copy.deepcopy(result),
                "final_completion": True,
            },
            "missing-verification-ok": copy.deepcopy(result),
            "missing-final-completion-verified": copy.deepcopy(result),
            "missing-committed-state": copy.deepcopy(result),
            "result-version": {
                **copy.deepcopy(result),
                "apiVersion":
                "serverware.liveAttestationVerificationResult/v0",
            },
            "wrong-committed-state-shape": copy.deepcopy(result),
            "committed-state-version": copy.deepcopy(result),
            "committed-state-time-type": copy.deepcopy(result),
            "evidence-counter-type": copy.deepcopy(result),
            "final-verification-substitution": copy.deepcopy(result),
            "action-authorization-substitution": copy.deepcopy(result),
            "evidence-unknown-field": copy.deepcopy(result),
        }
        del shape_cases["missing-verification-ok"]["verificationOk"]
        del shape_cases["missing-final-completion-verified"][
            "finalCompletionVerified"
        ]
        del shape_cases["missing-committed-state"][
            "committedNonceAuthorityVerifierState"
        ]
        del shape_cases["wrong-committed-state-shape"][
            "committedNonceAuthorityVerifierState"
        ]["stateStoreHeadSha256"]
        shape_cases["committed-state-version"][
            "committedNonceAuthorityVerifierState"
        ]["apiVersion"] = "serverware.nonceAuthorityVerifierState/v0"
        shape_cases["committed-state-time-type"][
            "committedNonceAuthorityVerifierState"
        ]["committedAtUnix"] = True
        shape_cases["evidence-counter-type"]["evidence"][
            "nonceAuthoritySequence"
        ] = True
        shape_cases["final-verification-substitution"][
            "finalCompletionVerified"
        ] = False
        shape_cases["action-authorization-substitution"][
            "actionAuthorization"
        ] = {"capability": "forbidden"}
        shape_cases["evidence-unknown-field"]["evidence"][
            "unboundSha256"
        ] = verifier.sha256(b"unbound-live-result")
        for name, changed in shape_cases.items():
            with self.subTest(name=name), self.assertRaises(
                verifier.VerificationError
            ):
                verifier.validate_non_actionable_live_result(changed)
            with self.subTest(name=f"{name}-schema"), self.assertRaises(
                ValidationError
            ):
                schema_validator.validate(changed)
        substituted = copy.deepcopy(result)
        substituted["evidence"][
            "committedNonceAuthorityVerifierStateSha256"
        ] = verifier.sha256(b"substituted-committed-state")
        schema_validator.validate(substituted)
        with self.assertRaises(verifier.VerificationError):
            verifier.validate_non_actionable_live_result(substituted)
        self.assertEqual(
            fixture.body,
            verifier.canonical_json_bytes(fixture.document) + b"\n",
        )

    def test_public_v3_wire_schemas_validate_real_production_shapes(
        self,
    ) -> None:
        fixture_case = bridge_fixture.PublicEvidenceTests(
            methodName="test_public_v3_uses_real_stable_and_live_verifiers"
        )
        try:
            fixture = fixture_case.public_v3_fixture()
        finally:
            fixture_case.doCleanups()
        descriptor = json.loads(
            fixture.artifacts["descriptorSha256"].decode("ascii")
        )
        producer_request = json.loads(
            fixture.producer_request_raw.decode("ascii")
        )
        valid_documents = {
            "public-attestation-producer-descriptor.v2.schema.json":
            descriptor,
            "public-attestation-config.v2.schema.json":
            fixture.immutable_config,
            "public-attestation-producer-request.v2.schema.json":
            producer_request,
            "public-attestation-bundle.v3.schema.json":
            fixture.document,
        }
        validators = {
            name: public_schema_validator(name)
            for name in valid_documents
        }
        for name, document in valid_documents.items():
            with self.subTest(valid=name):
                validators[name].validate(document)

        hostile = {
            "descriptor-version": (
                "public-attestation-producer-descriptor.v2.schema.json",
                copy.deepcopy(descriptor),
            ),
            "descriptor-peer-uid": (
                "public-attestation-producer-descriptor.v2.schema.json",
                copy.deepcopy(descriptor),
            ),
            "descriptor-endpoint": (
                "public-attestation-producer-descriptor.v2.schema.json",
                copy.deepcopy(descriptor),
            ),
            "config-store-assurance-omission": (
                "public-attestation-config.v2.schema.json",
                copy.deepcopy(fixture.immutable_config),
            ),
            "config-store-assurance-null": (
                "public-attestation-config.v2.schema.json",
                copy.deepcopy(fixture.immutable_config),
            ),
            "config-rollback-substitution": (
                "public-attestation-config.v2.schema.json",
                copy.deepcopy(fixture.immutable_config),
            ),
            "request-version": (
                "public-attestation-producer-request.v2.schema.json",
                copy.deepcopy(producer_request),
            ),
            "request-service-endpoint": (
                "public-attestation-producer-request.v2.schema.json",
                copy.deepcopy(producer_request),
            ),
            "request-authorization-null": (
                "public-attestation-producer-request.v2.schema.json",
                copy.deepcopy(producer_request),
            ),
            "request-nonce-receipt-null": (
                "public-attestation-producer-request.v2.schema.json",
                copy.deepcopy(producer_request),
            ),
            "request-commit-receipt-null": (
                "public-attestation-producer-request.v2.schema.json",
                copy.deepcopy(producer_request),
            ),
            "request-store-proof-null": (
                "public-attestation-producer-request.v2.schema.json",
                copy.deepcopy(producer_request),
            ),
            "request-store-assurance-null": (
                "public-attestation-producer-request.v2.schema.json",
                copy.deepcopy(producer_request),
            ),
            "bundle-artifact-base64url": (
                "public-attestation-bundle.v3.schema.json",
                copy.deepcopy(fixture.document),
            ),
            "bundle-transition-omission": (
                "public-attestation-bundle.v3.schema.json",
                copy.deepcopy(fixture.document),
            ),
        }
        hostile["descriptor-version"][1]["apiVersion"] = (
            "serverware.publicAttestationProducerDescriptor/v1"
        )
        hostile["descriptor-peer-uid"][1]["nonceService"][
            "expectedPeerUid"
        ] = 2147483648
        hostile["descriptor-endpoint"][1]["verifierStateService"][
            "endpoint"
        ] = "https://256.1.1.1:70000"
        del hostile["config-store-assurance-omission"][1][
            "nonceAuthorityVerifierStateStoreAssuranceEvidence"
        ]
        hostile["config-store-assurance-null"][1][
            "nonceAuthorityVerifierStateStoreAssuranceEvidence"
        ] = None
        hostile["config-rollback-substitution"][1][
            "nonceAuthorityVerifierStateStoreRollbackMechanism"
        ] = "customRollbackClaim"
        hostile["request-version"][1]["apiVersion"] = (
            "serverware.publicAttestationProducerRequest/v1"
        )
        hostile["request-service-endpoint"][1]["liveSessionRequest"][
            "nonceAuthorityVerifierStateTransition"
        ]["serviceBinding"]["endpoint"] = "https://192.0.2.1:70000"
        for case, field in (
            ("request-authorization-null", "authorization"),
            ("request-nonce-receipt-null", "nonceConsumptionReceipt"),
            ("request-commit-receipt-null", "commitReceipt"),
            ("request-store-proof-null", "signedStoreCommitProof"),
            ("request-store-assurance-null", "storeAssuranceEvidence"),
        ):
            hostile[case][1]["liveSessionRequest"][
                "nonceAuthorityVerifierStateTransition"
            ][field] = None
        hostile["bundle-artifact-base64url"][1]["bundle"]["artifacts"][
            0
        ]["contentBase64url"] = "A"
        del hostile["bundle-transition-omission"][1][
            "nonceAuthorityVerifierStateTransition"
        ]
        for name, (schema_name, document) in hostile.items():
            with self.subTest(invalid=name), self.assertRaises(
                ValidationError
            ):
                validators[schema_name].validate(document)

    def test_release_identity_is_stable_across_live_sessions(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        first = signed_live_session_fixture(private_key)
        changed_tls = live_tls_binding()
        changed_tls["connectionId"] = "connection-0002"
        changed_tls_core = {
            key: value
            for key, value in changed_tls.items()
            if key != "bindingSha256"
        }
        changed_tls["bindingSha256"] = verifier.sha256_json(
            changed_tls_core
        )
        second = signed_live_session_fixture(
            private_key,
            caller_nonce=b"m" * 32,
            tls_binding=changed_tls,
        )
        self.assertEqual(
            first["releaseIdentity"], second["releaseIdentity"]
        )
        self.assertEqual(
            verifier.sha256_json(first["releaseIdentity"]),
            verifier.sha256_json(second["releaseIdentity"]),
        )
        self.assertNotEqual(first["proof"], second["proof"])

    def test_release_identity_rejects_dynamic_and_generic_ok_fields(
        self,
    ) -> None:
        fixture = signed_live_session_fixture(
            Ed25519PrivateKey.generate()
        )
        for field, value in (
            ("callerNonceSha256", verifier.sha256(b"nonce")),
            ("evidenceBodySha256", verifier.sha256(b"body")),
            ("liveSessionProof", {}),
            ("ok", False),
            ("request", {}),
            ("tlsBinding", live_tls_binding()),
        ):
            changed = copy.deepcopy(fixture["releaseIdentity"])
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(
                verifier.VerificationError
            ):
                verifier.validate_release_identity(
                    changed,
                    label="fixture stable release identity",
                )

    def test_live_proof_rejects_crossed_external_bindings(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        fixture = signed_live_session_fixture(private_key)
        cases = (
            {"callerNonce": b"x" * 32},
            {"evidenceBody": fixture["evidenceBody"] + b"\n"},
            {"requestBody": fixture["requestBody"] + b" "},
        )
        for changes in cases:
            crossed = {**fixture, **changes}
            with self.subTest(changes=changes), self.assertRaises(
                verifier.VerificationError
            ):
                self.verify_live(crossed)

        wrong_tls = copy.deepcopy(fixture)
        wrong_tls["tlsBinding"] = copy.deepcopy(fixture["tlsBinding"])
        wrong_tls["tlsBinding"]["leafSpkiSha256"] = verifier.sha256(
            b"other-leaf"
        )
        with self.assertRaises(verifier.VerificationError):
            self.verify_live(wrong_tls)

        wrong_witness = copy.deepcopy(fixture)
        wrong_witness["proof"]["witness"]["headSha256"] = verifier.sha256(
            b"other-current-head"
        )
        wrong_witness["signature"] = "ed25519:" + b64u(
            private_key.sign(
                verifier.canonical_json_bytes(wrong_witness["proof"])
            )
        )
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_live_session_proof(
                wrong_witness["proof"],
                signature=wrong_witness["signature"],
                response_signing_public_key_pem=wrong_witness[
                    "responseSigningPublicKeyPem"
                ],
                evidence_body=wrong_witness["evidenceBody"],
                caller_nonce=wrong_witness["callerNonce"],
                request_body=wrong_witness["requestBody"],
                expected_tls_binding=wrong_witness["tlsBinding"],
                expected_release_identity=wrong_witness[
                    "releaseIdentity"
                ],
                expected_witness=fixture["proof"]["witness"],
                now=1_015,
            )

    def test_live_proof_is_closed_and_rejects_boolean_integers(
        self,
    ) -> None:
        fixture = signed_live_session_fixture(
            Ed25519PrivateKey.generate()
        )
        release_paths = (
            ("policy", "sequence"),
            ("monotonicRelease", "releaseGeneration"),
            ("monotonicRelease", "rollbackEpoch"),
        )
        for parent, field in release_paths:
            changed = copy.deepcopy(fixture["releaseIdentity"])
            changed[parent][field] = True
            with self.subTest(path=f"{parent}.{field}"), self.assertRaises(
                verifier.VerificationError
            ):
                verifier.validate_release_identity(
                    changed,
                    label="fixture stable release identity",
                )
        proof_paths = (
            (None, "producedAtUnix"),
            (None, "expiresAtUnix"),
            ("witness", "generation"),
            ("witness", "rollbackEpoch"),
            ("witness", "sequence"),
            ("witness", "treeSize"),
        )
        for parent, field in proof_paths:
            changed = copy.deepcopy(fixture)
            target = (
                changed["proof"]
                if parent is None
                else changed["proof"][parent]
            )
            target[field] = True
            with self.subTest(path=f"{parent}.{field}"), self.assertRaises(
                verifier.VerificationError
            ):
                self.verify_live(changed)
        changed = copy.deepcopy(fixture)
        changed["proof"]["ok"] = False
        with self.assertRaises(verifier.VerificationError):
            self.verify_live(changed)


class CompletionIdentityAndHeaderFixtures(unittest.TestCase):
    @staticmethod
    def completion_v6_contract_fixture() -> dict:
        proof = {
            field: None
            for field in {
                "actionAuthorization",
                "aggregate_authentication",
                "apiVersion",
                "artifacts",
                "assurance_ceiling",
                "benchmark",
                "bootstrap_launcher",
                "completion_status",
                "current_completion_host",
                "final_challenge_consumption",
                "finalCompletionVerified",
                "generated_at_unix",
                "hardware_assurance_evidence",
                "hardware_proof",
                "image_signatures",
                "independently_authenticated",
                "integrity_metadata",
                "kind",
                "nitro_evidence_binding",
                "nitro_kms_evidence",
                "nonce_rollback_assurance",
                "okForAction",
                "production_continuity",
                "production_env_binding",
                "production_host_preflight",
                "production_images_build",
                "production_images_published",
                "production_proxy_response_proof",
                "production_readiness",
                "production_readiness_config",
                "proof_core_sha256",
                "proof_path",
                "readiness_ok",
                "readiness_only",
                "release_completion",
                "release_provenance",
                "release_security_evidence",
                "result_scope",
                "running_production_containers",
                "verification_mode",
                "verification_passed",
                "verificationOk",
            }
        }
        proof.update(
            {
                "actionAuthorization": None,
                "aggregate_authentication": {
                    "required": False,
                    "independently_authenticated": False,
                    "scope": "readiness-only",
                },
                "apiVersion": verifier.COMPLETION_PROOF_VERSION,
                "completion_status": "pre-enclave-readiness",
                "final_challenge_consumption": {
                    "required": False,
                    "consumed": False,
                },
                "finalCompletionVerified": False,
                "hardware_proof": False,
                "independently_authenticated": False,
                "integrity_metadata": {
                    "authenticity_requires_external_signature_or_checkpoint":
                    True,
                    "detached_sha256_path": "/run/readiness.sha256",
                    "generation": 1,
                    "independently_authenticated": False,
                    "scope": "checksum-only",
                },
                "kind": "ServerwarePreEnclaveReadiness",
                "okForAction": False,
                "proof_core_sha256": verifier.sha256(
                    b"readiness-only-core"
                ),
                "readiness_ok": True,
                "readiness_only": True,
                "release_completion": "not-final",
                "result_scope": "readiness-only",
                "verification_mode": "readiness",
                "verification_passed": True,
                "verificationOk": True,
            }
        )
        return proof

    def test_completion_v6_contract_rejects_mismatch_and_substitution(
        self,
    ) -> None:
        valid = self.completion_v6_contract_fixture()
        self.assertEqual(
            verifier.validate_completion_v6_contract_shape(valid),
            valid,
        )
        for name, field, value in (
            ("final", "finalCompletionVerified", True),
            ("actionable", "okForAction", True),
            ("final-kind", "kind", "ServerwareCompletionProof"),
            ("final-mode", "verification_mode", "final"),
            ("final-scope", "result_scope", "final-completion"),
        ):
            changed = copy.deepcopy(valid)
            changed[field] = value
            with self.subTest(name=name), self.assertRaises(
                verifier.VerificationError
            ):
                verifier.validate_completion_v6_contract_shape(changed)
        for injected in (
            "authentication_artifacts",
            "public_verifier_bridge",
            "completionProofFileB64",
        ):
            changed = copy.deepcopy(valid)
            changed[injected] = {}
            with self.subTest(injected=injected), self.assertRaises(
                verifier.VerificationError
            ):
                verifier.validate_completion_v6_contract_shape(changed)

    def test_signed_completion_authentication_artifact_substitution_fails(
        self,
    ) -> None:
        readiness = self.completion_v6_contract_fixture()
        readiness["authentication_artifacts"] = {}
        with self.assertRaises(verifier.VerificationError):
            verifier.validate_completion_v6_contract_shape(readiness)

    def test_builder_requires_expectations_explicitly(self) -> None:
        parameters = inspect.signature(verifier.verify_builder).parameters
        self.assertIn("expectations", parameters)
        self.assertEqual(parameters["expectations"].kind, inspect.Parameter.KEYWORD_ONLY)

    def test_exact_completion_identity_and_canonical_digest(self) -> None:
        identity = completion_identity()
        digest = verifier.sha256_json(identity)
        self.assertEqual(
            verifier.verify_completion_identity(
                identity,
                digest,
                label="fixture completion identity",
            ),
            identity,
        )

    def test_missing_completion_identity_field_is_rejected(self) -> None:
        identity = completion_identity()
        del identity["coreDigests"]["witness"]
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_completion_identity(
                identity,
                verifier.sha256_json(identity),
                label="fixture completion identity",
            )

    def test_unknown_completion_identity_field_is_rejected(self) -> None:
        identity = completion_identity()
        identity["trusted"] = True
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_completion_identity(
                identity,
                verifier.sha256_json(identity),
                label="fixture completion identity",
            )

    def test_cross_assembled_completion_identity_is_rejected(self) -> None:
        identity = completion_identity()
        original_digest = verifier.sha256_json(identity)
        identity["coreDigests"]["custody"] = verifier.sha256(
            b"other-custody"
        )
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_completion_identity(
                identity,
                original_digest,
                label="fixture completion identity",
            )

    def test_custody_core_cross_assembly_is_rejected(self) -> None:
        custody_core = {
            "apiVersion": verifier.RUNTIME_CUSTODY_VERSION,
            "materials": [{"name": "broker-kek"}],
            "pipeline": verifier.PIPELINE,
        }
        identity = completion_identity()
        identity["coreDigests"]["custody"] = verifier.sha256_json(
            verifier.completion_core("custody", custody_core)
        )
        identity_sha256 = verifier.sha256_json(identity)
        custody = {
            **custody_core,
            "completionIdentity": identity,
            "completionIdentitySha256": identity_sha256,
        }
        bound_identity, core_sha256 = verifier.verify_custody_completion_binding(
            custody
        )
        self.assertEqual(bound_identity, identity)
        self.assertEqual(
            core_sha256,
            identity["coreDigests"]["custody"],
        )
        crossed = dict(custody)
        crossed["materials"] = [{"name": "response"}]
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_custody_completion_binding(
                crossed,
            )

    def test_core_construction_rejects_nested_completion_binding(self) -> None:
        with self.assertRaises(verifier.VerificationError):
            verifier.completion_core(
                "release",
                {
                    "nested": {
                        "completionIdentitySha256": verifier.sha256(b"cycle")
                    }
                },
            )

    def test_builder_core_is_constructible_before_outer_identity_binding(
        self,
    ) -> None:
        first_identity = completion_identity()
        second_identity = copy.deepcopy(first_identity)
        second_identity["challengeNonceSha256"] = verifier.sha256(
            b"other-challenge"
        )

        def transcript_for(identity: dict) -> dict:
            event = {
                "completionIdentity": identity,
                "completionIdentitySha256": verifier.sha256_json(identity),
                "type": "build-started",
            }
            event_payload = {
                "event": event,
                "previousEventSha256": verifier.sha256(b""),
                "sequence": 1,
            }
            event_sha256 = verifier.sha256_json(event_payload)
            return {
                "apiVersion": verifier.BUILDER_TRANSCRIPT_VERSION,
                "completionIdentity": identity,
                "completionIdentitySha256": verifier.sha256_json(identity),
                "eventHeadSha256": event_sha256,
                "events": [{**event_payload, "eventSha256": event_sha256}],
                "pipeline": verifier.PIPELINE,
                "transcriptSha256": verifier.sha256(
                    identity["challengeNonceSha256"].encode("ascii")
                ),
            }

        first_outer = transcript_for(first_identity)
        second_outer = transcript_for(second_identity)
        self.assertNotEqual(
            verifier.sha256_json(first_outer),
            verifier.sha256_json(second_outer),
        )
        self.assertEqual(
            verifier.builder_transcript_core_payload(first_outer),
            verifier.builder_transcript_core_payload(second_outer),
        )

    def test_builder_core_rejects_non_identity_event_substitution(self) -> None:
        identity = completion_identity()
        event = {
            "completionIdentity": identity,
            "completionIdentitySha256": verifier.sha256_json(identity),
            "type": "build-started",
        }
        event_payload = {
            "event": event,
            "previousEventSha256": verifier.sha256(b""),
            "sequence": 1,
        }
        event_sha256 = verifier.sha256_json(event_payload)
        transcript = {
            "events": [{**event_payload, "eventSha256": event_sha256}],
        }
        original = verifier.builder_transcript_core_payload(transcript)
        substituted = copy.deepcopy(transcript)
        substituted["events"][0]["event"]["type"] = "build-completed"
        self.assertNotEqual(
            verifier.sha256_json(original),
            verifier.sha256_json(
                verifier.builder_transcript_core_payload(substituted)
            ),
        )

    def test_cross_core_substitution_is_rejected(self) -> None:
        identity = completion_identity()
        substituted = copy.deepcopy(identity)
        substituted["coreDigests"]["builderA"] = identity["coreDigests"][
            "builderB"
        ]
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_reconstructed_completion_identity(
                identity,
                [
                    (
                        "substituted builder core",
                        substituted,
                        verifier.sha256_json(substituted),
                    )
                ],
            )

    def test_detached_proof_headers_match_signed_producer_schema(self) -> None:
        self.assertEqual(
            verifier.DETACHED_PROOF_HEADERS,
            {
                "statement": (
                    "x-serverware-attestation-statement-b64:"
                    "base64url(canonical-statement)"
                ),
                "statementSha256": (
                    "x-serverware-attestation-statement-sha256:"
                    "sha256(canonical-statement)"
                ),
                "signature": (
                    "x-serverware-attestation-signature:"
                    "ed25519(canonical-statement)"
                ),
            },
        )

    def test_legacy_detached_header_schema_is_not_accepted(self) -> None:
        legacy = {
            "names": [
                "x-serverware-attestation-statement-b64",
                "x-serverware-attestation-statement-sha256",
                "x-serverware-attestation-signature",
            ],
            "statementAndSignatureExcludedFromSignedCore": True,
        }
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_detached_proof_headers(legacy)


class PromotionAndLaneFixtures(unittest.TestCase):
    def test_single_promotion_acceptance_payload(self) -> None:
        contract = verifier.sha256(b"candidate promotion contract")
        payload = {
            "apiVersion": verifier.PROMOTION_ACCEPTANCE_VERSION,
            "candidatePromotionContractSha256": contract,
        }
        acceptance = {**payload, "acceptanceSha256": verifier.sha256_json(payload)}
        copied = dict(acceptance)
        supplied = copied.pop("acceptanceSha256")
        self.assertEqual(supplied, verifier.sha256_json(copied))

    def test_fixed_lane_and_npm_inventory(self) -> None:
        self.assertEqual(len(verifier.LANE_ORDER), 14)
        self.assertEqual(
            verifier.IMAGE_ORDER[-1], "npm-publish-companion"
        )
        self.assertEqual(
            set(verifier.SOURCE_CONTRACTS), set(verifier.LANE_ORDER)
        )
        npm = verifier.expected_manifest_process("npm-publish-companion")
        self.assertEqual(npm["argv"], [])
        self.assertEqual(npm["uid"], 65532)


class ChallengeWitnessAndCasFixtures(unittest.TestCase):
    def test_challenge_is_exactly_32_bytes(self) -> None:
        challenge = b"c" * 32
        self.assertEqual(len(challenge), 32)
        self.assertNotEqual(len(challenge[:-1]), 32)

    def test_indexed_inclusion_rejects_missing_index_range(self) -> None:
        with self.assertRaises(verifier.VerificationError):
            verifier.verify_indexed_merkle_inclusion(
                leaf_sha256=verifier.sha256(b"leaf"),
                leaf_index=1,
                tree_size=1,
                proof=[],
                root_sha256=verifier.sha256(b"leaf"),
                label="fixture",
            )

    def test_non_actionable_final_contract_rejects_conventional_success(
        self,
    ) -> None:
        valid = {
            "verificationOk": True,
            "finalCompletionVerified": True,
            "actionAuthorization": None,
            "okForAction": False,
        }
        self.assertEqual(
            verifier.validate_non_actionable_final_result(
                valid,
                label="fixture",
            ),
            valid,
        )
        for field, value in (
            ("ok", True),
            ("finalCompletion", True),
            ("final_completion", True),
            ("stateCommitRequired", False),
        ):
            changed = {**valid, field: value}
            with self.subTest(field=field), self.assertRaises(
                verifier.VerificationError
            ):
                verifier.validate_non_actionable_final_result(
                    changed,
                    label="fixture",
                )

    def test_nested_counter_booleans_are_rejected_before_hashing(
        self,
    ) -> None:
        paths = (
            {"events": [{"sequence": True}]},
            {"runtime": {"releaseGeneration": True}},
            {"runtime": {"rollbackEpoch": True}},
            {"kms": {"keyGeneration": True}},
            {"kms": {"releaseConditions": {"rollbackEpoch": True}}},
            {"witness": {"inclusion": {"treeSize": True}}},
            {"witness": {"inclusion": {"leafIndex": True}}},
        )
        for value in paths:
            with self.subTest(value=value), self.assertRaises(
                verifier.VerificationError
            ):
                verifier.sha256_json(value)

    def test_cas_and_authorization_remain_non_actionable_until_redemption(
        self,
    ) -> None:
        private_key = Ed25519PrivateKey.generate()
        current_head_private_key = Ed25519PrivateKey.generate()
        redemption_private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        current_head_public_key = current_head_private_key.public_key()
        redemption_public_key = redemption_private_key.public_key()
        key_id = verifier.sha256(
            public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        current_head_key_id = verifier.sha256(
            current_head_public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        redemption_key_id = verifier.sha256(
            redemption_public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        roots = verifier.sha256(b"roots")
        pending = pending_state_commit_result()
        payload = cas_payload(pending, roots=roots)
        receipt = standard_envelope(
            private_key,
            api_version=verifier.STATE_COMMIT_VERSION,
            domain=verifier.STATE_COMMIT_DOMAIN,
            payload=payload,
        )
        with self.assertRaises(verifier.VerificationError):
            verifier.finalize_state_commit(
                {**pending, "ok": False},
                receipt,
                trust={
                    "keys": {"stateCommit": public_key},
                    "keyIds": {"stateCommit": key_id},
                    "trustRootBundleSha256": roots,
                },
                now=150,
            )
        result = verifier.finalize_state_commit(
            pending,
            receipt,
            trust={
                "keys": {"stateCommit": public_key},
                "keyIds": {"stateCommit": key_id},
                "trustRootBundleSha256": roots,
            },
            now=150,
        )
        self.assertEqual(
            result["status"],
            "pending-current-head-authorization",
        )
        self.assertNotIn("ok", result)
        self.assertFalse(result["okForAction"])
        verifier_nonce = b"v" * 32
        authorization = standard_envelope(
            current_head_private_key,
            api_version=verifier.CURRENT_HEAD_AUTHORIZATION_VERSION,
            domain=verifier.CURRENT_HEAD_AUTHORIZATION_DOMAIN,
            payload=current_head_authorization_payload(
                result,
                verifier_nonce=verifier_nonce,
                roots=roots,
            ),
        )
        with self.assertRaises(verifier.VerificationError):
            verifier.authorize_current_head(
                {**result, "ok": False},
                authorization,
                verifier_nonce=verifier_nonce,
                trust={
                    "keys": {
                        "currentHeadAuthorization": current_head_public_key,
                    },
                    "keyIds": {
                        "currentHeadAuthorization": current_head_key_id,
                    },
                    "trustRootBundleSha256": roots,
                },
                now=150,
            )
        authorized = verifier.authorize_current_head(
            result,
            authorization,
            verifier_nonce=verifier_nonce,
            trust={
                "keys": {
                    "currentHeadAuthorization": current_head_public_key,
                },
                "keyIds": {
                    "currentHeadAuthorization": current_head_key_id,
                },
                "trustRootBundleSha256": roots,
            },
            now=150,
        )
        self.assertEqual(
            authorized["status"],
            "pending-current-head-redemption",
        )
        self.assertNotIn("ok", authorized)
        self.assertFalse(authorized["okForAction"])
        redemption_nonce = b"r" * 32
        redemption = standard_envelope(
            redemption_private_key,
            api_version=verifier.CURRENT_HEAD_REDEMPTION_VERSION,
            domain=verifier.CURRENT_HEAD_REDEMPTION_DOMAIN,
            payload=current_head_redemption_payload(
                authorized,
                verifier_nonce=redemption_nonce,
                roots=roots,
            ),
        )
        with self.assertRaises(verifier.VerificationError):
            verifier.finalize_current_head_redemption(
                {**authorized, "ok": False},
                redemption,
                verifier_nonce=redemption_nonce,
                trust={
                    "keys": {
                        "currentHeadRedemption": redemption_public_key,
                    },
                    "keyIds": {
                        "currentHeadRedemption": redemption_key_id,
                    },
                    "trustRootBundleSha256": roots,
                },
                now=155,
            )
        verified = verifier.finalize_current_head_redemption(
            authorized,
            redemption,
            verifier_nonce=redemption_nonce,
            trust={
                "keys": {
                    "currentHeadRedemption": redemption_public_key,
                },
                "keyIds": {
                    "currentHeadRedemption": redemption_key_id,
                },
                "trustRootBundleSha256": roots,
            },
            now=155,
        )
        self.assertEqual(
            verified["status"],
            "redemption-verified-non-actionable",
        )
        self.assertTrue(verified["currentHeadRedemptionVerified"])
        self.assertTrue(verified["verificationOk"])
        self.assertTrue(verified["finalCompletionVerified"])
        self.assertIsNone(verified["actionAuthorization"])
        self.assertFalse(verified["okForAction"])
        self.assertNotIn("ok", verified)
        self.assertNotIn("finalCompletion", verified)
        self.assertNotIn("stateCommitRequired", verified)

    def test_cas_generation_booleans_are_rejected(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        roots = verifier.sha256(b"roots")
        pending = pending_state_commit_result()
        for field in (
            "oldStoreGeneration",
            "newStoreGeneration",
            "oldRedemptionSequence",
            "newRedemptionSequence",
        ):
            payload = cas_payload(pending, roots=roots)
            payload[field] = True
            receipt = standard_envelope(
                private_key,
                api_version=verifier.STATE_COMMIT_VERSION,
                domain=verifier.STATE_COMMIT_DOMAIN,
                payload=payload,
            )
            with self.subTest(field=field), self.assertRaises(
                verifier.VerificationError
            ):
                verifier.finalize_state_commit(
                    pending,
                    receipt,
                    trust={
                        "keys": {
                            "stateCommit": private_key.public_key()
                        },
                        "keyIds": {
                            "stateCommit": trust_key_record(private_key)[
                                "keyId"
                            ]
                        },
                        "trustRootBundleSha256": roots,
                    },
                    now=150,
                )

    def test_authorization_generation_booleans_are_rejected(self) -> None:
        cas_private_key = Ed25519PrivateKey.generate()
        head_private_key = Ed25519PrivateKey.generate()
        roots = verifier.sha256(b"roots")
        pending = pending_state_commit_result()
        receipt = standard_envelope(
            cas_private_key,
            api_version=verifier.STATE_COMMIT_VERSION,
            domain=verifier.STATE_COMMIT_DOMAIN,
            payload=cas_payload(pending, roots=roots),
        )
        post_cas = verifier.finalize_state_commit(
            pending,
            receipt,
            trust={
                "keys": {"stateCommit": cas_private_key.public_key()},
                "keyIds": {
                    "stateCommit": trust_key_record(cas_private_key)["keyId"]
                },
                "trustRootBundleSha256": roots,
            },
            now=150,
        )
        nonce = b"v" * 32
        paths = (
            ("storeGeneration",),
            ("currentHead", "generation"),
            ("currentHead", "redemptionSequence"),
            ("headReservation", "generation"),
            ("headReservation", "currentRedemptionSequence"),
            ("headReservation", "expectedFinalGeneration"),
            ("headReservation", "expectedOneUseSequence"),
        )
        for path in paths:
            payload = current_head_authorization_payload(
                post_cas,
                verifier_nonce=nonce,
                roots=roots,
            )
            target = payload
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = True
            authorization = standard_envelope(
                head_private_key,
                api_version=verifier.CURRENT_HEAD_AUTHORIZATION_VERSION,
                domain=verifier.CURRENT_HEAD_AUTHORIZATION_DOMAIN,
                payload=payload,
            )
            with self.subTest(path=path), self.assertRaises(
                verifier.VerificationError
            ):
                verifier.authorize_current_head(
                    post_cas,
                    authorization,
                    verifier_nonce=nonce,
                    trust={
                        "keys": {
                            "currentHeadAuthorization": (
                                head_private_key.public_key()
                            )
                        },
                        "keyIds": {
                            "currentHeadAuthorization": trust_key_record(
                                head_private_key
                            )["keyId"]
                        },
                        "trustRootBundleSha256": roots,
                    },
                    now=150,
                )
        valid_payload = current_head_authorization_payload(
            post_cas,
            verifier_nonce=nonce,
            roots=roots,
        )
        valid_authorization = standard_envelope(
            head_private_key,
            api_version=verifier.CURRENT_HEAD_AUTHORIZATION_VERSION,
            domain=verifier.CURRENT_HEAD_AUTHORIZATION_DOMAIN,
            payload=valid_payload,
        )
        for field in (
            "stateStoreGeneration",
            "stateStoreRedemptionSequence",
        ):
            crossed = copy.deepcopy(post_cas)
            crossed[field] = True
            with self.subTest(pending_field=field), self.assertRaises(
                verifier.VerificationError
            ):
                verifier.authorize_current_head(
                    crossed,
                    valid_authorization,
                    verifier_nonce=nonce,
                    trust={
                        "keys": {
                            "currentHeadAuthorization": (
                                head_private_key.public_key()
                            )
                        },
                        "keyIds": {
                            "currentHeadAuthorization": trust_key_record(
                                head_private_key
                            )["keyId"]
                        },
                        "trustRootBundleSha256": roots,
                    },
                    now=150,
                )

    def test_redemption_booleans_and_replay_never_become_actionable(
        self,
    ) -> None:
        cas_private_key = Ed25519PrivateKey.generate()
        head_private_key = Ed25519PrivateKey.generate()
        redemption_private_key = Ed25519PrivateKey.generate()
        roots = verifier.sha256(b"roots")
        pending = pending_state_commit_result()
        receipt = standard_envelope(
            cas_private_key,
            api_version=verifier.STATE_COMMIT_VERSION,
            domain=verifier.STATE_COMMIT_DOMAIN,
            payload=cas_payload(pending, roots=roots),
        )
        post_cas = verifier.finalize_state_commit(
            pending,
            receipt,
            trust={
                "keys": {"stateCommit": cas_private_key.public_key()},
                "keyIds": {
                    "stateCommit": trust_key_record(cas_private_key)["keyId"]
                },
                "trustRootBundleSha256": roots,
            },
            now=150,
        )
        authorization_nonce = b"v" * 32
        authorization = standard_envelope(
            head_private_key,
            api_version=verifier.CURRENT_HEAD_AUTHORIZATION_VERSION,
            domain=verifier.CURRENT_HEAD_AUTHORIZATION_DOMAIN,
            payload=current_head_authorization_payload(
                post_cas,
                verifier_nonce=authorization_nonce,
                roots=roots,
            ),
        )
        authorized = verifier.authorize_current_head(
            post_cas,
            authorization,
            verifier_nonce=authorization_nonce,
            trust={
                "keys": {
                    "currentHeadAuthorization": head_private_key.public_key(),
                },
                "keyIds": {
                    "currentHeadAuthorization": trust_key_record(
                        head_private_key
                    )["keyId"],
                },
                "trustRootBundleSha256": roots,
            },
            now=150,
        )
        redemption_nonce = b"r" * 32
        paths = (
            ("currentStoreGeneration",),
            ("finalStoreGeneration",),
            ("currentRedemptionSequence",),
            ("oneUseSequence",),
            ("preRedemptionHead", "generation"),
            ("preRedemptionHead", "redemptionSequence"),
            ("finalHead", "generation"),
            ("finalHead", "redemptionSequence"),
        )
        for path in paths:
            payload = current_head_redemption_payload(
                authorized,
                verifier_nonce=redemption_nonce,
                roots=roots,
            )
            target = payload
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = True
            redemption = standard_envelope(
                redemption_private_key,
                api_version=verifier.CURRENT_HEAD_REDEMPTION_VERSION,
                domain=verifier.CURRENT_HEAD_REDEMPTION_DOMAIN,
                payload=payload,
            )
            with self.subTest(path=path), self.assertRaises(
                verifier.VerificationError
            ):
                verifier.finalize_current_head_redemption(
                    authorized,
                    redemption,
                    verifier_nonce=redemption_nonce,
                    trust={
                        "keys": {
                            "currentHeadRedemption": (
                                redemption_private_key.public_key()
                            )
                        },
                        "keyIds": {
                            "currentHeadRedemption": trust_key_record(
                                redemption_private_key
                            )["keyId"]
                        },
                        "trustRootBundleSha256": roots,
                    },
                    now=155,
                )
        pending_paths = (
            ("stateStoreGeneration",),
            ("stateStoreRedemptionSequence",),
            ("currentHeadExpectedFinalGeneration",),
            ("currentHeadExpectedOneUseSequence",),
            ("currentHead", "generation"),
            ("currentHead", "redemptionSequence"),
            ("currentHeadReservationIdentity", "generation"),
            (
                "currentHeadReservationIdentity",
                "currentRedemptionSequence",
            ),
            (
                "currentHeadReservationIdentity",
                "expectedFinalGeneration",
            ),
            (
                "currentHeadReservationIdentity",
                "expectedOneUseSequence",
            ),
        )
        valid_redemption = standard_envelope(
            redemption_private_key,
            api_version=verifier.CURRENT_HEAD_REDEMPTION_VERSION,
            domain=verifier.CURRENT_HEAD_REDEMPTION_DOMAIN,
            payload=current_head_redemption_payload(
                authorized,
                verifier_nonce=redemption_nonce,
                roots=roots,
            ),
        )
        for path in pending_paths:
            crossed = copy.deepcopy(authorized)
            target = crossed
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = True
            with self.subTest(pending_path=path), self.assertRaises(
                verifier.VerificationError
            ):
                verifier.finalize_current_head_redemption(
                    crossed,
                    valid_redemption,
                    verifier_nonce=redemption_nonce,
                    trust={
                        "keys": {
                            "currentHeadRedemption": (
                                redemption_private_key.public_key()
                            )
                        },
                        "keyIds": {
                            "currentHeadRedemption": trust_key_record(
                                redemption_private_key
                            )["keyId"]
                        },
                        "trustRootBundleSha256": roots,
                    },
                    now=155,
                )
        first = verifier.finalize_current_head_redemption(
            authorized,
            valid_redemption,
            verifier_nonce=redemption_nonce,
            trust={
                "keys": {
                    "currentHeadRedemption": (
                        redemption_private_key.public_key()
                    )
                },
                "keyIds": {
                    "currentHeadRedemption": trust_key_record(
                        redemption_private_key
                    )["keyId"]
                },
                "trustRootBundleSha256": roots,
            },
            now=155,
        )
        replayed = verifier.finalize_current_head_redemption(
            authorized,
            valid_redemption,
            verifier_nonce=redemption_nonce,
            trust={
                "keys": {
                    "currentHeadRedemption": (
                        redemption_private_key.public_key()
                    )
                },
                "keyIds": {
                    "currentHeadRedemption": trust_key_record(
                        redemption_private_key
                    )["keyId"]
                },
                "trustRootBundleSha256": roots,
            },
            now=155,
        )
        for historical in (first, replayed):
            self.assertEqual(
                historical["status"],
                "redemption-verified-non-actionable",
            )
            self.assertTrue(historical["verificationOk"])
            self.assertTrue(historical["finalCompletionVerified"])
            self.assertIsNone(historical["actionAuthorization"])
            self.assertFalse(historical["okForAction"])
            self.assertNotIn("ok", historical)
            self.assertNotIn("finalCompletion", historical)
            self.assertNotIn("stateCommitRequired", historical)
        with self.assertRaises(verifier.VerificationError):
            verifier.finalize_current_head_redemption(
                authorized,
                valid_redemption,
                verifier_nonce=b"n" * 32,
                trust={
                    "keys": {
                        "currentHeadRedemption": (
                            redemption_private_key.public_key()
                        )
                    },
                    "keyIds": {
                        "currentHeadRedemption": trust_key_record(
                            redemption_private_key
                        )["keyId"]
                    },
                    "trustRootBundleSha256": roots,
                },
                now=155,
            )

    def test_final_completion_witness_leaf_index_handoff_is_exact(
        self,
    ) -> None:
        release_leaf = {
            "releaseGeneration": 7,
            "releaseCoreSha256": verifier.sha256(b"release-core"),
            "rollbackEpoch": 3,
        }
        leaf_sha256 = verifier.sha256(
            b"\x00" + verifier.canonical_json_bytes(release_leaf)
        )
        witness_payload = {
            **release_leaf,
            "inclusion": {
                "leafIndex": 0,
                "leafSha256": leaf_sha256,
                "proof": [],
                "rootHash": leaf_sha256,
                "treeSize": 1,
            },
            "rootHash": leaf_sha256,
            "treeSize": 1,
        }
        pending = {"witness": {"leafIndex": 0}}
        handoff = release_completion.verify_final_v6_witness_handoff(
            pending_public_result=pending,
            witness_payload=witness_payload,
        )
        self.assertEqual(handoff["leafIndex"], 0)
        crossed_pending = copy.deepcopy(pending)
        crossed_pending["witness"]["leafIndex"] = 1
        with self.assertRaises(ValueError):
            release_completion.verify_final_v6_witness_handoff(
                pending_public_result=crossed_pending,
                witness_payload=witness_payload,
            )
        crossed_payload = copy.deepcopy(witness_payload)
        crossed_payload["inclusion"]["leafIndex"] = True
        with self.assertRaises(verifier.VerificationError):
            release_completion.verify_final_v6_witness_handoff(
                pending_public_result=pending,
                witness_payload=crossed_payload,
            )
        boolean_pending = copy.deepcopy(pending)
        boolean_pending["witness"]["leafIndex"] = True
        crossed_payload = copy.deepcopy(witness_payload)
        crossed_payload["inclusion"]["leafIndex"] = 1
        with self.assertRaises(verifier.VerificationError):
            release_completion.verify_final_v6_witness_handoff(
                pending_public_result=boolean_pending,
                witness_payload=crossed_payload,
            )

    def test_wrong_cas_old_state_is_rejected(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        key_id = verifier.sha256(
            public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        roots = verifier.sha256(b"roots")
        pending = pending_state_commit_result()
        payload = cas_payload(pending, roots=roots)
        payload["oldStateSha256"] = verifier.sha256(b"wrong-old")
        receipt = standard_envelope(
            private_key,
            api_version=verifier.STATE_COMMIT_VERSION,
            domain=verifier.STATE_COMMIT_DOMAIN,
            payload=payload,
        )
        with self.assertRaises(verifier.VerificationError):
            verifier.finalize_state_commit(
                {
                    **pending,
                },
                receipt,
                trust={
                    "keys": {"stateCommit": public_key},
                    "keyIds": {"stateCommit": key_id},
                    "trustRootBundleSha256": roots,
                },
                now=150,
            )

    def test_historical_authorization_replay_nonce_is_rejected(self) -> None:
        cas_private_key = Ed25519PrivateKey.generate()
        head_private_key = Ed25519PrivateKey.generate()
        roots = verifier.sha256(b"roots")
        pending = pending_state_commit_result()
        receipt = standard_envelope(
            cas_private_key,
            api_version=verifier.STATE_COMMIT_VERSION,
            domain=verifier.STATE_COMMIT_DOMAIN,
            payload=cas_payload(pending, roots=roots),
        )
        post_cas = verifier.finalize_state_commit(
            pending,
            receipt,
            trust={
                "keys": {"stateCommit": cas_private_key.public_key()},
                "keyIds": {
                    "stateCommit": trust_key_record(cas_private_key)["keyId"]
                },
                "trustRootBundleSha256": roots,
            },
            now=150,
        )
        old_nonce = b"o" * 32
        authorization = standard_envelope(
            head_private_key,
            api_version=verifier.CURRENT_HEAD_AUTHORIZATION_VERSION,
            domain=verifier.CURRENT_HEAD_AUTHORIZATION_DOMAIN,
            payload=current_head_authorization_payload(
                post_cas,
                verifier_nonce=old_nonce,
                roots=roots,
            ),
        )
        with self.assertRaises(verifier.VerificationError):
            verifier.authorize_current_head(
                post_cas,
                authorization,
                verifier_nonce=b"n" * 32,
                trust={
                    "keys": {
                        "currentHeadAuthorization": (
                            head_private_key.public_key()
                        )
                    },
                    "keyIds": {
                        "currentHeadAuthorization": trust_key_record(
                            head_private_key
                        )["keyId"]
                    },
                    "trustRootBundleSha256": roots,
                },
                now=150,
            )

    def test_advanced_store_head_is_rejected(self) -> None:
        cas_private_key = Ed25519PrivateKey.generate()
        head_private_key = Ed25519PrivateKey.generate()
        roots = verifier.sha256(b"roots")
        pending = pending_state_commit_result()
        receipt = standard_envelope(
            cas_private_key,
            api_version=verifier.STATE_COMMIT_VERSION,
            domain=verifier.STATE_COMMIT_DOMAIN,
            payload=cas_payload(pending, roots=roots),
        )
        post_cas = verifier.finalize_state_commit(
            pending,
            receipt,
            trust={
                "keys": {"stateCommit": cas_private_key.public_key()},
                "keyIds": {
                    "stateCommit": trust_key_record(cas_private_key)["keyId"]
                },
                "trustRootBundleSha256": roots,
            },
            now=150,
        )
        nonce = b"v" * 32
        payload = current_head_authorization_payload(
            post_cas,
            verifier_nonce=nonce,
            roots=roots,
        )
        payload["storeGeneration"] += 1
        payload["currentHead"]["generation"] += 1
        payload["currentHeadSha256"] = verifier.sha256_json(
            payload["currentHead"]
        )
        payload["headReservation"]["generation"] += 1
        payload["headReservation"]["headSha256"] = payload[
            "currentHeadSha256"
        ]
        authorization = standard_envelope(
            head_private_key,
            api_version=verifier.CURRENT_HEAD_AUTHORIZATION_VERSION,
            domain=verifier.CURRENT_HEAD_AUTHORIZATION_DOMAIN,
            payload=payload,
        )
        with self.assertRaises(verifier.VerificationError):
            verifier.authorize_current_head(
                post_cas,
                authorization,
                verifier_nonce=nonce,
                trust={
                    "keys": {
                        "currentHeadAuthorization": (
                            head_private_key.public_key()
                        )
                    },
                    "keyIds": {
                        "currentHeadAuthorization": trust_key_record(
                            head_private_key
                        )["keyId"]
                    },
                    "trustRootBundleSha256": roots,
                },
                now=150,
            )

    def test_substituted_current_head_reservation_is_rejected(self) -> None:
        cas_private_key = Ed25519PrivateKey.generate()
        head_private_key = Ed25519PrivateKey.generate()
        roots = verifier.sha256(b"roots")
        pending = pending_state_commit_result()
        receipt = standard_envelope(
            cas_private_key,
            api_version=verifier.STATE_COMMIT_VERSION,
            domain=verifier.STATE_COMMIT_DOMAIN,
            payload=cas_payload(pending, roots=roots),
        )
        post_cas = verifier.finalize_state_commit(
            pending,
            receipt,
            trust={
                "keys": {"stateCommit": cas_private_key.public_key()},
                "keyIds": {
                    "stateCommit": trust_key_record(cas_private_key)["keyId"]
                },
                "trustRootBundleSha256": roots,
            },
            now=150,
        )
        nonce = b"v" * 32
        payload = current_head_authorization_payload(
            post_cas,
            verifier_nonce=nonce,
            roots=roots,
        )
        payload["headReservation"]["completionResultSha256"] = verifier.sha256(
            b"substituted-result"
        )
        authorization = standard_envelope(
            head_private_key,
            api_version=verifier.CURRENT_HEAD_AUTHORIZATION_VERSION,
            domain=verifier.CURRENT_HEAD_AUTHORIZATION_DOMAIN,
            payload=payload,
        )
        with self.assertRaises(verifier.VerificationError):
            verifier.authorize_current_head(
                post_cas,
                authorization,
                verifier_nonce=nonce,
                trust={
                    "keys": {
                        "currentHeadAuthorization": (
                            head_private_key.public_key()
                        )
                    },
                    "keyIds": {
                        "currentHeadAuthorization": trust_key_record(
                            head_private_key
                        )["keyId"]
                    },
                    "trustRootBundleSha256": roots,
                },
                now=150,
            )

    def test_substituted_completion_result_is_rejected(self) -> None:
        cas_private_key = Ed25519PrivateKey.generate()
        head_private_key = Ed25519PrivateKey.generate()
        roots = verifier.sha256(b"roots")
        pending = pending_state_commit_result()
        receipt = standard_envelope(
            cas_private_key,
            api_version=verifier.STATE_COMMIT_VERSION,
            domain=verifier.STATE_COMMIT_DOMAIN,
            payload=cas_payload(pending, roots=roots),
        )
        post_cas = verifier.finalize_state_commit(
            pending,
            receipt,
            trust={
                "keys": {"stateCommit": cas_private_key.public_key()},
                "keyIds": {
                    "stateCommit": trust_key_record(cas_private_key)["keyId"]
                },
                "trustRootBundleSha256": roots,
            },
            now=150,
        )
        nonce = b"v" * 32
        payload = current_head_authorization_payload(
            post_cas,
            verifier_nonce=nonce,
            roots=roots,
        )
        payload["completionResultSha256"] = verifier.sha256(
            b"another-result"
        )
        authorization = standard_envelope(
            head_private_key,
            api_version=verifier.CURRENT_HEAD_AUTHORIZATION_VERSION,
            domain=verifier.CURRENT_HEAD_AUTHORIZATION_DOMAIN,
            payload=payload,
        )
        with self.assertRaises(verifier.VerificationError):
            verifier.authorize_current_head(
                post_cas,
                authorization,
                verifier_nonce=nonce,
                trust={
                    "keys": {
                        "currentHeadAuthorization": (
                            head_private_key.public_key()
                        )
                    },
                    "keyIds": {
                        "currentHeadAuthorization": trust_key_record(
                            head_private_key
                        )["keyId"]
                    },
                    "trustRootBundleSha256": roots,
                },
                now=150,
            )


def nonce_authority_assurance(*, production: bool) -> dict:
    if production:
        return {
            "apiVersion": verifier.NONCE_AUTHORITY_ASSURANCE_VERSION,
            "administrativeDomainSha256":
            verifier.sha256(b"nonce-authority-admin"),
            "assuranceEvidenceSha256":
            verifier.sha256(b"assurance-evidence-placeholder"),
            "assuranceEvidenceType":
            "linearizableCasOperatorAttestation",
            "assuranceLevel": "productionRollbackProtected",
            "authorityEpoch": 4,
            "authorityGeneration": 9,
            "authorityIdentitySha256":
            verifier.sha256(b"nonce-authority-identity"),
            "backendClass":
            "independentlyAdministeredLinearizableCas",
            "productionEligible": True,
            "rollbackProtection": {
                "administrativeRollbackResistance": True,
                "backendAttestationRequired": True,
                "exactSuccessorRequired": True,
                "freshVerifierChallengeRequired": True,
                "keyProtection": "nonExportableKmsHsm",
                "mechanism":
                "linearizableCasWithRollbackProtectedStorage",
                "stateCommitment":
                "hashChainedLinearizableCommitment",
                "verifierStateStoreClass":
                "independentlyAdministeredLinearizableCas",
            },
        }
    return {
        "apiVersion": verifier.NONCE_AUTHORITY_ASSURANCE_VERSION,
        "administrativeDomainSha256":
        verifier.sha256(b"nonproduction-authority-admin"),
        "assuranceEvidenceSha256": None,
        "assuranceEvidenceType": "none",
        "assuranceLevel": "nonProductionDurableReference",
        "authorityEpoch": 4,
        "authorityGeneration": 9,
        "authorityIdentitySha256":
        verifier.sha256(b"nonproduction-authority-identity"),
        "backendClass": "nonProductionSqlite",
        "productionEligible": False,
        "rollbackProtection": {
            "administrativeRollbackResistance": False,
            "backendAttestationRequired": False,
            "exactSuccessorRequired": True,
            "freshVerifierChallengeRequired": True,
            "keyProtection": "retainedFdReference",
            "mechanism": "none",
            "stateCommitment": "localHashChain",
            "verifierStateStoreClass": "nonProductionCallerFile",
        },
    }


class NonceAuthorityVerifierStateServiceFixtures(unittest.TestCase):
    def setUp(self) -> None:
        self.reset_reference_service()

    def reset_reference_service(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store_path = (
            Path(temporary.name) / "verifier-state.sqlite3"
        )
        self.assurance = nonce_authority_assurance(production=False)
        self.assurance_sha256 = verifier.sha256_json(self.assurance)
        self.store_identity_sha256 = verifier.sha256(
            b"independent-verifier-state-store"
        )
        self.store_admin_sha256 = verifier.sha256(
            b"independent-verifier-state-administrator"
        )
        self.signer = (
            verifier_state_service.NonProductionEd25519Signer(
                Ed25519PrivateKey.generate()
            )
        )
        self.nonce_signer = (
            verifier_state_service.NonProductionEd25519Signer(
                Ed25519PrivateKey.generate()
            )
        )
        nonce_key_der = self.nonce_signer.public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.nonce_authority = (
            verifier_state_service.NonceAuthorityReceiptVerifier(
                signing_public_key_spki_der_base64url=b64u(
                    nonce_key_der
                ),
                store_identity_sha256=self.assurance[
                    "authorityIdentitySha256"
                ],
                administrative_domain_sha256=self.assurance[
                    "administrativeDomainSha256"
                ],
                endpoint_identity_sha256=verifier.sha256(
                    b"nonproduction-nonce-authority-endpoint"
                ),
                credential_identity_sha256=verifier.sha256(
                    b"nonproduction-nonce-authority-credential"
                ),
                assurance_evidence_sha256=None,
            )
        )
        self.store = (
            verifier_state_service.NonProductionSqliteStateStore(
                self.store_path,
                store_identity_sha256=self.store_identity_sha256,
                administrative_domain_sha256=self.store_admin_sha256,
            )
        )
        self.service = verifier_state_service.VerifierStateService(
            mode="nonProductionReference",
            assurance=self.assurance,
            assurance_sha256=self.assurance_sha256,
            store=self.store,
            signer=self.signer,
            nonce_authority=self.nonce_authority,
        )
        self.now = int(time.time())
        self.challenge = b""
        self.last_read_response = None

    def read_state(self) -> dict:
        response = self.service.read_state(
            {
                "apiVersion":
                verifier_state_service.READ_REQUEST_VERSION,
                "assuranceSha256": self.assurance_sha256,
            },
            now=self.now,
        )
        self.assertIs(response["nonActionable"], True)
        self.last_read_response = response
        return response["state"]

    def prepare_transition(
        self,
        *,
        operation: bytes = b"o" * 32,
        attach_consumption: bool = True,
    ) -> dict:
        prior_document = self.read_state()
        prior_read = copy.deepcopy(self.last_read_response)
        caller_nonce_sha256 = verifier.sha256(operation)
        request_body_sha256 = verifier.sha256(
            b"fixture-request-body"
        )
        immutable_config_sha256 = verifier.sha256(
            b"fixture-immutable-config"
        )
        release_identity_sha256 = verifier.sha256(
            b"fixture-release-identity"
        )
        recovery_identity = {
            "apiVersion":
            verifier_state_service.RECOVERY_IDENTITY_VERSION,
            "assuranceSha256": self.assurance_sha256,
            "callerNonceSha256": caller_nonce_sha256,
            "immutableConfigSha256": immutable_config_sha256,
            "releaseIdentitySha256": release_identity_sha256,
            "requestBodySha256": request_body_sha256,
        }
        operation_id = self.service._operation_id(
            recovery_identity
        )
        expires_at = self.now + 30
        producer_ephemeral_key = Ed25519PrivateKey.generate()
        producer_ephemeral_spki = (
            producer_ephemeral_key.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        producer_channel_challenge = b64u(b"p" * 32)
        producer_invocation = {
            "apiVersion":
            "serverware.publicAttestationProducerInvocation/v1",
            "callerNonceSha256": caller_nonce_sha256,
            "expiresAtUnix": expires_at,
            "issuedAtUnix": self.now,
            "minimumReleaseIdentitySha256":
            release_identity_sha256,
            "minimumRollbackContinuityCommitmentSha256":
            verifier.sha256(b"fixture-rollback-continuity"),
            "nonceAuthorityVerifierChallengeBase64url":
            b64u(self.challenge),
            "nonceAuthorityVerifierStateOperationIdBase64url":
            operation_id,
            "producerChannelChallengeBase64url":
            producer_channel_challenge,
            "producerEphemeralKeySpkiDerBase64url":
            b64u(producer_ephemeral_spki),
            "producerEphemeralKeySpkiSha256":
            verifier.sha256(producer_ephemeral_spki),
            "releaseIdentitySha256": release_identity_sha256,
            "requestBodySha256": request_body_sha256,
            "staticPins": {
                name: verifier.sha256(
                    f"fixture-static-pin:{name}".encode("ascii")
                )
                for name in (
                    "descriptorSha256",
                    "executableSha256",
                    "immutableConfigSha256",
                    "nonceStoreIdentitySha256",
                    "nonceStoreKeySpkiSha256",
                    "producerRequestSchemaSha256",
                    "sandboxDescriptorSha256",
                    "sandboxLauncherSha256",
                    "trustRootsSha256",
                    "witnessStoreIdentitySha256",
                    "witnessStoreKeySpkiSha256",
                )
            },
            "tlsBindingSha256":
            verifier.sha256(b"fixture-tls-binding"),
            "witnessVerifierChallengeBase64url":
            b64u(b"w" * 32),
        }
        producer_invocation_base = {
            key: value
            for key, value in producer_invocation.items()
            if key
            not in {
                "nonceAuthorityVerifierChallengeBase64url",
                "nonceAuthorityVerifierStateOperationIdBase64url",
            }
        }
        producer_invocation_base_sha256 = verifier.sha256_json(
            producer_invocation_base
        )
        challenge_request = {
            "apiVersion":
            verifier_state_service.ISSUE_CHALLENGE_REQUEST_VERSION,
            "assuranceSha256": self.assurance_sha256,
            "expectedVerifierStateSha256":
            verifier.sha256_json(prior_document),
            "operationIdBase64url": operation_id,
            "producerInvocationBaseSha256":
            producer_invocation_base_sha256,
            "recoveryIdentity": recovery_identity,
            "recoveryIdentitySha256":
            verifier.sha256_json(recovery_identity),
            "recoveryKeySha256":
            self.service._recovery_key(recovery_identity),
        }
        challenge_issue = self.service.issue_challenge(
            challenge_request,
            now=self.now,
        )
        self.challenge = verifier.b64url_decode_exact(
            challenge_issue["challengeBase64url"],
            "fixture verifier challenge",
            exact_bytes=32,
        )
        producer_invocation[
            "nonceAuthorityVerifierChallengeBase64url"
        ] = b64u(self.challenge)
        producer_invocation[
            "nonceAuthorityVerifierStateOperationIdBase64url"
        ] = operation_id
        producer_invocation_sha256 = verifier.sha256_json(
            producer_invocation
        )
        request_binding = {
            "apiVersion":
            verifier_state_service.REQUEST_BINDING_VERSION,
            "expiresAtUnix": expires_at,
            "nonceSha256": caller_nonce_sha256,
            "producerChannelChallengeBase64url":
            producer_channel_challenge,
            "producerEphemeralKeySha256":
            producer_invocation["producerEphemeralKeySpkiSha256"],
            "producerInvocationSha256":
            producer_invocation_sha256,
            "requestBodySha256": request_body_sha256,
            "tlsBindingSha256":
            producer_invocation["tlsBindingSha256"],
            "transactionIdBase64url": operation_id,
        }
        request_binding_sha256 = verifier.sha256(
            verifier_state_service.REQUEST_BINDING_DOMAIN
            + verifier.canonical_json_bytes(request_binding)
        )
        recovery_key_sha256 = self.service._recovery_key(
            recovery_identity
        )
        prepare_request = {
            "apiVersion":
            verifier_state_service.PREPARE_REQUEST_VERSION,
            "assuranceSha256": self.assurance_sha256,
            "challengeIssue": challenge_issue,
            "challengeIssueSha256":
            verifier.sha256_json(challenge_issue),
            "expectedVerifierStateSha256":
            verifier.sha256_json(prior_document),
            "operationIdBase64url": operation_id,
            "priorStateRead": prior_read,
            "priorStateReadSha256":
            verifier.sha256_json(prior_read),
            "producerInvocation": producer_invocation,
            "producerInvocationBaseSha256":
            producer_invocation_base_sha256,
            "producerInvocationSha256":
            producer_invocation_sha256,
            "recoveryIdentity": recovery_identity,
            "recoveryIdentitySha256":
            verifier.sha256_json(recovery_identity),
            "recoveryKeySha256": recovery_key_sha256,
            "requestBinding": request_binding,
            "requestBindingSha256": request_binding_sha256,
            "verifierChallengeBase64url": b64u(self.challenge),
        }
        prepare_response = self.service.prepare(
            prepare_request,
            now=self.now,
        )
        prepared_operation = prepare_response[
            "preparedOperation"
        ]
        authorization = prepared_operation["authorization"]
        prior_payload = prior_document["payload"]
        consumed_at = self.now
        nonce_consumption = {
            "apiVersion":
            verifier_state_service.NONCE_CONSUMPTION_VERSION,
            "consumedAtUnix": consumed_at,
            "nonceSha256": caller_nonce_sha256,
            "oneUse": True,
            "requestBodySha256": request_body_sha256,
            "sequence": prior_payload["highWaterSequence"] + 1,
            "storeIdentitySha256":
            self.assurance["authorityIdentitySha256"],
            "tlsBindingSha256":
            producer_invocation["tlsBindingSha256"],
        }
        preimage = {
            "apiVersion":
            verifier.NONCE_AUTHORITY_HIGH_WATER_INPUT_VERSION,
            "assuranceSha256": self.assurance_sha256,
            "authorityEpoch": self.assurance["authorityEpoch"],
            "authorityGeneration":
            self.assurance["authorityGeneration"],
            "nonceConsumptionSha256":
            verifier.sha256_json(nonce_consumption),
            "nonceVerifierStateAuthorizationSha256":
            verifier.sha256_json(authorization),
            "previousHighWaterCommitmentSha256":
            prior_payload["highWaterCommitmentSha256"],
            "previousReceiptSha256":
            prior_payload["highWaterReceiptSha256"],
            "sequence": prior_payload["highWaterSequence"] + 1,
            "transactionIdBase64url": operation_id,
        }
        nonce_state = {
            "apiVersion": verifier.NONCE_AUTHORITY_STATE_VERSION,
            "assuranceSha256": self.assurance_sha256,
            "authorityEpoch": self.assurance["authorityEpoch"],
            "authorityGeneration":
            self.assurance["authorityGeneration"],
            "highWaterCommitmentSha256":
            verifier_state_service.high_water_commitment(preimage),
            "highWaterSequence": preimage["sequence"],
            "previousHighWaterCommitmentSha256":
            prior_payload["highWaterCommitmentSha256"],
        }
        consume_request = prepared_operation[
            "nonceConsumeRequest"
        ]
        nonce_receipt_payload = {
            "apiVersion":
            verifier_state_service.NONCE_RECEIPT_PAYLOAD_VERSION,
            "consumeRequestSha256":
            verifier.sha256(
                verifier_state_service.NONCE_CONSUME_REQUEST_DIGEST_DOMAIN
                + verifier.canonical_json_bytes(consume_request)
            ),
            "consumedAtUnix": consumed_at,
            "expiresAtUnix": expires_at,
            "finalExternalVerifierChallengeConsumed": False,
            "finalExternalVerifierChallengeConsumptionRequired": True,
            "nonceAuthorityAssuranceSha256":
            self.assurance_sha256,
            "nonceAuthorityState": nonce_state,
            "nonceAuthorityStateSha256":
            verifier.sha256_json(nonce_state),
            "nonceAuthorityVerifierStateAuthorizationSha256":
            verifier.sha256_json(authorization),
            "nonceConsumption": nonce_consumption,
            "nonceConsumptionSha256":
            verifier.sha256_json(nonce_consumption),
            "nonceSha256": nonce_consumption["nonceSha256"],
            "previousReceiptSha256":
            prior_payload["highWaterReceiptSha256"],
            "producerChannelChallengeBase64url":
            producer_channel_challenge,
            "producerEphemeralKeySha256":
            producer_invocation["producerEphemeralKeySpkiSha256"],
            "producerInvocationSha256":
            producer_invocation_sha256,
            "receiptIssuedAtUnix": consumed_at,
            "requestBodySha256":
            nonce_consumption["requestBodySha256"],
            "sequence": nonce_consumption["sequence"],
            "signerChannelBindingSha256":
            verifier.sha256(b"fixture-signer-channel"),
            "storeIdentitySha256":
            self.assurance["authorityIdentitySha256"],
            "tlsBindingSha256":
            nonce_consumption["tlsBindingSha256"],
            "transactionIdBase64url":
            preimage["transactionIdBase64url"],
        }
        nonce_receipt = verifier_state_service.sign_envelope(
            self.nonce_signer,
            api_version=(
                verifier_state_service.SIGNED_NONCE_RECEIPT_VERSION
            ),
            domain=verifier_state_service.NONCE_RECEIPT_DOMAIN,
            payload=nonce_receipt_payload,
        )
        status_evidence_payload = {
            "apiVersion":
            verifier_state_service.NONCE_STATUS_EVIDENCE_VERSION,
            "consumeRequestSha256":
            prepared_operation["nonceConsumeRequestSha256"],
            "evidenceIssuedAtUnix": consumed_at,
            "neverConsumable": False,
            "nonceAuthorityVerifierStateAuthorizationSha256":
            prepared_operation["authorizationSha256"],
            "nonceConsumptionReceiptSha256":
            verifier.sha256_json(nonce_receipt),
            "nonceSha256": nonce_consumption["nonceSha256"],
            "preparedOperationSha256":
            verifier.sha256_json(prepared_operation),
            "recoveryKeySha256": recovery_key_sha256,
            "requestBindingSha256": request_binding_sha256,
            "requestOperation": "recoverExact",
            "status": "consumed",
            "transactionIdBase64url": operation_id,
        }
        status_evidence = verifier_state_service.sign_envelope(
            self.nonce_signer,
            api_version=(
                verifier_state_service
                .SIGNED_NONCE_STATUS_EVIDENCE_VERSION
            ),
            domain=verifier_state_service.NONCE_STATUS_EVIDENCE_DOMAIN,
            payload=status_evidence_payload,
        )
        if attach_consumption:
            self.service.mark_consumption(
                {
                    "apiVersion":
                    verifier_state_service
                    .MARK_CONSUMPTION_REQUEST_VERSION,
                    "preparedOperationSha256":
                    verifier.sha256_json(prepared_operation),
                    "recoveryKeySha256": recovery_key_sha256,
                    "requestBindingSha256": request_binding_sha256,
                },
                now=self.now,
            )
            self.service.attach_nonce_status(
                {
                    "apiVersion":
                    verifier_state_service
                    .ATTACH_NONCE_STATUS_REQUEST_VERSION,
                    "nonceConsumptionReceipt": nonce_receipt,
                    "nonceStatusEvidence": status_evidence,
                    "preparedOperationSha256":
                    verifier.sha256_json(prepared_operation),
                    "recoveryKeySha256": recovery_key_sha256,
                    "requestBindingSha256": request_binding_sha256,
                },
                now=self.now,
            )
        request = {
            "apiVersion":
            verifier_state_service.COMMIT_REQUEST_VERSION,
            "authorization": authorization,
            "nonceConsumptionReceipt": nonce_receipt,
            "preparedOperationSha256":
            verifier.sha256_json(prepared_operation),
            "recoveryKeySha256": recovery_key_sha256,
            "requestBindingSha256": request_binding_sha256,
            "verifierChallengeBase64url": b64u(self.challenge),
        }
        verified_prior = (
            verifier.verify_nonce_authority_verifier_state(
                prior_document,
                signing_key=self.signer.public_key,
                signing_key_id=self.signer.key_id,
                expected_state_store_identity_sha256=(
                    self.store_identity_sha256
                ),
                assurance=self.assurance,
                assurance_sha256=self.assurance_sha256,
            )
        )
        verified_authorization = (
            verifier.verify_nonce_authority_state_authorization(
                authorization,
                signing_key=self.signer.public_key,
                signing_key_id=self.signer.key_id,
                expected_state_store_identity_sha256=(
                    self.store_identity_sha256
                ),
                expected_state_store_attestation_key_id=(
                    self.store.attestation_key_id
                ),
                expected_state_store_assurance_evidence_sha256=None,
                expected_state_store_configuration_sha256=(
                    self.store.configuration_sha256
                ),
                expected_nonce_receipt_signing_key_id=(
                    self.nonce_authority.key_id
                ),
                assurance=self.assurance,
                assurance_sha256=self.assurance_sha256,
                prior_verifier_state=verified_prior,
                verifier_challenge=self.challenge,
                now=self.now,
            )
        )
        return {
            "authorization": authorization,
            "challenge": self.challenge,
            "challengeIssue": challenge_issue,
            "challengeRequest": challenge_request,
            "nonceConsumption": nonce_consumption,
            "nonceReceipt": nonce_receipt,
            "nonceState": nonce_state,
            "preimage": preimage,
            "prepareRequest": prepare_request,
            "prepareResponse": prepare_response,
            "preparedOperation": prepared_operation,
            "recoveryIdentity": recovery_identity,
            "recoveryKeySha256": recovery_key_sha256,
            "request": request,
            "requestBindingSha256": request_binding_sha256,
            "statusEvidence": status_evidence,
            "verifiedAuthorization": verified_authorization,
            "verifiedPrior": verified_prior,
        }

    def test_lost_issue_challenge_reply_recovers_exact_restart_state(
        self,
    ) -> None:
        transition = self.prepare_transition(
            attach_consumption=False
        )
        restarted_store = (
            verifier_state_service.NonProductionSqliteStateStore(
                self.store_path,
                store_identity_sha256=self.store_identity_sha256,
                administrative_domain_sha256=self.store_admin_sha256,
            )
        )
        restarted = verifier_state_service.VerifierStateService(
            mode="nonProductionReference",
            assurance=self.assurance,
            assurance_sha256=self.assurance_sha256,
            store=restarted_store,
            signer=self.signer,
            nonce_authority=self.nonce_authority,
        )
        challenge_request = transition["challengeRequest"]
        recovered = restarted.recover_challenge(
            {
                "apiVersion":
                verifier_state_service
                .RECOVER_CHALLENGE_REQUEST_VERSION,
                "assuranceSha256": self.assurance_sha256,
                "issueRequestSha256":
                verifier.sha256_json(challenge_request),
                "operationIdBase64url":
                challenge_request["operationIdBase64url"],
                "recoveryIdentity":
                challenge_request["recoveryIdentity"],
                "recoveryIdentitySha256":
                challenge_request["recoveryIdentitySha256"],
                "recoveryKeySha256":
                challenge_request["recoveryKeySha256"],
            },
            now=self.now,
        )
        self.assertEqual(recovered["status"], "bound")
        for field in (
            "challengeBase64url",
            "challengeSha256",
            "expectedVerifierStateSha256",
            "issueRequestSha256",
            "operationIdBase64url",
            "producerInvocationBaseSha256",
            "recoveryKeySha256",
        ):
            self.assertEqual(
                recovered["challenge"][field],
                transition["challengeIssue"][field],
            )
        crossed = copy.deepcopy(challenge_request)
        crossed["recoveryKeySha256"] = verifier.sha256(
            b"crossed-recovery-key"
        )
        with self.assertRaises(verifier_state_service.ContractError):
            restarted.issue_challenge(crossed, now=self.now)

    def test_transaction_alias_yields_exactly_five_identities(
        self,
    ) -> None:
        caller_nonce = b"o" * 32
        transition = self.prepare_transition(
            operation=caller_nonce,
            attach_consumption=False,
        )
        invocation = transition["prepareRequest"][
            "producerInvocation"
        ]
        operation_id = verifier.b64url_decode_exact(
            invocation[
                "nonceAuthorityVerifierStateOperationIdBase64url"
            ],
            "fixture verifier operation",
            exact_bytes=32,
        )
        transaction_id = verifier.b64url_decode_exact(
            transition["nonceReceipt"]["payload"][
                "transactionIdBase64url"
            ],
            "fixture nonce transaction",
            exact_bytes=32,
        )
        identities = {
            caller_nonce,
            verifier.b64url_decode_exact(
                invocation[
                    "nonceAuthorityVerifierChallengeBase64url"
                ],
                "fixture verifier challenge",
                exact_bytes=32,
            ),
            operation_id,
            verifier.b64url_decode_exact(
                invocation["producerChannelChallengeBase64url"],
                "fixture producer challenge",
                exact_bytes=32,
            ),
            verifier.b64url_decode_exact(
                invocation["witnessVerifierChallengeBase64url"],
                "fixture witness challenge",
                exact_bytes=32,
            ),
        }
        self.assertEqual(transaction_id, operation_id)
        self.assertEqual(len(identities), 5)

    def verify_receipt(
        self,
        receipt: object,
        transition: dict,
    ) -> dict:
        return verifier.verify_nonce_authority_state_commit_receipt(
            receipt,
            signing_key=self.signer.public_key,
            signing_key_id=self.signer.key_id,
            expected_state_store_identity_sha256=(
                self.store_identity_sha256
            ),
            expected_state_store_administrative_domain_sha256=(
                self.store_admin_sha256
            ),
            expected_state_store_assurance_evidence_sha256=None,
            expected_state_store_configuration_sha256=(
                self.store.configuration_sha256
            ),
            minimum_state_store_generation=(
                self.store.minimum_generation
            ),
            minimum_state_store_commit_index=(
                self.store.minimum_commit_index
            ),
            expected_production_eligible=False,
            state_store_attestation_key=(
                self.store.attestation_public_key
            ),
            state_store_attestation_key_id=(
                self.store.attestation_key_id
            ),
            assurance=self.assurance,
            assurance_sha256=self.assurance_sha256,
            prior_verifier_state=transition["verifiedPrior"]["document"],
            authorization=transition["authorization"],
            commit_request=transition["request"],
            nonce_consumption_receipt=transition["nonceReceipt"],
            nonce_receipt_signing_key=(
                self.nonce_authority.public_key
            ),
            nonce_receipt_signing_key_id=(
                self.nonce_authority.key_id
            ),
            verifier_challenge=transition["challenge"],
            now=self.now + 1,
        )

    def resign_authorization(
        self,
        transition: dict,
        field: str,
        value: object,
    ) -> None:
        payload = copy.deepcopy(
            transition["request"]["authorization"]["payload"]
        )
        payload[field] = value
        authorization = verifier_state_service.sign_envelope(
            self.signer,
            api_version=verifier_state_service.AUTHORIZATION_VERSION,
            domain=verifier_state_service.AUTHORIZATION_DOMAIN,
            payload=payload,
        )
        transition["request"]["authorization"] = authorization
        preimage = transition["preimage"]
        preimage["nonceVerifierStateAuthorizationSha256"] = (
            verifier.sha256_json(authorization)
        )
        transition["nonceState"]["highWaterCommitmentSha256"] = (
            verifier_state_service.high_water_commitment(preimage)
        )
        receipt_payload = copy.deepcopy(
            transition["nonceReceipt"]["payload"]
        )
        receipt_payload[
            "nonceAuthorityVerifierStateAuthorizationSha256"
        ] = verifier.sha256_json(authorization)
        receipt_payload["nonceAuthorityState"] = transition["nonceState"]
        receipt_payload["nonceAuthorityStateSha256"] = (
            verifier.sha256_json(transition["nonceState"])
        )
        nonce_receipt = verifier_state_service.sign_envelope(
            self.nonce_signer,
            api_version=(
                verifier_state_service.SIGNED_NONCE_RECEIPT_VERSION
            ),
            domain=verifier_state_service.NONCE_RECEIPT_DOMAIN,
            payload=receipt_payload,
        )
        transition["nonceReceipt"] = nonce_receipt
        transition["request"]["nonceConsumptionReceipt"] = nonce_receipt

    def resign_nonce_receipt(
        self,
        transition: dict,
        payload: dict,
    ) -> None:
        nonce_receipt = verifier_state_service.sign_envelope(
            self.nonce_signer,
            api_version=(
                verifier_state_service.SIGNED_NONCE_RECEIPT_VERSION
            ),
            domain=verifier_state_service.NONCE_RECEIPT_DOMAIN,
            payload=payload,
        )
        transition["nonceReceipt"] = nonce_receipt
        transition["request"]["nonceConsumptionReceipt"] = nonce_receipt

    def resign_commit_receipt(self, receipt: dict) -> dict:
        return verifier_state_service.sign_envelope(
            self.signer,
            api_version=verifier_state_service.COMMIT_RECEIPT_VERSION,
            domain=verifier_state_service.COMMIT_RECEIPT_DOMAIN,
            payload=copy.deepcopy(receipt["payload"]),
        )

    def recover_transition(self, transition: dict) -> dict:
        return self.service.recover(
            {
                "apiVersion":
                verifier_state_service.RECOVERY_REQUEST_VERSION,
                "recoveryIdentity": transition["recoveryIdentity"],
                "recoveryIdentitySha256": verifier.sha256_json(
                    transition["recoveryIdentity"]
                ),
                "recoveryKeySha256":
                transition["recoveryKeySha256"],
            },
            now=self.now + 1,
        )

    def complete_public_transition_fixture(self) -> dict:
        prepared = self.prepare_transition()
        prior_read = copy.deepcopy(self.last_read_response)
        receipt = self.service.commit(
            prepared["request"],
            now=self.now + 1,
        )
        verified_receipt = self.verify_receipt(receipt, prepared)
        final_read = self.service.read_state(
            {
                "apiVersion":
                verifier_state_service.READ_REQUEST_VERSION,
                "assuranceSha256": self.assurance_sha256,
            },
            now=self.now + 2,
        )
        service_config = {
            "apiVersion":
            verifier.PUBLIC_ATTESTATION_VERIFIER_STATE_CLIENT_VERSION,
            "abortPath": "/v1/state/abort",
            "attachNonceStatusPath":
            "/v1/state/attach-nonce-status",
            "clientCertificateSpkiSha256":
            verifier.sha256(b"fixture-client-certificate"),
            "commitPath": "/v1/state/commit",
            "concurrencyLimit": 1,
            "endpoint": "https://192.0.2.10:8443",
            "issueChallengePath": "/v1/state/issue-challenge",
            "markConsumptionPath":
            "/v1/state/mark-consumption",
            "maxResponseBytes": 256 * 1024,
            "preparePath": "/v1/state/prepare",
            "readPath": "/v1/state/read",
            "recoverPath": "/v1/state/recover",
            "recoverChallengePath":
            "/v1/state/recover-challenge",
            "recoveryLookupPath":
            "/v1/state/recovery-lookup",
            "serverLeafSpkiSha256":
            verifier.sha256(b"fixture-server-leaf"),
            "serviceConfigurationSha256":
            verifier.sha256(b"fixture-service-configuration"),
            "timeoutMilliseconds": 1_000,
        }
        document = {
            "apiVersion":
            verifier.NONCE_AUTHORITY_VERIFIER_STATE_TRANSITION_VERSION,
            "assurance": self.assurance,
            "assuranceEvidence": None,
            "assuranceEvidenceSha256": None,
            "assuranceSha256": self.assurance_sha256,
            "authorization": prepared["authorization"],
            "authorizationSha256":
            prepared["verifiedAuthorization"]["envelopeSha256"],
            "commitRequest": prepared["request"],
            "commitRequestSha256":
            verifier.sha256_json(prepared["request"]),
            "commitReceipt": receipt,
            "commitReceiptSha256":
            verified_receipt["envelopeSha256"],
            "committedState": final_read["state"],
            "committedStateRead": final_read,
            "committedStateReadSha256":
            verifier.sha256_json(final_read),
            "committedStateSha256":
            verifier.sha256_json(final_read["state"]),
            "nonActionable": True,
            "nonceAuthorityState":
            verified_receipt["nonceAuthorityState"],
            "nonceAuthorityStateSha256":
            verified_receipt["nonceAuthorityStateSha256"],
            "nonceConsumptionReceipt": prepared["nonceReceipt"],
            "nonceConsumptionReceiptSha256":
            verified_receipt["nonceConsumptionReceiptSha256"],
            "nonceConsumptionSha256":
            verified_receipt["nonceConsumptionSha256"],
            "operationIdBase64url":
            prepared["verifiedAuthorization"]["payload"][
                "operationIdBase64url"
            ],
            "preparedOperation": prepared["preparedOperation"],
            "preparedOperationSha256":
            verifier.sha256_json(prepared["preparedOperation"]),
            "priorState": prepared["verifiedPrior"]["document"],
            "priorStateRead": prior_read,
            "priorStateReadSha256":
            verifier.sha256_json(prior_read),
            "priorStateSha256":
            prepared["verifiedPrior"]["envelopeSha256"],
            "recoveryIdentity": prepared["recoveryIdentity"],
            "recoveryIdentitySha256":
            verifier.sha256_json(prepared["recoveryIdentity"]),
            "recoveryKeySha256":
            prepared["recoveryKeySha256"],
            "requestBindingSha256":
            prepared["requestBindingSha256"],
            "roleSeparationEvidence": None,
            "roleSeparationEvidenceSha256": None,
            "serviceBinding": {
                "apiVersion":
                verifier.PUBLIC_ATTESTATION_VERIFIER_STATE_CLIENT_VERSION,
                "clientCertificateSpkiSha256":
                service_config["clientCertificateSpkiSha256"],
                "endpoint": service_config["endpoint"],
                "serverLeafSpkiSha256":
                service_config["serverLeafSpkiSha256"],
                "serviceConfigurationSha256":
                service_config["serviceConfigurationSha256"],
                "signingKeySpkiSha256": self.signer.key_id,
                "roleSeparationEvidenceSha256": None,
                "stateStoreAdministrativeDomainSha256":
                self.store_admin_sha256,
                "stateStoreAssuranceEvidenceSha256": None,
                "stateStoreAttestationKeySpkiSha256":
                self.store.attestation_key_id,
                "stateStoreConfigurationSha256":
                self.store.configuration_sha256,
                "stateStoreIdentitySha256":
                self.store_identity_sha256,
                "stateStoreMinimumCommitIndex":
                self.store.minimum_commit_index,
                "stateStoreMinimumGeneration":
                self.store.minimum_generation,
            },
            "signedStoreCommitProof":
            verified_receipt["storeCommitProof"],
            "signedStoreCommitProofSha256":
            verified_receipt["storeCommitProofSha256"],
            "storeAssuranceEvidence": None,
            "storeAssuranceEvidenceSha256": None,
            "transactionIdBase64url":
            prepared["nonceReceipt"]["payload"][
                "transactionIdBase64url"
            ],
            "verifierChallengeBase64url":
            b64u(prepared["challenge"]),
            "verifierChallengeSha256":
            verifier.sha256(prepared["challenge"]),
        }
        return {
            "document": document,
            "prepared": prepared,
            "serviceConfig": service_config,
            "verifiedReceipt": verified_receipt,
        }

    def verify_public_transition_fixture(
        self,
        fixture: dict,
        document: object,
    ) -> dict:
        prepared = fixture["prepared"]
        return (
            verifier
            .verify_public_attestation_verifier_state_transition(
                document,
                assurance=self.assurance,
                assurance_evidence=None,
                assurance_evidence_sha256=None,
                authorization=prepared["verifiedAuthorization"],
                commit_request=prepared["request"],
                commit_receipt=fixture["verifiedReceipt"],
                nonce_consumption_receipt=prepared["nonceReceipt"],
                prior_state=prepared["verifiedPrior"],
                verifier_state_service=fixture["serviceConfig"],
                verifier_state_key=self.signer.public_key,
                verifier_state_key_id=self.signer.key_id,
                state_store_identity_sha256=(
                    self.store_identity_sha256
                ),
                state_store_administrative_domain_sha256=(
                    self.store_admin_sha256
                ),
                state_store_assurance_evidence_sha256=None,
                state_store_assurance_evidence=None,
                role_separation_evidence=None,
                role_separation_evidence_sha256=None,
                state_store_configuration_sha256=(
                    self.store.configuration_sha256
                ),
                state_store_minimum_commit_index=(
                    self.store.minimum_commit_index
                ),
                state_store_minimum_generation=(
                    self.store.minimum_generation
                ),
                state_store_attestation_key_id=(
                    self.store.attestation_key_id
                ),
                verifier_challenge=prepared["challenge"],
                now=self.now + 2,
            )
        )

    def test_final_commit_and_recovery_versions_reject_old_aliases(
        self,
    ) -> None:
        finalized = (
            "serverware.attestationVerifierStateCommitRequest/v3"
        )
        obsolete = (
            "serverware.nonceAuthorityVerifierStateCommitRequest/v2"
        )
        self.assertEqual(
            verifier_state_service.COMMIT_REQUEST_VERSION,
            finalized,
        )
        self.assertEqual(
            verifier.VERIFIER_STATE_COMMIT_REQUEST_VERSION,
            finalized,
        )
        transition = self.prepare_transition()
        old_commit = copy.deepcopy(transition["request"])
        old_commit["apiVersion"] = obsolete
        with self.assertRaises(verifier_state_service.ContractError):
            self.service.commit(old_commit, now=self.now + 1)
        exact_recovery = {
            "apiVersion":
            verifier_state_service.RECOVERY_REQUEST_VERSION,
            "recoveryIdentity": transition["recoveryIdentity"],
            "recoveryIdentitySha256": verifier.sha256_json(
                transition["recoveryIdentity"]
            ),
            "recoveryKeySha256":
            transition["recoveryKeySha256"],
        }
        recovered = self.service.recover(
            exact_recovery,
            now=self.now + 1,
        )
        self.assertEqual(recovered["status"], "committed")
        self.assertEqual(
            recovered["preparedOperation"],
            transition["preparedOperation"],
        )
        self.assertEqual(
            verifier_state_service.RECOVERY_REQUEST_VERSION,
            "serverware.attestationVerifierStateRecoveryRequest/v3",
        )
        self.assertEqual(
            verifier_state_service.RECOVERY_RESPONSE_VERSION,
            "serverware.attestationVerifierStateRecoveryResponse/v3",
        )
        for obsolete_recovery_version in (
            "serverware.attestationVerifierStateRecoveryRequest/v1",
            "serverware.nonceAuthorityVerifierStateRecoveryRequest/v1",
            "serverware.nonceAuthorityVerifierStateRecoveryRequest/v2",
        ):
            hostile = {
                "apiVersion": obsolete_recovery_version,
                "recoveryIdentity": transition["recoveryIdentity"],
                "recoveryIdentitySha256": verifier.sha256_json(
                    transition["recoveryIdentity"]
                ),
                "recoveryKeySha256":
                transition["recoveryKeySha256"],
            }
            with self.subTest(
                api_version=obsolete_recovery_version
            ), self.assertRaises(verifier_state_service.ContractError):
                self.service.recover(hostile, now=self.now + 1)

    def test_complete_public_transition_rejects_contract_drift(
        self,
    ) -> None:
        fixture = self.complete_public_transition_fixture()
        verified = self.verify_public_transition_fixture(
            fixture,
            fixture["document"],
        )
        self.assertEqual(
            verified["document"],
            fixture["document"],
        )
        omitted = copy.deepcopy(fixture["document"])
        omitted.pop("nonceConsumptionReceipt")
        substituted = copy.deepcopy(fixture["document"])
        substituted["commitRequestSha256"] = verifier.sha256(
            b"substituted-commit-request"
        )
        obsolete_summary = {
            "apiVersion":
            "serverware.nonceAuthorityVerifierStateTransition/v1",
            "nonceConsumptionReceiptSha256":
            fixture["document"]["nonceConsumptionReceiptSha256"],
            "nonceConsumptionSha256":
            fixture["document"]["nonceConsumptionSha256"],
            "priorStateSha256":
            fixture["document"]["priorStateSha256"],
        }
        for label, hostile in (
            ("omitted", omitted),
            ("substituted", substituted),
            ("obsolete-summary", obsolete_summary),
        ):
            with self.subTest(label=label), self.assertRaises(
                verifier.VerificationError
            ):
                self.verify_public_transition_fixture(
                    fixture,
                    hostile,
                )

    def test_producer_request_reconstruction_carries_full_transition(
        self,
    ) -> None:
        transition = {"complete": {"signed": "transition"}}
        tls_binding = {
            "bindingSha256": verifier.sha256(b"fixture-tls")
        }
        request, _raw = (
            verifier.reconstruct_public_attestation_producer_request(
                caller_nonce=b"n" * 32,
                request_body=b"{}",
                tls_binding=tls_binding,
                release_identity_sha256=verifier.sha256(
                    b"fixture-release"
                ),
                static_pins={},
                nonce_consumption={},
                nonce_consumption_receipt={},
                nonce_authority_verifier_state_transition=transition,
                producer_invocation={},
                producer_invocation_sha256=verifier.sha256(
                    b"fixture-invocation"
                ),
                issued_at_unix=self.now,
                expires_at_unix=self.now + 30,
            )
        )
        self.assertIs(
            request["liveSessionRequest"][
                "nonceAuthorityVerifierStateTransition"
            ],
            transition,
        )

    def test_exact_valid_flow_has_preimage_parity_and_is_nonactionable(
        self,
    ) -> None:
        transition = self.prepare_transition()
        preimage = transition["preimage"]
        self.assertEqual(
            verifier_state_service.high_water_commitment(preimage),
            verifier.nonce_authority_high_water_commitment(
                assurance_sha256=preimage["assuranceSha256"],
                authority_epoch=preimage["authorityEpoch"],
                authority_generation=preimage["authorityGeneration"],
                nonce_consumption_sha256=preimage[
                    "nonceConsumptionSha256"
                ],
                nonce_verifier_state_authorization_sha256=preimage[
                    "nonceVerifierStateAuthorizationSha256"
                ],
                previous_high_water_commitment_sha256=preimage[
                    "previousHighWaterCommitmentSha256"
                ],
                previous_receipt_sha256=preimage[
                    "previousReceiptSha256"
                ],
                sequence=preimage["sequence"],
                transaction_id_base64url=preimage[
                    "transactionIdBase64url"
                ],
            ),
        )
        receipt = self.service.commit(
            transition["request"],
            now=self.now + 1,
        )
        committed = self.verify_receipt(receipt, transition)
        self.assertEqual(
            committed["commitRequestSha256"],
            verifier.sha256_json(transition["request"]),
        )
        self.assertEqual(
            receipt["payload"]["nonceConsumptionSha256"],
            verifier.sha256_json(transition["nonceConsumption"]),
        )
        self.assertEqual(
            receipt["payload"]["nonceConsumptionReceiptSha256"],
            verifier.sha256_json(transition["nonceReceipt"]),
        )
        self.assertEqual(
            receipt["payload"]["committedAtUnix"],
            receipt["payload"]["signedStoreCommitProof"]["payload"][
                "committedAtUnix"
            ],
        )
        self.assertEqual(
            receipt["payload"]["signedStoreCommitProofSha256"],
            verifier.sha256_json(
                receipt["payload"]["signedStoreCommitProof"]
            ),
        )
        current = verifier.verify_nonce_authority_verifier_state(
            self.read_state(),
            signing_key=self.signer.public_key,
            signing_key_id=self.signer.key_id,
            expected_state_store_identity_sha256=(
                self.store_identity_sha256
            ),
            assurance=self.assurance,
            assurance_sha256=self.assurance_sha256,
        )
        self.assertEqual(
            current["payload"],
            committed["committedState"],
        )
        recovery = self.recover_transition(transition)
        self.assertEqual(recovery["commitReceipt"], receipt)
        self.assertEqual(recovery["status"], "committed")
        self.assertIs(recovery["nonActionable"], True)
        self.assertEqual(
            recovery["commitRequestSha256"],
            verifier.sha256_json(transition["request"]),
        )
        self.assertIs(recovery["replacementForbidden"], True)
        self.assertIs(recovery["sameOperationOnly"], True)
        self.assertNotIn("actionAuthorization", recovery)

    def test_sqlite_production_rejection_is_unconditional(self) -> None:
        production = nonce_authority_assurance(production=True)
        with self.assertRaises(verifier_state_service.ContractError):
            verifier_state_service.VerifierStateService(
                mode="production",
                assurance=production,
                assurance_sha256=verifier.sha256_json(production),
                store=self.store,
                signer=self.signer,
                nonce_authority=self.nonce_authority,
                initialize_reference_genesis=False,
            )

    def test_release_generator_requires_independent_complete_pins(
        self,
    ) -> None:
        parser = launch_manifest_generator.build_parser()
        required_actions = {
            action.dest: action.required
            for action in parser._actions
        }
        self.assertIs(
            required_actions["nonce_rollback_assurance_pins"],
            True,
        )
        self.assertIs(
            required_actions[
                "expected_nonce_rollback_assurance_pins_sha256"
            ],
            True,
        )
        self.assertIs(
            required_actions["pipeline_metadata_out"],
            True,
        )
        loader_source = inspect.getsource(
            launch_manifest_generator.load_nonce_rollback_assurance_pins
        )
        for required_pin in (
            "expectedNonceAuthorityAssuranceIssuerSpkiSha256",
            "expectedNonceAuthorityAssuranceSha256",
            "nonceAuthorityAssurance",
            "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url",
            "nonceAuthorityAssuranceSha256",
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url",
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256",
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256",
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url",
            "nonceAuthorityVerifierStateStoreIdentitySha256",
            "authorityEpoch",
            "authorityGeneration",
            "backendClass",
            "mechanism",
        ):
            self.assertIn(required_pin, loader_source)
        self.assertIn("before.st_uid != 0", loader_source)
        self.assertIn("before.st_nlink != 1", loader_source)
        self.assertIn(
            "expected_file_sha256",
            loader_source,
        )

    def test_service_schema_closes_production_cas_contract(self) -> None:
        schema_path = (
            Path(__file__).resolve().parent.parent
            / "schemas"
            / "attestation-verifier-state-service.v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        schema_validator = Draft202012Validator(schema)
        transition = self.prepare_transition()
        receipt = self.service.commit(
            transition["request"],
            now=self.now + 1,
        )
        recovery_request = {
            "apiVersion":
            verifier_state_service.RECOVERY_REQUEST_VERSION,
            "recoveryIdentity": transition["recoveryIdentity"],
            "recoveryIdentitySha256": verifier.sha256_json(
                transition["recoveryIdentity"]
            ),
            "recoveryKeySha256":
            transition["recoveryKeySha256"],
        }
        recovery = self.service.recover(
            recovery_request,
            now=self.now + 2,
        )
        read_request = {
            "apiVersion": verifier_state_service.READ_REQUEST_VERSION,
            "assuranceSha256": self.assurance_sha256,
        }
        nonce_signing_key_der = (
            self.nonce_authority.public_key.public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        service_configuration = {
            "apiVersion":
            "serverware.attestationVerifierStateServiceConfiguration/v3",
            "assurance": self.assurance,
            "assuranceSha256": self.assurance_sha256,
            "authorizationLifetimeSeconds": 12,
            "listen": {
                "expectedHostAuthority": "127.0.0.1:9443",
                "host": "127.0.0.1",
                "port": 9443,
            },
            "listenerTls": None,
            "maxConcurrentRequests": 4,
            "mode": "nonProductionReference",
            "nonceAuthority": {
                "administrativeDomainSha256":
                self.nonce_authority.administrative_domain_sha256,
                "assuranceEvidenceSha256": None,
                "assuranceEvidenceSigningPublicKeySpkiDerBase64url":
                None,
                "credentialIdentitySha256":
                self.nonce_authority.credential_identity_sha256,
                "endpointIdentitySha256":
                self.nonce_authority.endpoint_identity_sha256,
                "signingPublicKeySpkiDerBase64url":
                b64u(nonce_signing_key_der),
                "storeIdentitySha256":
                self.nonce_authority.store_identity_sha256,
            },
            "nonceAuthorityAssuranceEvidenceIssuer": None,
            "roleSeparationEvidence": None,
            "roleSeparationEvidenceIssuer": None,
            "roleSeparationEvidenceSigningPublicKeySpkiDerBase64url":
            None,
            "signer": {
                "kind": "nonProductionFileEd25519",
                "privateKeyFile": "/tmp/verifier-state-key",
            },
            "stateStore": {
                "administrativeDomainSha256":
                self.store.administrative_domain_sha256,
                "kind": "nonProductionSqlite",
                "path": "/tmp/verifier-state.sqlite3",
                "storeIdentitySha256":
                self.store.store_identity_sha256,
            },
        }
        valid_wire_documents = {
            "service-configuration": service_configuration,
            "read-request": read_request,
            "read-response": self.last_read_response,
            "prepare-request": transition["prepareRequest"],
            "recovery-request": recovery_request,
        }
        for label, document in valid_wire_documents.items():
            with self.subTest(valid=label):
                schema_validator.validate(document)

        hostile_documents = {
            "obsolete-commit-version":
            {
                **copy.deepcopy(transition["request"]),
                "apiVersion":
                "serverware.nonceAuthorityVerifierStateCommitRequest/v2",
            },
            "obsolete-recovery-version":
            {
                **copy.deepcopy(recovery_request),
                "apiVersion":
                "serverware.attestationVerifierStateRecoveryRequest/v1",
            },
            "commit-omission":
            {
                key: value
                for key, value in transition["request"].items()
                if key != "nonceConsumptionReceipt"
            },
            "recovery-operation-shape":
            {
                **copy.deepcopy(recovery),
                "operationIdBase64url": "invalid",
            },
            "production-proof-without-assurance":
            copy.deepcopy(
                receipt["payload"]["signedStoreCommitProof"]["payload"]
            ),
            "reference-proof-with-production-assurance":
            copy.deepcopy(
                receipt["payload"]["signedStoreCommitProof"]["payload"]
            ),
            "receipt-unknown-field":
            {
                **copy.deepcopy(receipt),
                "unexpected": False,
            },
            "service-config-path":
            copy.deepcopy(service_configuration),
        }
        hostile_documents["service-config-path"]["signer"][
            "privateKeyFile"
        ] = "/tmp/../substituted-key"
        hostile_documents["production-proof-without-assurance"][
            "productionEligible"
        ] = True
        hostile_documents["reference-proof-with-production-assurance"][
            "stateStoreAssuranceEvidenceSha256"
        ] = verifier.sha256(b"substituted-production-assurance")
        for label, document in hostile_documents.items():
            with self.subTest(invalid=label), self.assertRaises(
                ValidationError
            ):
                schema_validator.validate(document)
        semantic_substitution = {
            **copy.deepcopy(recovery_request),
            "recoveryIdentity": {
                **copy.deepcopy(
                    recovery_request["recoveryIdentity"]
                ),
                "requestBodySha256":
                verifier.sha256(b"substituted-request"),
            },
        }
        schema_validator.validate(semantic_substitution)
        with self.assertRaises(verifier_state_service.ContractError):
            self.service.recover(
                semantic_substitution,
                now=self.now + 2,
            )

    def test_lost_prepare_response_recovers_exact_prepared_operation(
        self,
    ) -> None:
        first = self.prepare_transition(operation=b"a" * 32)
        self.assertEqual(
            self.service.prepare(
                first["prepareRequest"],
                now=self.now,
            ),
            first["prepareResponse"],
        )
        lookup = self.service.lookup_recovery(
            {
                "apiVersion":
                verifier_state_service
                .RECOVERY_LOOKUP_REQUEST_VERSION,
                "recoveryIdentity": first["recoveryIdentity"],
                "recoveryIdentitySha256": verifier.sha256_json(
                    first["recoveryIdentity"]
                ),
                "recoveryKeySha256":
                first["recoveryKeySha256"],
            },
            now=self.now,
        )
        self.assertEqual(
            lookup["preparedOperation"],
            first["preparedOperation"],
        )
        substituted_prepare_request = copy.deepcopy(
            first["prepareRequest"]
        )
        substituted_prepare_request[
            "expectedVerifierStateSha256"
        ] = verifier.sha256(b"substituted-authorization-predecessor")
        with self.assertRaises(verifier_state_service.ContractError):
            self.service.prepare(
                substituted_prepare_request,
                now=self.now,
            )
        with self.assertRaises(verifier_state_service.ConflictError):
            self.prepare_transition(operation=b"b" * 32)
        receipt = self.service.commit(
            first["request"],
            now=self.now + 1,
        )
        self.assertEqual(
            self.service.commit(first["request"], now=self.now + 2),
            receipt,
        )
        self.assertEqual(
            self.read_state()["payload"]["highWaterSequence"],
            1,
        )
        reused = copy.deepcopy(first["request"])
        reused["nonceConsumptionReceipt"]["payload"][
            "nonceSha256"
        ] = verifier.sha256(b"different-receipt")
        with self.assertRaises(verifier_state_service.ContractError):
            self.service.commit(reused, now=self.now + 2)

    def test_restart_recovers_exact_prepared_nonce_transaction(
        self,
    ) -> None:
        transition = self.prepare_transition(
            operation=b"r" * 32,
            attach_consumption=False,
        )
        restarted_store = (
            verifier_state_service.NonProductionSqliteStateStore(
                self.store_path,
                store_identity_sha256=self.store_identity_sha256,
                administrative_domain_sha256=self.store_admin_sha256,
            )
        )
        restarted = verifier_state_service.VerifierStateService(
            mode="nonProductionReference",
            assurance=self.assurance,
            assurance_sha256=self.assurance_sha256,
            store=restarted_store,
            signer=self.signer,
            nonce_authority=self.nonce_authority,
            initialize_reference_genesis=False,
        )
        recovery_request = {
            "apiVersion":
            verifier_state_service.RECOVERY_REQUEST_VERSION,
            "recoveryIdentity": transition["recoveryIdentity"],
            "recoveryIdentitySha256": verifier.sha256_json(
                transition["recoveryIdentity"]
            ),
            "recoveryKeySha256":
            transition["recoveryKeySha256"],
        }
        pending = restarted.recover(
            recovery_request,
            now=self.now + 1,
        )
        self.assertEqual(pending["status"], "prepared")
        self.assertIs(pending["nonceRecoveryRequired"], True)
        self.assertEqual(
            pending["preparedOperation"],
            transition["preparedOperation"],
        )
        restarted.mark_consumption(
            {
                "apiVersion":
                verifier_state_service
                .MARK_CONSUMPTION_REQUEST_VERSION,
                "preparedOperationSha256":
                verifier.sha256_json(
                    transition["preparedOperation"]
                ),
                "recoveryKeySha256":
                transition["recoveryKeySha256"],
                "requestBindingSha256":
                transition["requestBindingSha256"],
            },
            now=self.now + 1,
        )
        restarted.attach_nonce_status(
            {
                "apiVersion":
                verifier_state_service
                .ATTACH_NONCE_STATUS_REQUEST_VERSION,
                "nonceConsumptionReceipt":
                transition["nonceReceipt"],
                "nonceStatusEvidence":
                transition["statusEvidence"],
                "preparedOperationSha256":
                verifier.sha256_json(
                    transition["preparedOperation"]
                ),
                "recoveryKeySha256":
                transition["recoveryKeySha256"],
                "requestBindingSha256":
                transition["requestBindingSha256"],
            },
            now=self.now + 1,
        )
        completed = restarted.recover(
            recovery_request,
            now=self.now + 2,
        )
        self.assertEqual(completed["status"], "committed")
        self.assertIs(completed["nonceRecoveryRequired"], False)
        self.assertEqual(
            completed["operationIdBase64url"],
            transition["preparedOperation"]["authorization"][
                "payload"
            ]["operationIdBase64url"],
        )

    def test_exact_authenticated_abort_requires_nonce_tombstone(
        self,
    ) -> None:
        transition = self.prepare_transition(
            operation=b"x" * 32,
            attach_consumption=False,
        )
        prepared = transition["preparedOperation"]
        status_payload = {
            **copy.deepcopy(
                transition["statusEvidence"]["payload"]
            ),
            "neverConsumable": True,
            "nonceConsumptionReceiptSha256": None,
            "requestOperation": "proveNeverConsumedAndBlock",
            "status": "neverConsumed",
        }
        status_evidence = verifier_state_service.sign_envelope(
            self.nonce_signer,
            api_version=(
                verifier_state_service
                .SIGNED_NONCE_STATUS_EVIDENCE_VERSION
            ),
            domain=verifier_state_service.NONCE_STATUS_EVIDENCE_DOMAIN,
            payload=status_payload,
        )
        abort_request = {
            "apiVersion":
            verifier_state_service.ABORT_REQUEST_VERSION,
            "nonceStatusEvidence": status_evidence,
            "preparedOperationSha256":
            verifier.sha256_json(prepared),
            "recoveryKeySha256":
            transition["recoveryKeySha256"],
            "requestBindingSha256":
            transition["requestBindingSha256"],
        }
        first = self.service.abort(
            abort_request,
            now=self.now,
        )
        self.assertEqual(
            self.service.abort(abort_request, now=self.now),
            first,
        )
        self.assertEqual(first["status"], "aborted")
        self.assertIs(first["replacementForbidden"], False)
        hostile_substitutions = {
            "consumeRequestSha256":
            verifier.sha256(b"crossed-consume-request"),
            "nonceAuthorityVerifierStateAuthorizationSha256":
            verifier.sha256(b"crossed-authorization"),
            "nonceSha256": verifier.sha256(b"crossed-nonce"),
            "preparedOperationSha256":
            verifier.sha256(b"crossed-prepared-operation"),
            "recoveryKeySha256":
            verifier.sha256(b"crossed-recovery-key"),
            "requestBindingSha256":
            verifier.sha256(b"crossed-request-binding"),
            "transactionIdBase64url": b64u(b"z" * 32),
        }
        for field, replacement in hostile_substitutions.items():
            crossed_payload = copy.deepcopy(status_payload)
            crossed_payload[field] = replacement
            crossed = {
                **abort_request,
                "nonceStatusEvidence":
                verifier_state_service.sign_envelope(
                    self.nonce_signer,
                    api_version=(
                        verifier_state_service
                        .SIGNED_NONCE_STATUS_EVIDENCE_VERSION
                    ),
                    domain=(
                        verifier_state_service
                        .NONCE_STATUS_EVIDENCE_DOMAIN
                    ),
                    payload=crossed_payload,
                ),
            }
            with self.subTest(field=field), self.assertRaises(
                verifier_state_service.ContractError
            ):
                self.service.abort(crossed, now=self.now)
        replacement = self.prepare_transition(
            operation=b"y" * 32,
            attach_consumption=False,
        )
        self.assertNotEqual(
            replacement["recoveryKeySha256"],
            transition["recoveryKeySha256"],
        )

    def test_concurrent_prepare_redrive_cannot_replace_exact_successor(
        self,
    ) -> None:
        prepared = self.prepare_transition(operation=b"a" * 32)
        exact_request = prepared["prepareRequest"]
        crossed_request = copy.deepcopy(exact_request)
        crossed_request["recoveryIdentity"][
            "callerNonceSha256"
        ] = verifier.sha256(b"crossed-caller")
        requests = [exact_request, crossed_request]
        start = threading.Barrier(3)
        accepted: list[tuple[dict, dict]] = []
        rejected: list[Exception] = []

        def prepare(request: dict) -> None:
            start.wait()
            try:
                accepted.append(
                    (
                        request,
                        self.service.prepare(
                            request,
                            now=self.now,
                        ),
                    )
                )
            except Exception as exc:
                rejected.append(exc)

        threads = [
            threading.Thread(target=prepare, args=(request,))
            for request in requests
        ]
        for thread in threads:
            thread.start()
        start.wait()
        for thread in threads:
            thread.join()
        self.assertEqual(len(accepted), 1)
        self.assertEqual(len(rejected), 1)
        self.assertIsInstance(
            rejected[0],
            verifier_state_service.ContractError,
        )
        winning_request, retained_prepare = accepted[0]
        self.assertEqual(
            self.service.prepare(
                winning_request,
                now=self.now,
            ),
            retained_prepare,
        )
        losing_request = next(
            request
            for request in requests
            if request != winning_request
        )
        with self.assertRaises(verifier_state_service.ContractError):
            self.service.prepare(losing_request, now=self.now)

    def test_stale_challenge_expiry_and_authentication_reuse(self) -> None:
        transition = self.prepare_transition()
        recovered_receipt = self.service.commit(
            transition["request"],
            now=self.now + 31,
        )
        self.assertTrue(recovered_receipt["payload"]["casCommitted"])
        self.reset_reference_service()
        transition = self.prepare_transition()
        crossed = copy.deepcopy(transition["request"])
        crossed["verifierChallengeBase64url"] = b64u(b"x" * 32)
        with self.assertRaises(verifier_state_service.ContractError):
            self.service.commit(crossed, now=self.now + 1)
        self.reset_reference_service()
        crossed_transition = self.prepare_transition(
            operation=b"e" * 32
        )
        self.resign_authorization(
            crossed_transition,
            "expiresAtUnix",
            self.now + 300
        )
        with self.assertRaises(verifier_state_service.ContractError):
            self.service.commit(
                crossed_transition["request"],
                now=self.now + 1,
            )

    def test_complete_signed_nonce_receipt_mutations_fail_closed(
        self,
    ) -> None:
        for mutation in ("envelope", "payload", "signature"):
            self.reset_reference_service()
            transition = self.prepare_transition()
            request = copy.deepcopy(transition["request"])
            receipt = request["nonceConsumptionReceipt"]
            if mutation == "envelope":
                receipt["unexpected"] = False
            elif mutation == "payload":
                receipt["payload"]["requestBodySha256"] = verifier.sha256(
                    b"mutated-request-body"
                )
            else:
                receipt["signatureBase64url"] = b64u(b"\x00" * 64)
            with self.subTest(mutation=mutation), self.assertRaises(
                verifier_state_service.ContractError
            ):
                self.service.commit(request, now=self.now + 1)

    def test_challenge_replay_across_operations_and_heads_fails(
        self,
    ) -> None:
        transition = self.prepare_transition(operation=b"c" * 32)
        replay = copy.deepcopy(transition["prepareRequest"])
        replay["recoveryIdentity"]["callerNonceSha256"] = (
            verifier.sha256(b"different-caller")
        )
        with self.assertRaises(verifier_state_service.ContractError):
            self.service.prepare(replay, now=self.now)
        self.service.commit(
            transition["request"],
            now=self.now + 1,
        )
        current = self.read_state()
        replay["expectedVerifierStateSha256"] = verifier.sha256_json(current)
        with self.assertRaises(verifier_state_service.ContractError):
            self.service.prepare(replay, now=self.now + 1)

    def test_consumed_transaction_completes_after_authorization_expiry(
        self,
    ) -> None:
        transition = self.prepare_transition()
        expires = transition["authorization"]["payload"]["expiresAtUnix"]
        with mock.patch.object(
            verifier_state_service.time,
            "time",
            return_value=expires,
        ):
            receipt = self.service.commit(
                transition["request"],
                now=expires,
            )
        self.assertTrue(receipt["payload"]["casCommitted"])
        self.assertGreaterEqual(
            receipt["payload"]["committedAtUnix"],
            transition["nonceReceipt"]["payload"]["consumedAtUnix"],
        )

    def test_wrong_predecessor_sequence_commitment_epoch_generation(
        self,
    ) -> None:
        mutations = (
            ("previousHighWaterCommitmentSha256",
             verifier.sha256(b"wrong-predecessor")),
            ("highWaterSequence", 3),
            ("highWaterCommitmentSha256",
             verifier.sha256(b"wrong-commitment")),
            ("authorityEpoch", 5),
            ("authorityGeneration", 10),
        )
        for field, value in mutations:
            self.reset_reference_service()
            transition = self.prepare_transition()
            transition["nonceState"][field] = value
            payload = copy.deepcopy(
                transition["nonceReceipt"]["payload"]
            )
            payload["nonceAuthorityState"] = transition["nonceState"]
            payload["nonceAuthorityStateSha256"] = (
                verifier.sha256_json(transition["nonceState"])
            )
            self.resign_nonce_receipt(transition, payload)
            with self.subTest(field=field), self.assertRaises(
                verifier_state_service.ContractError
            ):
                self.service.commit(
                    transition["request"],
                    now=self.now + 1,
                )

    def test_wrong_operation_prior_and_store_generation(self) -> None:
        mutations = (
            ("operationIdBase64url", b64u(b"z" * 32)),
            ("priorVerifierStateSha256",
             verifier.sha256(b"wrong-prior")),
            ("stateStoreGeneration", 2),
        )
        for field, value in mutations:
            self.reset_reference_service()
            transition = self.prepare_transition()
            self.resign_authorization(
                transition,
                field,
                value,
            )
            with self.subTest(field=field), self.assertRaises(
                verifier_state_service.ContractError
            ):
                self.service.commit(
                    transition["request"],
                    now=self.now + 1,
                )

    def test_missing_and_malformed_cas_never_verify(self) -> None:
        transition = self.prepare_transition()
        receipt = self.service.commit(
            transition["request"],
            now=self.now + 1,
        )
        cases = {
            "missing": None,
            "unknown": {**copy.deepcopy(receipt), "unknown": True},
            "cas-false": copy.deepcopy(receipt),
            "consumed-false": copy.deepcopy(receipt),
            "generation": copy.deepcopy(receipt),
            "operation": copy.deepcopy(receipt),
        }
        cases["cas-false"]["payload"]["casCommitted"] = False
        cases["consumed-false"]["payload"][
            "oneUseAuthorizationConsumed"
        ] = False
        cases["generation"]["payload"]["committedVerifierState"][
            "stateStoreGeneration"
        ] += 1
        cases["operation"]["payload"][
            "commitOperationIdBase64url"
        ] = b64u(b"q" * 32)
        for name in (
            "cas-false",
            "consumed-false",
            "generation",
            "operation",
        ):
            cases[name] = self.resign_commit_receipt(cases[name])
        for name, malformed in cases.items():
            with self.subTest(name=name), self.assertRaises(
                verifier.VerificationError
            ):
                self.verify_receipt(malformed, transition)

    def test_store_commit_proof_substitution_never_verifies(self) -> None:
        transition = self.prepare_transition()
        receipt = self.service.commit(
            transition["request"],
            now=self.now + 1,
        )
        for mutation in ("signature", "identity", "digest"):
            crossed = copy.deepcopy(receipt)
            proof = crossed["payload"]["signedStoreCommitProof"]
            if mutation == "signature":
                proof["signatureBase64url"] = b64u(b"\x00" * 64)
            elif mutation == "identity":
                proof["payload"][
                    "stateStoreIdentitySha256"
                ] = verifier.sha256(b"substituted-store")
            else:
                crossed["payload"][
                    "signedStoreCommitProofSha256"
                ] = verifier.sha256(b"substituted-proof")
            crossed = self.resign_commit_receipt(crossed)
            with self.subTest(mutation=mutation), self.assertRaises(
                verifier.VerificationError
            ):
                self.verify_receipt(crossed, transition)

    def test_crash_after_cas_uses_idempotent_recovery(self) -> None:
        transition = self.prepare_transition()
        self.store.raise_unknown_after_commit_once = True
        receipt = self.service.commit(
            transition["request"],
            now=self.now + 1,
        )
        self.verify_receipt(receipt, transition)
        after = self.read_state()
        self.assertEqual(
            self.service.commit(
                transition["request"],
                now=self.now + 2,
            ),
            receipt,
        )
        self.assertEqual(self.read_state(), after)
        self.assertEqual(after["payload"]["highWaterSequence"], 1)

    def test_generic_exception_after_ambiguous_cas_recovers_same_operation(
        self,
    ) -> None:
        transition = self.prepare_transition()
        original_commit_candidate = self.store.commit_candidate

        def commit_then_fail(**values: object) -> dict:
            original_commit_candidate(**values)
            raise RuntimeError("fixture transport failed after CAS")

        self.store.commit_candidate = commit_then_fail
        try:
            receipt = self.service.commit(
                transition["request"],
                now=self.now + 1,
            )
        finally:
            self.store.commit_candidate = original_commit_candidate
        self.verify_receipt(receipt, transition)
        self.assertEqual(
            self.recover_transition(transition)["commitReceipt"],
            receipt,
        )

    def test_signing_starts_only_after_durable_candidate_proof(
        self,
    ) -> None:
        transition = self.prepare_transition()
        events = []
        original_commit_candidate = self.store.commit_candidate
        original_sign = self.signer.sign

        def recorded_commit_candidate(**values: object) -> dict:
            events.append("candidateCommitted")
            return original_commit_candidate(**values)

        def recorded_sign(value: bytes) -> bytes:
            events.append("signed")
            return original_sign(value)

        self.store.commit_candidate = recorded_commit_candidate
        self.signer.sign = recorded_sign
        try:
            receipt = self.service.commit(
                transition["request"],
                now=self.now + 1,
            )
        finally:
            self.store.commit_candidate = original_commit_candidate
            self.signer.sign = original_sign
        self.verify_receipt(receipt, transition)
        self.assertEqual(
            events,
            ["candidateCommitted", "signed", "signed"],
        )

    def test_malformed_first_post_cas_signature_requires_recovery(
        self,
    ) -> None:
        transition = self.prepare_transition()
        original_sign = self.signer.sign
        self.signer.sign = lambda _value: b"malformed"
        try:
            with self.assertRaises(
                verifier_state_service.UnknownOutcomeError
            ):
                self.service.commit(
                    transition["request"],
                    now=self.now + 1,
                )
        finally:
            self.signer.sign = original_sign
        recovery = self.recover_transition(transition)
        self.assertEqual(recovery["status"], "committed")
        self.verify_receipt(recovery["commitReceipt"], transition)

    def test_failure_between_post_cas_signatures_requires_recovery(
        self,
    ) -> None:
        transition = self.prepare_transition()
        original_sign = self.signer.sign
        calls = 0

        def fail_second(value: bytes) -> bytes:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise verifier_state_service.ContractError(
                    "fixture signer failed between signatures"
                )
            return original_sign(value)

        self.signer.sign = fail_second
        try:
            with self.assertRaises(
                verifier_state_service.UnknownOutcomeError
            ):
                self.service.commit(
                    transition["request"],
                    now=self.now + 1,
                )
        finally:
            self.signer.sign = original_sign
        recovery = self.recover_transition(transition)
        self.assertEqual(recovery["status"], "committed")
        self.verify_receipt(recovery["commitReceipt"], transition)

    def test_post_cas_recovery_transport_and_output_fail_unknown(
        self,
    ) -> None:
        for failure in ("transport", "malformed"):
            with self.subTest(failure=failure):
                self.reset_reference_service()
                transition = self.prepare_transition(
                    operation=(
                        b"r" * 32
                        if failure == "transport"
                        else b"s" * 32
                    )
                )
                self.store.raise_unknown_after_commit_once = True
                original_recover = self.store.recover
                calls = 0

                def fail_second_recovery(
                    **values: object,
                ) -> dict:
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        if failure == "transport":
                            raise OSError("fixture recovery transport")
                        return {"status": "casCommitted"}
                    return original_recover(**values)

                self.store.recover = fail_second_recovery
                try:
                    with self.assertRaises(
                        verifier_state_service.UnknownOutcomeError
                    ):
                        self.service.commit(
                            transition["request"],
                            now=self.now + 1,
                        )
                finally:
                    self.store.recover = original_recover
                recovery = self.recover_transition(transition)
                self.assertEqual(recovery["status"], "committed")
                self.verify_receipt(
                    recovery["commitReceipt"],
                    transition,
                )

    def test_crash_after_finalization_recovers_retained_artifacts(
        self,
    ) -> None:
        transition = self.prepare_transition()
        self.store.raise_unknown_after_finalize_once = True
        receipt = self.service.commit(
            transition["request"],
            now=self.now + 1,
        )
        self.verify_receipt(receipt, transition)
        self.assertEqual(
            self.service.commit(
                transition["request"],
                now=self.now + 2,
            ),
            receipt,
        )

    def test_unknown_fields_and_noncanonical_json_fail_closed(
        self,
    ) -> None:
        with self.assertRaises(verifier_state_service.ContractError):
            self.service.read_state(
                {
                    "apiVersion":
                    verifier_state_service.READ_REQUEST_VERSION,
                    "assuranceSha256": self.assurance_sha256,
                    "verifierChallengeSha256":
                    verifier.sha256(self.challenge),
                    "unknown": False,
                },
                now=self.now,
            )
        cases = (
            b'{"apiVersion":"fixture","value":1}\n',
            b'{"apiVersion":"fixture","value":1.0}',
            b'{"apiVersion":"fixture","apiVersion":"fixture","value":1}',
            b'{ "apiVersion":"fixture","value":1}',
            '{"apiVersion":"fixture","value":"e\u0301"}'.encode(
                "utf-8"
            ),
        )
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(
                verifier_state_service.ContractError
            ):
                verifier_state_service.parse_canonical_json(
                    raw,
                    label="hostile fixture",
                )

    def test_unsigned_u64_boundary_and_all_additions_are_bounded(
        self,
    ) -> None:
        boundary = {"value": verifier.MAX_U64}
        self.assertEqual(
            verifier_state_service.canonical_json(boundary),
            verifier.canonical_json_bytes(boundary),
        )
        with self.assertRaises(verifier_state_service.ContractError):
            verifier_state_service.canonical_json(
                {"value": verifier.MAX_U64 + 1}
            )
        for value in (True, verifier.MAX_U64):
            with self.subTest(value=value), self.assertRaises(
                verifier_state_service.ContractError
            ):
                verifier_state_service.checked_add_uint(
                    value,
                    1,
                    "boundary fixture",
                )
        transition = self.prepare_transition()
        with self.assertRaises(verifier_state_service.ContractError):
            self.service._validated_nonce_successor(
                transition["nonceReceipt"],
                authorization_payload={
                    **transition["authorization"]["payload"],
                    "highWaterSequence": verifier.MAX_U64,
                },
                authorization_sha256=verifier.sha256_json(
                    transition["authorization"]
                ),
                now=self.now,
            )
        terminal_commitment = (
            nonce_service.nonce_authority_high_water_commitment(
                assurance_sha256=self.assurance_sha256,
                authority_epoch=self.assurance["authorityEpoch"],
                authority_generation=(
                    self.assurance["authorityGeneration"]
                ),
                nonce_consumption_sha256=verifier.sha256(
                    b"terminal-consumption"
                ),
                nonce_verifier_state_authorization_sha256=(
                    verifier.sha256(b"terminal-authorization")
                ),
                previous_high_water_commitment_sha256=(
                    verifier.sha256(b"terminal-predecessor")
                ),
                previous_receipt_sha256=verifier.sha256(
                    b"terminal-receipt"
                ),
                sequence=nonce_service.U64_MAX,
                transaction_id_base64url=b64u(b"m" * 32),
            )
        )
        self.assertEqual(
            terminal_commitment,
            verifier_state_service.high_water_commitment(
                {
                    "apiVersion":
                    verifier.NONCE_AUTHORITY_HIGH_WATER_INPUT_VERSION,
                    "assuranceSha256": self.assurance_sha256,
                    "authorityEpoch": self.assurance["authorityEpoch"],
                    "authorityGeneration":
                    self.assurance["authorityGeneration"],
                    "nonceConsumptionSha256":
                    verifier.sha256(b"terminal-consumption"),
                    "nonceVerifierStateAuthorizationSha256":
                    verifier.sha256(b"terminal-authorization"),
                    "previousHighWaterCommitmentSha256":
                    verifier.sha256(b"terminal-predecessor"),
                    "previousReceiptSha256":
                    verifier.sha256(b"terminal-receipt"),
                    "sequence": nonce_service.U64_MAX,
                    "transactionIdBase64url": b64u(b"m" * 32),
                }
            ),
        )
        terminal_source = inspect.getsource(
            nonce_service.DurableNonceStore._commit_consumption
        )
        self.assertIn("terminal_sequence = sequence == U64_MAX", terminal_source)
        self.assertIn("sequenceExhausted", terminal_source)
        self.assertIn("capacityExceeded", terminal_source)

    def test_runtime_clock_rollback_fails_closed(self) -> None:
        with mock.patch.object(
            verifier_state_service.time,
            "time",
            return_value=self.now + 1,
        ):
            self.assertEqual(
                self.service.observe_runtime_time(),
                self.now + 1,
            )
        with mock.patch.object(
            verifier_state_service.time,
            "time",
            return_value=self.now,
        ), self.assertRaises(verifier_state_service.ContractError):
            self.service.observe_runtime_time()

    def test_role_collisions_and_config_only_capability_fail_closed(
        self,
    ) -> None:
        for field in (
            "administrative_domain_sha256",
            "endpoint_identity_sha256",
            "credential_identity_sha256",
        ):
            collision = copy.copy(self.nonce_authority)
            setattr(collision, field, getattr(self.signer, field))
            with self.subTest(field=field), self.assertRaises(
                verifier_state_service.ContractError
            ):
                verifier_state_service.VerifierStateService(
                    mode="nonProductionReference",
                    assurance=self.assurance,
                    assurance_sha256=self.assurance_sha256,
                    store=self.store,
                    signer=self.signer,
                    nonce_authority=collision,
                    initialize_reference_genesis=False,
                )
        signer_key_der = self.signer.public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        key_collision = (
            verifier_state_service.NonceAuthorityReceiptVerifier(
                signing_public_key_spki_der_base64url=b64u(
                    signer_key_der
                ),
                store_identity_sha256=self.assurance[
                    "authorityIdentitySha256"
                ],
                administrative_domain_sha256=self.assurance[
                    "administrativeDomainSha256"
                ],
                endpoint_identity_sha256=verifier.sha256(
                    b"nonce-key-collision-endpoint"
                ),
                credential_identity_sha256=verifier.sha256(
                    b"nonce-key-collision-credential"
                ),
                assurance_evidence_sha256=None,
            )
        )
        with self.assertRaises(verifier_state_service.ContractError):
            verifier_state_service.VerifierStateService(
                mode="nonProductionReference",
                assurance=self.assurance,
                assurance_sha256=self.assurance_sha256,
                store=self.store,
                signer=self.signer,
                nonce_authority=key_collision,
                initialize_reference_genesis=False,
            )
        service_source = inspect.getsource(
            verifier_state_service.VerifierStateService.__init__
        )
        self.assertLess(
            service_source.index("validate_role_separation_evidence("),
            service_source.index("self.production_capable = True"),
        )
        self.assertFalse(
            verifier_state_service.ExternalEd25519Signer.production_capable
        )
        self.assertFalse(
            verifier_state_service.ExternalLinearizableStateStore
            .production_capable
        )

    def test_consumption_and_transaction_preimage_substitution_fails(
        self,
    ) -> None:
        cases = (
            ("consumeRequestSha256",
             verifier.sha256(b"substituted-consume-request")),
            ("nonceConsumptionSha256",
             verifier.sha256(b"substituted-consumption")),
            ("transactionIdBase64url", b64u(b"s" * 32)),
        )
        for field, value in cases:
            self.reset_reference_service()
            transition = self.prepare_transition()
            payload = copy.deepcopy(
                transition["nonceReceipt"]["payload"]
            )
            payload[field] = value
            self.resign_nonce_receipt(transition, payload)
            with self.subTest(field=field), self.assertRaises(
                verifier_state_service.ContractError
            ):
                self.service.commit(
                    transition["request"],
                    now=self.now + 1,
                )

    def test_listener_rejects_wrong_client_spki_and_spiffe_identity(
        self,
    ) -> None:
        client_key = Ed25519PrivateKey.generate()
        subject = x509.Name(
            [
                x509.NameAttribute(
                    NameOID.COMMON_NAME,
                    "serverware-verifier-fixture",
                )
            ]
        )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(client_key.public_key())
            .serial_number(1)
            .not_valid_before(
                datetime.now(timezone.utc) - timedelta(minutes=1)
            )
            .not_valid_after(
                datetime.now(timezone.utc) + timedelta(minutes=5)
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.UniformResourceIdentifier(
                            "spiffe://serverware/verifier"
                        )
                    ]
                ),
                critical=False,
            )
            .sign(client_key, algorithm=None)
        )
        certificate_der = certificate.public_bytes(
            serialization.Encoding.DER
        )
        client_spki_der = client_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        verifier_state_service.ListenerPeerPolicy(
            expected_spki_sha256=verifier.sha256(client_spki_der),
            expected_spiffe_uri="spiffe://serverware/verifier",
        ).validate_certificate_der(certificate_der)
        hostile = (
            {
                "expected_spki_sha256":
                verifier.sha256(b"wrong-client-spki"),
                "expected_spiffe_uri":
                "spiffe://serverware/verifier",
            },
            {
                "expected_spki_sha256":
                verifier.sha256(client_spki_der),
                "expected_spiffe_uri":
                "spiffe://serverware/other",
            },
        )
        for policy in hostile:
            with self.subTest(policy=policy), self.assertRaises(
                verifier_state_service.ContractError
            ):
                verifier_state_service.ListenerPeerPolicy(
                    **policy
                ).validate_certificate_der(certificate_der)

    def canonical_https_behavior(
        self,
        *,
        chunks: list[bytes],
        trailing: bytes = b"",
        status: int = 200,
        response_error: Exception | None = None,
        outcome_may_be_unknown: bool = False,
        monotonic_values: list[float] | None = None,
    ) -> dict:
        response_document = {
            "apiVersion": "fixture.externalResponse/v1",
            "operation": "fixture",
            "requestSha256": verifier.sha256(b"fixture-request"),
            "result": {},
        }
        response_body = (
            verifier_state_service.canonical_json(
                response_document
            ).encode("ascii")
        )
        headers = mock.Mock()
        header_values = {
            "Content-Length": [str(len(response_body))],
            "Content-Type": ["application/json"],
            "Connection": ["close"],
            "Transfer-Encoding": None,
            "Trailer": None,
            "Content-Encoding": None,
        }
        headers.get_all.side_effect = header_values.get
        headers.items.return_value = [
            ("Content-Length", str(len(response_body))),
            ("Content-Type", "application/json"),
            ("Connection", "close"),
        ]

        class ScriptedTlsSocket:
            def __init__(self) -> None:
                self.timeouts: list[float] = []

            def getpeercert(self, *, binary_form: bool) -> bytes:
                if binary_form is not True:
                    raise AssertionError("binary certificate required")
                return b"fixture-certificate"

            def settimeout(self, value: float) -> None:
                self.timeouts.append(value)

            def recv(self, size: int) -> bytes:
                if size != 1:
                    raise AssertionError("EOF probe must read one byte")
                return trailing

        scripted_socket = ScriptedTlsSocket()

        class ScriptedResponse:
            version = 11

            def __init__(self) -> None:
                self.status = status
                self.headers = headers
                self._chunks = list(chunks)

            def read1(self, maximum: int) -> bytes:
                if not self._chunks:
                    return b""
                chunk = self._chunks.pop(0)
                if len(chunk) > maximum:
                    raise AssertionError(
                        "scripted response exceeded requested read"
                    )
                return chunk

        scripted_response = ScriptedResponse()

        class ScriptedConnection:
            def __init__(self) -> None:
                self.sock = scripted_socket
                self.timeout = None
                self.closed = False

            def close(self) -> None:
                self.closed = True

            def connect(self) -> None:
                return None

            def putrequest(self, *args: object, **kwargs: object) -> None:
                return None

            def putheader(self, *args: object) -> None:
                return None

            def endheaders(self, body: bytes) -> None:
                if not body:
                    raise AssertionError("request body is required")

            def getresponse(self) -> ScriptedResponse:
                if response_error is not None:
                    raise response_error
                return scripted_response

        connection = ScriptedConnection()
        timer = mock.Mock()
        client = object.__new__(
            verifier_state_service.CanonicalHttpsClient
        )
        client._context = object()
        client._host = "192.0.2.20"
        client._port = 443
        client._authority = "192.0.2.20"
        client._expected_server_certificate_spki_sha256 = (
            verifier.sha256(b"fixture-server-certificate")
        )
        client._expected_server_spiffe_uri = (
            "spiffe://serverware/verifier-state"
        )
        client._timeout = 1.0
        client._request_slots = threading.BoundedSemaphore(1)
        monotonic_patch = (
            mock.patch.object(
                verifier_state_service.time,
                "monotonic",
                side_effect=monotonic_values,
            )
            if monotonic_values is not None
            else mock.patch.object(
                verifier_state_service.time,
                "monotonic",
                return_value=0.0,
            )
        )
        with mock.patch.object(
            verifier_state_service.http.client,
            "HTTPSConnection",
            return_value=connection,
        ), mock.patch.object(
            verifier_state_service.ssl,
            "SSLSocket",
            ScriptedTlsSocket,
        ), mock.patch.object(
            verifier_state_service,
            "validate_certificate_identity",
        ), mock.patch.object(
            verifier_state_service.threading,
            "Timer",
            return_value=timer,
        ), monotonic_patch:
            return client.post(
                "/v1/fixture",
                {"request": "fixture"},
                outcome_may_be_unknown=outcome_may_be_unknown,
            )

    def test_slow_response_status_and_headers_fail_closed(self) -> None:
        with self.assertRaises(
            verifier_state_service.ContractError
        ):
            self.canonical_https_behavior(
                chunks=[],
                response_error=(
                    verifier_state_service.socket.timeout(
                        "fixture response-header deadline"
                    )
                ),
            )

    def test_partial_declared_response_body_fails_closed(self) -> None:
        with self.assertRaises(
            verifier_state_service.ContractError
        ):
            self.canonical_https_behavior(
                chunks=[b'{"apiVersion":', b""],
            )

    def test_response_requires_clean_connection_eof(self) -> None:
        valid_body = verifier_state_service.canonical_json(
            {
                "apiVersion": "fixture.externalResponse/v1",
                "operation": "fixture",
                "requestSha256":
                verifier.sha256(b"fixture-request"),
                "result": {},
            }
        ).encode("ascii")
        with self.assertRaises(
            verifier_state_service.ContractError
        ):
            self.canonical_https_behavior(
                chunks=[valid_body],
                trailing=b"x",
            )

    def test_adapter_uses_one_shared_total_deadline(self) -> None:
        with self.assertRaisesRegex(
            verifier_state_service.ContractError,
            "total deadline",
        ):
            self.canonical_https_behavior(
                chunks=[],
                monotonic_values=[
                    0.00,
                    0.05,
                    0.10,
                    0.20,
                    0.30,
                    0.45,
                    0.65,
                    0.85,
                    1.01,
                ],
            )

    def test_mutating_non_200_is_an_unknown_outcome(self) -> None:
        valid_body = verifier_state_service.canonical_json(
            {
                "apiVersion": "fixture.externalResponse/v1",
                "operation": "fixture",
                "requestSha256":
                verifier.sha256(b"fixture-request"),
                "result": {},
            }
        ).encode("ascii")
        with self.assertRaises(
            verifier_state_service.UnknownOutcomeError
        ):
            self.canonical_https_behavior(
                chunks=[valid_body],
                status=503,
                outcome_may_be_unknown=True,
            )

    def assurance_evidence(
        self,
        *,
        issued: int,
        expires: int,
    ) -> tuple[dict, dict, object]:
        assurance = nonce_authority_assurance(production=True)
        signer = verifier_state_service.NonProductionEd25519Signer(
            Ed25519PrivateKey.generate()
        )
        payload = {
            "apiVersion":
            verifier.NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION,
            "administrativeDomainSha256":
            assurance["administrativeDomainSha256"],
            "assuranceEvidenceType":
            assurance["assuranceEvidenceType"],
            "authorityEpoch": assurance["authorityEpoch"],
            "authorityGeneration":
            assurance["authorityGeneration"],
            "authorityIdentitySha256":
            assurance["authorityIdentitySha256"],
            "backendClass": assurance["backendClass"],
            "expiresAtUnix": expires,
            "issuedAtUnix": issued,
            "nonceAuthorityStateSigningKeySpkiSha256":
            verifier.sha256(b"nonce-state-key"),
            "rollbackMechanism":
            assurance["rollbackProtection"]["mechanism"],
            "stateCommitment":
            assurance["rollbackProtection"]["stateCommitment"],
            "verifierStateStoreAdministrativeDomainSha256":
            self.store_admin_sha256,
            "verifierStateStoreClass":
            assurance["rollbackProtection"][
                "verifierStateStoreClass"
            ],
            "verifierStateStoreIdentitySha256":
            self.store_identity_sha256,
            "verifierStateStoreSigningKeySpkiSha256":
            self.signer.key_id,
        }
        evidence = verifier_state_service.sign_envelope(
            signer,
            api_version=(
                verifier.SIGNED_NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION
            ),
            domain=verifier.NONCE_AUTHORITY_ASSURANCE_EVIDENCE_DOMAIN,
            payload=payload,
        )
        assurance["assuranceEvidenceSha256"] = verifier.sha256_json(
            evidence
        )
        return assurance, evidence, signer

    def test_assurance_expiry_wrong_pins_and_backend(self) -> None:
        assurance, evidence, signer = self.assurance_evidence(
            issued=self.now,
            expires=self.now + 10,
        )
        verifier.verify_nonce_authority_assurance_evidence(
            evidence,
            signing_key=signer.public_key,
            signing_key_id=signer.key_id,
            assurance=assurance,
            nonce_authority_state_signing_key_id=verifier.sha256(
                b"nonce-state-key"
            ),
            verifier_state_store_administrative_domain_sha256=(
                self.store_admin_sha256
            ),
            verifier_state_store_identity_sha256=(
                self.store_identity_sha256
            ),
            verifier_state_store_signing_key_id=self.signer.key_id,
            now=self.now + 1,
        )
        defaults = {
            "signing_key": signer.public_key,
            "signing_key_id": signer.key_id,
            "assurance": assurance,
            "nonce_authority_state_signing_key_id":
            verifier.sha256(b"nonce-state-key"),
            "verifier_state_store_administrative_domain_sha256":
            self.store_admin_sha256,
            "verifier_state_store_identity_sha256":
            self.store_identity_sha256,
            "verifier_state_store_signing_key_id": self.signer.key_id,
        }
        hostile = (
            {"now": self.now + 10},
            {
                "now": self.now + 1,
                "signing_key_id": verifier.sha256(b"wrong-issuer"),
            },
            {
                "now": self.now + 1,
                "verifier_state_store_identity_sha256":
                verifier.sha256(b"wrong-store"),
            },
        )
        for changes in hostile:
            with self.subTest(changes=changes), self.assertRaises(
                verifier.VerificationError
            ):
                verifier.verify_nonce_authority_assurance_evidence(
                    evidence,
                    **{**defaults, **changes},
                )
        wrong_backend = copy.deepcopy(assurance)
        wrong_backend["backendClass"] = "nonProductionSqlite"
        with self.assertRaises(verifier.VerificationError):
            verifier.validate_nonce_authority_assurance(
                wrong_backend,
                expected_authority_identity_sha256=wrong_backend[
                    "authorityIdentitySha256"
                ],
            )

    def test_assurance_future_and_overlong_validity(self) -> None:
        cases = (
            (self.now + 1, self.now + 10, self.now),
            (
                self.now,
                self.now + verifier.MAX_RELEASE_VALIDITY_SECONDS + 1,
                self.now + 1,
            ),
        )
        for issued, expires, checked_at in cases:
            assurance, evidence, signer = self.assurance_evidence(
                issued=issued,
                expires=expires,
            )
            with self.subTest(
                issued=issued,
                expires=expires,
            ), self.assertRaises(verifier.VerificationError):
                verifier.verify_nonce_authority_assurance_evidence(
                    evidence,
                    signing_key=signer.public_key,
                    signing_key_id=signer.key_id,
                    assurance=assurance,
                    nonce_authority_state_signing_key_id=(
                        verifier.sha256(b"nonce-state-key")
                    ),
                    verifier_state_store_administrative_domain_sha256=(
                        self.store_admin_sha256
                    ),
                    verifier_state_store_identity_sha256=(
                        self.store_identity_sha256
                    ),
                    verifier_state_store_signing_key_id=(
                        self.signer.key_id
                    ),
                    now=checked_at,
                )

class PublicNitroFinalSignerFixtures(unittest.TestCase):
    @staticmethod
    def final_result() -> tuple[
        dict[str, object],
        Ed25519PrivateKey,
    ]:
        final = readiness_fixture.release_completion_result_v1_fixture()
        result = copy.deepcopy(
            final["publicNitroVerification"]["envelope"]["result"]
        )
        private_key, _pem, key_id = (
            readiness_fixture._fixture_ed25519_material(
                "public-nitro-result"
            )
        )
        result["roleKeyIds"]["publicNitroResult"] = key_id
        result["roleRegistrySha256"] = verifier.sha256_json(
            {
                "apiVersion":
                verifier.PUBLIC_NITRO_ROLE_REGISTRY_VERSION,
                "roles": result["roleKeyIds"],
            }
        )
        verifier.validate_public_nitro_final_result_contract(result)
        return result, private_key

    def test_two_phase_external_signer_is_deterministic_and_exact(
        self,
    ) -> None:
        result, private_key = self.final_result()
        key_id = result["roleKeyIds"]["publicNitroResult"]
        signer_tls = verifier.sha256(
            b"fixture-public-nitro-signer-server-tls"
        )
        self.assertEqual(
            producer_issuer.PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN,
            verifier.PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN,
        )
        self.assertEqual(
            release_completion
            .PUBLIC_NITRO_LIVE_RESULT_SIGNATURE_DOMAIN,
            verifier.PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN,
        )
        self.assertEqual(
            producer_issuer.PUBLIC_NITRO_CANONICAL_INTEGER_MAX,
            verifier.PUBLIC_NITRO_CANONICAL_INTEGER_MAX,
        )
        self.assertEqual(
            release_completion.PUBLIC_NITRO_CANONICAL_INTEGER_MAX,
            verifier.PUBLIC_NITRO_CANONICAL_INTEGER_MAX,
        )
        self.assertEqual(
            inspect.getclosurevars(
                producer_issuer.validate_public_nitro_signing_request
            ).unbound,
            set(),
        )
        self.assertEqual(
            verifier.PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN,
            (
                b"serverware.publicNitroLiveVerificationResultEnvelope/v1"
                b"\x00signatureAlgorithm=Ed25519\x00"
            ),
        )
        request = verifier.build_public_nitro_result_signing_request(
            result,
            provider="fixture-public-nitro-signer",
            signing_key_id=key_id,
            signing_key_spki_sha256=key_id,
            signer_server_tls_spki_sha256=signer_tls,
        )
        self.assertEqual(
            request,
            verifier.build_public_nitro_result_signing_request(
                result,
                provider="fixture-public-nitro-signer",
                signing_key_id=key_id,
                signing_key_spki_sha256=key_id,
                signer_server_tls_spki_sha256=signer_tls,
            ),
        )
        envelope = {
            **request["envelopeCore"],
            "signature": (
                "ed25519:"
                + b64u(
                    private_key.sign(
                        verifier.PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN
                        + verifier.canonical_json_bytes(
                            request["envelopeCore"]
                        )
                    )
                )
            ),
        }
        response = {
            "apiVersion":
            verifier.PUBLIC_NITRO_RESULT_SIGNING_RESPONSE_VERSION,
            "envelope": envelope,
            "operationIdSha256": request["operationIdSha256"],
            "recoveryKeySha256": request["recoveryKeySha256"],
            "requestSha256": request["requestSha256"],
            "status": "signed",
            "transportPins": request["transportPins"],
        }
        self.assertEqual(
            verifier.verify_public_nitro_result_signing_response(
                request,
                response,
                signing_key=private_key.public_key(),
            ),
            envelope,
        )
        self.assertEqual(
            producer_issuer.validate_public_nitro_signing_request(
                request
            ),
            request,
        )
        self.assertEqual(
            producer_issuer.validate_public_nitro_signer_response(
                response,
                request=request,
                signing_key=private_key.public_key(),
            ),
            response,
        )
        recovery_request = (
            verifier.build_public_nitro_result_recovery_request(
                request
            )
        )
        self.assertEqual(
            verifier.validate_public_nitro_result_recovered_response(
                recovery_request,
                response,
                signing_key=private_key.public_key(),
            ),
            envelope,
        )
        self.assertEqual(
            producer_issuer.validate_public_nitro_result_recovery_request(
                recovery_request
            ),
            recovery_request,
        )
        status_request = (
            verifier.build_public_nitro_result_status_request(request)
        )
        self.assertEqual(
            verifier.validate_public_nitro_result_status_response(
                status_request,
                response,
                signing_key=private_key.public_key(),
            ),
            envelope,
        )
        self.assertEqual(
            producer_issuer.validate_public_nitro_result_status_request(
                status_request
            ),
            status_request,
        )
        signing_schema = json.loads(
            (
                Path(__file__).parents[1]
                / "schemas"
                / "live-attestation-verification-result.v1.schema.json"
            ).read_text()
        )
        signing_validator = Draft202012Validator(signing_schema)
        signing_validator.evolve(
            schema={
                "$ref":
                "#/$defs/publicNitroResultSigningRequest"
            }
        ).validate(request)
        signing_validator.evolve(
            schema={
                "$ref":
                "#/$defs/publicNitroResultSigningResponse"
            }
        ).validate(response)
        signing_validator.evolve(
            schema={
                "$ref":
                "#/$defs/publicNitroResultSignerRecoveryRequest"
            }
        ).validate(recovery_request)
        signing_validator.evolve(
            schema={
                "$ref":
                "#/$defs/publicNitroResultSignerStatusRequest"
            }
        ).validate(status_request)
        response_raw = (
            producer_issuer.canonical_json(response) + b"\n"
        )
        retained: dict[str, tuple[bytes, bytes]] = {}
        invoked_versions: list[str] = []

        def invoke_signer(operation: Any) -> bytes:
            operation_version = operation.get("apiVersion")
            invoked_versions.append(operation_version)
            if operation_version == (
                verifier.PUBLIC_NITRO_RESULT_RECOVERY_REQUEST_VERSION
            ):
                signing_request = (
                    producer_issuer
                    .validate_public_nitro_result_recovery_request(
                        operation
                    )["signingRequest"]
                )
            elif operation_version == (
                verifier.PUBLIC_NITRO_RESULT_STATUS_REQUEST_VERSION
            ):
                signing_request = (
                    producer_issuer
                    .validate_public_nitro_result_status_request(
                        operation
                    )["signingRequest"]
                )
            else:
                signing_request = (
                    producer_issuer.validate_public_nitro_signing_request(
                        operation
                    )
                )
            recovery_key = signing_request["recoveryKeySha256"]
            request_raw = (
                producer_issuer.canonical_json(signing_request)
                + b"\n"
            )
            previous = retained.get(recovery_key)
            if previous is not None:
                if previous[0] != request_raw:
                    raise producer_issuer.ContractError(
                        "same recovery identity has a different request"
                    )
                return previous[1]
            retained[recovery_key] = (request_raw, response_raw)
            return response_raw

        direct_terminal = (
            producer_issuer
            .relay_public_nitro_result_signer_operation(
                request,
                invoke_signer=invoke_signer,
                signing_key=private_key.public_key(),
            )
        )
        recovered_terminal = (
            producer_issuer
            .relay_public_nitro_result_signer_operation(
                recovery_request,
                invoke_signer=invoke_signer,
                signing_key=private_key.public_key(),
            )
        )
        status_terminal = (
            producer_issuer
            .relay_public_nitro_result_signer_operation(
                status_request,
                invoke_signer=invoke_signer,
                signing_key=private_key.public_key(),
            )
        )
        self.assertEqual(direct_terminal, response_raw)
        self.assertEqual(recovered_terminal, direct_terminal)
        self.assertEqual(status_terminal, direct_terminal)
        self.assertEqual(
            invoked_versions,
            [
                verifier.PUBLIC_NITRO_RESULT_SIGNING_REQUEST_VERSION,
                verifier.PUBLIC_NITRO_RESULT_RECOVERY_REQUEST_VERSION,
                verifier.PUBLIC_NITRO_RESULT_STATUS_REQUEST_VERSION,
            ],
        )
        conflicting_signing_request = (
            verifier.build_public_nitro_result_signing_request(
                result,
                provider="fixture-conflicting-public-nitro-signer",
                signing_key_id=key_id,
                signing_key_spki_sha256=key_id,
                signer_server_tls_spki_sha256=signer_tls,
            )
        )
        conflicting_recovery = copy.deepcopy(recovery_request)
        conflicting_recovery["signingRequest"] = (
            conflicting_signing_request
        )
        with self.assertRaises(producer_issuer.ContractError):
            producer_issuer.relay_public_nitro_result_signer_operation(
                conflicting_recovery,
                invoke_signer=invoke_signer,
                signing_key=private_key.public_key(),
            )
        conflicting_status = copy.deepcopy(status_request)
        conflicting_status["signingRequest"] = (
            conflicting_signing_request
        )
        with self.assertRaises(producer_issuer.ContractError):
            producer_issuer.relay_public_nitro_result_signer_operation(
                conflicting_status,
                invoke_signer=invoke_signer,
                signing_key=private_key.public_key(),
            )
        for field, replacement in (
            ("operationIdSha256", verifier.sha256(b"crossed-operation")),
            ("recoveryKeySha256", verifier.sha256(b"crossed-recovery")),
            ("requestSha256", verifier.sha256(b"crossed-request")),
        ):
            crossed = copy.deepcopy(response)
            crossed[field] = replacement
            with self.subTest(field=field), self.assertRaises(
                verifier.VerificationError
            ):
                verifier.verify_public_nitro_result_signing_response(
                    request,
                    crossed,
                    signing_key=private_key.public_key(),
                )
        self.assertNotIn(
            "private",
            inspect.signature(
                verifier.verify_public_nitro_result_signing_response
            ).parameters,
        )
        self.assertNotIn(
            "private",
            inspect.signature(
                verifier
                .validate_public_nitro_result_recovered_response
            ).parameters,
        )
        self.assertNotIn(
            "private",
            inspect.signature(
                verifier.validate_public_nitro_result_status_response
            ).parameters,
        )

    def test_public_nitro_integer_and_provider_contract_parity(
        self,
    ) -> None:
        result, _private_key = self.final_result()
        schema = json.loads(
            (
                Path(__file__).parents[1]
                / "schemas"
                / "live-attestation-verification-result.v1.schema.json"
            ).read_text()
        )
        result_validator = Draft202012Validator(schema).evolve(
            schema={"$ref": "#/$defs/publicNitroResult"}
        )
        provider_validator = Draft202012Validator(schema).evolve(
            schema={"$ref": "#/$defs/publicNitroProvider"}
        )
        signed_max = verifier.PUBLIC_NITRO_CANONICAL_INTEGER_MAX
        self.assertEqual(signed_max, (1 << 63) - 1)
        self.assertEqual(
            schema["$defs"]["unsignedU64"]["maximum"],
            signed_max,
        )
        self.assertEqual(
            schema["$defs"]["positiveU64"]["maximum"],
            signed_max,
        )
        self.assertEqual(
            schema["$defs"]["publicNitroProvider"]["pattern"],
            verifier.PUBLIC_NITRO_PROVIDER_RE.pattern,
        )
        self.assertEqual(
            producer_issuer.PUBLIC_NITRO_PROVIDER_RE.pattern,
            verifier.PUBLIC_NITRO_PROVIDER_RE.pattern,
        )
        maximum_result = copy.deepcopy(result)
        maximum_result["verifiedAtUnix"] = signed_max
        self.assertEqual(
            verifier.validate_public_nitro_final_result_contract(
                maximum_result
            ),
            maximum_result,
        )
        self.assertEqual(
            producer_issuer.validate_public_nitro_final_result_contract(
                maximum_result
            ),
            maximum_result,
        )
        self.assertEqual(
            release_completion._validate_public_nitro_live_result(
                maximum_result
            ),
            maximum_result,
        )
        result_validator.validate(maximum_result)

        above_maximum = copy.deepcopy(result)
        above_maximum["verifiedAtUnix"] = signed_max + 1
        with self.assertRaises(verifier.VerificationError):
            verifier.validate_public_nitro_final_result_contract(
                above_maximum
            )
        with self.assertRaises(producer_issuer.ContractError):
            producer_issuer.validate_public_nitro_final_result_contract(
                above_maximum
            )
        with self.assertRaises(ValueError):
            release_completion._validate_public_nitro_live_result(
                above_maximum
            )
        with self.assertRaises(ValidationError):
            result_validator.validate(above_maximum)

        for provider in ("a", "fixture.signer-1", "a" * 128):
            with self.subTest(provider=provider):
                self.assertEqual(
                    verifier.require_public_nitro_provider(
                        provider,
                        "fixture provider",
                    ),
                    provider,
                )
                self.assertEqual(
                    producer_issuer.require_public_nitro_provider(
                        provider,
                        "fixture provider",
                    ),
                    provider,
                )
                self.assertEqual(
                    release_completion.require_public_nitro_provider(
                        provider,
                        "fixture provider",
                    ),
                    provider,
                )
                provider_validator.validate(provider)
        for provider in ("", ".leading", "kms:primary", "a" * 129):
            with self.subTest(provider=provider):
                with self.assertRaises(verifier.VerificationError):
                    verifier.require_public_nitro_provider(
                        provider,
                        "fixture provider",
                    )
                with self.assertRaises(producer_issuer.ContractError):
                    producer_issuer.require_public_nitro_provider(
                        provider,
                        "fixture provider",
                    )
                with self.assertRaises(ValueError):
                    release_completion.require_public_nitro_provider(
                        provider,
                        "fixture provider",
                    )
                with self.assertRaises(ValidationError):
                    provider_validator.validate(provider)

    def test_native_relay_and_schema_share_the_closed_result_contract(
        self,
    ) -> None:
        result, _private_key = self.final_result()
        schema = json.loads(
            (
                Path(__file__).parents[1]
                / "schemas"
                / "live-attestation-verification-result.v1.schema.json"
            ).read_text()
        )
        result_schema = schema["$defs"]["publicNitroResult"]
        self.assertEqual(
            set(result_schema["required"]),
            verifier.PUBLIC_NITRO_RESULT_FIELDS,
        )
        self.assertEqual(
            set(result_schema["properties"]),
            verifier.PUBLIC_NITRO_RESULT_FIELDS,
        )
        self.assertEqual(
            producer_issuer.PUBLIC_NITRO_RESULT_FIELDS,
            verifier.PUBLIC_NITRO_RESULT_FIELDS,
        )
        self.assertEqual(
            producer_issuer.PUBLIC_NITRO_RESULT_ROLE_NAMES,
            verifier.PUBLIC_NITRO_RESULT_ROLE_NAMES,
        )
        validator = Draft202012Validator(schema).evolve(
            schema={"$ref": "#/$defs/publicNitroResult"}
        )
        validator.validate(result)
        hostile_results = []
        extra_top_level = copy.deepcopy(result)
        extra_top_level["unexpected"] = True
        hostile_results.append(extra_top_level)
        extra_witness = copy.deepcopy(result)
        extra_witness["witness"]["unexpected"] = True
        hostile_results.append(extra_witness)
        missing_commit_field = copy.deepcopy(result)
        missing_commit_field["stateCommit"].pop("transitionSha256")
        hostile_results.append(missing_commit_field)
        crossed_roles = copy.deepcopy(result)
        crossed_roles["roleKeyIds"]["unexpected"] = verifier.sha256(
            b"unexpected-role"
        )
        hostile_results.append(crossed_roles)
        extra_pcr = copy.deepcopy(result)
        extra_pcr["pcrs"]["PCR3"] = extra_pcr["pcrs"]["PCR2"]
        hostile_results.append(extra_pcr)
        for hostile in hostile_results:
            with self.subTest(fields=tuple(sorted(hostile))):
                with self.assertRaises(verifier.VerificationError):
                    verifier.validate_public_nitro_final_result_contract(
                        hostile
                    )
                with self.assertRaises(producer_issuer.ContractError):
                    producer_issuer.validate_public_nitro_final_result_contract(
                        hostile
                    )
                with self.assertRaises(ValidationError):
                    validator.validate(hostile)


class PublicBoundaryInventory(unittest.TestCase):
    def test_public_secret_fields_are_rejected(self) -> None:
        for field in (
            "password",
            "accessToken",
            "refresh_token",
            "privateKeyPem",
            "Authorization",
        ):
            with self.assertRaises(verifier.VerificationError):
                verifier.reject_public_secret_fields({field: "redacted"})


class GlobalAttestationRoleSeparationFixtures(unittest.TestCase):
    @staticmethod
    def _load_producer() -> Any:
        import importlib.util
        from pathlib import Path

        path = Path(__file__).resolve().with_name(
            "production_attestation_producer_issuer.py"
        )
        spec = importlib.util.spec_from_file_location(
            "global_role_fixture_producer",
            path,
        )
        if spec is None or spec.loader is None:
            raise AssertionError("cannot load production producer issuer")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_every_visible_role_is_pairwise_collision_checked(self) -> None:
        producer = self._load_producer()
        roles = tuple(producer.GLOBAL_ATTESTATION_KEY_ROLES)
        required = {
            "releaseCa",
            "responseKey",
            "remoteSignerServerTls",
            "remoteStoreServerTls",
            "verifierStateSignerClientTls",
            "verifierStateSignerServerTls",
            "verifierStateStoreClientTls",
            "verifierStateStoreServerTls",
        }
        self.assertTrue(required.issubset(set(roles)))
        baseline = {
            role: f"fixture-key-{index}"
            for index, role in enumerate(roles)
        }
        self.assertEqual(
            producer.validate_global_attestation_key_role_separation(
                baseline
            ),
            baseline,
        )
        for left_index, left in enumerate(roles):
            for right in roles[left_index + 1 :]:
                crossed = dict(baseline)
                crossed[right] = crossed[left]
                with self.subTest(left=left, right=right):
                    with self.assertRaises(Exception):
                        producer.validate_global_attestation_key_role_separation(
                            crossed
                        )


if __name__ == "__main__":
    unittest.main()
