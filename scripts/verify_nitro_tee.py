#!/usr/bin/env python3
"""Offline, fail-closed verification of a Serverware production Nitro proof.

This verifier deliberately performs no network lookup. The caller must supply:

* a public verification input bundle assembled from the service's bounded
  evidence endpoint, the challenged live response, and independent artifacts;
* an independent expectations document;
* independent public trust roots, including AWS Nitro root certificates; and
* durable prior witness state.

The verifier accepts only the Manifest v6 Nitro production pipeline. Development
quotes and the legacy Docker /dev/nsm pipeline are different protocols and are
rejected before any evidence is considered.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import ipaddress
import io
import json
import os
import re
import stat
import sys
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit

import cbor2
from cbor2 import CBORTag
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import ExtensionOID


PIPELINE = "manifest-v6-promoted-oci-nitro-eif"
CANONICAL_PROFILE = (
    "serverware.canonicalJson/integer-string-bool-null-array-object-nfc-v1"
)
BUNDLE_VERSION = "serverware.publicNitroVerificationBundle/v2"
EXPECTATIONS_VERSION = "serverware.publicNitroExpectations/v2"
TRUST_ROOTS_VERSION = "serverware.publicNitroTrustRoots/v4"
CLIENT_STATE_VERSION = "serverware.monotonicReleaseWitnessState/v2"
PROTECTED_STATE_VERSION = "serverware.protectedNitroClientState/v1"
PROTECTED_STATE_CHECKPOINT_VERSION = (
    "serverware.protectedNitroClientStateCheckpoint/v1"
)
STATE_COMMIT_VERSION = "serverware.publicNitroStateCommit/v1"
CURRENT_HEAD_AUTHORIZATION_VERSION = (
    "serverware.publicNitroCurrentHeadAuthorization/v1"
)
CURRENT_HEAD_REDEMPTION_VERSION = (
    "serverware.publicNitroCurrentHeadRedemption/v1"
)
CURRENT_HEAD_AUTHORIZATION_IDENTITY_VERSION = (
    "serverware.publicNitroCurrentHeadAuthorizationIdentity/v1"
)
CURRENT_HEAD_RESERVATION_IDENTITY_VERSION = (
    "serverware.publicNitroCurrentHeadReservationIdentity/v1"
)
CURRENT_HEAD_REDEMPTION_RECEIPT_IDENTITY_VERSION = (
    "serverware.publicNitroCurrentHeadRedemptionReceiptIdentity/v1"
)
STATE_STORE_HEAD_VERSION = "serverware.publicNitroStateStoreHead/v2"
STATE_STORE_FINAL_HEAD_VERSION = (
    "serverware.publicNitroStateStoreFinalHead/v1"
)
STATE_COMMIT_RECEIPT_IDENTITY_VERSION = (
    "serverware.publicNitroStateCommitReceiptIdentity/v1"
)
PRE_AUTHORIZATION_RESULT_CORE_VERSION = (
    "serverware.publicNitroPreAuthorizationResultCore/v1"
)
RESULT_VERSION = "serverware.publicNitroVerificationResult/v2"
PUBLIC_NITRO_ROLE_REGISTRY_VERSION = (
    "serverware.publicNitroRoleRegistry/v1"
)
PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_VERSION = (
    "serverware.publicNitroLiveVerificationResultEnvelope/v1"
)
PUBLIC_NITRO_RESULT_SIGNING_REQUEST_VERSION = (
    "serverware.publicNitroLiveVerificationResultSigningRequest/v1"
)
PUBLIC_NITRO_RESULT_SIGNING_RESPONSE_VERSION = (
    "serverware.publicNitroLiveVerificationResultSigningResponse/v1"
)
PUBLIC_NITRO_RESULT_RECOVERY_REQUEST_VERSION = (
    "serverware.publicNitroLiveVerificationResultRecoveryRequest/v1"
)
PUBLIC_NITRO_RESULT_STATUS_REQUEST_VERSION = (
    "serverware.publicNitroLiveVerificationResultStatusRequest/v1"
)
CLAIMS_VERSION = "serverware.productionAttestationClaims/v2"
PRODUCTION_IDENTITY_VERSION = "serverware.productionAttestationIdentity/v2"
PRODUCTION_RUNTIME_VERSION = "serverware.productionAttestationRuntime/v2"
RUNTIME_CUSTODY_VERSION = "serverware.enclaveKeyCustody/v3"
PROMOTED_MANIFEST_VERSION = "serverware.consolidatedTestArtifacts/v6"
BUILDER_STATEMENT_VERSION = "serverware.rawBuilderStatement/v1"
BUILDER_TRANSCRIPT_VERSION = "serverware.rawBuilderTranscript/v1"
TLS_EVIDENCE_VERSION = "serverware.liveEnclaveTlsEvidence/v2"
TLS_SCOPE_VERSION = "serverware.enclaveTlsScope/v2"
TLS_SCOPE_ENVELOPE_VERSION = "serverware.enclaveTlsScopeEnvelope/v2"
TLS_BINDING_VERSION = "serverware.enclaveTlsBinding/v2"
RESPONSE_STATEMENT_VERSION = "serverware.attestationResponse/v2"
HTTP_RESPONSE_VERSION = "serverware.attestationHttpResponse/v1"
WITNESS_VERSION = "serverware.monotonicReleaseWitness/v2"
KEY_GENERATION_VERSION = "serverware.enclaveKeyGeneration/v1"
KMS_AUDIT_VERSION = "serverware.awsKmsRecipientAuditProof/v1"
EIF_BUILD_VERSION = "serverware.manifestV6EifBuildStatement/v1"
COMPLETION_PROOF_VERSION = "serverware.completionProof/v6"
READINESS_CHECKSUM_API_VERSION = "serverware.readinessChecksum/v1"
COMPLETION_AUTHENTICATION_VERSION = (
    "serverware.completionProofAuthentication/v1"
)
COMPLETION_CHECKPOINT_VERSION = "serverware.completionProofCheckpoint/v1"
COMPLETION_IDENTITY_VERSION = "serverware.finalCompletionIdentity/v3"
RELEASE_IDENTITY_VERSION = "serverware.releaseIdentity/v1"
LIVE_SESSION_PROOF_VERSION = "serverware.liveSessionProof/v1"
PUBLIC_ATTESTATION_DELIVERY_REBIND_VERSION = (
    "serverware.publicAttestationDeliveryRebind/v2"
)
SIGNED_PUBLIC_ATTESTATION_DELIVERY_REBIND_VERSION = (
    "serverware.signedPublicAttestationDeliveryRebind/v2"
)
LIVE_WITNESS_HEAD_VERSION = "serverware.liveWitnessHead/v1"
PUBLIC_ATTESTATION_BUNDLE_VERSION = (
    "serverware.publicAttestationBundle/v3"
)
PUBLIC_ATTESTATION_CONFIG_VERSION = (
    "serverware.publicAttestationConfig/v2"
)
PUBLIC_ATTESTATION_PRODUCER_REQUEST_VERSION = (
    "serverware.publicAttestationProducerRequest/v2"
)
PUBLIC_ATTESTATION_LIVE_REQUEST_VERSION = (
    "serverware.publicAttestationLiveRequest/v1"
)
PUBLIC_ATTESTATION_NONCE_CONSUMPTION_VERSION = (
    "serverware.publicAttestationNonceConsumption/v1"
)
PUBLIC_ATTESTATION_NONCE_CONSUME_ONCE_REQUEST_VERSION = (
    "serverware.attestationNonceConsumeOnceRequest/v3"
)
PUBLIC_ATTESTATION_SIGNED_NONCE_RECEIPT_VERSION = (
    "serverware.signedAttestationNonceConsumptionReceipt/v2"
)
PUBLIC_ATTESTATION_NONCE_RECEIPT_PAYLOAD_VERSION = (
    "serverware.attestationNonceConsumptionReceiptPayload/v2"
)
NONCE_AUTHORITY_ASSURANCE_VERSION = (
    "serverware.nonceAuthorityAssurance/v1"
)
SIGNED_NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION = (
    "serverware.signedNonceAuthorityAssuranceEvidence/v1"
)
NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION = (
    "serverware.nonceAuthorityAssuranceEvidence/v1"
)
SIGNED_VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION = (
    "serverware.signedVerifierStateStoreAssuranceEvidence/v1"
)
VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION = (
    "serverware.verifierStateStoreAssuranceEvidence/v1"
)
SIGNED_VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_VERSION = (
    "serverware.signedVerifierStateRoleSeparationEvidence/v1"
)
VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_VERSION = (
    "serverware.verifierStateRoleSeparationEvidence/v1"
)
NONCE_AUTHORITY_STATE_VERSION = "serverware.nonceAuthorityState/v1"
NONCE_AUTHORITY_HIGH_WATER_INPUT_VERSION = (
    "serverware.nonceAuthorityHighWaterCommitment/v1"
)
SIGNED_NONCE_AUTHORITY_VERIFIER_STATE_VERSION = (
    "serverware.signedNonceAuthorityVerifierState/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_VERSION = (
    "serverware.nonceAuthorityVerifierState/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_CANDIDATE_VERSION = (
    "serverware.nonceAuthorityVerifierStateCandidate/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_VERSION = (
    "serverware.nonceAuthorityVerifierStatePreparedAuthorization/v3"
)
NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_VERSION = (
    "serverware.nonceAuthorityVerifierStateCommitReceipt/v3"
)
SIGNED_VERIFIER_STATE_STORE_COMMIT_PROOF_VERSION = (
    "serverware.signedVerifierStateStoreCommitProof/v3"
)
VERIFIER_STATE_STORE_COMMIT_PROOF_VERSION = (
    "serverware.verifierStateStoreCommitProof/v3"
)
VERIFIER_STATE_STORE_COMMIT_CANDIDATE_VERSION = (
    "serverware.verifierStateStoreCommitCandidate/v2"
)
VERIFIER_STATE_COMMIT_REQUEST_VERSION = (
    "serverware.attestationVerifierStateCommitRequest/v3"
)
NONCE_AUTHORITY_VERIFIER_STATE_READ_RESPONSE_VERSION = (
    "serverware.nonceAuthorityVerifierStateReadResponse/v3"
)
NONCE_AUTHORITY_VERIFIER_STATE_TRANSITION_VERSION = (
    "serverware.nonceAuthorityVerifierStateTransition/v3"
)
PUBLIC_ATTESTATION_VERIFIER_STATE_CLIENT_VERSION = (
    "serverware.attestationVerifierStateClient/v2"
)
VERIFIER_STATE_PREPARED_OPERATION_VERSION = (
    "serverware.attestationVerifierStatePreparedOperation/v1"
)
VERIFIER_STATE_PREPARE_REQUEST_VERSION = (
    "serverware.attestationVerifierStatePrepareRequest/v4"
)
VERIFIER_STATE_REQUEST_BINDING_VERSION = (
    "serverware.attestationVerifierStateRequestBinding/v1"
)
VERIFIER_STATE_RECOVERY_BINDING_VERSION = (
    "serverware.attestationVerifierStateRecoveryBinding/v1"
)
VERIFIER_STATE_RECOVERY_IDENTITY_VERSION = (
    "serverware.attestationVerifierStateRecoveryIdentity/v1"
)
VERIFIER_STATE_SUCCESSOR_INTENT_VERSION = (
    "serverware.attestationVerifierStateSuccessorIntent/v1"
)
PUBLIC_ATTESTATION_PRODUCER_INVOCATION_VERSION = (
    "serverware.publicAttestationProducerInvocation/v1"
)
PUBLIC_ATTESTATION_PRODUCER_BINDING_VERSION = (
    "serverware.publicAttestationProducerBinding/v3"
)
PUBLIC_ATTESTATION_SIGNED_PRODUCER_BINDING_VERSION = (
    "serverware.signedPublicAttestationProducerBinding/v1"
)
ATTESTATION_WITNESS_INVOCATION_BINDING_VERSION = (
    "serverware.attestationWitnessInvocationBinding/v1"
)
PUBLIC_RELEASE_GRAPH_VERSION = "serverware.publicReleaseGraph/v1"
STABLE_RELEASE_STATEMENT_VERSION = (
    "serverware.stableReleaseStatement/v1"
)
PROTECTED_LIVE_WITNESS_STATE_VERSION = (
    "serverware.protectedLiveWitnessState/v2"
)
LIVE_WITNESS_STORE_CAS_RECEIPT_VERSION = (
    "serverware.liveWitnessCasReceipt/v1"
)
LIVE_WITNESS_CONTINUITY_VERSION = (
    "serverware.liveWitnessContinuity/v1"
)
LIVE_WITNESS_STORE_IDENTITY_VERSION = (
    "serverware.attestationWitnessStoreIdentity/v2"
)
LIVE_ATTESTATION_RESULT_VERSION = (
    "serverware.liveAttestationVerificationResult/v1"
)
COMPLETION_CORE_VERSIONS = {
    "builderA": "serverware.completionBuilderCore/v1",
    "builderB": "serverware.completionBuilderCore/v1",
    "custody": "serverware.completionCustodyCore/v1",
    "eif": "serverware.completionEifCore/v1",
    "hardware": "serverware.completionHardwareCore/v1",
    "promotion": "serverware.completionPromotionCore/v1",
    "release": "serverware.completionReleaseCore/v1",
    "response": "serverware.completionResponseCore/v1",
    "runtime": "serverware.completionRuntimeCore/v1",
    "source": "serverware.completionSourceCore/v1",
    "trust": "serverware.completionTrustCore/v1",
    "witness": "serverware.completionWitnessCore/v1",
}
COMPLETION_CORE_DIGEST_FIELDS = frozenset(
    {
        *COMPLETION_CORE_VERSIONS,
        "continuity",
    }
)
COMPLETION_BINDING_FIELD_NAMES = frozenset(
    {
        "completionIdentity",
        "completionIdentitySha256",
        "completion_identity",
        "completion_identity_sha256",
    }
)
DETACHED_PROOF_HEADERS = {
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
}

CANDIDATE_VERSION = "serverware.consolidatedCandidateArtifacts/v6"
SOURCE_INPUT_VERSION = "serverware.sourceInputManifest/v3"
SOURCE_SNAPSHOT_VERSION = "serverware.sourceSnapshot/v7"
GIT_INVENTORY_VERSION = "serverware.gitSourceInventory/v3"
UNTRACKED_APPROVAL_VERSION = "serverware.untrackedSourceApproval/v2"
BUILD_PLAN_VERSION = "serverware.ociLaneBuildPlan/v4"
DEPENDENCY_BUNDLE_VERSION = "serverware.ociDependencyBundle/v5"
BUILD_BUNDLE_VERSION = "serverware.ociBuildBundle/v3"
BUILD_WATCHDOG_VERSION = "serverware.ociBuildWatchdogReceipt/v4"
PROMOTION_VERSION = "serverware.verificationPromotionReceipt/v4"
PROMOTION_ACCEPTANCE_VERSION = (
    "serverware.verificationPromotionAcceptance/v2"
)
SOURCE_SELECTION_MODEL = (
    "signed-raw-git-index-tree-worktree-status-plus-approved-untracked/v3"
)

GIT_INVENTORY_DOMAIN = b"serverware.gitSourceInventory/v3\x00Ed25519\x00"
UNTRACKED_APPROVAL_DOMAIN = (
    b"serverware.untrackedSourceApproval/v2\x00Ed25519\x00"
)
BUILD_WATCHDOG_DOMAIN = (
    b"serverware.ociBuildWatchdogReceipt/v4\x00Ed25519\x00"
)
PROMOTION_DOMAIN = (
    b"serverware.verificationPromotionReceipt/v4\x00Ed25519\x00"
)
BUILDER_STATEMENT_DOMAIN = (
    b"serverware.rawBuilderStatement/v1\x00Ed25519\x00"
)
WITNESS_DOMAIN = (
    b"serverware.monotonicReleaseWitness/v2\x00Ed25519\x00"
)
LIVE_WITNESS_HEAD_DOMAIN = (
    b"serverware.liveWitnessHead/v1\x00Ed25519\x00"
)
STABLE_RELEASE_STATEMENT_DOMAIN = (
    b"serverware.stableReleaseStatement/v1\x00Ed25519\x00"
)
PROTECTED_LIVE_WITNESS_STATE_DOMAIN = (
    b"serverware.protectedLiveWitnessState/v2\x00Ed25519\x00"
)
LIVE_WITNESS_HEAD_CHAIN_DOMAIN = (
    b"serverware:live-witness-head-chain:v1:"
)
LIVE_WITNESS_CONTINUITY_DOMAIN = (
    b"serverware:live-witness-continuity:v1:"
)
PUBLIC_ATTESTATION_NONCE_RECEIPT_DOMAIN = (
    b"serverware.attestationNonceConsumptionReceipt/v2\x00Ed25519\x00"
)
PUBLIC_ATTESTATION_NONCE_CONSUME_REQUEST_DIGEST_DOMAIN = (
    b"serverware.attestationNonceConsumeRequestDigest/v3\x00"
)
NONCE_AUTHORITY_GENESIS_DOMAIN = (
    b"serverware.nonceAuthorityGenesisCommitment/v1\x00"
)
NONCE_AUTHORITY_ASSURANCE_EVIDENCE_DOMAIN = (
    b"serverware.nonceAuthorityAssuranceEvidence/v1\x00Ed25519\x00"
)
VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_DOMAIN = (
    b"serverware.verifierStateStoreAssuranceEvidence/v1\x00Ed25519\x00"
)
VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_DOMAIN = (
    b"serverware.verifierStateRoleSeparationEvidence/v1\x00Ed25519\x00"
)
NONCE_AUTHORITY_HIGH_WATER_DOMAIN = (
    b"serverware.nonceAuthorityHighWaterCommitment/v1\x00"
)
NONCE_AUTHORITY_VERIFIER_STATE_DOMAIN = (
    b"serverware.nonceAuthorityVerifierState/v1\x00Ed25519\x00"
)
NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_DOMAIN = (
    b"serverware.nonceAuthorityVerifierStatePreparedAuthorization/v3\x00"
    b"Ed25519\x00"
)
NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_DOMAIN = (
    b"serverware.nonceAuthorityVerifierStateCommitReceipt/v3\x00"
    b"Ed25519\x00"
)
VERIFIER_STATE_STORE_COMMIT_PROOF_DOMAIN = (
    b"serverware.verifierStateStoreCommitProof/v3\x00Ed25519\x00"
)
VERIFIER_STATE_RECOVERY_KEY_DOMAIN = (
    b"serverware.attestationVerifierStateRecoveryKey/v1\x00"
)
VERIFIER_STATE_OPERATION_ID_DOMAIN = (
    b"serverware.attestationVerifierStateOperationId/v1\x00"
)
VERIFIER_STATE_REQUEST_BINDING_DOMAIN = (
    b"serverware.attestationVerifierStateRequestBinding/v1\x00"
)
NONCE_AUTHORITY_VERIFIER_STATE_HEAD_DOMAIN = (
    b"serverware.nonceAuthorityVerifierStateHead/v1\x00"
)
PUBLIC_ATTESTATION_PRODUCER_BINDING_DOMAIN = (
    b"serverware.publicAttestationProducerBinding/v3\x00Ed25519\x00"
)
TLS_SCOPE_ENVELOPE_DOMAIN = (
    b"serverware.enclaveTlsScopeEnvelope/v2\x00Ed25519\x00"
)
KEY_GENERATION_DOMAIN = b"serverware.enclaveKeyGeneration/v1\x00Ed25519\x00"
KEY_GENERATION_USER_DATA_PREFIX = b"serverware:key-generation:v1:"
KMS_AUDIT_DOMAIN = b"serverware.awsKmsRecipientAuditProof/v1\x00Ed25519\x00"
EIF_BUILD_DOMAIN = b"serverware.manifestV6EifBuildStatement/v1\x00Ed25519\x00"
COMPLETION_PROOF_DOMAIN = (
    b"serverware.completionProofAuthentication/v1\x00Ed25519\x00"
)
COMPLETION_CHECKPOINT_DOMAIN = (
    b"serverware.completionProofCheckpoint/v1\x00Ed25519\x00"
)
PROTECTED_STATE_DOMAIN = (
    b"serverware.protectedNitroClientState/v1\x00Ed25519\x00"
)
PROTECTED_STATE_CHECKPOINT_DOMAIN = (
    b"serverware.protectedNitroClientStateCheckpoint/v1\x00Ed25519\x00"
)
STATE_COMMIT_DOMAIN = b"serverware.publicNitroStateCommit/v1\x00Ed25519\x00"
CURRENT_HEAD_AUTHORIZATION_DOMAIN = (
    b"serverware.publicNitroCurrentHeadAuthorization/v1\x00Ed25519\x00"
)
CURRENT_HEAD_REDEMPTION_DOMAIN = (
    b"serverware.publicNitroCurrentHeadRedemption/v1\x00Ed25519\x00"
)
PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN = (
    b"serverware.publicNitroLiveVerificationResultEnvelope/v1\x00"
    b"signatureAlgorithm=Ed25519\x00"
)
PUBLIC_NITRO_RESULT_SIGNING_OPERATION_DOMAIN = (
    b"serverware.publicNitroLiveVerificationResultSigningOperation/v1\x00"
)
PUBLIC_NITRO_RESULT_SIGNING_RECOVERY_DOMAIN = (
    b"serverware.publicNitroLiveVerificationResultSigningRecovery/v1\x00"
)

COSE_ALG_ES384 = -35
NITRO_USER_DATA_PREFIX = b"serverware:nitro-production-claims:v2:"
MAX_JSON_BYTES = 64 * 1024 * 1024
MAX_NITRO_BYTES = 64 * 1024
MAX_CERT_BYTES = 64 * 1024
MAX_CERTIFICATES = 16
MAX_ARRAY_ITEMS = 100_000
MAX_TRANSCRIPT_EVENTS = 100_000
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
MAX_CIPHERTEXT_BYTES = 64 * 1024
MAX_VALIDITY_SECONDS = 600
MAX_CURRENT_HEAD_AUTHORIZATION_SECONDS = 30
MAX_CURRENT_HEAD_REDEMPTION_SECONDS = 30
MAX_LIVE_WITNESS_HEAD_SECONDS = 30
MAX_PROTECTED_LIVE_WITNESS_STATE_SECONDS = 30
MAX_RELEASE_VALIDITY_SECONDS = 900
MAX_U64 = (1 << 64) - 1
PUBLIC_NITRO_CANONICAL_INTEGER_MAX = (1 << 63) - 1
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA384_RE = re.compile(r"^sha384:[0-9a-f]{96}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,255}$")
PUBLIC_NITRO_PROVIDER_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$",
    re.ASCII,
)
ENCLAVE_PROVIDER_RE = re.compile(
    r"^enclave-[A-Za-z0-9._:@+-]{1,120}$"
)
WITNESS_STORE_IDENTIFIER_RE = re.compile(
    r"^[a-z0-9][a-z0-9._:/-]{1,126}[a-z0-9]$"
)
UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
IMAGE_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

LANE_ORDER = (
    "approval-review",
    "browser-python-compatibility",
    "chromium-compatibility",
    "clean-room",
    "credential-constraints",
    "credential-constraints-proxy",
    "host-python-compatibility",
    "internal-service-auth",
    "jit-transaction-sqlite-full",
    "onboarding-evidence",
    "portal-browser-oauth",
    "proxy-python-compatibility",
    "rust-decision-gate-tests",
    "webauthn-attestation",
)
IMAGE_ORDER = tuple(f"lane-{name}" for name in LANE_ORDER) + (
    "npm-publish-companion",
)
BASE_LANE_ENVIRONMENT = {
    "HOME": "/work/home",
    "LANG": "C",
    "LC_ALL": "C",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONHASHSEED": "0",
    "PYTHONNOUSERSITE": "1",
    "TMPDIR": "/work/tmp",
    "TZ": "UTC",
    "XDG_RUNTIME_DIR": "/run/serverware-runtime",
}
PORTAL_DYNAMIC_ENVIRONMENT = [
    "SERVERWARE_ATTEMPT",
    "SERVERWARE_LANE",
    "SERVERWARE_LEASE_ID",
    "SERVERWARE_MANIFEST_SHA256",
    "SERVERWARE_NPM_COMPANION_IMAGE_ID",
    "SERVERWARE_NPM_ENTRYPOINT_SHA256",
    "SERVERWARE_NPM_NODE_SHA256",
    "SERVERWARE_NPM_PACKAGE_SHA256",
    "SERVERWARE_ONE_USE_NONCE",
    "SERVERWARE_PROMOTION_RECEIPT_SHA256",
    "SERVERWARE_WATCHDOG_ENDPOINT",
    "SERVERWARE_WATCHDOG_TLS_SPKI_SHA256",
]
SOURCE_CONTRACTS = {
    "approval-review": {
        "exact": ["scripts/oci_lane_entrypoint.py", "scripts/test_approval_review.py"],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "browser-python-compatibility": {"exact": ["scripts/oci_lane_entrypoint.py"], "prefixes": []},
    "chromium-compatibility": {"exact": ["scripts/oci_lane_entrypoint.py"], "prefixes": []},
    "clean-room": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_agent_trust_clean_room.py",
            "scripts/verify_offline_artifact_manifest.py",
        ],
        "prefixes": ["serverware_agent_trust/"],
    },
    "credential-constraints": {
        "exact": ["scripts/oci_lane_entrypoint.py", "scripts/test_credential_constraints.py"],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "credential-constraints-proxy": {
        "exact": ["scripts/oci_lane_entrypoint.py", "scripts/test_credential_constraints.py"],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "host-python-compatibility": {"exact": ["scripts/oci_lane_entrypoint.py"], "prefixes": []},
    "internal-service-auth": {
        "exact": ["scripts/oci_lane_entrypoint.py", "scripts/test_internal_service_auth.py"],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "jit-transaction-sqlite-full": {
        "exact": ["scripts/oci_lane_entrypoint.py", "scripts/test_jit_transaction_state.py"],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "onboarding-evidence": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_onboarding_evidence.py",
            "scripts/verify_onboarding_evidence.py",
        ],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "portal-browser-oauth": {
        "exact": [
            "scripts/oauth_provider_simulator.py",
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_portal_browser_oauth.py",
        ],
        "prefixes": [
            "data-plane/decision-gate-rs/",
            "serverware/",
            "serverware_agent_trust/",
        ],
    },
    "proxy-python-compatibility": {"exact": ["scripts/oci_lane_entrypoint.py"], "prefixes": []},
    "rust-decision-gate-tests": {"exact": [], "prefixes": ["data-plane/decision-gate-rs/"]},
    "webauthn-attestation": {
        "exact": ["scripts/oci_lane_entrypoint.py", "scripts/test_webauthn_attestation.py"],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
}
DEPENDENCY_CAPABILITIES = {
    "browser-runtime": ["chromium", "python"],
    "clean-room-runtime": ["packaging-25.0", "python", "sealed-wheelhouse"],
    "npm-11.8-runtime": ["node", "npm-11.8"],
    "python-runtime": ["python"],
    "rust-runtime": ["rust-test-binary"],
}
MATERIALS = (
    "broker-kek",
    "ca",
    "credentials",
    "release",
    "response",
    "tls",
)
TRUST_KEY_ROLES = (
    "sourceGitInventory",
    "sourceUntrackedApproval",
    "buildWatchdog",
    "promotion",
    "builderA",
    "builderB",
    "manifestV6EifBuilder",
    "completion",
    "completionCheckpoint",
    "witness",
    "kmsAudit",
    "clientState",
    "clientStateCheckpoint",
    "stateCommit",
    "currentHeadAuthorization",
    "currentHeadRedemption",
)
ALLOWED_CERT_SIGNATURE_OIDS = frozenset(
    {
        "1.2.840.10045.4.3.2",
        "1.2.840.10045.4.3.3",
        "1.2.840.10045.4.3.4",
        "1.2.840.113549.1.1.11",
        "1.2.840.113549.1.1.12",
        "1.2.840.113549.1.1.13",
    }
)
PROTECTED_STATE_PROVENANCE = (
    "client-or-out-of-band-pinned-protected-state/v1"
)
STABLE_DYNAMIC_FIELD_NAMES = frozenset(
    {
        "actionauthorization",
        "callernonce",
        "callernoncesha256",
        "challenge",
        "challengenonce",
        "challengenoncesha256",
        "connectionid",
        "evidence",
        "evidencebodysha256",
        "expiresatunix",
        "httprequest",
        "issuedatunix",
        "livesession",
        "livesessionproof",
        "nonce",
        "noncesha256",
        "oneuse",
        "producerrequest",
        "producerrequestsha256",
        "request",
        "requestbodysha256",
        "session",
        "tlsbinding",
        "tlsbindingsha256",
    }
)


class VerificationError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def canonical_json_bytes(value: Any) -> bytes:
    validate_json_shape(value, label="canonical JSON")
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha384(value: bytes) -> str:
    return "sha384:" + hashlib.sha384(value).hexdigest()


def sha256_json(value: Any) -> str:
    return sha256(canonical_json_bytes(value))


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"JSON object duplicates key {key!r}")
        result[key] = value
    return result


def reject_float(_: str) -> None:
    raise VerificationError("floating-point JSON values are not accepted")


def parse_json(raw: bytes, label: str) -> Any:
    require(len(raw) <= MAX_JSON_BYTES, f"{label} exceeds {MAX_JSON_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"{label} is not UTF-8") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicate_pairs,
            parse_float=reject_float,
            parse_constant=reject_float,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise VerificationError(f"{label} is not strict JSON") from exc
    validate_json_shape(value, label=label)
    return value


def external_counter_field(name: str, value: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    return (
        normalized == "ordinal"
        or normalized.endswith("generation")
        or normalized.endswith("epoch")
        or normalized.endswith("sequence")
        or normalized.endswith("treesize")
        or normalized.endswith("index")
    )


def validate_json_shape(
    value: Any,
    *,
    label: str,
    depth: int = 0,
    field_name: str | None = None,
) -> None:
    require(depth <= 64, f"{label} exceeds the nesting limit")
    if field_name is not None and external_counter_field(field_name, value):
        require(
            type(value) is int and value >= 0,
            f"{label} {field_name} must be an unsigned integer",
        )
    if isinstance(value, dict):
        require(len(value) <= MAX_ARRAY_ITEMS, f"{label} has too many object fields")
        for key, child in value.items():
            require(
                isinstance(key, str)
                and 0 < len(key) <= 256
                and "\x00" not in key
                and unicodedata.normalize("NFC", key) == key
                and not any(0xD800 <= ord(character) <= 0xDFFF for character in key),
                f"{label} contains an invalid object key",
            )
            validate_json_shape(
                child,
                label=label,
                depth=depth + 1,
                field_name=key,
            )
    elif isinstance(value, list):
        require(len(value) <= MAX_ARRAY_ITEMS, f"{label} has too many array items")
        for child in value:
            validate_json_shape(child, label=label, depth=depth + 1)
    elif isinstance(value, str):
        require(len(value.encode("utf-8")) <= MAX_JSON_BYTES, f"{label} string is too large")
        require("\x00" not in value, f"{label} contains NUL")
        require(
            unicodedata.normalize("NFC", value) == value
            and not any(0xD800 <= ord(character) <= 0xDFFF for character in value),
            f"{label} contains non-NFC or surrogate text",
        )
    elif value is None or isinstance(value, bool):
        return
    elif type(value) is int:
        require(
            -(1 << 63) <= value <= MAX_U64,
            f"{label} integer is outside signed-64/u64 range",
        )
    else:
        raise VerificationError(f"{label} contains an unsupported JSON value")


def reject_public_secret_fields(value: Any, *, path: str = "$") -> None:
    forbidden = {
        "authorization",
        "clientsecret",
        "cookie",
        "password",
        "privatekey",
        "refreshtoken",
        "accesstoken",
        "bearertoken",
    }
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            require(
                not any(token in normalized for token in forbidden),
                f"public evidence contains secret-bearing field at {path}.{key}",
            )
            reject_public_secret_fields(child, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_public_secret_fields(child, path=f"{path}[{index}]")


def read_regular(path: Path, *, label: str, max_bytes: int = MAX_JSON_BYTES) -> bytes:
    raw_path = require_normalized_absolute_path(
        os.fspath(path),
        f"{label} path",
    )
    path = Path(raw_path)
    parts = path.parts
    fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in parts[1:-1]:
            require(component not in {"", ".", ".."}, f"{label} path is not canonical")
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=fd,
            )
            os.close(fd)
            fd = next_fd
        leaf = os.open(
            parts[-1],
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=fd,
        )
        try:
            before = os.fstat(leaf)
            require(stat.S_ISREG(before.st_mode), f"{label} is not a regular file")
            require(before.st_nlink == 1, f"{label} must have one hard link")
            require(0 <= before.st_size <= max_bytes, f"{label} exceeds its size bound")
            chunks: list[bytes] = []
            remaining = before.st_size
            while remaining:
                chunk = os.read(leaf, min(remaining, 1024 * 1024))
                require(bool(chunk), f"{label} changed during read")
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(leaf)
            require(
                (
                    before.st_dev,
                    before.st_ino,
                    before.st_mode,
                    before.st_nlink,
                    before.st_size,
                    before.st_mtime_ns,
                )
                == (
                    after.st_dev,
                    after.st_ino,
                    after.st_mode,
                    after.st_nlink,
                    after.st_size,
                    after.st_mtime_ns,
                ),
                f"{label} changed during read",
            )
            return b"".join(chunks)
        finally:
            os.close(leaf)
    except OSError as exc:
        raise VerificationError(f"{label} could not be opened safely: {exc}") from exc
    finally:
        os.close(fd)


def load_json_file(path: Path, label: str) -> tuple[Any, bytes]:
    raw = read_regular(path, label=label)
    return parse_json(raw, label), raw


def exact_keys(value: Any, keys: Iterable[str], label: str) -> dict[str, Any]:
    required = set(keys)
    validate_json_shape(value, label=label)
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == required, f"{label} fields are not exact")
    return value


def verify_detached_proof_headers(value: Any) -> dict[str, str]:
    headers = exact_keys(
        value,
        DETACHED_PROOF_HEADERS,
        "signed detached proof-header schema",
    )
    require(
        headers == DETACHED_PROOF_HEADERS,
        "signed detached proof-header schema differs from the producer contract",
    )
    return headers


def require_sha256(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, f"{label} is not canonical SHA-256")
    return value


def require_sha384(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA384_RE.fullmatch(value) is not None, f"{label} is not canonical SHA-384")
    return value


def require_identifier(value: Any, label: str) -> str:
    require(isinstance(value, str) and IDENTIFIER_RE.fullmatch(value) is not None, f"{label} is invalid")
    return value


def require_public_nitro_provider(value: Any, label: str) -> str:
    require(
        isinstance(value, str)
        and PUBLIC_NITRO_PROVIDER_RE.fullmatch(value) is not None,
        f"{label} is invalid",
    )
    return value


def require_uint(value: Any, label: str, *, maximum: int = MAX_U64) -> int:
    require(type(value) is int and 0 <= value <= maximum, f"{label} is invalid")
    return value


def require_positive_uint(
    value: Any,
    label: str,
    *,
    maximum: int = MAX_U64,
) -> int:
    result = require_uint(value, label, maximum=maximum)
    require(result >= 1, f"{label} must be positive")
    return result


def require_normalized_absolute_path(value: Any, label: str) -> str:
    require(
        isinstance(value, str)
        and 1 < len(value) <= 4096
        and value.startswith("/")
        and not value.endswith("/")
        and "//" not in value
        and "\x00" not in value,
        f"{label} is not a bounded absolute path",
    )
    parts = value.split("/")[1:]
    require(
        bool(parts)
        and all(part not in {"", ".", ".."} for part in parts)
        and os.path.normpath(value) == value,
        f"{label} is not normalized or contains a dot component",
    )
    return value


def reject_dynamic_stable_fields(
    value: Any,
    *,
    label: str,
    path: str = "$",
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", key.lower())
            require(
                normalized not in STABLE_DYNAMIC_FIELD_NAMES,
                f"{label} contains dynamic field at {path}.{key}",
            )
            reject_dynamic_stable_fields(
                child,
                label=label,
                path=f"{path}.{key}",
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_dynamic_stable_fields(
                child,
                label=label,
                path=f"{path}[{index}]",
            )


def validate_non_actionable_final_result(
    document: Any,
    *,
    label: str,
) -> dict[str, Any]:
    require(isinstance(document, dict), f"{label} must be an object")
    forbidden = {
        "final_completion",
        "finalCompletion",
        "ok",
        "stateCommitRequired",
    }
    require(
        not forbidden.intersection(document),
        f"{label} contains conventional success fields",
    )
    require(
        document.get("verificationOk") is True
        and document.get("finalCompletionVerified") is True
        and document.get("actionAuthorization") is None
        and document.get("okForAction") is False,
        f"{label} is not explicitly verified and non-actionable",
    )
    return document


LIVE_ATTESTATION_EVIDENCE_FIELDS = frozenset(
    {
        "evidenceBodySha256",
        "deliveryRebindSha256",
        "liveSessionProofSha256",
        "liveSessionSignatureSha256",
        "liveWitnessHeadPayloadSha256",
        "committedNonceAuthorityVerifierStateSha256",
        "nonceAuthorityAssuranceEvidenceSha256",
        "nonceAuthorityAssuranceSha256",
        "nonceAuthorityHighWaterCommitmentSha256",
        "nonceAuthorityStateSha256",
        "nonceAuthorityVerifierChallengeSha256",
        "nonceAuthorityVerifierStateAuthorizationSha256",
        "nonceAuthorityVerifierStateCommitReceiptSha256",
        "nonceAuthorityVerifierStateSigningKeySpkiSha256",
        "nonceAuthorityVerifierStateStoreIdentitySha256",
        "nonceConsumptionReceiptSha256",
        "nonceConsumptionSha256",
        "nonceStoreKeySpkiSha256",
        "priorProtectedLiveWitnessStateSha256",
        "priorNonceAuthorityVerifierStateSha256",
        "producerBindingSha256",
        "producerEphemeralKeySpkiSha256",
        "producerInvocationSha256",
        "producerRequestSha256",
        "protectedLiveWitnessStateSha256",
        "releaseConfigSha256",
        "releaseIdentitySha256",
        "stableReleaseStatementSha256",
        "witnessGeneration",
        "witnessCurrentRequestSha256",
        "witnessSequence",
        "witnessStoreIdentitySha256",
        "witnessVerifierChallengeSha256",
        "nonceAuthorityEpoch",
        "nonceAuthorityGeneration",
        "nonceAuthoritySequence",
        "nonceAuthorityVerifierStateStoreGeneration",
    }
)


def validate_non_actionable_live_result(
    document: Any,
) -> dict[str, Any]:
    result = exact_keys(
        document,
        {
            "actionAuthorization",
            "apiVersion",
            "committedNonceAuthorityVerifierState",
            "evidence",
            "finalCompletionVerified",
            "okForAction",
            "verificationOk",
        },
        "live attestation verification result",
    )
    require(
        result["apiVersion"] == LIVE_ATTESTATION_RESULT_VERSION
        and result["verificationOk"] is True
        and result["finalCompletionVerified"] is True
        and result["actionAuthorization"] is None
        and result["okForAction"] is False,
        "live attestation result is not explicitly verified and non-actionable",
    )
    evidence = exact_keys(
        result["evidence"],
        LIVE_ATTESTATION_EVIDENCE_FIELDS,
        "live attestation verification evidence",
    )
    for field, value in evidence.items():
        if field.endswith("Sha256"):
            require_sha256(
                value,
                f"live attestation evidence {field}",
            )
    committed_state = exact_keys(
        result["committedNonceAuthorityVerifierState"],
        {
            "apiVersion",
            "assuranceSha256",
            "authorityEpoch",
            "authorityGeneration",
            "commitOperationIdBase64url",
            "committedAtUnix",
            "highWaterCommitmentSha256",
            "highWaterReceiptSha256",
            "highWaterSequence",
            "priorVerifierStateSha256",
            "stateStoreGeneration",
            "stateStoreHeadSha256",
            "stateStoreIdentitySha256",
        },
        "committed nonce authority verifier state result",
    )
    require(
        committed_state["apiVersion"]
        == NONCE_AUTHORITY_VERIFIER_STATE_VERSION
        and sha256_json(committed_state)
        == evidence[
            "committedNonceAuthorityVerifierStateSha256"
        ],
        "live result crossed its committed nonce authority verifier state",
    )
    b64url_decode_exact(
        committed_state["commitOperationIdBase64url"],
        "committed nonce authority verifier-state operation",
        exact_bytes=32,
    )
    for field in (
        "assuranceSha256",
        "highWaterCommitmentSha256",
        "highWaterReceiptSha256",
        "priorVerifierStateSha256",
        "stateStoreHeadSha256",
        "stateStoreIdentitySha256",
    ):
        require_sha256(
            committed_state[field],
            f"committed nonce authority verifier state {field}",
        )
    require(
        committed_state["assuranceSha256"]
        == evidence["nonceAuthorityAssuranceSha256"]
        and committed_state["authorityEpoch"]
        == evidence["nonceAuthorityEpoch"]
        and committed_state["authorityGeneration"]
        == evidence["nonceAuthorityGeneration"]
        and committed_state["highWaterCommitmentSha256"]
        == evidence["nonceAuthorityHighWaterCommitmentSha256"]
        and committed_state["highWaterReceiptSha256"]
        == evidence["nonceConsumptionReceiptSha256"]
        and committed_state["highWaterSequence"]
        == evidence["nonceAuthoritySequence"]
        and committed_state["priorVerifierStateSha256"]
        == evidence["priorNonceAuthorityVerifierStateSha256"]
        and committed_state["stateStoreGeneration"]
        == evidence[
            "nonceAuthorityVerifierStateStoreGeneration"
        ]
        and committed_state["stateStoreIdentitySha256"]
        == evidence[
            "nonceAuthorityVerifierStateStoreIdentitySha256"
        ],
        "live result nonce authority state and evidence disagree",
    )
    for field in (
        "authorityEpoch",
        "authorityGeneration",
        "committedAtUnix",
        "highWaterSequence",
        "stateStoreGeneration",
    ):
        require_positive_uint(
            committed_state[field],
            f"committed nonce authority verifier state {field}",
        )
    for field in (
        "nonceAuthorityEpoch",
        "nonceAuthorityGeneration",
        "nonceAuthoritySequence",
        "nonceAuthorityVerifierStateStoreGeneration",
    ):
        require_positive_uint(
            evidence[field],
            f"live attestation evidence {field}",
        )
    require_positive_uint(
        evidence["witnessGeneration"],
        "live attestation witness generation",
    )
    require_positive_uint(
        evidence["witnessSequence"],
        "live attestation witness sequence",
    )
    return result


def b64url_decode(value: Any, label: str, *, max_bytes: int) -> bytes:
    require(isinstance(value, str) and value and "=" not in value, f"{label} is not unpadded base64url")
    require(re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None, f"{label} is not unpadded base64url")
    require(len(value) % 4 != 1, f"{label} is not canonical base64url")
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, binascii.Error) as exc:
        raise VerificationError(f"{label} is invalid base64url") from exc
    require(len(decoded) <= max_bytes, f"{label} exceeds its byte bound")
    require(
        base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") == value,
        f"{label} is not canonical base64url",
    )
    return decoded


def b64url_decode_exact(
    value: Any,
    label: str,
    *,
    exact_bytes: int,
) -> bytes:
    decoded = b64url_decode(value, label, max_bytes=exact_bytes)
    require(
        len(decoded) == exact_bytes,
        f"{label} must contain exactly {exact_bytes} bytes",
    )
    return decoded


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def strict_b64_decode(value: Any, label: str, *, max_bytes: int) -> bytes:
    require(isinstance(value, str) and value, f"{label} is missing")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise VerificationError(f"{label} is not strict base64") from exc
    require(len(decoded) <= max_bytes, f"{label} exceeds its byte bound")
    require(base64.b64encode(decoded).decode("ascii") == value, f"{label} is not canonical base64")
    return decoded


def load_ed25519_key_file(
    document: Any,
    label: str,
) -> tuple[Ed25519PublicKey, str, str, str]:
    document = exact_keys(
        document,
        {"fileBase64url", "keyFileSha256", "keyId", "rawKeySha256"},
        label,
    )
    key_file = b64url_decode(
        document["fileBase64url"], f"{label} file", max_bytes=8192
    )
    require(
        document["keyFileSha256"] == sha256(key_file),
        f"{label} raw key-file digest mismatch",
    )
    try:
        if key_file.startswith(b"-----BEGIN PUBLIC KEY-----"):
            key = serialization.load_pem_public_key(key_file)
        else:
            key = serialization.load_der_public_key(key_file)
    except ValueError as exc:
        raise VerificationError(f"{label} is not a public key file") from exc
    require(isinstance(key, Ed25519PublicKey), f"{label} is not Ed25519")
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw = key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    key_id = sha256(der)
    raw_key_id = sha256(raw)
    require(document["keyId"] == key_id, f"{label} DER SPKI key ID mismatch")
    require(
        document["rawKeySha256"] == raw_key_id,
        f"{label} raw Ed25519 key digest mismatch",
    )
    return key, key_id, sha256(key_file), raw_key_id


def ed25519_raw_key_id(key: Ed25519PublicKey) -> str:
    return sha256(
        key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )


def load_ed25519_key(pem: Any, label: str) -> tuple[Ed25519PublicKey, str]:
    require(isinstance(pem, str) and len(pem) <= 8192, f"{label} PEM is invalid")
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise VerificationError(f"{label} is not a public PEM key") from exc
    require(isinstance(key, Ed25519PublicKey), f"{label} is not Ed25519")
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return key, sha256(der)


def embedded_ed25519_spki(
    value: Any,
    *,
    label: str,
) -> tuple[Ed25519PublicKey, str]:
    der = b64url_decode(value, label, max_bytes=256)
    try:
        key = serialization.load_der_public_key(der)
    except ValueError as exc:
        raise VerificationError(f"{label} is not a DER public key") from exc
    require(isinstance(key, Ed25519PublicKey), f"{label} is not Ed25519")
    canonical_der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    require(der == canonical_der, f"{label} is not canonical DER SPKI")
    return key, sha256(canonical_der)


def verify_ed25519(
    key: Ed25519PublicKey,
    signature_b64url: Any,
    message: bytes,
    label: str,
) -> None:
    signature = b64url_decode_exact(
        signature_b64url,
        f"{label} signature",
        exact_bytes=64,
    )
    try:
        key.verify(signature, message)
    except InvalidSignature as exc:
        raise VerificationError(f"{label} signature is invalid") from exc


def verify_standard_envelope(
    document: Any,
    *,
    api_version: str,
    domain: bytes,
    key: Ed25519PublicKey,
    key_id: str,
    label: str,
) -> tuple[dict[str, Any], str]:
    document = exact_keys(
        document,
        {"apiVersion", "payload", "payloadSha256", "signingKeyId", "signature"},
        label,
    )
    require(document["apiVersion"] == api_version, f"{label} apiVersion mismatch")
    payload = document["payload"]
    require(isinstance(payload, dict), f"{label} payload must be an object")
    payload_digest = sha256_json(payload)
    require(document["payloadSha256"] == payload_digest, f"{label} payload digest mismatch")
    require(document["signingKeyId"] == key_id, f"{label} signer is not independently trusted")
    signed = domain + canonical_json_bytes(
        {"payload": payload, "payloadSha256": payload_digest}
    )
    verify_ed25519(key, document["signature"], signed, label)
    return payload, sha256(canonical_json_bytes(document) + b"\n")


def verify_service_envelope(
    document: Any,
    *,
    api_version: str,
    domain: bytes,
    key: Ed25519PublicKey,
    key_id: str,
    label: str,
) -> tuple[dict[str, Any], str]:
    envelope = exact_keys(
        document,
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "signatureAlgorithm",
            "signatureBase64url",
            "signingKeyId",
            "signingKeySpkiSha256",
        },
        label,
    )
    payload = envelope["payload"]
    require(isinstance(payload, dict), f"{label} payload must be an object")
    payload_sha256 = sha256_json(payload)
    require(
        envelope["apiVersion"] == api_version
        and envelope["payloadSha256"] == payload_sha256
        and envelope["signatureAlgorithm"] == "Ed25519"
        and envelope["signingKeyId"] == key_id
        and envelope["signingKeySpkiSha256"] == key_id,
        f"{label} version, digest, or signer mismatch",
    )
    verify_ed25519(
        key,
        envelope["signatureBase64url"],
        domain
        + canonical_json_bytes(
            {
                "payload": payload,
                "payloadSha256": payload_sha256,
            }
        ),
        label,
    )
    return payload, sha256_json(envelope)


def verify_existing_envelope(
    document: Any,
    *,
    api_version: str,
    domain: bytes,
    key: Ed25519PublicKey,
    key_id: str,
    key_file_sha256: str,
    raw_key_sha256: str,
    label: str,
) -> tuple[dict[str, Any], str]:
    document = exact_keys(
        document,
        {"apiVersion", "payload", "payloadSha256", "signature"},
        label,
    )
    require(document["apiVersion"] == api_version, f"{label} apiVersion mismatch")
    payload = document["payload"]
    require(isinstance(payload, dict), f"{label} payload must be an object")
    payload_digest = sha256_json(payload)
    require(document["payloadSha256"] == payload_digest, f"{label} payload digest mismatch")
    signature = exact_keys(
        document["signature"],
        {"algorithm", "domain", "keyFileSha256", "rawKeySha256", "value"},
        f"{label} signature",
    )
    require(signature["algorithm"] == "Ed25519", f"{label} algorithm mismatch")
    require(signature["domain"] == domain[:-1].decode("ascii"), f"{label} signature domain mismatch")
    require(
        signature["keyFileSha256"] == key_file_sha256,
        f"{label} signer key-file bytes are not independently trusted",
    )
    require(
        signature["rawKeySha256"] == raw_key_sha256
        and signature["rawKeySha256"] == ed25519_raw_key_id(key),
        f"{label} raw signer is not independently trusted",
    )
    raw = strict_b64_decode(signature["value"], f"{label} signature", max_bytes=64)
    require(len(raw) == 64, f"{label} signature is not 64 bytes")
    try:
        key.verify(
            raw,
            domain
            + canonical_json_bytes(
                {"payload": payload, "payloadSha256": payload_digest}
            ),
        )
    except InvalidSignature as exc:
        raise VerificationError(f"{label} signature is invalid") from exc
    return payload, sha256(canonical_json_bytes(document) + b"\n")


def verify_tls_scope_envelope(
    document: Any,
    *,
    key: Ed25519PublicKey,
    key_id: str,
) -> tuple[dict[str, Any], str]:
    document = exact_keys(
        document,
        {"apiVersion", "payload", "payloadSha256", "signature", "signingKeyId"},
        "TLS scope envelope",
    )
    require(
        document["apiVersion"] == TLS_SCOPE_ENVELOPE_VERSION
        and document["signingKeyId"] == key_id,
        "TLS scope envelope version or signer mismatch",
    )
    payload = document["payload"]
    require(isinstance(payload, dict), "TLS scope envelope payload is invalid")
    payload_sha256 = sha256_json(payload)
    require(
        document["payloadSha256"] == payload_sha256,
        "TLS scope envelope payload digest mismatch",
    )
    signature = document["signature"]
    require(
        isinstance(signature, str) and signature.startswith("ed25519:"),
        "TLS scope envelope signature encoding is invalid",
    )
    verify_ed25519(
        key,
        signature.split(":", 1)[1],
        TLS_SCOPE_ENVELOPE_DOMAIN
        + canonical_json_bytes(
            {"payload": payload, "payloadSha256": payload_sha256}
        ),
        "TLS scope envelope",
    )
    return payload, sha256(canonical_json_bytes(document) + b"\n")


def validate_cbor_encoding(raw: bytes, label: str) -> None:
    cursor = 0
    items = 0

    def read_length(additional: int) -> int:
        nonlocal cursor
        if additional < 24:
            return additional
        byte_count = {24: 1, 25: 2, 26: 4, 27: 8}.get(additional)
        require(byte_count is not None, f"{label} uses indefinite or reserved CBOR")
        require(cursor + byte_count <= len(raw), f"{label} CBOR is truncated")
        value = int.from_bytes(raw[cursor : cursor + byte_count], "big")
        cursor += byte_count
        minimum = {1: 24, 2: 1 << 8, 4: 1 << 16, 8: 1 << 32}[byte_count]
        require(value >= minimum, f"{label} CBOR integer/length is non-minimal")
        return value

    def walk(depth: int) -> None:
        nonlocal cursor, items
        require(depth <= 64, f"{label} CBOR nesting is excessive")
        require(cursor < len(raw), f"{label} CBOR is truncated")
        items += 1
        require(items <= MAX_ARRAY_ITEMS, f"{label} CBOR item count is excessive")
        initial = raw[cursor]
        cursor += 1
        major = initial >> 5
        additional = initial & 0x1F
        if major in {0, 1}:
            read_length(additional)
            return
        if major in {2, 3}:
            length = read_length(additional)
            require(cursor + length <= len(raw), f"{label} CBOR string is truncated")
            cursor += length
            return
        if major == 4:
            length = read_length(additional)
            require(length <= MAX_ARRAY_ITEMS, f"{label} CBOR array is excessive")
            for _ in range(length):
                walk(depth + 1)
            return
        if major == 5:
            length = read_length(additional)
            require(length <= MAX_ARRAY_ITEMS, f"{label} CBOR map is excessive")
            observed: set[bytes] = set()
            previous_order: tuple[int, bytes] | None = None
            for _ in range(length):
                key_start = cursor
                walk(depth + 1)
                encoded_key = raw[key_start:cursor]
                require(
                    encoded_key not in observed,
                    f"{label} CBOR map contains a duplicate key",
                )
                order = (len(encoded_key), encoded_key)
                require(
                    previous_order is None or order > previous_order,
                    f"{label} CBOR map keys are not in canonical order",
                )
                previous_order = order
                observed.add(encoded_key)
                walk(depth + 1)
            return
        if major == 6:
            read_length(additional)
            walk(depth + 1)
            return
        require(
            major == 7 and additional in {20, 21, 22},
            f"{label} CBOR uses an unsupported simple or floating value",
        )

    walk(0)
    require(cursor == len(raw), f"{label} has trailing CBOR data")


def parse_cbor_one(raw: bytes, label: str) -> Any:
    validate_cbor_encoding(raw, label)
    stream = io.BytesIO(raw)
    try:
        value = cbor2.CBORDecoder(stream).decode()
    except Exception as exc:
        raise VerificationError(f"{label} is not valid CBOR") from exc
    require(stream.read(1) == b"", f"{label} has trailing CBOR data")
    return value


def certificate_time(cert: x509.Certificate, name: str) -> datetime:
    preferred = getattr(cert, f"{name}_utc", None)
    if preferred is not None:
        return preferred
    value = getattr(cert, name)
    return value.replace(tzinfo=timezone.utc)


def certificate_sha256(cert: x509.Certificate) -> str:
    return sha256(cert.public_bytes(serialization.Encoding.DER))


def verify_cert_signature(issuer: x509.Certificate, child: x509.Certificate) -> None:
    require(child.issuer == issuer.subject, "Nitro certificate issuer/subject mismatch")
    require(
        child.signature_algorithm_oid.dotted_string
        in ALLOWED_CERT_SIGNATURE_OIDS,
        "Nitro certificate signature algorithm is not allowed",
    )
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm,
            )
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        else:
            raise VerificationError("unsupported Nitro certificate issuer key")
    except InvalidSignature as exc:
        raise VerificationError("Nitro certificate signature is invalid") from exc


def verify_crl_signature(
    issuer: x509.Certificate,
    crl: x509.CertificateRevocationList,
) -> None:
    require(crl.issuer == issuer.subject, "Nitro CRL issuer mismatch")
    require(
        crl.signature_algorithm_oid.dotted_string in ALLOWED_CERT_SIGNATURE_OIDS,
        "Nitro CRL signature algorithm is not allowed",
    )
    key = issuer.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                padding.PKCS1v15(),
                crl.signature_hash_algorithm,
            )
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                ec.ECDSA(crl.signature_hash_algorithm),
            )
        else:
            raise VerificationError("unsupported Nitro CRL issuer key")
    except InvalidSignature as exc:
        raise VerificationError("Nitro CRL signature is invalid") from exc


def basic_constraints(cert: x509.Certificate, label: str) -> x509.BasicConstraints:
    try:
        return cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound as exc:
        raise VerificationError(f"{label} lacks BasicConstraints") from exc


def verify_nitro_chain(
    leaf_der: bytes,
    bundle_der: list[bytes],
    roots: list[x509.Certificate],
    crls: list[x509.CertificateRevocationList],
    certificate_profile: dict[str, Any],
    *,
    at: datetime,
    now_at: datetime,
) -> tuple[x509.Certificate, x509.Certificate]:
    require(1 <= len(bundle_der) <= MAX_CERTIFICATES, "Nitro cabundle size is invalid")
    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
        supplied = [x509.load_der_x509_certificate(item) for item in bundle_der]
    except ValueError as exc:
        raise VerificationError("Nitro certificate chain contains invalid DER") from exc
    root_by_der = {
        cert.public_bytes(serialization.Encoding.DER): cert for cert in roots
    }
    require(len(root_by_der) == len(roots) and bool(roots), "AWS Nitro trust roots are empty or duplicated")
    candidates = [leaf, *supplied]
    require(
        len({cert.public_bytes(serialization.Encoding.DER) for cert in candidates})
        == len(candidates),
        "Nitro certificate chain contains duplicates",
    )
    chain = [leaf]
    unused = list(supplied)
    trusted_root: x509.Certificate | None = None
    while len(chain) <= MAX_CERTIFICATES:
        current = chain[-1]
        current_der = current.public_bytes(serialization.Encoding.DER)
        if current_der in root_by_der:
            trusted_root = root_by_der[current_der]
            break
        issuers = [candidate for candidate in unused if candidate.subject == current.issuer]
        issuers.extend(
            root
            for root in roots
            if root.subject == current.issuer
            and root.public_bytes(serialization.Encoding.DER)
            not in {item.public_bytes(serialization.Encoding.DER) for item in issuers}
        )
        require(len(issuers) == 1, "Nitro certificate chain is missing or ambiguous")
        issuer = issuers[0]
        verify_cert_signature(issuer, current)
        chain.append(issuer)
        if issuer in unused:
            unused.remove(issuer)
    require(trusted_root is not None, "Nitro certificate chain does not terminate at an independent AWS root")
    require(not unused, "Nitro cabundle contains certificates outside the verified chain")
    verify_cert_signature(trusted_root, trusted_root)
    for index, cert in enumerate(chain):
        require(
            certificate_time(cert, "not_valid_before")
            <= at
            <= certificate_time(cert, "not_valid_after")
            and certificate_time(cert, "not_valid_before")
            <= now_at
            <= certificate_time(cert, "not_valid_after"),
            "Nitro certificate is not valid at issuance and verification time",
        )
        constraints = basic_constraints(cert, f"Nitro certificate {index}")
        require(
            constraints.ca is (index != 0),
            "Nitro leaf/CA BasicConstraints role mismatch",
        )
        if constraints.path_length is not None:
            require(
                constraints.path_length >= max(0, index - 1),
                "Nitro CA BasicConstraints path length is exceeded",
            )
        try:
            key_usage = cert.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            ).value
        except x509.ExtensionNotFound as exc:
            raise VerificationError(
                f"Nitro certificate {index} lacks KeyUsage"
            ) from exc
        if index == 0:
            require(
                key_usage.digital_signature
                and not key_usage.key_cert_sign
                and not key_usage.crl_sign,
                "Nitro leaf KeyUsage is not the production signing profile",
            )
            try:
                eku = cert.extensions.get_extension_for_oid(
                    ExtensionOID.EXTENDED_KEY_USAGE
                ).value
                eku_oids = sorted(oid.dotted_string for oid in eku)
            except x509.ExtensionNotFound:
                eku_oids = []
            require(
                eku_oids
                == certificate_profile["allowedLeafExtendedKeyUsageOids"],
                "Nitro leaf ExtendedKeyUsage differs from the pinned profile",
            )
        else:
            require(
                key_usage.key_cert_sign and key_usage.crl_sign,
                "Nitro CA KeyUsage lacks certificate/CRL signing",
            )
    for index, cert in enumerate(chain[:-1]):
        issuer = chain[index + 1]
        matching_crls = [crl for crl in crls if crl.issuer == issuer.subject]
        require(
            len(matching_crls) == 1,
            "Nitro certificate does not have exactly one current issuer CRL",
        )
        crl = matching_crls[0]
        verify_crl_signature(issuer, crl)
        last_update = getattr(crl, "last_update_utc", None) or crl.last_update.replace(
            tzinfo=timezone.utc
        )
        next_update = getattr(crl, "next_update_utc", None)
        if next_update is None and crl.next_update is not None:
            next_update = crl.next_update.replace(tzinfo=timezone.utc)
        require(
            next_update is not None
            and last_update <= now_at <= next_update
            and last_update <= at <= next_update,
            "Nitro revocation material is stale at issuance or verification",
        )
        require(
            crl.get_revoked_certificate_by_serial_number(cert.serial_number)
            is None,
            "Nitro certificate serial is revoked",
        )
    leaf_key = leaf.public_key()
    require(
        isinstance(leaf_key, ec.EllipticCurvePublicKey)
        and leaf_key.curve.name == "secp384r1",
        "Nitro leaf key must be ECDSA P-384",
    )
    return leaf, trusted_root


def decode_cose_es384(signature: bytes) -> bytes:
    require(len(signature) == 96, "Nitro COSE ES384 signature must be 96 bytes")
    r = int.from_bytes(signature[:48], "big")
    s = int.from_bytes(signature[48:], "big")
    require(r > 0 and s > 0, "Nitro COSE signature scalar is zero")
    return encode_dss_signature(r, s)


def expected_user_data(claims: dict[str, Any]) -> bytes:
    return (
        NITRO_USER_DATA_PREFIX
        + hashlib.sha256(canonical_json_bytes(claims)).hexdigest().encode("ascii")
    )


def verify_nitro_document(
    raw: bytes,
    *,
    claims: dict[str, Any] | None,
    expected_user_data_bytes: bytes | None = None,
    challenge: bytes,
    expected_pcrs: dict[str, str],
    expected_eif: str,
    roots: list[x509.Certificate],
    crls: list[x509.CertificateRevocationList],
    certificate_profile: dict[str, Any],
    expected_module_id: str,
    now: int | None,
    max_age: int,
    future_skew: int,
) -> dict[str, Any]:
    require(1 <= len(raw) <= MAX_NITRO_BYTES, "Nitro attestation document size is invalid")
    require(
        expected_pcrs.get("PCR0") == expected_eif,
        "independently expected EIF digest does not map exactly to PCR0",
    )
    cose = parse_cbor_one(raw, "Nitro attestation document")
    require(isinstance(cose, CBORTag) and cose.tag == 18, "production Nitro evidence must be tagged COSE_Sign1")
    require(isinstance(cose.value, list) and len(cose.value) == 4, "Nitro COSE_Sign1 shape is invalid")
    protected, unprotected, payload_raw, signature = cose.value
    require(isinstance(protected, bytes) and protected, "Nitro protected header is missing")
    require(unprotected == {}, "Nitro unprotected COSE headers are forbidden")
    require(isinstance(payload_raw, bytes) and isinstance(signature, bytes), "Nitro COSE payload/signature types are invalid")
    protected_map = parse_cbor_one(protected, "Nitro protected header")
    require(protected_map == {1: COSE_ALG_ES384}, "Nitro COSE protected header must contain only ES384")
    payload = parse_cbor_one(payload_raw, "Nitro attestation payload")
    required_payload = {
        "module_id",
        "timestamp",
        "digest",
        "pcrs",
        "certificate",
        "cabundle",
        "public_key",
        "user_data",
        "nonce",
    }
    require(isinstance(payload, dict) and set(payload) == required_payload, "Nitro payload fields are not exact")
    require(isinstance(payload["module_id"], str) and 1 <= len(payload["module_id"]) <= 256, "Nitro module_id is invalid")
    require(
        payload["module_id"] == expected_module_id,
        "Nitro module_id does not match the expected enclave instance",
    )
    require(payload["digest"] == "SHA384", "Nitro digest algorithm is not SHA384")
    timestamp_ms = require_uint(payload["timestamp"], "Nitro timestamp")
    issued_at = timestamp_ms // 1000
    require(issued_at <= now + future_skew, "Nitro attestation is issued in the future")
    require(now - issued_at <= max_age, "Nitro attestation is stale")
    require(payload["nonce"] == challenge, "Nitro nonce does not match the caller challenge")
    required_user_data = (
        expected_user_data(claims)
        if claims is not None
        else expected_user_data_bytes
    )
    require(
        isinstance(required_user_data, bytes)
        and payload["user_data"] == required_user_data,
        "Nitro user_data does not bind the exact expected payload",
    )
    require(isinstance(payload["certificate"], bytes) and len(payload["certificate"]) <= MAX_CERT_BYTES, "Nitro leaf certificate is invalid")
    require(isinstance(payload["cabundle"], list), "Nitro cabundle is invalid")
    cabundle: list[bytes] = []
    for item in payload["cabundle"]:
        require(isinstance(item, bytes) and 1 <= len(item) <= MAX_CERT_BYTES, "Nitro cabundle certificate is invalid")
        cabundle.append(item)
    attestation_time = datetime.fromtimestamp(timestamp_ms / 1000, tz=timezone.utc)
    leaf, root = verify_nitro_chain(
        payload["certificate"],
        cabundle,
        roots,
        crls,
        certificate_profile,
        at=attestation_time,
        now_at=datetime.fromtimestamp(now, tz=timezone.utc),
    )
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload_raw])
    try:
        leaf.public_key().verify(
            decode_cose_es384(signature),
            sig_structure,
            ec.ECDSA(hashes.SHA384()),
        )
    except InvalidSignature as exc:
        raise VerificationError("Nitro COSE signature is invalid") from exc
    pcrs = payload["pcrs"]
    require(isinstance(pcrs, dict), "Nitro PCR map is invalid")
    normalized: dict[str, str] = {}
    for index in (0, 1, 2):
        value = pcrs.get(index)
        require(isinstance(value, bytes) and len(value) == 48, f"Nitro PCR{index} is invalid")
        require(value != b"\x00" * 48, "Nitro debug PCRs are not accepted")
        normalized[f"PCR{index}"] = "sha384:" + value.hex()
    require(set(pcrs) == {0, 1, 2}, "Nitro PCR map must be exactly PCR0/PCR1/PCR2")
    require(normalized == expected_pcrs, "Nitro PCR0/PCR1/PCR2 do not match independent expectations")
    if claims is not None:
        require(
            claims["eif"]["imageSha384"] == expected_eif,
            "Nitro claims do not bind the independently expected EIF",
        )
    recipient_der = payload["public_key"]
    require(isinstance(recipient_der, bytes) and 1 <= len(recipient_der) <= 4096, "Nitro recipient public key is invalid")
    try:
        recipient = serialization.load_der_public_key(recipient_der)
    except ValueError as exc:
        raise VerificationError("Nitro recipient public key is invalid DER") from exc
    require(
        isinstance(recipient, rsa.RSAPublicKey)
        and 2048 <= recipient.key_size <= 4096
        and recipient.public_numbers().e == 65537,
        "Nitro recipient key must be RSA 2048-4096/e=65537",
    )
    return {
        "raw": raw,
        "attestationDocumentSha256": sha256(raw),
        "issuedAtUnix": issued_at,
        "moduleId": payload["module_id"],
        "pcrs": normalized,
        "leafCertificateSha256": certificate_sha256(leaf),
        "rootCertificateSha256": certificate_sha256(root),
        "recipientPublicKeyDerB64": base64.urlsafe_b64encode(recipient_der).decode("ascii").rstrip("="),
        "recipientPublicKeySha256": sha256(recipient_der),
        "userDataSha256": sha256(payload["user_data"]),
    }


def load_trust_roots(
    document: Any,
    raw: bytes,
    *,
    independently_expected_sha256: str,
) -> dict[str, Any]:
    document = exact_keys(
        document,
        {
            "apiVersion",
            "awsNitroCrlsDerBase64url",
            "awsNitroRootCertificatesPem",
            "keys",
            "nitroCertificateProfile",
        },
        "public trust roots",
    )
    require(document["apiVersion"] == TRUST_ROOTS_VERSION, "public trust roots apiVersion mismatch")
    trust_root_bundle_sha256 = sha256(raw)
    require(
        independently_expected_sha256 == trust_root_bundle_sha256,
        "public trust-root bundle differs from the independently supplied digest",
    )
    roots_pem = document["awsNitroRootCertificatesPem"]
    require(
        isinstance(roots_pem, list) and 1 <= len(roots_pem) <= MAX_CERTIFICATES,
        "AWS Nitro root inventory is invalid",
    )
    roots: list[x509.Certificate] = []
    for index, pem in enumerate(roots_pem):
        require(isinstance(pem, str) and len(pem) <= MAX_CERT_BYTES, f"AWS Nitro root {index} PEM is invalid")
        try:
            cert = x509.load_pem_x509_certificate(pem.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise VerificationError(f"AWS Nitro root {index} is invalid") from exc
        require(basic_constraints(cert, f"AWS Nitro root {index}").ca, f"AWS Nitro root {index} is not a CA")
        roots.append(cert)
    require(
        len({certificate_sha256(cert) for cert in roots}) == len(roots),
        "AWS Nitro roots are duplicated",
    )
    crls_doc = document["awsNitroCrlsDerBase64url"]
    require(
        isinstance(crls_doc, list) and 1 <= len(crls_doc) <= MAX_CERTIFICATES,
        "AWS Nitro CRL inventory is invalid",
    )
    crls: list[x509.CertificateRevocationList] = []
    for index, encoded in enumerate(crls_doc):
        der = b64url_decode(
            encoded, f"AWS Nitro CRL {index}", max_bytes=MAX_CERT_BYTES
        )
        try:
            crls.append(x509.load_der_x509_crl(der))
        except ValueError as exc:
            raise VerificationError(f"AWS Nitro CRL {index} is invalid") from exc
    require(
        len(
            {
                sha256(crl.public_bytes(serialization.Encoding.DER))
                for crl in crls
            }
        )
        == len(crls),
        "AWS Nitro CRLs are duplicated",
    )
    certificate_profile = exact_keys(
        document["nitroCertificateProfile"],
        {"allowedLeafExtendedKeyUsageOids", "profileId"},
        "Nitro certificate profile",
    )
    require(
        certificate_profile["profileId"]
        == "aws-nitro-attestation-pki-offline-v1",
        "Nitro certificate profile is unsupported",
    )
    eku_oids = certificate_profile["allowedLeafExtendedKeyUsageOids"]
    require(
        isinstance(eku_oids, list)
        and eku_oids == sorted(set(eku_oids))
        and all(
            isinstance(oid, str)
            and re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", oid) is not None
            for oid in eku_oids
        ),
        "Nitro certificate EKU profile is invalid",
    )
    keys_doc = exact_keys(document["keys"], TRUST_KEY_ROLES, "public trust-root keys")
    keys: dict[str, Ed25519PublicKey] = {}
    key_ids: dict[str, str] = {}
    key_file_sha256s: dict[str, str] = {}
    raw_key_sha256s: dict[str, str] = {}
    for role in TRUST_KEY_ROLES:
        key, key_id, key_file_sha256, raw_key_sha256 = load_ed25519_key_file(
            keys_doc[role], f"{role} trust root"
        )
        keys[role] = key
        key_ids[role] = key_id
        key_file_sha256s[role] = key_file_sha256
        raw_key_sha256s[role] = raw_key_sha256
    require(len(set(key_ids.values())) == len(key_ids), "independent trust-root roles reuse a key")
    return {
        "awsRoots": roots,
        "awsCrls": crls,
        "certificateProfile": certificate_profile,
        "keys": keys,
        "keyIds": key_ids,
        "keyFileSha256s": key_file_sha256s,
        "rawKeySha256s": raw_key_sha256s,
        "trustRootBundleSha256": trust_root_bundle_sha256,
    }


def validate_completion_identity(document: Any, *, label: str) -> dict[str, Any]:
    identity = exact_keys(
        document,
        {
            "apiVersion",
            "challengeNonceSha256",
            "coreDigests",
            "pipeline",
            "releaseGeneration",
            "rollbackEpoch",
        },
        label,
    )
    require(
        identity["apiVersion"] == COMPLETION_IDENTITY_VERSION,
        f"{label} apiVersion mismatch",
    )
    require(
        identity["pipeline"] == PIPELINE,
        f"{label} pipeline mismatch",
    )
    require_sha256(identity["challengeNonceSha256"], f"{label} challenge nonce")
    require_uint(identity["releaseGeneration"], f"{label} release generation")
    require_uint(identity["rollbackEpoch"], f"{label} rollback epoch")
    core_digests = exact_keys(
        identity["coreDigests"],
        COMPLETION_CORE_DIGEST_FIELDS,
        f"{label} core digests",
    )
    for name, digest in core_digests.items():
        require_sha256(digest, f"{label} {name} core digest")
    return identity


PUBLIC_ATTESTATION_COMPONENT_PIN_FIELDS = frozenset(
    {
        "nonceStoreIdentitySha256",
        "nonceStoreKeySpkiSha256",
        "producerDescriptorSha256",
        "producerExecutableSha256",
        "producerRequestSchemaSha256",
        "sandboxDescriptorSha256",
        "sandboxLauncherSha256",
        "witnessStoreIdentitySha256",
        "witnessStoreKeySpkiSha256",
    }
)
PUBLIC_ATTESTATION_STATEMENT_PIN_FIELDS = frozenset(
    {
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
    }
)


def validate_public_attestation_component_pins(
    document: Any,
    *,
    label: str,
) -> dict[str, str]:
    pins = exact_keys(
        document,
        PUBLIC_ATTESTATION_COMPONENT_PIN_FIELDS,
        label,
    )
    for field, value in pins.items():
        require_sha256(value, f"{label} {field}")
    return pins


def validate_public_attestation_statement_pins(
    document: Any,
    *,
    label: str,
) -> dict[str, str]:
    pins = exact_keys(
        document,
        PUBLIC_ATTESTATION_STATEMENT_PIN_FIELDS,
        label,
    )
    for field, value in pins.items():
        require_sha256(value, f"{label} {field}")
    return pins


def component_pins_from_statement(
    statement_pins: dict[str, str],
) -> dict[str, str]:
    return {
        "nonceStoreIdentitySha256":
        statement_pins["nonceStoreIdentitySha256"],
        "nonceStoreKeySpkiSha256":
        statement_pins["nonceStoreKeySpkiSha256"],
        "producerDescriptorSha256":
        statement_pins["descriptorSha256"],
        "producerExecutableSha256":
        statement_pins["executableSha256"],
        "producerRequestSchemaSha256":
        statement_pins["producerRequestSchemaSha256"],
        "sandboxDescriptorSha256":
        statement_pins["sandboxDescriptorSha256"],
        "sandboxLauncherSha256":
        statement_pins["sandboxLauncherSha256"],
        "witnessStoreIdentitySha256":
        statement_pins["witnessStoreIdentitySha256"],
        "witnessStoreKeySpkiSha256":
        statement_pins["witnessStoreKeySpkiSha256"],
    }


def validate_release_identity(
    document: Any,
    *,
    label: str,
) -> dict[str, Any]:
    reject_dynamic_stable_fields(document, label=label)
    identity = exact_keys(
        document,
        {
            "apiVersion",
            "build",
            "configuration",
            "eif",
            "monotonicRelease",
            "pipeline",
            "policy",
            "source",
        },
        label,
    )
    require(
        identity["apiVersion"] == RELEASE_IDENTITY_VERSION
        and identity["pipeline"] == PIPELINE,
        f"{label} version or pipeline mismatch",
    )
    source = exact_keys(
        identity["source"],
        {
            "sourceClosureSha256",
            "sourceInputApprovalSha256",
            "sourceInputManifestFileSha256",
            "sourceInputManifestPayloadSha256",
        },
        f"{label} source roots",
    )
    build = exact_keys(
        identity["build"],
        {
            "builderCoreSha256s",
            "buildWatchdogReceiptSha256",
            "candidateManifestFileSha256",
            "candidateManifestPayloadSha256",
            "dependencyClosureSha256",
            "eifBuildCoreSha256",
            "importedImageMappingsSha256",
            "promotedManifestSha256",
            "promotionReceiptSha256",
            "releaseCoreSha256",
        },
        f"{label} build roots",
    )
    eif = exact_keys(
        identity["eif"],
        {"imageSha384", "pcrs"},
        f"{label} EIF roots",
    )
    policy = exact_keys(
        identity["policy"],
        {"hash", "sequence"},
        f"{label} policy root",
    )
    configuration = exact_keys(
        identity["configuration"],
        {
            "caSpkiSha256",
            "publicAttestation",
            "releaseKeySpkiSha256",
            "responseKeySpkiSha256",
            "tlsScopeSigningKeySpkiSha256",
            "trustRootBundleSha256",
            "witnessKeySpkiSha256",
        },
        f"{label} configuration roots",
    )
    monotonic = exact_keys(
        identity["monotonicRelease"],
        {
            "releaseGeneration",
            "rollbackEpoch",
        },
        f"{label} monotonic release state",
    )
    digest_fields = [
        *source.items(),
        *[
            (key, value)
            for key, value in build.items()
            if key != "builderCoreSha256s"
        ],
        ("policy hash", policy["hash"]),
        *configuration.items(),
    ]
    for field, value in digest_fields:
        if field != "publicAttestation":
            require_sha256(value, f"{label} {field}")
    validate_public_attestation_component_pins(
        configuration["publicAttestation"],
        label=f"{label} public attestation component pins",
    )
    builders = build["builderCoreSha256s"]
    require(
        isinstance(builders, list)
        and len(builders) == 2
        and builders == sorted(set(builders)),
        f"{label} builder roots are invalid",
    )
    for digest in builders:
        require_sha256(digest, f"{label} builder statement")
    image_sha384 = require_sha384(
        eif["imageSha384"], f"{label} EIF image"
    )
    pcrs = exact_keys(
        eif["pcrs"], {"PCR0", "PCR1", "PCR2"}, f"{label} PCRs"
    )
    for name, digest in pcrs.items():
        require_sha384(digest, f"{label} {name}")
    require(
        pcrs["PCR0"] == image_sha384,
        f"{label} EIF image does not match PCR0",
    )
    require(
        require_uint(policy["sequence"], f"{label} policy sequence") >= 1,
        f"{label} policy sequence is not positive",
    )
    require(
        require_uint(
            monotonic["releaseGeneration"],
            f"{label} release generation",
        )
        >= 1,
        f"{label} release generation is not positive",
    )
    require_uint(
        monotonic["rollbackEpoch"],
        f"{label} rollback epoch",
    )
    return identity


def reconstruct_release_identity(
    *,
    identity: dict[str, Any],
    candidate_to_eif: dict[str, Any],
    trust: dict[str, Any],
) -> dict[str, Any]:
    payload = identity["payload"]
    runtime = identity["runtime"]
    custody_materials = identity["custodyMaterials"]
    release_core_payload = identity["releaseCore"]["payload"]
    document = {
        "apiVersion": RELEASE_IDENTITY_VERSION,
        "build": {
            "builderCoreSha256s":
            release_core_payload["builderCoreSha256s"],
            "buildWatchdogReceiptSha256":
            payload["buildWatchdogReceiptSha256"],
            "candidateManifestFileSha256":
            payload["candidateManifestFileSha256"],
            "candidateManifestPayloadSha256":
            payload["candidateManifestPayloadSha256"],
            "dependencyClosureSha256":
            payload["dependencyClosureSha256"],
            "eifBuildCoreSha256":
            candidate_to_eif["coreSha256"],
            "importedImageMappingsSha256":
            payload["importedImageMappingsSha256"],
            "promotedManifestSha256":
            payload["promotedManifestSha256"],
            "promotionReceiptSha256":
            payload["promotionReceiptSha256"],
            "releaseCoreSha256": identity["releaseCoreSha256"],
        },
        "configuration": {
            "caSpkiSha256": runtime["caSpkiSha256"],
            "publicAttestation":
            validate_public_attestation_component_pins(
                runtime["publicAttestation"],
                label="reconstructed public attestation component pins",
            ),
            "releaseKeySpkiSha256":
            custody_materials["release"]["identitySpkiSha256"],
            "responseKeySpkiSha256":
            custody_materials["response"]["identitySpkiSha256"],
            "tlsScopeSigningKeySpkiSha256":
            runtime["tlsScopeSigningKeySpkiSha256"],
            "trustRootBundleSha256": trust[
                "trustRootBundleSha256"
            ],
            "witnessKeySpkiSha256": trust["keyIds"]["witness"],
        },
        "eif": {
            "imageSha384": payload["eifImageSha384"],
            "pcrs": payload["pcrs"],
        },
        "monotonicRelease": {
            "releaseGeneration": runtime["releaseGeneration"],
            "rollbackEpoch": runtime["rollbackEpoch"],
        },
        "pipeline": PIPELINE,
        "policy": {
            "hash": runtime["policyHash"],
            "sequence": runtime["policySequence"],
        },
        "source": {
            "sourceClosureSha256": payload["sourceClosureSha256"],
            "sourceInputApprovalSha256":
            payload["sourceInputApprovalSha256"],
            "sourceInputManifestFileSha256":
            payload["sourceInputManifestFileSha256"],
            "sourceInputManifestPayloadSha256":
            payload["sourceInputManifestPayloadSha256"],
        },
    }
    return validate_release_identity(
        document, label="reconstructed stable release identity"
    )


def verify_stable_release(
    document: Any,
    *,
    trust: dict[str, Any],
) -> dict[str, Any]:
    payload, statement_sha256 = verify_standard_envelope(
        document,
        api_version=STABLE_RELEASE_STATEMENT_VERSION,
        domain=STABLE_RELEASE_STATEMENT_DOMAIN,
        key=trust["keys"]["completion"],
        key_id=trust["keyIds"]["completion"],
        label="stable release statement",
    )
    payload = exact_keys(
        payload,
        {
            "attestationPins",
            "releaseIdentity",
            "releaseIdentitySha256",
            "trustRootBundleSha256",
        },
        "stable release statement payload",
    )
    release_identity = validate_release_identity(
        payload["releaseIdentity"],
        label="authenticated stable release identity",
    )
    release_identity_sha256 = sha256_json(release_identity)
    attestation_pins = validate_public_attestation_statement_pins(
        payload["attestationPins"],
        label="stable release public attestation pins",
    )
    release_component_pins = (
        release_identity["configuration"]["publicAttestation"]
    )
    require(
        payload["releaseIdentitySha256"] == release_identity_sha256
        and payload["trustRootBundleSha256"]
        == trust["trustRootBundleSha256"]
        == release_identity["configuration"]["trustRootBundleSha256"]
        == attestation_pins["trustRootsSha256"]
        and component_pins_from_statement(attestation_pins)
        == release_component_pins
        and trust["keyIds"]["completion"]
        == release_identity["configuration"]["releaseKeySpkiSha256"]
        and trust["keyIds"]["witness"]
        == release_identity["configuration"]["witnessKeySpkiSha256"],
        "stable release statement crossed its identity or pinned trust roots",
    )
    return {
        "attestationPins": attestation_pins,
        "releaseIdentity": release_identity,
        "releaseIdentitySha256": release_identity_sha256,
        "statementSha256": statement_sha256,
    }


def verify_live_witness_head(
    document: Any,
    *,
    trust: dict[str, Any],
    expected_release_identity: dict[str, Any],
    expected_witness: dict[str, Any],
    expected_invocation_binding: dict[str, Any],
    expected_live_witness_payload_sha256: str,
    now: int,
) -> dict[str, Any]:
    release_identity = validate_release_identity(
        expected_release_identity,
        label="verified stable release identity",
    )
    payload, _ = verify_standard_envelope(
        document,
        api_version=LIVE_WITNESS_HEAD_VERSION,
        domain=LIVE_WITNESS_HEAD_DOMAIN,
        key=trust["keys"]["witness"],
        key_id=trust["keyIds"]["witness"],
        label="live witness head",
    )
    require(
        document["payloadSha256"]
        == require_sha256(
            expected_live_witness_payload_sha256,
            "protected live-witness payload",
        ),
        "live witness head payload differs from its signed protected checkpoint",
    )
    payload = exact_keys(
        payload,
        {
            "expiresAtUnix",
            "generation",
            "headSha256",
            "invocationBinding",
            "issuedAtUnix",
            "releaseIdentitySha256",
            "rollbackEpoch",
            "sequence",
            "treeSize",
        },
        "live witness head payload",
    )
    issued = require_positive_uint(
        payload["issuedAtUnix"], "live witness issue time"
    )
    expires = require_positive_uint(
        payload["expiresAtUnix"], "live witness expiry"
    )
    generation = require_positive_uint(
        payload["generation"], "live witness generation"
    )
    rollback_epoch = require_uint(
        payload["rollbackEpoch"], "live witness rollback epoch"
    )
    sequence = require_positive_uint(
        payload["sequence"], "live witness sequence"
    )
    tree_size = require_positive_uint(
        payload["treeSize"], "live witness tree size"
    )
    head_sha256 = require_sha256(
        payload["headSha256"], "live witness head"
    )
    invocation_binding = validate_attestation_witness_invocation_binding(
        payload["invocationBinding"],
        label="live witness invocation binding",
    )
    require(
        issued <= now < expires
        and 1 <= expires - issued <= MAX_LIVE_WITNESS_HEAD_SECONDS
        and generation
        == release_identity["monotonicRelease"]["releaseGeneration"]
        and rollback_epoch
        == release_identity["monotonicRelease"]["rollbackEpoch"]
        and sequence >= 1
        and tree_size >= 1
        and payload["releaseIdentitySha256"]
        == sha256_json(release_identity),
        "live witness head is stale or crossed its stable release",
    )
    require(
        invocation_binding == expected_invocation_binding,
        "live witness head crossed its signed protected invocation",
    )
    witness = {
        "generation": generation,
        "headSha256": head_sha256,
        "rollbackEpoch": rollback_epoch,
        "sequence": sequence,
        "treeSize": tree_size,
    }
    expected = validate_live_witness_coordinates(
        expected_witness,
        label="signed protected current witness",
        current=False,
    )
    require(
        witness == witness_coordinates(expected),
        "live witness head is not the signed protected current head",
    )
    return witness


def validate_attestation_witness_invocation_binding(
    document: Any,
    *,
    label: str,
) -> dict[str, Any]:
    binding = exact_keys(
        document,
        {
            "apiVersion",
            "currentRequestSha256",
            "producerEphemeralKeySpkiSha256",
            "producerInvocationSha256",
            "producerRequestSha256",
            "tlsBindingSha256",
            "verifierChallengeBase64url",
        },
        label,
    )
    require(
        binding["apiVersion"]
        == ATTESTATION_WITNESS_INVOCATION_BINDING_VERSION,
        f"{label} apiVersion mismatch",
    )
    for field in (
        "currentRequestSha256",
        "producerEphemeralKeySpkiSha256",
        "producerInvocationSha256",
        "producerRequestSha256",
        "tlsBindingSha256",
    ):
        require_sha256(binding[field], f"{label} {field}")
    b64url_decode_exact(
        binding["verifierChallengeBase64url"],
        f"{label} verifier challenge",
        exact_bytes=32,
    )
    return binding


def validate_witness_store_identity(
    document: Any,
    *,
    label: str,
) -> dict[str, Any]:
    identity = exact_keys(
        document,
        {
            "apiVersion",
            "assurance",
            "deploymentId",
            "serviceId",
            "storageBackend",
        },
        label,
    )
    require(
        identity["apiVersion"] == LIVE_WITNESS_STORE_IDENTITY_VERSION
        and identity["assurance"]
        == "externallyWitnessedRollbackProtected"
        and identity["storageBackend"] == "external-linearizable-cas",
        f"{label} is not the production external rollback-protected contract",
    )
    for field in ("deploymentId", "serviceId"):
        require(
            isinstance(identity[field], str)
            and WITNESS_STORE_IDENTIFIER_RE.fullmatch(
                identity[field]
            )
            is not None,
            f"{label} {field} is invalid",
        )
    return identity


def validate_live_witness_coordinates(
    document: Any,
    *,
    label: str,
    current: bool,
) -> dict[str, Any]:
    fields = {
        "checkpointSha256",
        "generation",
        "headSha256",
        "releaseIdentitySha256",
        "rollbackEpoch",
        "sequence",
        "treeSize",
    }
    if current:
        fields.add("liveWitnessHeadPayloadSha256")
    checkpoint = exact_keys(document, fields, label)
    for field in (
        "checkpointSha256",
        "headSha256",
        "releaseIdentitySha256",
    ):
        require_sha256(checkpoint[field], f"{label} {field}")
    if current:
        require_sha256(
            checkpoint["liveWitnessHeadPayloadSha256"],
            f"{label} live witness payload",
        )
    require_positive_uint(checkpoint["generation"], f"{label} generation")
    require_uint(checkpoint["rollbackEpoch"], f"{label} rollback epoch")
    require_positive_uint(checkpoint["sequence"], f"{label} sequence")
    require_positive_uint(checkpoint["treeSize"], f"{label} tree size")
    return checkpoint


def witness_coordinates(checkpoint: dict[str, Any]) -> dict[str, Any]:
    return {
        "generation": checkpoint["generation"],
        "headSha256": checkpoint["headSha256"],
        "rollbackEpoch": checkpoint["rollbackEpoch"],
        "sequence": checkpoint["sequence"],
        "treeSize": checkpoint["treeSize"],
    }


def prior_checkpoint_projection(
    checkpoint: dict[str, Any],
) -> dict[str, Any]:
    return {
        "checkpointSha256": checkpoint["checkpointSha256"],
        **witness_coordinates(checkpoint),
        "releaseIdentitySha256": checkpoint[
            "releaseIdentitySha256"
        ],
    }


def live_witness_head_chain_sha256(
    checkpoint: dict[str, Any],
    previous: dict[str, Any] | None,
) -> str:
    return sha256(
        LIVE_WITNESS_HEAD_CHAIN_DOMAIN
        + canonical_json_bytes(
            {
                "checkpointSha256":
                checkpoint["checkpointSha256"],
                "previousHeadSha256": (
                    None if previous is None else previous["headSha256"]
                ),
            }
        )
    )


def validate_live_witness_cas_receipt(
    document: Any,
    *,
    label: str,
) -> dict[str, Any]:
    receipt = exact_keys(
        document,
        {
            "apiVersion",
            "checkpointSha256",
            "committedAtUnix",
            "committedRollbackContinuityCommitmentSha256",
            "generation",
            "previousRollbackContinuityCommitmentSha256",
            "releaseIdentitySha256",
            "sequence",
            "transactionIdBase64url",
            "witnessStoreIdentitySha256",
        },
        label,
    )
    require(
        receipt["apiVersion"] == LIVE_WITNESS_STORE_CAS_RECEIPT_VERSION,
        f"{label} apiVersion mismatch",
    )
    for field in (
        "checkpointSha256",
        "committedRollbackContinuityCommitmentSha256",
        "releaseIdentitySha256",
    ):
        require_sha256(receipt[field], f"{label} {field}")
    previous_commitment = receipt[
        "previousRollbackContinuityCommitmentSha256"
    ]
    if previous_commitment is not None:
        require_sha256(
            previous_commitment,
            f"{label} previous rollback commitment",
        )
    require_positive_uint(
        receipt["committedAtUnix"],
        f"{label} commit time",
    )
    require_positive_uint(receipt["generation"], f"{label} generation")
    require_positive_uint(receipt["sequence"], f"{label} sequence")
    require_sha256(
        receipt["witnessStoreIdentitySha256"],
        f"{label} witness-store identity",
    )
    b64url_decode_exact(
        receipt["transactionIdBase64url"],
        f"{label} transaction ID",
        exact_bytes=32,
    )
    return receipt


def live_witness_rollback_commitment_sha256(
    *,
    current: dict[str, Any],
    previous_commitment_sha256: str | None,
    witness_store_identity_sha256: str,
    witness_store_key_spki_sha256: str,
) -> str:
    return sha256(
        LIVE_WITNESS_CONTINUITY_DOMAIN
        + canonical_json_bytes(
            {
                "apiVersion": LIVE_WITNESS_CONTINUITY_VERSION,
                "checkpointSha256": current["checkpointSha256"],
                "generation": current["generation"],
                "headSha256": current["headSha256"],
                "previousRollbackContinuityCommitmentSha256":
                previous_commitment_sha256,
                "releaseIdentitySha256":
                current["releaseIdentitySha256"],
                "rollbackEpoch": current["rollbackEpoch"],
                "sequence": current["sequence"],
                "treeSize": current["treeSize"],
                "witnessStoreIdentitySha256":
                witness_store_identity_sha256,
                "witnessStoreKeySpkiSha256":
                witness_store_key_spki_sha256,
            }
        )
    )


def validate_protected_live_witness_state(
    document: Any,
    *,
    expected_release_identity_sha256: str,
    signing_key: Ed25519PublicKey,
    signing_key_id: str,
    expected_store_identity_sha256: str,
    expected_witness_signing_key_id: str,
    now: int,
    require_current: bool,
) -> dict[str, Any]:
    payload, envelope_sha256 = verify_standard_envelope(
        document,
        api_version=PROTECTED_LIVE_WITNESS_STATE_VERSION,
        domain=PROTECTED_LIVE_WITNESS_STATE_DOMAIN,
        key=signing_key,
        key_id=signing_key_id,
        label="signed protected live-witness state",
    )
    state = exact_keys(
        payload,
        {
            "checkpointCasReceipt",
            "current",
            "expiresAtUnix",
            "invocationBinding",
            "issuedAtUnix",
            "previous",
            "releaseIdentitySha256",
            "rollbackContinuityCommitmentSha256",
            "storeAssurance",
            "witnessSigningKeyId",
            "witnessStoreIdentity",
            "witnessStoreIdentitySha256",
            "witnessStoreKeySpkiSha256",
        },
        "signed protected live-witness payload",
    )
    release_identity_sha256 = require_sha256(
        expected_release_identity_sha256,
        "expected protected release identity",
    )
    witness_store_identity = validate_witness_store_identity(
        state["witnessStoreIdentity"],
        label="protected live-witness store identity",
    )
    witness_store_identity_sha256 = require_sha256(
        state["witnessStoreIdentitySha256"],
        "protected live-witness store identity digest",
    )
    issued = require_positive_uint(
        state["issuedAtUnix"],
        "protected live-witness issue time",
    )
    expires = require_positive_uint(
        state["expiresAtUnix"],
        "protected live-witness expiry",
    )
    require(
        state["releaseIdentitySha256"] == release_identity_sha256
        and state["storeAssurance"]
        == "externallyWitnessedRollbackProtected"
        == witness_store_identity["assurance"]
        and document["signingKeyId"] == signing_key_id
        and state["witnessStoreKeySpkiSha256"] == signing_key_id
        and state["witnessSigningKeyId"]
        == require_sha256(
            expected_witness_signing_key_id,
            "expected live-witness signing key",
        )
        and sha256_json(witness_store_identity)
        == witness_store_identity_sha256
        and witness_store_identity_sha256
        == require_sha256(
            expected_store_identity_sha256,
            "expected live-witness store identity",
        ),
        "protected live-witness state crossed its signed store or release trust",
    )
    require(
        issued < expires
        and expires - issued
        <= MAX_PROTECTED_LIVE_WITNESS_STATE_SECONDS
        and (not require_current or issued <= now < expires),
        "protected live-witness state is stale, future, or overlong",
    )
    current = validate_live_witness_coordinates(
        state["current"],
        label="protected current live-witness checkpoint",
        current=True,
    )
    previous_value = state["previous"]
    previous = (
        None
        if previous_value is None
        else validate_live_witness_coordinates(
            previous_value,
            label="protected prior live-witness checkpoint",
            current=False,
        )
    )
    receipt = validate_live_witness_cas_receipt(
        state["checkpointCasReceipt"],
        label="protected live-witness CAS receipt",
    )
    commitment = require_sha256(
        state["rollbackContinuityCommitmentSha256"],
        "protected live-witness rollback continuity commitment",
    )
    invocation_binding = validate_attestation_witness_invocation_binding(
        state["invocationBinding"],
        label="protected live-witness invocation binding",
    )
    receipt_previous_commitment = receipt[
        "previousRollbackContinuityCommitmentSha256"
    ]
    if previous is None:
        require(
            current["sequence"] == 1
            and receipt_previous_commitment is None,
            "initial protected live-witness state has a predecessor",
        )
    else:
        require(
            current["releaseIdentitySha256"]
            == previous["releaseIdentitySha256"]
            and current["generation"] == previous["generation"]
            and current["rollbackEpoch"] == previous["rollbackEpoch"]
            and current["sequence"] == previous["sequence"] + 1
            and current["treeSize"] >= previous["treeSize"]
            and receipt_previous_commitment is not None,
            "protected live-witness payload is not a monotonic prior-to-current transition",
        )
    require(
        current["releaseIdentitySha256"] == release_identity_sha256
        and (
            previous is None
            or previous["releaseIdentitySha256"]
            == release_identity_sha256
        )
        and current["headSha256"]
        == live_witness_head_chain_sha256(current, previous)
        and receipt["checkpointSha256"]
        == current["checkpointSha256"]
        and receipt["committedAtUnix"] <= issued
        and receipt["generation"] == current["generation"]
        and receipt["sequence"] == current["sequence"]
        and receipt["releaseIdentitySha256"]
        == release_identity_sha256
        and receipt["witnessStoreIdentitySha256"]
        == witness_store_identity_sha256
        and receipt[
            "committedRollbackContinuityCommitmentSha256"
        ]
        == commitment
        and commitment
        == live_witness_rollback_commitment_sha256(
            current=current,
            previous_commitment_sha256=receipt_previous_commitment,
            witness_store_identity_sha256=(
                witness_store_identity_sha256
            ),
            witness_store_key_spki_sha256=signing_key_id,
        ),
        "protected live-witness checkpoint, CAS receipt, or commitment is invalid",
    )
    return {
        "current": current,
        "envelopeSha256": envelope_sha256,
        "expiresAtUnix": expires,
        "issuedAtUnix": issued,
        "invocationBinding": invocation_binding,
        "payload": state,
        "previous": previous,
        "rollbackContinuityCommitmentSha256": commitment,
        "witnessStoreIdentity": witness_store_identity,
        "witnessStoreIdentitySha256":
        witness_store_identity_sha256,
    }


def verify_protected_live_witness_transition(
    current_document: Any,
    prior_document: Any,
    *,
    expected_release_identity: dict[str, Any],
    signing_key: Ed25519PublicKey,
    signing_key_id: str,
    expected_store_identity_sha256: str,
    expected_witness_signing_key_id: str,
    now: int,
) -> dict[str, Any]:
    release_identity_sha256 = sha256_json(
        validate_release_identity(
            expected_release_identity,
            label="protected witness stable release identity",
        )
    )
    prior = validate_protected_live_witness_state(
        prior_document,
        expected_release_identity_sha256=release_identity_sha256,
        signing_key=signing_key,
        signing_key_id=signing_key_id,
        expected_store_identity_sha256=(
            expected_store_identity_sha256
        ),
        expected_witness_signing_key_id=(
            expected_witness_signing_key_id
        ),
        now=now,
        require_current=False,
    )
    current = validate_protected_live_witness_state(
        current_document,
        expected_release_identity_sha256=release_identity_sha256,
        signing_key=signing_key,
        signing_key_id=signing_key_id,
        expected_store_identity_sha256=(
            expected_store_identity_sha256
        ),
        expected_witness_signing_key_id=(
            expected_witness_signing_key_id
        ),
        now=now,
        require_current=True,
    )
    prior_current = prior["current"]
    current_checkpoint = current["current"]
    same_checkpoint = current_checkpoint == prior_current
    one_step_advance = (
        current_checkpoint["sequence"]
        == prior_current["sequence"] + 1
    )
    require(
        current["witnessStoreIdentitySha256"]
        == prior["witnessStoreIdentitySha256"]
        and current_checkpoint["generation"]
        == prior_current["generation"]
        and current_checkpoint["rollbackEpoch"]
        == prior_current["rollbackEpoch"]
        and current_checkpoint["treeSize"] >= prior_current["treeSize"],
        "protected live-witness state is not a monotonic signed transition from the independently retained prior state",
    )
    if same_checkpoint:
        require(
            current["rollbackContinuityCommitmentSha256"]
            == prior["rollbackContinuityCommitmentSha256"]
            and current["previous"] == prior["previous"]
            and current["payload"]["checkpointCasReceipt"]
            == prior["payload"]["checkpointCasReceipt"]
            and prior["issuedAtUnix"] <= current["issuedAtUnix"],
            "current witness replay changed an unchanged checkpoint",
        )
    else:
        require(
            one_step_advance
            and current["previous"]
            == prior_checkpoint_projection(prior_current)
            and current["payload"]["checkpointCasReceipt"][
                "previousRollbackContinuityCommitmentSha256"
            ]
            == prior["rollbackContinuityCommitmentSha256"]
            and prior["issuedAtUnix"]
            <= current["payload"]["checkpointCasReceipt"][
                "committedAtUnix"
            ]
            <= current["issuedAtUnix"],
            "current witness skipped or rewrote the retained continuity floor",
        )
    current["priorEnvelopeSha256"] = prior["envelopeSha256"]
    current["priorState"] = prior
    return current


def verify_live_session_proof(
    document: Any,
    *,
    signature: str,
    response_signing_public_key_pem: str,
    evidence_body: bytes,
    caller_nonce: bytes,
    request_body: bytes,
    expected_tls_binding: dict[str, Any],
    delivery_rebind: Any | None = None,
    expected_release_identity: dict[str, Any],
    expected_witness: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    release_identity = validate_release_identity(
        expected_release_identity,
        label="verified stable release identity",
    )
    release_identity_sha256 = sha256_json(release_identity)
    proof = exact_keys(
        document,
        {
            "apiVersion",
            "callerNonceSha256",
            "evidenceBodySha256",
            "expiresAtUnix",
            "producedAtUnix",
            "releaseIdentity",
            "releaseIdentitySha256",
            "request",
            "responseSigningKeyId",
            "tlsBinding",
            "tlsBindingSha256",
            "witness",
        },
        "live session proof",
    )
    require(
        proof["apiVersion"] == LIVE_SESSION_PROOF_VERSION,
        "live session proof version is invalid",
    )
    proof_release_identity = validate_release_identity(
        proof["releaseIdentity"],
        label="live session stable release identity",
    )
    require(
        proof_release_identity == release_identity
        and proof["releaseIdentitySha256"] == release_identity_sha256,
        "live session proof crossed its stable release identity",
    )
    request = exact_keys(
        proof["request"],
        {"bodySha256", "method", "path"},
        "live session request",
    )
    witness = exact_keys(
        proof["witness"],
        {
            "generation",
            "headSha256",
            "rollbackEpoch",
            "sequence",
            "treeSize",
        },
        "live session witness",
    )
    expected_current_witness = exact_keys(
        expected_witness,
        {
            "generation",
            "headSha256",
            "rollbackEpoch",
            "sequence",
            "treeSize",
        },
        "independently expected current witness",
    )
    require(
        witness == expected_current_witness,
        "live session proof differs from the independently expected current witness",
    )
    tls_binding = exact_keys(
        proof["tlsBinding"],
        {
            "apiVersion",
            "bindingSha256",
            "connectionId",
            "connectionNonceSha256",
            "enclaveBootId",
            "enclaveInstanceId",
            "expiresAtUnix",
            "exporterLabel",
            "exporterSha256",
            "issuedAtUnix",
            "leafCertificateSha256",
            "leafSpkiSha256",
            "peerCertificateSha256",
            "peerIdentity",
            "peerSpkiSha256",
            "provider",
            "tlsKeyGeneration",
            "tlsScopeEnvelopeSha256",
            "tlsScopeKeyGeneration",
            "tlsScopeKeySpkiSha256",
            "tlsStackMeasurementSha256",
        },
        "live session authenticated TLS binding",
    )
    tls_binding_without_digest = {
        key: value
        for key, value in tls_binding.items()
        if key != "bindingSha256"
    }
    for field in (
        "bindingSha256",
        "connectionNonceSha256",
        "exporterSha256",
        "leafCertificateSha256",
        "leafSpkiSha256",
        "peerCertificateSha256",
        "peerSpkiSha256",
        "tlsScopeEnvelopeSha256",
        "tlsScopeKeySpkiSha256",
        "tlsStackMeasurementSha256",
    ):
        require_sha256(
            tls_binding[field], f"live TLS binding {field}"
        )
    require_positive_uint(
        tls_binding["issuedAtUnix"], "live TLS binding issue time"
    )
    require_positive_uint(
        tls_binding["expiresAtUnix"], "live TLS binding expiry"
    )
    require(
        require_uint(
            tls_binding["tlsKeyGeneration"],
            "live TLS key generation",
        )
        >= 1,
        "live TLS key generation is not positive",
    )
    require(
        require_uint(
            tls_binding["tlsScopeKeyGeneration"],
            "live TLS scope-key generation",
        )
        >= 1,
        "live TLS scope-key generation is not positive",
    )
    for field in (
        "connectionId",
        "enclaveBootId",
        "enclaveInstanceId",
        "peerIdentity",
    ):
        require_identifier(
            tls_binding[field], f"live TLS binding {field}"
        )
    require(
        tls_binding["apiVersion"] == TLS_SCOPE_VERSION
        and isinstance(tls_binding["provider"], str)
        and ENCLAVE_PROVIDER_RE.fullmatch(tls_binding["provider"])
        is not None
        and tls_binding["exporterLabel"]
        == "EXPORTER-Serverware-Attestation-v1"
        and tls_binding["bindingSha256"]
        == sha256_json(tls_binding_without_digest)
        and proof["tlsBindingSha256"]
        == tls_binding["bindingSha256"],
        "live session proof crossed its historical authenticated TLS scope",
    )
    produced = require_positive_uint(
        proof["producedAtUnix"], "live session production time"
    )
    expires = require_positive_uint(
        proof["expiresAtUnix"], "live session expiry"
    )
    require(
        produced <= now
        and 1 <= expires - produced <= 30
        and tls_binding["issuedAtUnix"] <= produced
        and expires <= tls_binding["expiresAtUnix"],
        "live session proof is stale, future, or overlong",
    )
    require(
        type(caller_nonce) is bytes
        and len(caller_nonce) == 32
        and type(request_body) is bytes
        and type(evidence_body) is bytes
        and proof["callerNonceSha256"] == sha256(caller_nonce)
        and proof["evidenceBodySha256"] == sha256(evidence_body)
        and request["method"] == "POST"
        and request["path"] == "/attestation/public-evidence"
        and request["bodySha256"] == sha256(request_body),
        "live session proof crossed its nonce, request, or response body",
    )
    require(
        require_uint(witness["generation"], "live witness generation")
        == release_identity["monotonicRelease"]["releaseGeneration"]
        and require_uint(
            witness["rollbackEpoch"], "live witness rollback epoch"
        )
        == release_identity["monotonicRelease"]["rollbackEpoch"],
        "live session witness crossed its stable release coordinates",
    )
    require(
        require_uint(witness["sequence"], "live witness sequence") >= 1
        and require_uint(
            witness["treeSize"], "live witness tree size"
        )
        >= 1,
        "live witness sequence or tree size is not positive",
    )
    require_sha256(witness["headSha256"], "live witness head")
    key, key_id = load_ed25519_key(
        response_signing_public_key_pem,
        "live session response signing public key",
    )
    require(
        key_id
        == release_identity["configuration"][
            "responseKeySpkiSha256"
        ]
        == proof["responseSigningKeyId"],
        "live session proof signing key crossed release custody",
    )
    require(
        isinstance(signature, str) and signature.startswith("ed25519:"),
        "live session proof signature is invalid",
    )
    signature_bytes = b64url_decode_exact(
        signature.split(":", 1)[1],
        "live session proof signature",
        exact_bytes=64,
    )
    try:
        key.verify(signature_bytes, canonical_json_bytes(proof))
    except InvalidSignature as exc:
        raise VerificationError(
            "live session proof signature is invalid"
        ) from exc
    if delivery_rebind is None:
        require(
            tls_binding == expected_tls_binding
            and now < expires,
            "a historical TLS proof requires an authenticated current-connection delivery rebind",
        )
        return proof
    rebind = exact_keys(
        delivery_rebind,
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "responseSigningKeyId",
            "signature",
            "signatureAlgorithm",
        },
        "signed public attestation delivery rebind",
    )
    payload = exact_keys(
        rebind["payload"],
        {
            "apiVersion",
            "currentTlsBinding",
            "currentTlsBindingSha256",
            "rebindIssuedAtUnix",
            "expiresAtUnix",
            "historicalResult",
            "historicalResultSha256",
            "historicalTlsBindingSha256",
            "recoveryIdentity",
            "recoveryIdentitySha256",
            "responseSigningKeyId",
        },
        "public attestation delivery-rebind payload",
    )
    current_tls_binding = exact_keys(
        payload["currentTlsBinding"],
        set(tls_binding),
        "current public attestation delivery TLS binding",
    )
    current_without_digest = {
        field: value
        for field, value in current_tls_binding.items()
        if field != "bindingSha256"
    }
    historical_result = exact_keys(
        payload["historicalResult"],
        {
            "evidenceBodySha256",
            "liveSessionProofSha256",
            "liveSessionSignatureSha256",
        },
        "historical public attestation delivery result",
    )
    recovery_identity = exact_keys(
        payload["recoveryIdentity"],
        {
            "apiVersion",
            "assuranceSha256",
            "callerNonceSha256",
            "immutableConfigSha256",
            "releaseIdentitySha256",
            "requestBodySha256",
        },
        "public attestation delivery recovery identity",
    )
    for field in (
        "bindingSha256",
        "connectionNonceSha256",
        "exporterSha256",
        "leafCertificateSha256",
        "leafSpkiSha256",
        "peerCertificateSha256",
        "peerSpkiSha256",
        "tlsScopeEnvelopeSha256",
        "tlsScopeKeySpkiSha256",
        "tlsStackMeasurementSha256",
    ):
        require_sha256(
            current_tls_binding[field],
            f"current delivery TLS binding {field}",
        )
    for field in (
        "assuranceSha256",
        "immutableConfigSha256",
    ):
        require_sha256(
            recovery_identity[field],
            f"delivery recovery identity {field}",
        )
    for field in (
        "connectionId",
        "enclaveBootId",
        "enclaveInstanceId",
        "peerIdentity",
    ):
        require_identifier(
            current_tls_binding[field],
            f"current delivery TLS binding {field}",
        )
    rebind_issued_at = require_positive_uint(
        payload["rebindIssuedAtUnix"],
        "response-rebind issue time",
    )
    delivery_expires = require_positive_uint(
        payload["expiresAtUnix"],
        "delivery-rebind expiry",
    )
    rebind_core = {
        key_name: value
        for key_name, value in rebind.items()
        if key_name != "signature"
    }
    expected_historical_result = {
        "evidenceBodySha256": sha256(evidence_body),
        "liveSessionProofSha256": sha256_json(proof),
        "liveSessionSignatureSha256": sha256(
            signature.encode("ascii")
        ),
    }
    require(
        rebind["apiVersion"]
        == SIGNED_PUBLIC_ATTESTATION_DELIVERY_REBIND_VERSION
        and rebind["signatureAlgorithm"] == "Ed25519"
        and rebind["responseSigningKeyId"]
        == payload["responseSigningKeyId"]
        == key_id
        and payload["apiVersion"]
        == PUBLIC_ATTESTATION_DELIVERY_REBIND_VERSION
        and current_tls_binding["apiVersion"] == TLS_SCOPE_VERSION
        and isinstance(current_tls_binding["provider"], str)
        and ENCLAVE_PROVIDER_RE.fullmatch(
            current_tls_binding["provider"]
        )
        is not None
        and current_tls_binding["exporterLabel"]
        == "EXPORTER-Serverware-Attestation-v1"
        and require_uint(
            current_tls_binding["tlsKeyGeneration"],
            "current delivery TLS key generation",
        )
        >= 1
        and require_uint(
            current_tls_binding["tlsScopeKeyGeneration"],
            "current delivery TLS scope-key generation",
        )
        >= 1,
        "public attestation delivery rebind envelope is invalid",
    )
    require(
        rebind["payloadSha256"] == sha256_json(payload)
        and current_tls_binding == expected_tls_binding
        and payload["currentTlsBindingSha256"]
        == current_tls_binding["bindingSha256"]
        == sha256_json(current_without_digest)
        and payload["historicalTlsBindingSha256"]
        == tls_binding["bindingSha256"]
        and historical_result == expected_historical_result
        and payload["historicalResultSha256"]
        == sha256_json(historical_result)
        and recovery_identity["callerNonceSha256"]
        == sha256(caller_nonce)
        and recovery_identity["requestBodySha256"]
        == sha256(request_body)
        and recovery_identity["releaseIdentitySha256"]
        == release_identity_sha256
        and payload["recoveryIdentitySha256"]
        == sha256_json(recovery_identity)
        and current_tls_binding["issuedAtUnix"]
        <= rebind_issued_at
        <= now
        < delivery_expires
        <= current_tls_binding["expiresAtUnix"]
        and 1 <= delivery_expires - rebind_issued_at <= 30,
        "public attestation delivery rebind crossed its current TLS connection, historical result, or recovery identity",
    )
    require(
        isinstance(rebind["signature"], str)
        and rebind["signature"].startswith("ed25519:"),
        "public attestation delivery rebind signature is invalid",
    )
    rebind_signature = b64url_decode_exact(
        rebind["signature"].split(":", 1)[1],
        "public attestation delivery rebind signature",
        exact_bytes=64,
    )
    try:
        key.verify(
            rebind_signature,
            canonical_json_bytes(rebind_core),
        )
    except InvalidSignature as exc:
        raise VerificationError(
            "public attestation delivery rebind signature is invalid"
        ) from exc
    return proof


def verify_release_then_live_session(
    *,
    stable_release_statement: Any,
    live_witness_head: Any,
    live_session_proof: Any,
    live_session_signature: str,
    trust: dict[str, Any],
    expected_witness: dict[str, Any],
    expected_witness_invocation_binding: dict[str, Any],
    expected_live_witness_payload_sha256: str,
    response_signing_public_key_pem: str,
    evidence_body: bytes,
    caller_nonce: bytes,
    request_body: bytes,
    expected_tls_binding: dict[str, Any],
    delivery_rebind: Any | None = None,
    now: int,
) -> dict[str, Any]:
    verified_release = verify_stable_release(
        stable_release_statement,
        trust=trust,
    )
    current_witness = verify_live_witness_head(
        live_witness_head,
        trust=trust,
        expected_release_identity=verified_release["releaseIdentity"],
        expected_witness=expected_witness,
        expected_invocation_binding=(
            expected_witness_invocation_binding
        ),
        expected_live_witness_payload_sha256=(
            expected_live_witness_payload_sha256
        ),
        now=now,
    )
    verified_live_session = verify_live_session_proof(
        live_session_proof,
        signature=live_session_signature,
        response_signing_public_key_pem=response_signing_public_key_pem,
        evidence_body=evidence_body,
        caller_nonce=caller_nonce,
        request_body=request_body,
        expected_tls_binding=expected_tls_binding,
        delivery_rebind=delivery_rebind,
        expected_release_identity=verified_release["releaseIdentity"],
        expected_witness=current_witness,
        now=now,
    )
    live_witness_payload = live_witness_head["payload"]
    require(
        live_witness_payload["issuedAtUnix"]
        <= verified_live_session["producedAtUnix"]
        and verified_live_session["expiresAtUnix"]
        <= live_witness_payload["expiresAtUnix"],
        "live session proof validity exceeds its authenticated witness head",
    )
    return {
        "liveSessionProof": verified_live_session,
        "release": verified_release,
        "witness": current_witness,
    }


PRODUCTION_NONCE_AUTHORITY_PROFILES = frozenset(
    {
        (
            "hardwareMonotonicCounter",
            "hardwareMonotonicCounter",
            "nonExportableHsm",
            "monotonicCounterCommitment",
            "hardwareProtectedStateStore",
            "hardwareMonotonicCounterAttestation",
        ),
        (
            "independentlyAdministeredLinearizableCas",
            "linearizableCasWithRollbackProtectedStorage",
            "nonExportableKmsHsm",
            "hashChainedLinearizableCommitment",
            "independentlyAdministeredLinearizableCas",
            "linearizableCasOperatorAttestation",
        ),
        (
            "appendOnlyTransparencyLedger",
            "appendOnlyWitnessedLedger",
            "nonExportableKmsHsm",
            "appendOnlyMerkleCommitment",
            "independentlyAdministeredLinearizableCas",
            "transparencyLedgerOperatorAttestation",
        ),
    }
)


def validate_nonce_authority_assurance(
    document: Any,
    *,
    expected_authority_identity_sha256: str,
) -> dict[str, Any]:
    assurance = exact_keys(
        document,
        {
            "apiVersion",
            "administrativeDomainSha256",
            "assuranceEvidenceSha256",
            "assuranceEvidenceType",
            "assuranceLevel",
            "authorityEpoch",
            "authorityGeneration",
            "authorityIdentitySha256",
            "backendClass",
            "productionEligible",
            "rollbackProtection",
        },
        "nonce authority assurance",
    )
    rollback = exact_keys(
        assurance["rollbackProtection"],
        {
            "administrativeRollbackResistance",
            "backendAttestationRequired",
            "exactSuccessorRequired",
            "freshVerifierChallengeRequired",
            "keyProtection",
            "mechanism",
            "stateCommitment",
            "verifierStateStoreClass",
        },
        "nonce authority rollback protection",
    )
    require(
        assurance["apiVersion"] == NONCE_AUTHORITY_ASSURANCE_VERSION
        and assurance["authorityIdentitySha256"]
        == require_sha256(
            expected_authority_identity_sha256,
            "expected nonce authority identity",
        )
        and require_sha256(
            assurance["administrativeDomainSha256"],
            "nonce authority administrative domain",
        )
        == assurance["administrativeDomainSha256"]
        and require_positive_uint(
            assurance["authorityEpoch"],
            "nonce authority epoch",
        )
        >= 1
        and require_positive_uint(
            assurance["authorityGeneration"],
            "nonce authority generation",
        )
        >= 1
        and rollback["exactSuccessorRequired"] is True
        and rollback["freshVerifierChallengeRequired"] is True,
        "nonce authority assurance crossed its identity or continuity contract",
    )
    profile = (
        assurance["backendClass"],
        rollback["mechanism"],
        rollback["keyProtection"],
        rollback["stateCommitment"],
        rollback["verifierStateStoreClass"],
        assurance["assuranceEvidenceType"],
    )
    if assurance["productionEligible"] is True:
        require(
            assurance["assuranceLevel"]
            == "productionRollbackProtected"
            and require_sha256(
                assurance["assuranceEvidenceSha256"],
                "nonce authority assurance evidence",
            )
            == assurance["assuranceEvidenceSha256"]
            and rollback["administrativeRollbackResistance"] is True
            and rollback["backendAttestationRequired"] is True
            and profile in PRODUCTION_NONCE_AUTHORITY_PROFILES,
            "nonce authority does not carry an allowed production rollback profile",
        )
    else:
        require(
            assurance["productionEligible"] is False
            and assurance["assuranceLevel"]
            in {
                "nonProductionFixture",
                "nonProductionDurableReference",
            }
            and assurance["assuranceEvidenceSha256"] is None
            and rollback["administrativeRollbackResistance"] is False
            and rollback["backendAttestationRequired"] is False
            and profile
            == (
                "nonProductionSqlite",
                "none",
                "retainedFdReference",
                "localHashChain",
                "nonProductionCallerFile",
                "none",
            ),
            "non-production nonce authority assurance is not closed",
        )
    return assurance


def nonce_authority_genesis_commitment(
    assurance_sha256: str,
) -> str:
    return sha256(
        NONCE_AUTHORITY_GENESIS_DOMAIN
        + canonical_json_bytes(
            {
                "assuranceSha256": require_sha256(
                    assurance_sha256,
                    "nonce authority assurance",
                ),
            }
        )
    )


def verify_nonce_authority_assurance_evidence(
    document: Any,
    *,
    signing_key: Ed25519PublicKey,
    signing_key_id: str,
    assurance: dict[str, Any],
    nonce_authority_state_signing_key_id: str,
    verifier_state_store_administrative_domain_sha256: str,
    verifier_state_store_identity_sha256: str,
    verifier_state_store_signing_key_id: str,
    now: int,
) -> dict[str, Any]:
    envelope = exact_keys(
        document,
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "signatureAlgorithm",
            "signatureBase64url",
            "signingKeyId",
            "signingKeySpkiSha256",
        },
        "signed nonce authority assurance evidence",
    )
    require(
        envelope["apiVersion"]
        == SIGNED_NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION
        and envelope["signatureAlgorithm"] == "Ed25519"
        and envelope["signingKeyId"] == signing_key_id
        and envelope["signingKeySpkiSha256"] == signing_key_id,
        "nonce authority assurance evidence crossed its pinned issuer",
    )
    payload = exact_keys(
        envelope["payload"],
        {
            "administrativeDomainSha256",
            "apiVersion",
            "assuranceEvidenceType",
            "authorityEpoch",
            "authorityGeneration",
            "authorityIdentitySha256",
            "backendClass",
            "expiresAtUnix",
            "issuedAtUnix",
            "nonceAuthorityStateSigningKeySpkiSha256",
            "rollbackMechanism",
            "stateCommitment",
            "verifierStateStoreAdministrativeDomainSha256",
            "verifierStateStoreClass",
            "verifierStateStoreIdentitySha256",
            "verifierStateStoreSigningKeySpkiSha256",
        },
        "nonce authority assurance evidence payload",
    )
    payload_sha256 = sha256_json(payload)
    require(
        envelope["payloadSha256"] == payload_sha256,
        "nonce authority assurance evidence payload digest is invalid",
    )
    signature = b64url_decode_exact(
        envelope["signatureBase64url"],
        "nonce authority assurance evidence signature",
        exact_bytes=64,
    )
    try:
        signing_key.verify(
            signature,
            NONCE_AUTHORITY_ASSURANCE_EVIDENCE_DOMAIN
            + canonical_json_bytes(
                {
                    "payload": payload,
                    "payloadSha256": payload_sha256,
                }
            ),
        )
    except InvalidSignature as exc:
        raise VerificationError(
            "nonce authority assurance evidence signature is invalid"
        ) from exc
    issued = require_positive_uint(
        payload["issuedAtUnix"],
        "nonce authority assurance evidence issue time",
    )
    expires = require_positive_uint(
        payload["expiresAtUnix"],
        "nonce authority assurance evidence expiry",
    )
    rollback = assurance["rollbackProtection"]
    require(
        sha256_json(envelope)
        == assurance["assuranceEvidenceSha256"]
        and payload["apiVersion"]
        == NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION
        and payload["administrativeDomainSha256"]
        == assurance["administrativeDomainSha256"]
        and payload["assuranceEvidenceType"]
        == assurance["assuranceEvidenceType"]
        and payload["authorityEpoch"] == assurance["authorityEpoch"]
        and payload["authorityGeneration"]
        == assurance["authorityGeneration"]
        and payload["authorityIdentitySha256"]
        == assurance["authorityIdentitySha256"]
        and payload["backendClass"] == assurance["backendClass"]
        and payload["nonceAuthorityStateSigningKeySpkiSha256"]
        == nonce_authority_state_signing_key_id
        and payload["rollbackMechanism"]
        == rollback["mechanism"]
        and payload["stateCommitment"]
        == rollback["stateCommitment"]
        and payload[
            "verifierStateStoreAdministrativeDomainSha256"
        ]
        == verifier_state_store_administrative_domain_sha256
        and payload["verifierStateStoreClass"]
        == rollback["verifierStateStoreClass"]
        and payload["verifierStateStoreIdentitySha256"]
        == verifier_state_store_identity_sha256
        and payload[
            "verifierStateStoreSigningKeySpkiSha256"
        ]
        == verifier_state_store_signing_key_id
        and payload[
            "verifierStateStoreAdministrativeDomainSha256"
        ]
        != assurance["administrativeDomainSha256"]
        and (
            now is None
            or issued <= now < expires
        )
        and expires - issued <= MAX_RELEASE_VALIDITY_SECONDS,
        "nonce authority assurance evidence is stale or differs from the pinned contract",
    )
    return {
        "document": envelope,
        "envelopeSha256": sha256_json(envelope),
        "payload": payload,
    }


def validate_global_attestation_key_role_separation(
    role_key_ids: Mapping[str, Any],
    *,
    expected_roles: Any = None,
) -> dict[str, str]:
    expected = tuple(
        role_key_ids if expected_roles is None else expected_roles
    )
    require(
        bool(expected) and set(role_key_ids) == set(expected),
        "global attestation key role registry is not exact",
    )
    normalized = {
        name: require_sha256(
            role_key_ids[name],
            f"global attestation {name} role",
        )
        for name in expected
    }
    collisions: dict[str, list[str]] = {}
    for name, key_id in normalized.items():
        collisions.setdefault(key_id, []).append(name)
    duplicate_roles = sorted(
        sorted(names)
        for names in collisions.values()
        if len(names) > 1
    )
    require(
        not duplicate_roles,
        "global attestation key roles collide: "
        f"{duplicate_roles!r}",
    )
    return normalized


def verify_verifier_state_store_and_role_assurance(
    config: dict[str, Any],
    *,
    assurance: dict[str, Any],
    nonce_store_key_id: str,
    verifier_state_key_id: str,
    store_attestation_key_id: str,
    service: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    _assurance_key, assurance_evidence_key_id = (
        embedded_ed25519_spki(
            config[
                "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
            ],
            label="nonce authority assurance-evidence issuer key",
        )
    )
    store_key, store_key_id = embedded_ed25519_spki(
        config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
        ],
        label="verifier-state store assurance issuer key",
    )
    store_payload, store_sha256 = verify_service_envelope(
        config["nonceAuthorityVerifierStateStoreAssuranceEvidence"],
        api_version=SIGNED_VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION,
        domain=VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_DOMAIN,
        key=store_key,
        key_id=store_key_id,
        label="verifier-state store assurance evidence",
    )
    store_payload = exact_keys(
        store_payload,
        {
            "apiVersion",
            "commitIndexSemantics",
            "evidenceExpiresAtUnix",
            "evidenceIssuedAtUnix",
            "generationSemantics",
            "issuerAdministrativeDomainSha256",
            "issuerCredentialIdentitySha256",
            "issuerIdentitySha256",
            "minimumStoreCommitIndex",
            "minimumStoreGeneration",
            "productionEligible",
            "rollbackMechanism",
            "storeAdministrativeDomainSha256",
            "storeAttestationKeySpkiSha256",
            "storeConfigurationSha256",
            "storeCredentialIdentitySha256",
            "storeIdentitySha256",
        },
        "verifier-state store assurance payload",
    )
    store_issued = require_positive_uint(
        store_payload["evidenceIssuedAtUnix"],
        "verifier-state store assurance issue time",
    )
    store_expires = require_positive_uint(
        store_payload["evidenceExpiresAtUnix"],
        "verifier-state store assurance expiry",
    )
    minimum_generation = require_positive_uint(
        store_payload["minimumStoreGeneration"],
        "verifier-state store assurance minimum generation",
    )
    minimum_commit_index = require_positive_uint(
        store_payload["minimumStoreCommitIndex"],
        "verifier-state store assurance minimum commit index",
    )
    for field in (
        "issuerAdministrativeDomainSha256",
        "issuerCredentialIdentitySha256",
        "issuerIdentitySha256",
        "storeAdministrativeDomainSha256",
        "storeAttestationKeySpkiSha256",
        "storeConfigurationSha256",
        "storeCredentialIdentitySha256",
        "storeIdentitySha256",
    ):
        require_sha256(
            store_payload[field],
            f"verifier-state store assurance {field}",
        )
    require(
        store_sha256
        == config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ]
        and store_payload["apiVersion"]
        == VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION
        and store_payload["productionEligible"] is True
        and store_payload["generationSemantics"]
        == "strictlyMonotonicU64"
        and store_payload["commitIndexSemantics"]
        == "equalToVerifierStateGeneration"
        and store_payload["rollbackMechanism"]
        == config[
            "nonceAuthorityVerifierStateStoreRollbackMechanism"
        ]
        and store_payload["storeIdentitySha256"]
        == config["nonceAuthorityVerifierStateStoreIdentitySha256"]
        and store_payload["storeAdministrativeDomainSha256"]
        == config[
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        ]
        and store_payload["storeCredentialIdentitySha256"]
        == config[
            "nonceAuthorityVerifierStateStoreCredentialIdentitySha256"
        ]
        and store_payload["storeAttestationKeySpkiSha256"]
        == store_attestation_key_id
        and store_payload["storeConfigurationSha256"]
        == config[
            "nonceAuthorityVerifierStateStoreConfigurationSha256"
        ]
        and store_payload["issuerAdministrativeDomainSha256"]
        == config[
            "nonceAuthorityVerifierStateStoreAssuranceIssuerAdministrativeDomainSha256"
        ]
        and store_payload["issuerCredentialIdentitySha256"]
        == config[
            "nonceAuthorityVerifierStateStoreAssuranceIssuerCredentialIdentitySha256"
        ]
        and store_payload["issuerIdentitySha256"]
        == config[
            "nonceAuthorityVerifierStateStoreAssuranceIssuerIdentitySha256"
        ]
        and minimum_generation
        == config[
            "nonceAuthorityVerifierStateStoreMinimumGeneration"
        ]
        and minimum_commit_index
        == config[
            "nonceAuthorityVerifierStateStoreMinimumCommitIndex"
        ]
        and store_issued <= now < store_expires
        and store_expires - store_issued <= 86400
        and store_payload["issuerAdministrativeDomainSha256"]
        != store_payload["storeAdministrativeDomainSha256"]
        and store_payload["issuerCredentialIdentitySha256"]
        != store_payload["storeCredentialIdentitySha256"]
        and store_payload["issuerIdentitySha256"]
        != store_payload["storeIdentitySha256"]
        and store_key_id != store_attestation_key_id,
        "verifier-state store assurance is stale, crossed, or self-attested",
    )
    role_key, role_key_id = embedded_ed25519_spki(
        config[
            "nonceAuthorityVerifierStateRoleSeparationEvidenceSigningPublicKeySpkiDerBase64url"
        ],
        label="verifier-state role-separation issuer key",
    )
    role_payload, role_sha256 = verify_service_envelope(
        config["nonceAuthorityVerifierStateRoleSeparationEvidence"],
        api_version=SIGNED_VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_VERSION,
        domain=VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_DOMAIN,
        key=role_key,
        key_id=role_key_id,
        label="verifier-state role-separation evidence",
    )
    role_payload = exact_keys(
        role_payload,
        {
            "apiVersion",
            "assuranceSha256",
            "evidenceExpiresAtUnix",
            "evidenceIssuedAtUnix",
            "nonceAuthority",
            "nonceAuthorityAssuranceEvidenceIssuer",
            "productionEligible",
            "publicAttestationClientTls",
            "roleSeparationEvidenceIssuer",
            "storeAssuranceEvidenceIssuer",
            "verifierStateServiceListenerTls",
            "verifierStateSigner",
            "verifierStateSignerClientTls",
            "verifierStateSignerServerTls",
            "verifierStateStore",
            "verifierStateStoreClientTls",
            "verifierStateStoreServerTls",
        },
        "verifier-state role-separation payload",
    )

    def role(value: Any, label: str) -> dict[str, Any]:
        result = exact_keys(
            value,
            {
                "administrativeDomainSha256",
                "assuranceEvidenceSha256",
                "credentialIdentitySha256",
                "endpointIdentitySha256",
                "keySpkiSha256",
                "roleIdentitySha256",
            },
            label,
        )
        for field in result:
            require_sha256(result[field], f"{label} {field}")
        return result

    role_names = (
        "nonceAuthority",
        "nonceAuthorityAssuranceEvidenceIssuer",
        "publicAttestationClientTls",
        "roleSeparationEvidenceIssuer",
        "storeAssuranceEvidenceIssuer",
        "verifierStateServiceListenerTls",
        "verifierStateSigner",
        "verifierStateSignerClientTls",
        "verifierStateSignerServerTls",
        "verifierStateStore",
        "verifierStateStoreClientTls",
        "verifierStateStoreServerTls",
    )
    roles = {
        name: role(role_payload[name], f"{name} role")
        for name in role_names
    }
    pinned_issuer = role(
        config[
            "nonceAuthorityVerifierStateRoleSeparationEvidenceIssuer"
        ],
        "pinned role-separation issuer",
    )
    role_issued = require_positive_uint(
        role_payload["evidenceIssuedAtUnix"],
        "verifier-state role-separation issue time",
    )
    role_expires = require_positive_uint(
        role_payload["evidenceExpiresAtUnix"],
        "verifier-state role-separation expiry",
    )
    require(
        role_payload["apiVersion"]
        == VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_VERSION
        and role_payload["assuranceSha256"]
        == config["nonceAuthorityAssuranceSha256"]
        and role_payload["productionEligible"] is True
        and role_issued <= now < role_expires
        and role_expires - role_issued <= 86400
        and roles["roleSeparationEvidenceIssuer"] == pinned_issuer
        and roles["roleSeparationEvidenceIssuer"]["keySpkiSha256"]
        == role_key_id
        and roles["nonceAuthority"]["keySpkiSha256"]
        == nonce_store_key_id
        and roles["nonceAuthority"]["administrativeDomainSha256"]
        == assurance["administrativeDomainSha256"]
        and roles["nonceAuthority"]["roleIdentitySha256"]
        == assurance["authorityIdentitySha256"]
        and roles["nonceAuthority"]["assuranceEvidenceSha256"]
        == assurance["assuranceEvidenceSha256"]
        and roles["nonceAuthorityAssuranceEvidenceIssuer"][
            "keySpkiSha256"
        ]
        == assurance_evidence_key_id
        and roles["verifierStateSigner"]["keySpkiSha256"]
        == verifier_state_key_id
        and roles["verifierStateStore"]["keySpkiSha256"]
        == store_attestation_key_id
        and roles["verifierStateStore"]["roleIdentitySha256"]
        == store_payload["storeIdentitySha256"]
        and roles["verifierStateStore"]["administrativeDomainSha256"]
        == store_payload["storeAdministrativeDomainSha256"]
        and roles["verifierStateStore"]["credentialIdentitySha256"]
        == store_payload["storeCredentialIdentitySha256"]
        and roles["verifierStateStore"]["assuranceEvidenceSha256"]
        == store_sha256
        and roles["storeAssuranceEvidenceIssuer"]["keySpkiSha256"]
        == store_key_id
        and roles["storeAssuranceEvidenceIssuer"][
            "administrativeDomainSha256"
        ]
        == store_payload["issuerAdministrativeDomainSha256"]
        and roles["storeAssuranceEvidenceIssuer"][
            "credentialIdentitySha256"
        ]
        == store_payload["issuerCredentialIdentitySha256"]
        and roles["storeAssuranceEvidenceIssuer"]["roleIdentitySha256"]
        == store_payload["issuerIdentitySha256"]
        and roles["publicAttestationClientTls"]["keySpkiSha256"]
        == service["clientCertificateSpkiSha256"]
        and roles["verifierStateServiceListenerTls"]["keySpkiSha256"]
        == service["serverLeafSpkiSha256"],
        "verifier-state role separation is stale or crossed",
    )
    for field in (
        "administrativeDomainSha256",
        "credentialIdentitySha256",
        "endpointIdentitySha256",
        "keySpkiSha256",
        "roleIdentitySha256",
    ):
        require(
            len({roles[name][field] for name in role_names})
            == len(role_names),
            f"verifier-state roles collide on {field}",
        )
    return {
        "roleEvidenceSha256": role_sha256,
        "roleKeyId": role_key_id,
        "roleKeyIdsByRole": {
            name: roles[name]["keySpkiSha256"]
            for name in role_names
        },
        "roleKeyIds": tuple(
            roles[name]["keySpkiSha256"]
            for name in role_names
        ),
        "storeEvidenceSha256": store_sha256,
        "storeKeyId": store_key_id,
        "storePayload": store_payload,
    }


def nonce_authority_high_water_commitment(
    *,
    assurance_sha256: str,
    authority_epoch: int,
    authority_generation: int,
    nonce_consumption_sha256: str,
    nonce_verifier_state_authorization_sha256: str,
    previous_high_water_commitment_sha256: str,
    previous_receipt_sha256: str | None,
    sequence: int,
    transaction_id_base64url: str,
) -> str:
    checked_sequence = require_positive_uint(
        sequence,
        "nonce authority high-water sequence",
    )
    if checked_sequence == 1:
        require(
            previous_receipt_sha256 is None,
            "first nonce authority state has a receipt predecessor",
        )
    else:
        require_sha256(
            previous_receipt_sha256,
            "nonce authority receipt predecessor",
        )
    b64url_decode_exact(
        transaction_id_base64url,
        "nonce authority transaction ID",
        exact_bytes=32,
    )
    commitment_input = {
        "apiVersion": NONCE_AUTHORITY_HIGH_WATER_INPUT_VERSION,
        "assuranceSha256": require_sha256(
            assurance_sha256,
            "nonce authority assurance",
        ),
        "authorityEpoch": require_positive_uint(
            authority_epoch,
            "nonce authority epoch",
        ),
        "authorityGeneration": require_positive_uint(
            authority_generation,
            "nonce authority generation",
        ),
        "nonceConsumptionSha256": require_sha256(
            nonce_consumption_sha256,
            "nonce authority consumption",
        ),
        "nonceVerifierStateAuthorizationSha256": require_sha256(
            nonce_verifier_state_authorization_sha256,
            "nonce verifier-state authorization",
        ),
        "previousHighWaterCommitmentSha256": require_sha256(
            previous_high_water_commitment_sha256,
            "previous nonce authority high-water commitment",
        ),
        "previousReceiptSha256": previous_receipt_sha256,
        "sequence": checked_sequence,
        "transactionIdBase64url": transaction_id_base64url,
    }
    return sha256(
        NONCE_AUTHORITY_HIGH_WATER_DOMAIN
        + canonical_json_bytes(commitment_input)
    )


def verify_nonce_authority_verifier_state(
    document: Any,
    *,
    signing_key: Ed25519PublicKey,
    signing_key_id: str,
    expected_state_store_identity_sha256: str,
    assurance: dict[str, Any],
    assurance_sha256: str,
) -> dict[str, Any]:
    envelope = exact_keys(
        document,
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "signatureAlgorithm",
            "signatureBase64url",
            "signingKeyId",
            "signingKeySpkiSha256",
        },
        "signed nonce authority verifier state",
    )
    require(
        envelope["apiVersion"]
        == SIGNED_NONCE_AUTHORITY_VERIFIER_STATE_VERSION
        and envelope["signatureAlgorithm"] == "Ed25519"
        and envelope["signingKeyId"] == signing_key_id
        and envelope["signingKeySpkiSha256"] == signing_key_id,
        "nonce authority verifier state crossed its pinned signing key",
    )
    payload = exact_keys(
        envelope["payload"],
        {
            "apiVersion",
            "assuranceSha256",
            "authorityEpoch",
            "authorityGeneration",
            "commitOperationIdBase64url",
            "committedAtUnix",
            "highWaterCommitmentSha256",
            "highWaterReceiptSha256",
            "highWaterSequence",
            "priorVerifierStateSha256",
            "stateStoreGeneration",
            "stateStoreHeadSha256",
            "stateStoreIdentitySha256",
        },
        "nonce authority verifier state payload",
    )
    payload_sha256 = sha256_json(payload)
    require(
        envelope["payloadSha256"] == payload_sha256,
        "nonce authority verifier state payload digest is invalid",
    )
    signature = b64url_decode_exact(
        envelope["signatureBase64url"],
        "nonce authority verifier state signature",
        exact_bytes=64,
    )
    try:
        signing_key.verify(
            signature,
            NONCE_AUTHORITY_VERIFIER_STATE_DOMAIN
            + canonical_json_bytes(
                {
                    "payload": payload,
                    "payloadSha256": payload_sha256,
                }
            ),
        )
    except InvalidSignature as exc:
        raise VerificationError(
            "nonce authority verifier state signature is invalid"
        ) from exc
    require_positive_uint(
        payload["committedAtUnix"],
        "nonce authority verifier state commit time",
    )
    require_positive_uint(
        payload["stateStoreGeneration"],
        "nonce authority verifier-state store generation",
    )
    require_sha256(
        payload["stateStoreHeadSha256"],
        "nonce authority verifier-state store head",
    )
    sequence = require_uint(
        payload["highWaterSequence"],
        "nonce authority verifier-state high-water sequence",
    )
    require(
        payload["apiVersion"] == NONCE_AUTHORITY_VERIFIER_STATE_VERSION
        and payload["assuranceSha256"] == assurance_sha256
        and require_positive_uint(
            payload["authorityEpoch"],
            "nonce authority verifier-state epoch",
        )
        == assurance["authorityEpoch"]
        and require_positive_uint(
            payload["authorityGeneration"],
            "nonce authority verifier-state generation",
        )
        == assurance["authorityGeneration"]
        and payload["stateStoreIdentitySha256"]
        == require_sha256(
            expected_state_store_identity_sha256,
            "nonce authority verifier-state store identity",
        ),
        "nonce authority verifier state crossed its pinned authority",
    )
    if sequence == 0:
        require(
            payload["highWaterReceiptSha256"] is None
            and payload["commitOperationIdBase64url"] is None
            and payload["priorVerifierStateSha256"] is None
            and payload["highWaterCommitmentSha256"]
            == nonce_authority_genesis_commitment(
                assurance_sha256
            ),
            "nonce authority genesis verifier state is invalid",
        )
    else:
        b64url_decode_exact(
            payload["commitOperationIdBase64url"],
            "nonce authority verifier-state commit operation",
            exact_bytes=32,
        )
        require_sha256(
            payload["priorVerifierStateSha256"],
            "nonce authority prior verifier-state digest",
        )
        require_sha256(
            payload["highWaterReceiptSha256"],
            "nonce authority verifier-state receipt head",
        )
        require_sha256(
            payload["highWaterCommitmentSha256"],
            "nonce authority verifier-state commitment head",
        )
    return {
        "document": envelope,
        "envelopeSha256": sha256_json(envelope),
        "payload": payload,
    }


def verify_nonce_authority_state_authorization(
    document: Any,
    *,
    signing_key: Ed25519PublicKey,
    signing_key_id: str,
    expected_state_store_identity_sha256: str,
    expected_state_store_attestation_key_id: str,
    expected_state_store_assurance_evidence_sha256: str | None,
    expected_state_store_configuration_sha256: str,
    expected_nonce_receipt_signing_key_id: str,
    assurance: dict[str, Any],
    assurance_sha256: str,
    prior_verifier_state: dict[str, Any],
    verifier_challenge: bytes,
    now: int | None,
) -> dict[str, Any]:
    require(
        type(verifier_challenge) is bytes
        and len(verifier_challenge) == 32,
        "nonce authority verifier challenge must be exactly 32 bytes",
    )
    envelope = exact_keys(
        document,
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "signatureAlgorithm",
            "signatureBase64url",
            "signingKeyId",
            "signingKeySpkiSha256",
        },
        "signed nonce authority current-head authorization",
    )
    require(
        envelope["apiVersion"]
        == NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_VERSION
        and envelope["signatureAlgorithm"] == "Ed25519"
        and envelope["signingKeyId"] == signing_key_id
        and envelope["signingKeySpkiSha256"] == signing_key_id,
        "nonce authority current-head authorization crossed its pinned key",
    )
    payload = exact_keys(
        envelope["payload"],
        {
            "apiVersion",
            "assuranceSha256",
            "authorityEpoch",
            "authorityGeneration",
            "expiresAtUnix",
            "highWaterCommitmentSha256",
            "highWaterReceiptSha256",
            "highWaterSequence",
            "issuedAtUnix",
            "nonceReceiptSigningKeySpkiSha256",
            "nonceTransactionIdBase64url",
            "oneUse",
            "operationIdBase64url",
            "prepareRequestSha256",
            "priorCommittedAtUnix",
            "priorVerifierStateSha256",
            "recoveryIdentitySha256",
            "recoveryKeySha256",
            "requestBindingSha256",
            "stateStoreGeneration",
            "stateStoreHeadSha256",
            "stateStoreAssuranceEvidenceSha256",
            "stateStoreAttestationKeySpkiSha256",
            "stateStoreConfigurationSha256",
            "stateStoreIdentitySha256",
            "verifierChallengeSha256",
        },
        "nonce authority current-head authorization payload",
    )
    payload_sha256 = sha256_json(payload)
    require(
        envelope["payloadSha256"] == payload_sha256,
        "nonce authority current-head authorization digest is invalid",
    )
    signature = b64url_decode_exact(
        envelope["signatureBase64url"],
        "nonce authority current-head authorization signature",
        exact_bytes=64,
    )
    try:
        signing_key.verify(
            signature,
            NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_DOMAIN
            + canonical_json_bytes(
                {
                    "payload": payload,
                    "payloadSha256": payload_sha256,
                }
            ),
        )
    except InvalidSignature as exc:
        raise VerificationError(
            "nonce authority current-head authorization signature is invalid"
        ) from exc
    prior = prior_verifier_state["payload"]
    issued = require_positive_uint(
        payload["issuedAtUnix"],
        "nonce authority current-head authorization issue time",
    )
    expires = require_positive_uint(
        payload["expiresAtUnix"],
        "nonce authority current-head authorization expiry",
    )
    b64url_decode_exact(
        payload["operationIdBase64url"],
        "nonce authority current-head operation ID",
        exact_bytes=32,
    )
    b64url_decode_exact(
        payload["nonceTransactionIdBase64url"],
        "nonce authority transaction ID",
        exact_bytes=32,
    )
    for field in (
        "prepareRequestSha256",
        "recoveryIdentitySha256",
        "recoveryKeySha256",
        "requestBindingSha256",
    ):
        require_sha256(
            payload[field],
            f"nonce authority authorization {field}",
        )
    require(
        payload["apiVersion"]
        == NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_VERSION
        and payload["assuranceSha256"] == assurance_sha256
        and payload["authorityEpoch"] == assurance["authorityEpoch"]
        and payload["authorityGeneration"]
        == assurance["authorityGeneration"]
        and payload["priorVerifierStateSha256"]
        == prior_verifier_state["envelopeSha256"]
        and payload["stateStoreIdentitySha256"]
        == require_sha256(
            expected_state_store_identity_sha256,
            "nonce authority verifier-state store identity",
        )
        and payload["stateStoreAttestationKeySpkiSha256"]
        == require_sha256(
            expected_state_store_attestation_key_id,
            "nonce authority verifier-state store attestation key",
        )
        and payload["stateStoreAssuranceEvidenceSha256"]
        == expected_state_store_assurance_evidence_sha256
        and payload["stateStoreConfigurationSha256"]
        == require_sha256(
            expected_state_store_configuration_sha256,
            "nonce authority verifier-state store configuration",
        )
        and payload["nonceReceiptSigningKeySpkiSha256"]
        == require_sha256(
            expected_nonce_receipt_signing_key_id,
            "nonce receipt signing key",
        )
        and payload["priorCommittedAtUnix"]
        == prior["committedAtUnix"]
        and payload["stateStoreGeneration"]
        == prior["stateStoreGeneration"]
        and payload["stateStoreHeadSha256"]
        == prior["stateStoreHeadSha256"]
        and payload["highWaterSequence"]
        == prior["highWaterSequence"]
        and payload["highWaterCommitmentSha256"]
        == prior["highWaterCommitmentSha256"]
        and payload["highWaterReceiptSha256"]
        == prior["highWaterReceiptSha256"]
        and payload["verifierChallengeSha256"]
        == sha256(verifier_challenge)
        and payload["oneUse"] is True
        and payload["nonceTransactionIdBase64url"]
        == payload["operationIdBase64url"]
        and prior["committedAtUnix"] <= issued
        and (
            now is None
            or issued <= now < expires
        )
        and expires - issued <= 30,
        "nonce authority current-head authorization is stale or not for the retained head",
    )
    return {
        "document": envelope,
        "envelopeSha256": sha256_json(envelope),
        "payload": payload,
    }


def verify_verifier_state_store_commit_proof(
    document: Any,
    *,
    signing_key: Ed25519PublicKey,
    signing_key_id: str,
    expected_state_store_identity_sha256: str,
    expected_state_store_administrative_domain_sha256: str,
    expected_state_store_assurance_evidence_sha256: str | None,
    expected_state_store_configuration_sha256: str,
    minimum_state_store_generation: int,
    minimum_state_store_commit_index: int,
    expected_production_eligible: bool,
    authorization: dict[str, Any],
    commit_request_sha256: str,
    commit_candidate: dict[str, Any],
    nonce_consumed_at: int,
    now: int,
) -> dict[str, Any]:
    envelope = exact_keys(
        document,
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "signatureAlgorithm",
            "signatureBase64url",
            "signingKeyId",
            "signingKeySpkiSha256",
        },
        "signed verifier-state store commit proof",
    )
    require(
        envelope["apiVersion"]
        == SIGNED_VERIFIER_STATE_STORE_COMMIT_PROOF_VERSION
        and envelope["signatureAlgorithm"] == "Ed25519"
        and envelope["signingKeyId"] == signing_key_id
        and envelope["signingKeySpkiSha256"] == signing_key_id,
        "verifier-state store proof crossed its pinned key",
    )
    payload = exact_keys(
        envelope["payload"],
        {
            "apiVersion",
            "authorizationSha256",
            "casCommitted",
            "commitCandidateSha256",
            "commitClockMonotonic",
            "commitRequestSha256",
            "committedAtUnix",
            "operationIdBase64url",
            "previousCommittedAtUnix",
            "previousVerifierStateSha256",
            "productionEligible",
            "stateStoreAdministrativeDomainSha256",
            "stateStoreAssuranceEvidenceSha256",
            "stateStoreAttestationKeySpkiSha256",
            "stateStoreCommitIndex",
            "stateStoreConfigurationSha256",
            "stateStoreGeneration",
            "stateStoreIdentitySha256",
        },
        "verifier-state store commit proof payload",
    )
    payload_sha256 = sha256_json(payload)
    require(
        envelope["payloadSha256"] == payload_sha256,
        "verifier-state store proof payload digest is invalid",
    )
    signature = b64url_decode_exact(
        envelope["signatureBase64url"],
        "verifier-state store proof signature",
        exact_bytes=64,
    )
    try:
        signing_key.verify(
            signature,
            VERIFIER_STATE_STORE_COMMIT_PROOF_DOMAIN
            + canonical_json_bytes(
                {
                    "payload": payload,
                    "payloadSha256": payload_sha256,
                }
            ),
        )
    except InvalidSignature as exc:
        raise VerificationError(
            "verifier-state store proof signature is invalid"
        ) from exc
    authorization_payload = authorization["payload"]
    committed_at = require_positive_uint(
        payload["committedAtUnix"],
        "verifier-state store durable commit time",
    )
    state_store_generation = require_positive_uint(
        payload["stateStoreGeneration"],
        "verifier-state store generation",
    )
    state_store_commit_index = require_positive_uint(
        payload["stateStoreCommitIndex"],
        "verifier-state store commit index",
    )
    require(
        payload["apiVersion"]
        == VERIFIER_STATE_STORE_COMMIT_PROOF_VERSION
        and payload["authorizationSha256"]
        == authorization["envelopeSha256"]
        and payload["casCommitted"] is True
        and payload["commitCandidateSha256"]
        == sha256_json(commit_candidate)
        and payload["commitClockMonotonic"] is True
        and payload["commitRequestSha256"]
        == require_sha256(
            commit_request_sha256,
            "verifier-state commit request",
        )
        and payload["operationIdBase64url"]
        == authorization_payload["operationIdBase64url"]
        and payload["previousCommittedAtUnix"]
        == authorization_payload["priorCommittedAtUnix"]
        and payload["previousVerifierStateSha256"]
        == authorization_payload["priorVerifierStateSha256"]
        and type(expected_production_eligible) is bool
        and payload["productionEligible"] is expected_production_eligible
        and payload["stateStoreAdministrativeDomainSha256"]
        == require_sha256(
            expected_state_store_administrative_domain_sha256,
            "verifier-state store administrative domain",
        )
        and payload["stateStoreAssuranceEvidenceSha256"]
        == expected_state_store_assurance_evidence_sha256
        and payload["stateStoreAttestationKeySpkiSha256"]
        == require_sha256(
            signing_key_id,
            "verifier-state store attestation key",
        )
        and payload["stateStoreConfigurationSha256"]
        == require_sha256(
            expected_state_store_configuration_sha256,
            "verifier-state store configuration",
        )
        and state_store_generation
        == commit_candidate["proposedStateStoreGeneration"]
        and state_store_commit_index == state_store_generation
        and state_store_generation
        >= require_positive_uint(
            minimum_state_store_generation,
            "minimum verifier-state store generation",
        )
        and state_store_commit_index
        >= require_positive_uint(
            minimum_state_store_commit_index,
            "minimum verifier-state store commit index",
        )
        and payload["stateStoreIdentitySha256"]
        == require_sha256(
            expected_state_store_identity_sha256,
            "verifier-state store identity",
        )
        and authorization_payload["priorCommittedAtUnix"]
        <= committed_at
        and require_positive_uint(
            nonce_consumed_at,
            "verifier-state nonce consumption time",
        )
        <= committed_at
        <= now,
        "verifier-state store proof is stale, substituted, or crossed",
    )
    return {
        "document": envelope,
        "envelopeSha256": sha256_json(envelope),
        "payload": payload,
    }


def verify_nonce_authority_state_commit_receipt(
    document: Any,
    *,
    signing_key: Ed25519PublicKey,
    signing_key_id: str,
    expected_state_store_identity_sha256: str,
    expected_state_store_administrative_domain_sha256: str,
    expected_state_store_assurance_evidence_sha256: str | None,
    expected_state_store_configuration_sha256: str,
    minimum_state_store_generation: int,
    minimum_state_store_commit_index: int,
    expected_production_eligible: bool,
    state_store_attestation_key: Ed25519PublicKey,
    state_store_attestation_key_id: str,
    assurance: dict[str, Any],
    assurance_sha256: str,
    prior_verifier_state: dict[str, Any],
    authorization: dict[str, Any],
    commit_request: dict[str, Any],
    nonce_consumption_receipt: dict[str, Any],
    nonce_receipt_signing_key: Ed25519PublicKey,
    nonce_receipt_signing_key_id: str,
    verifier_challenge: bytes,
    now: int,
) -> dict[str, Any]:
    envelope = exact_keys(
        document,
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "signatureAlgorithm",
            "signatureBase64url",
            "signingKeyId",
            "signingKeySpkiSha256",
        },
        "signed nonce authority verifier-state commit receipt",
    )
    require(
        envelope["apiVersion"]
        == NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_VERSION
        and envelope["signatureAlgorithm"] == "Ed25519"
        and envelope["signingKeyId"] == signing_key_id
        and envelope["signingKeySpkiSha256"] == signing_key_id,
        "nonce authority verifier-state commit receipt crossed its pinned key",
    )
    payload = exact_keys(
        envelope["payload"],
        {
            "apiVersion",
            "assuranceSha256",
            "authorizationSha256",
            "casCommitted",
            "commitOperationIdBase64url",
            "commitRequestSha256",
            "committedAtUnix",
            "committedVerifierState",
            "committedVerifierStateSha256",
            "nonceAuthorityStateSha256",
            "nonceConsumptionReceiptSha256",
            "nonceConsumptionSha256",
            "nonceReceiptSigningKeySpkiSha256",
            "oneUseAuthorizationConsumed",
            "preparedOperationSha256",
            "previousStateStoreGeneration",
            "previousStateStoreHeadSha256",
            "priorVerifierStateSha256",
            "recoveryIdentitySha256",
            "recoveryKeySha256",
            "requestBindingSha256",
            "signedStoreCommitProof",
            "signedStoreCommitProofSha256",
            "stateStoreAdministrativeDomainSha256",
            "stateStoreAssuranceEvidenceSha256",
            "stateStoreAttestationKeySpkiSha256",
            "stateStoreCommitIndex",
            "stateStoreConfigurationSha256",
            "stateStoreGeneration",
            "stateStoreIdentitySha256",
            "verifierChallengeSha256",
        },
        "nonce authority verifier-state commit receipt payload",
    )
    payload_sha256 = sha256_json(payload)
    require(
        envelope["payloadSha256"] == payload_sha256,
        "nonce authority verifier-state commit receipt digest is invalid",
    )
    signature = b64url_decode_exact(
        envelope["signatureBase64url"],
        "nonce authority verifier-state commit receipt signature",
        exact_bytes=64,
    )
    try:
        signing_key.verify(
            signature,
            NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_DOMAIN
            + canonical_json_bytes(
                {
                    "payload": payload,
                    "payloadSha256": payload_sha256,
                }
            ),
        )
    except InvalidSignature as exc:
        raise VerificationError(
            "nonce authority verifier-state commit receipt signature is invalid"
        ) from exc
    prior_verifier_state = verify_nonce_authority_verifier_state(
        prior_verifier_state,
        signing_key=signing_key,
        signing_key_id=signing_key_id,
        expected_state_store_identity_sha256=(
            expected_state_store_identity_sha256
        ),
        assurance=assurance,
        assurance_sha256=assurance_sha256,
    )
    prior = prior_verifier_state["payload"]
    authorization = verify_nonce_authority_state_authorization(
        authorization,
        signing_key=signing_key,
        signing_key_id=signing_key_id,
        expected_state_store_identity_sha256=(
            expected_state_store_identity_sha256
        ),
        expected_state_store_attestation_key_id=(
            state_store_attestation_key_id
        ),
        expected_state_store_assurance_evidence_sha256=(
            expected_state_store_assurance_evidence_sha256
        ),
        expected_state_store_configuration_sha256=(
            expected_state_store_configuration_sha256
        ),
        expected_nonce_receipt_signing_key_id=(
            nonce_receipt_signing_key_id
        ),
        assurance=assurance,
        assurance_sha256=assurance_sha256,
        prior_verifier_state=prior_verifier_state,
        verifier_challenge=verifier_challenge,
        now=None,
    )
    authorization_payload = authorization["payload"]
    commit_request = exact_keys(
        commit_request,
        {
            "apiVersion",
            "authorization",
            "nonceConsumptionReceipt",
            "preparedOperationSha256",
            "recoveryKeySha256",
            "requestBindingSha256",
            "verifierChallengeBase64url",
        },
        "verifier-state commit request",
    )
    commit_request_sha256 = sha256_json(commit_request)
    require(
        commit_request["apiVersion"]
        == VERIFIER_STATE_COMMIT_REQUEST_VERSION
        and commit_request["authorization"]
        == authorization["document"]
        and commit_request["nonceConsumptionReceipt"]
        == nonce_consumption_receipt
        and commit_request["verifierChallengeBase64url"]
        == b64url_encode(verifier_challenge),
        "verifier-state commit request crossed its retained artifacts",
    )
    for field in (
        "preparedOperationSha256",
        "recoveryKeySha256",
        "requestBindingSha256",
    ):
        require_sha256(
            commit_request[field],
            f"verifier-state commit request {field}",
        )
    require(
        commit_request["recoveryKeySha256"]
        == authorization_payload["recoveryKeySha256"]
        and commit_request["requestBindingSha256"]
        == authorization_payload["requestBindingSha256"],
        "verifier-state commit request crossed recovery bindings",
    )
    verified_nonce_receipt = (
        verify_public_attestation_nonce_receipt_envelope(
            nonce_consumption_receipt,
            key=nonce_receipt_signing_key,
            key_id=nonce_receipt_signing_key_id,
        )
    )
    nonce_payload = verified_nonce_receipt["payload"]
    nonce_consumption = exact_keys(
        nonce_payload["nonceConsumption"],
        {
            "apiVersion",
            "consumedAtUnix",
            "nonceSha256",
            "oneUse",
            "requestBodySha256",
            "sequence",
            "storeIdentitySha256",
            "tlsBindingSha256",
        },
        "verified nonce consumption",
    )
    nonce_consumption_sha256 = sha256_json(nonce_consumption)
    nonce_consumption_receipt_sha256 = verified_nonce_receipt[
        "receiptSha256"
    ]
    nonce_authority_state = validate_nonce_authority_state_transition(
        nonce_payload["nonceAuthorityState"],
        assurance=assurance,
        assurance_sha256=assurance_sha256,
        nonce_consumption_sha256=nonce_consumption_sha256,
        nonce_verifier_state_authorization_sha256=authorization[
            "envelopeSha256"
        ],
        previous_receipt_sha256=nonce_payload[
            "previousReceiptSha256"
        ],
        sequence=nonce_payload["sequence"],
        transaction_id_base64url=nonce_payload[
            "transactionIdBase64url"
        ],
        prior_verifier_state=prior_verifier_state,
    )
    nonce_authority_state_sha256 = sha256_json(
        nonce_authority_state
    )
    nonce_consumed_at = require_positive_uint(
        nonce_payload["consumedAtUnix"],
        "nonce receipt consumed time",
    )
    nonce_expires_at = require_positive_uint(
        nonce_payload["expiresAtUnix"],
        "nonce receipt expiry",
    )
    nonce_consume_request_sha256 = sha256(
        PUBLIC_ATTESTATION_NONCE_CONSUME_REQUEST_DIGEST_DOMAIN
        + canonical_json_bytes(
            {
                "apiVersion":
                PUBLIC_ATTESTATION_NONCE_CONSUME_ONCE_REQUEST_VERSION,
                "expiresAtUnix": nonce_expires_at,
                "nonceAuthorityVerifierStateAuthorizationSha256":
                authorization["envelopeSha256"],
                "nonceSha256": nonce_payload["nonceSha256"],
                "producerChannelChallengeBase64url":
                nonce_payload["producerChannelChallengeBase64url"],
                "producerEphemeralKeySha256":
                nonce_payload["producerEphemeralKeySha256"],
                "producerInvocationSha256":
                nonce_payload["producerInvocationSha256"],
                "requestBodySha256":
                nonce_payload["requestBodySha256"],
                "tlsBindingSha256":
                nonce_payload["tlsBindingSha256"],
                "transactionIdBase64url":
                nonce_payload["transactionIdBase64url"],
            }
        )
    )
    for field in (
        "consumeRequestSha256",
        "nonceAuthorityAssuranceSha256",
        "nonceAuthorityStateSha256",
        "nonceAuthorityVerifierStateAuthorizationSha256",
        "nonceConsumptionSha256",
        "nonceSha256",
        "producerEphemeralKeySha256",
        "producerInvocationSha256",
        "requestBodySha256",
        "signerChannelBindingSha256",
        "storeIdentitySha256",
        "tlsBindingSha256",
    ):
        require_sha256(
            nonce_payload[field],
            f"signed nonce receipt {field}",
        )
    b64url_decode_exact(
        nonce_payload["producerChannelChallengeBase64url"],
        "signed nonce receipt producer channel challenge",
        exact_bytes=32,
    )
    b64url_decode_exact(
        nonce_payload["transactionIdBase64url"],
        "signed nonce receipt transaction ID",
        exact_bytes=32,
    )
    require(
        nonce_payload["apiVersion"]
        == PUBLIC_ATTESTATION_NONCE_RECEIPT_PAYLOAD_VERSION
        and nonce_payload["consumeRequestSha256"]
        == nonce_consume_request_sha256
        and nonce_payload["nonceAuthorityAssuranceSha256"]
        == assurance_sha256
        and nonce_payload[
            "nonceAuthorityVerifierStateAuthorizationSha256"
        ]
        == authorization["envelopeSha256"]
        and nonce_payload["nonceAuthorityStateSha256"]
        == nonce_authority_state_sha256
        and nonce_payload["nonceConsumptionSha256"]
        == nonce_consumption_sha256
        and nonce_payload["storeIdentitySha256"]
        == assurance["authorityIdentitySha256"]
        and nonce_payload["previousReceiptSha256"]
        == prior["highWaterReceiptSha256"]
        and nonce_payload[
            "finalExternalVerifierChallengeConsumptionRequired"
        ]
        is True
        and nonce_payload[
            "finalExternalVerifierChallengeConsumed"
        ]
        is False
        and nonce_consumption["apiVersion"]
        == PUBLIC_ATTESTATION_NONCE_CONSUMPTION_VERSION
        and nonce_consumption["oneUse"] is True
        and nonce_consumption["consumedAtUnix"]
        == nonce_consumed_at
        and nonce_consumption["sequence"]
        == nonce_payload["sequence"]
        and nonce_consumption["nonceSha256"]
        == nonce_payload["nonceSha256"]
        and nonce_consumption["requestBodySha256"]
        == nonce_payload["requestBodySha256"]
        and nonce_consumption["tlsBindingSha256"]
        == nonce_payload["tlsBindingSha256"]
        and nonce_consumption["storeIdentitySha256"]
        == nonce_payload["storeIdentitySha256"]
        and nonce_payload["receiptIssuedAtUnix"]
        == nonce_consumed_at
        < nonce_expires_at,
        "signed nonce receipt is internally crossed or incomplete",
    )
    require(
        authorization_payload["issuedAtUnix"]
        <= nonce_consumed_at
        <= now
        and nonce_consumed_at
        < authorization_payload["expiresAtUnix"],
        "signed nonce receipt is internally crossed or incomplete",
    )
    next_generation = require_positive_uint(
        prior["stateStoreGeneration"],
        "prior nonce authority state-store generation",
    ) + 1
    require(
        next_generation <= MAX_U64,
        "nonce authority state-store generation overflowed",
    )
    expected_state_head_sha256 = sha256(
        NONCE_AUTHORITY_VERIFIER_STATE_HEAD_DOMAIN
        + canonical_json_bytes(
            {
                "assuranceSha256": assurance_sha256,
                "authorizationSha256":
                authorization["envelopeSha256"],
                "commitOperationIdBase64url":
                authorization_payload["operationIdBase64url"],
                "nonceAuthorityStateSha256":
                nonce_authority_state_sha256,
                "nonceConsumptionReceiptSha256":
                nonce_consumption_receipt_sha256,
                "previousStateStoreHeadSha256":
                prior["stateStoreHeadSha256"],
                "stateStoreGeneration": next_generation,
            }
        )
    )
    commit_candidate = {
        "apiVersion": VERIFIER_STATE_STORE_COMMIT_CANDIDATE_VERSION,
        "assuranceSha256": assurance_sha256,
        "authorizationSha256": authorization["envelopeSha256"],
        "commitRequestSha256": require_sha256(
            commit_request_sha256,
            "verifier-state commit request",
        ),
        "expectedVerifierStateSha256":
        prior_verifier_state["envelopeSha256"],
        "nonceAuthorityStateSha256":
        nonce_authority_state_sha256,
        "nonceConsumptionReceiptSha256":
        nonce_consumption_receipt_sha256,
        "nonceConsumptionSha256": nonce_consumption_sha256,
        "operationIdBase64url":
        authorization_payload["operationIdBase64url"],
        "previousCommittedAtUnix": prior["committedAtUnix"],
        "previousStateStoreGeneration":
        prior["stateStoreGeneration"],
        "previousStateStoreHeadSha256":
        prior["stateStoreHeadSha256"],
        "proposedStateStoreGeneration": next_generation,
        "proposedStateStoreHeadSha256":
        expected_state_head_sha256,
        "verifierChallengeSha256":
        authorization_payload["verifierChallengeSha256"],
    }
    store_proof = verify_verifier_state_store_commit_proof(
        payload["signedStoreCommitProof"],
        signing_key=state_store_attestation_key,
        signing_key_id=state_store_attestation_key_id,
        expected_state_store_identity_sha256=(
            expected_state_store_identity_sha256
        ),
        expected_state_store_administrative_domain_sha256=(
            expected_state_store_administrative_domain_sha256
        ),
        expected_state_store_assurance_evidence_sha256=(
            expected_state_store_assurance_evidence_sha256
        ),
        expected_state_store_configuration_sha256=(
            expected_state_store_configuration_sha256
        ),
        minimum_state_store_generation=(
            minimum_state_store_generation
        ),
        minimum_state_store_commit_index=(
            minimum_state_store_commit_index
        ),
        expected_production_eligible=expected_production_eligible,
        authorization=authorization,
        commit_request_sha256=commit_request_sha256,
        commit_candidate=commit_candidate,
        nonce_consumed_at=nonce_consumed_at,
        now=None,
    )
    committed_at = require_positive_uint(
        payload["committedAtUnix"],
        "nonce authority verifier-state commit time",
    )
    require(
        payload["apiVersion"]
        == NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_VERSION
        and payload["assuranceSha256"] == assurance_sha256
        and payload["authorizationSha256"]
        == authorization["envelopeSha256"]
        and payload["casCommitted"] is True
        and payload["oneUseAuthorizationConsumed"] is True
        and payload["preparedOperationSha256"]
        == commit_request["preparedOperationSha256"]
        and payload["commitOperationIdBase64url"]
        == authorization_payload["operationIdBase64url"]
        and payload["commitRequestSha256"]
        == commit_request_sha256
        and payload["priorVerifierStateSha256"]
        == prior_verifier_state["envelopeSha256"]
        and payload["recoveryIdentitySha256"]
        == authorization_payload["recoveryIdentitySha256"]
        and payload["recoveryKeySha256"]
        == authorization_payload["recoveryKeySha256"]
        and payload["requestBindingSha256"]
        == authorization_payload["requestBindingSha256"]
        and payload["previousStateStoreGeneration"]
        == prior["stateStoreGeneration"]
        and payload["previousStateStoreHeadSha256"]
        == prior["stateStoreHeadSha256"]
        and payload["signedStoreCommitProof"]
        == store_proof["document"]
        and payload["signedStoreCommitProofSha256"]
        == store_proof["envelopeSha256"]
        and payload["stateStoreAdministrativeDomainSha256"]
        == expected_state_store_administrative_domain_sha256
        and payload["stateStoreAssuranceEvidenceSha256"]
        == expected_state_store_assurance_evidence_sha256
        and payload["stateStoreAttestationKeySpkiSha256"]
        == state_store_attestation_key_id
        and payload["stateStoreConfigurationSha256"]
        == expected_state_store_configuration_sha256
        and payload["stateStoreGeneration"]
        == store_proof["payload"]["stateStoreGeneration"]
        and payload["stateStoreCommitIndex"]
        == store_proof["payload"]["stateStoreCommitIndex"]
        and payload["stateStoreIdentitySha256"]
        == require_sha256(
            expected_state_store_identity_sha256,
            "nonce authority verifier-state store identity",
        )
        and payload["verifierChallengeSha256"]
        == sha256(verifier_challenge)
        and payload["nonceAuthorityStateSha256"]
        == nonce_authority_state_sha256
        and payload["nonceConsumptionReceiptSha256"]
        == nonce_consumption_receipt_sha256
        and payload["nonceConsumptionSha256"]
        == nonce_consumption_sha256
        and payload["nonceReceiptSigningKeySpkiSha256"]
        == nonce_receipt_signing_key_id
        and authorization_payload["priorCommittedAtUnix"]
        <= committed_at
        == store_proof["payload"]["committedAtUnix"]
        <= now
        and nonce_consumed_at <= committed_at,
        "nonce authority verifier-state CAS receipt is stale or crossed its authorization",
    )
    committed_state = exact_keys(
        payload["committedVerifierState"],
        {
            "apiVersion",
            "assuranceSha256",
            "authorityEpoch",
            "authorityGeneration",
            "commitOperationIdBase64url",
            "committedAtUnix",
            "highWaterCommitmentSha256",
            "highWaterReceiptSha256",
            "highWaterSequence",
            "priorVerifierStateSha256",
            "stateStoreGeneration",
            "stateStoreHeadSha256",
            "stateStoreIdentitySha256",
        },
        "committed nonce authority verifier state",
    )
    expected_committed_state = {
        "apiVersion": NONCE_AUTHORITY_VERIFIER_STATE_VERSION,
        "assuranceSha256": assurance_sha256,
        "authorityEpoch": assurance["authorityEpoch"],
        "authorityGeneration": assurance["authorityGeneration"],
        "commitOperationIdBase64url":
        authorization_payload["operationIdBase64url"],
        "committedAtUnix": committed_at,
        "highWaterCommitmentSha256":
        nonce_authority_state["highWaterCommitmentSha256"],
        "highWaterReceiptSha256":
        nonce_consumption_receipt_sha256,
        "highWaterSequence":
        nonce_authority_state["highWaterSequence"],
        "priorVerifierStateSha256":
        prior_verifier_state["envelopeSha256"],
        "stateStoreGeneration": next_generation,
        "stateStoreHeadSha256": expected_state_head_sha256,
        "stateStoreIdentitySha256":
        expected_state_store_identity_sha256,
    }
    require(
        committed_state == expected_committed_state
        and payload["committedVerifierStateSha256"]
        == sha256_json(committed_state),
        "nonce authority verifier-state CAS committed the wrong head",
    )
    return {
        "committedState": committed_state,
        "committedStateSha256": sha256_json(committed_state),
        "commitRequestSha256": commit_request_sha256,
        "document": envelope,
        "envelopeSha256": sha256_json(envelope),
        "nonceAuthorityState": nonce_authority_state,
        "nonceAuthorityStateSha256": nonce_authority_state_sha256,
        "nonceConsumptionReceiptSha256":
        nonce_consumption_receipt_sha256,
        "nonceConsumptionSha256": nonce_consumption_sha256,
        "storeCommitProof": store_proof["document"],
        "storeCommitProofSha256": store_proof["envelopeSha256"],
    }


def validate_nonce_authority_state_transition(
    document: Any,
    *,
    assurance: dict[str, Any],
    assurance_sha256: str,
    nonce_consumption_sha256: str,
    nonce_verifier_state_authorization_sha256: str,
    previous_receipt_sha256: str | None,
    sequence: int,
    transaction_id_base64url: str,
    prior_verifier_state: dict[str, Any],
) -> dict[str, Any]:
    state = exact_keys(
        document,
        {
            "apiVersion",
            "assuranceSha256",
            "authorityEpoch",
            "authorityGeneration",
            "highWaterCommitmentSha256",
            "highWaterSequence",
            "previousHighWaterCommitmentSha256",
        },
        "signed receipt nonce authority state",
    )
    prior = prior_verifier_state["payload"]
    expected_sequence = require_uint(
        prior["highWaterSequence"],
        "prior nonce authority high-water sequence",
    ) + 1
    require(
        expected_sequence <= MAX_U64
        and sequence == expected_sequence
        and state["apiVersion"] == NONCE_AUTHORITY_STATE_VERSION
        and state["assuranceSha256"] == assurance_sha256
        and require_positive_uint(
            state["authorityEpoch"],
            "nonce authority state epoch",
        )
        == assurance["authorityEpoch"]
        and require_positive_uint(
            state["authorityGeneration"],
            "nonce authority state generation",
        )
        == assurance["authorityGeneration"]
        and require_positive_uint(
            state["highWaterSequence"],
            "nonce authority state high-water sequence",
        )
        == sequence
        and state["previousHighWaterCommitmentSha256"]
        == prior["highWaterCommitmentSha256"]
        and previous_receipt_sha256
        == prior["highWaterReceiptSha256"],
        "nonce authority receipt is not the exact successor of fresh independently retained state",
    )
    expected_commitment = nonce_authority_high_water_commitment(
        assurance_sha256=assurance_sha256,
        authority_epoch=assurance["authorityEpoch"],
        authority_generation=assurance["authorityGeneration"],
        nonce_consumption_sha256=nonce_consumption_sha256,
        nonce_verifier_state_authorization_sha256=(
            nonce_verifier_state_authorization_sha256
        ),
        previous_high_water_commitment_sha256=prior[
            "highWaterCommitmentSha256"
        ],
        previous_receipt_sha256=previous_receipt_sha256,
        sequence=sequence,
        transaction_id_base64url=transaction_id_base64url,
    )
    require(
        state["highWaterCommitmentSha256"]
        == expected_commitment,
        "nonce authority high-water commitment is invalid",
    )
    return state


def validate_public_attestation_config(
    document: Any,
    raw: bytes,
    *,
    expected_sha256: str,
    expected_nonce_authority_assurance_sha256: str,
    expected_nonce_authority_assurance_issuer_spki_sha256: str,
    trust: dict[str, Any],
) -> dict[str, Any]:
    require(
        raw == canonical_json_bytes(document) + b"\n",
        "public attestation config is not canonical JSON plus LF",
    )
    require(
        sha256(raw)
        == require_sha256(
            expected_sha256,
            "independently expected public attestation config",
        ),
        "public attestation config differs from its independent pin",
    )
    config = exact_keys(
        document,
        {
            "apiVersion",
            "minimumRollbackContinuityCommitmentSha256",
            "nonceAuthorityAssurance",
            "nonceAuthorityAssuranceEvidence",
            "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url",
            "nonceAuthorityAssuranceSha256",
            "nonceAuthorityVerifierStateService",
            "nonceAuthorityVerifierStateRoleSeparationEvidence",
            "nonceAuthorityVerifierStateRoleSeparationEvidenceIssuer",
            "nonceAuthorityVerifierStateRoleSeparationEvidenceSigningPublicKeySpkiDerBase64url",
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url",
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256",
            "nonceAuthorityVerifierStateStoreAssuranceEvidence",
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256",
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSigningPublicKeySpkiDerBase64url",
            "nonceAuthorityVerifierStateStoreAssuranceIssuerAdministrativeDomainSha256",
            "nonceAuthorityVerifierStateStoreAssuranceIssuerCredentialIdentitySha256",
            "nonceAuthorityVerifierStateStoreAssuranceIssuerIdentitySha256",
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url",
            "nonceAuthorityVerifierStateStoreConfigurationSha256",
            "nonceAuthorityVerifierStateStoreCredentialIdentitySha256",
            "nonceAuthorityVerifierStateStoreIdentitySha256",
            "nonceAuthorityVerifierStateStoreMinimumCommitIndex",
            "nonceAuthorityVerifierStateStoreMinimumGeneration",
            "nonceAuthorityVerifierStateStoreRollbackMechanism",
            "nonceStoreSigningPublicKeySpkiDerBase64url",
            "producerPolicy",
            "releaseIdentity",
            "releaseIdentitySha256",
            "sandboxDescriptorSha256",
            "tlsScopeSigningPublicKeySpkiDerBase64url",
            "witnessStoreSigningPublicKeySpkiDerBase64url",
        },
        "public attestation config",
    )
    release_identity = validate_release_identity(
        config["releaseIdentity"],
        label="public attestation config release identity",
    )
    require(
        config["apiVersion"] == PUBLIC_ATTESTATION_CONFIG_VERSION
        and config["releaseIdentitySha256"]
        == sha256_json(release_identity)
        and config["sandboxDescriptorSha256"]
        == release_identity["configuration"]["publicAttestation"][
            "sandboxDescriptorSha256"
        ]
        and require_sha256(
            config["minimumRollbackContinuityCommitmentSha256"],
            "public attestation minimum rollback continuity commitment",
        )
        == config["minimumRollbackContinuityCommitmentSha256"]
        and validate_public_attestation_component_pins(
            config["producerPolicy"],
            label="public attestation config producer policy",
        )
        == release_identity["configuration"]["publicAttestation"]
        and release_identity["configuration"]["trustRootBundleSha256"]
        == trust["trustRootBundleSha256"]
        and release_identity["configuration"]["releaseKeySpkiSha256"]
        == trust["keyIds"]["completion"]
        and release_identity["configuration"]["witnessKeySpkiSha256"]
        == trust["keyIds"]["witness"],
        "public attestation config crossed its stable trust roots",
    )
    verifier_state_service = exact_keys(
        config["nonceAuthorityVerifierStateService"],
        {
            "abortPath",
            "apiVersion",
            "attachNonceStatusPath",
            "clientCertificateSpkiSha256",
            "commitPath",
            "concurrencyLimit",
            "endpoint",
            "issueChallengePath",
            "markConsumptionPath",
            "maxResponseBytes",
            "preparePath",
            "readPath",
            "recoverPath",
            "recoverChallengePath",
            "recoveryLookupPath",
            "serverLeafSpkiSha256",
            "serviceConfigurationSha256",
            "timeoutMilliseconds",
        },
        "public attestation verifier-state service",
    )
    endpoint = verifier_state_service["endpoint"]
    try:
        parsed_endpoint = urlsplit(endpoint)
        endpoint_port = parsed_endpoint.port
        endpoint_address = ipaddress.ip_address(
            parsed_endpoint.hostname or ""
        )
    except (TypeError, ValueError) as exc:
        raise VerificationError(
            "public attestation verifier-state endpoint is invalid"
        ) from exc
    require(
        verifier_state_service["apiVersion"]
        == PUBLIC_ATTESTATION_VERIFIER_STATE_CLIENT_VERSION
        and type(endpoint) is str
        and parsed_endpoint.scheme == "https"
        and parsed_endpoint.path == ""
        and parsed_endpoint.query == ""
        and parsed_endpoint.fragment == ""
        and parsed_endpoint.username is None
        and parsed_endpoint.password is None
        and isinstance(endpoint_address, ipaddress.IPv4Address)
        and str(endpoint_address) == parsed_endpoint.hostname
        and endpoint_port is not None
        and 1 <= endpoint_port <= 65535
        and endpoint
        == f"https://{endpoint_address.compressed}:{endpoint_port}"
        and verifier_state_service["readPath"] == "/v1/state/read"
        and verifier_state_service["issueChallengePath"]
        == "/v1/state/issue-challenge"
        and verifier_state_service["recoverChallengePath"]
        == "/v1/state/recover-challenge"
        and verifier_state_service["preparePath"]
        == "/v1/state/prepare"
        and verifier_state_service["recoveryLookupPath"]
        == "/v1/state/recovery-lookup"
        and verifier_state_service["markConsumptionPath"]
        == "/v1/state/mark-consumption"
        and verifier_state_service["attachNonceStatusPath"]
        == "/v1/state/attach-nonce-status"
        and verifier_state_service["abortPath"] == "/v1/state/abort"
        and verifier_state_service["commitPath"] == "/v1/state/commit"
        and verifier_state_service["recoverPath"]
        == "/v1/state/recover"
        and 1024
        <= require_positive_uint(
            verifier_state_service["maxResponseBytes"],
            "public attestation verifier-state response bound",
        )
        <= 256 * 1024
        and 100
        <= require_positive_uint(
            verifier_state_service["timeoutMilliseconds"],
            "public attestation verifier-state timeout",
        )
        <= 10_000
        and require_positive_uint(
            verifier_state_service["concurrencyLimit"],
            "public attestation verifier-state concurrency",
        )
        == 1,
        "public attestation verifier-state endpoint, paths, or bounds are invalid",
    )
    for field in (
        "clientCertificateSpkiSha256",
        "serverLeafSpkiSha256",
        "serviceConfigurationSha256",
    ):
        require_sha256(
            verifier_state_service[field],
            f"public attestation verifier-state {field}",
        )
    key_der = b64url_decode_exact(
        config["tlsScopeSigningPublicKeySpkiDerBase64url"],
        "public attestation TLS scope signing key",
        exact_bytes=44,
    )
    try:
        tls_scope_key = serialization.load_der_public_key(key_der)
    except (TypeError, ValueError) as exc:
        raise VerificationError(
            "public attestation TLS scope signing key is invalid"
        ) from exc
    tls_scope_key_id = sha256(key_der)
    require(
        isinstance(tls_scope_key, Ed25519PublicKey)
        and tls_scope_key_id
        == release_identity["configuration"][
            "tlsScopeSigningKeySpkiSha256"
        ],
        "public attestation TLS scope signing key crossed the stable release",
    )
    witness_store_key_der = b64url_decode_exact(
        config["witnessStoreSigningPublicKeySpkiDerBase64url"],
        "public attestation witness-store signing key",
        exact_bytes=44,
    )
    try:
        witness_store_key = serialization.load_der_public_key(
            witness_store_key_der
        )
    except (TypeError, ValueError) as exc:
        raise VerificationError(
            "public attestation witness-store signing key is invalid"
        ) from exc
    witness_store_key_id = sha256(witness_store_key_der)
    require(
        isinstance(witness_store_key, Ed25519PublicKey)
        and witness_store_key_id
        == release_identity["configuration"]["publicAttestation"][
            "witnessStoreKeySpkiSha256"
        ],
        "public attestation witness-store key crossed the stable release",
    )
    nonce_store_key_der = b64url_decode_exact(
        config["nonceStoreSigningPublicKeySpkiDerBase64url"],
        "public attestation nonce-store signing key",
        exact_bytes=44,
    )
    try:
        nonce_store_key = serialization.load_der_public_key(
            nonce_store_key_der
        )
    except (TypeError, ValueError) as exc:
        raise VerificationError(
            "public attestation nonce-store signing key is invalid"
        ) from exc
    nonce_store_key_id = sha256(nonce_store_key_der)
    require(
        isinstance(nonce_store_key, Ed25519PublicKey)
        and nonce_store_key_id
        == release_identity["configuration"]["publicAttestation"][
            "nonceStoreKeySpkiSha256"
        ]
        and len(
            {
                nonce_store_key_id,
                witness_store_key_id,
                trust["keyIds"]["completion"],
                trust["keyIds"]["witness"],
            }
        )
        == 4,
        "public attestation nonce-store key crossed or reused a stable trust role",
    )
    nonce_authority_assurance = validate_nonce_authority_assurance(
        config["nonceAuthorityAssurance"],
        expected_authority_identity_sha256=release_identity[
            "configuration"
        ]["publicAttestation"]["nonceStoreIdentitySha256"],
    )
    nonce_authority_assurance_sha256 = sha256_json(
        nonce_authority_assurance
    )
    require(
        config["nonceAuthorityAssuranceSha256"]
        == nonce_authority_assurance_sha256
        and nonce_authority_assurance_sha256
        == require_sha256(
            expected_nonce_authority_assurance_sha256,
            "independently expected nonce authority assurance",
        )
        and nonce_authority_assurance["productionEligible"] is True
        and nonce_authority_assurance["assuranceLevel"]
        == "productionRollbackProtected",
        "public attestation config does not pin production nonce rollback assurance",
    )
    verifier_state_key_der = b64url_decode_exact(
        config[
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
        ],
        "nonce authority verifier-state signing key",
        exact_bytes=44,
    )
    try:
        verifier_state_key = serialization.load_der_public_key(
            verifier_state_key_der
        )
    except (TypeError, ValueError) as exc:
        raise VerificationError(
            "nonce authority verifier-state signing key is invalid"
        ) from exc
    verifier_state_key_id = sha256(verifier_state_key_der)
    state_store_attestation_key_der = b64url_decode_exact(
        config[
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
        ],
        "nonce authority verifier-state store attestation key",
        exact_bytes=44,
    )
    try:
        state_store_attestation_key = serialization.load_der_public_key(
            state_store_attestation_key_der
        )
    except (TypeError, ValueError) as exc:
        raise VerificationError(
            "nonce authority verifier-state store attestation key is invalid"
        ) from exc
    state_store_attestation_key_id = sha256(
        state_store_attestation_key_der
    )
    assurance_evidence_key_der = b64url_decode_exact(
        config[
            "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
        ],
        "nonce authority assurance-evidence signing key",
        exact_bytes=44,
    )
    try:
        assurance_evidence_key = serialization.load_der_public_key(
            assurance_evidence_key_der
        )
    except (TypeError, ValueError) as exc:
        raise VerificationError(
            "nonce authority assurance-evidence signing key is invalid"
        ) from exc
    assurance_evidence_key_id = sha256(
        assurance_evidence_key_der
    )
    require(
        assurance_evidence_key_id
        == require_sha256(
            expected_nonce_authority_assurance_issuer_spki_sha256,
            "independently expected nonce assurance issuer key",
        ),
        "nonce authority assurance issuer differs from its independent pin",
    )
    require(
        isinstance(verifier_state_key, Ed25519PublicKey)
        and isinstance(
            state_store_attestation_key,
            Ed25519PublicKey,
        )
        and isinstance(assurance_evidence_key, Ed25519PublicKey)
        and verifier_state_key_id
        not in {
            nonce_store_key_id,
            witness_store_key_id,
            trust["keyIds"]["completion"],
            trust["keyIds"]["witness"],
        },
        "nonce authority verifier-state key crossed or reused a trust role",
    )
    require(
        state_store_attestation_key_id
        not in {
            assurance_evidence_key_id,
            verifier_state_key_id,
            nonce_store_key_id,
            witness_store_key_id,
            trust["keyIds"]["completion"],
            trust["keyIds"]["witness"],
        },
        "verifier-state store attestation key crossed or reused a trust role",
    )
    require(
        assurance_evidence_key_id
        not in {
            verifier_state_key_id,
            nonce_store_key_id,
            witness_store_key_id,
            trust["keyIds"]["completion"],
            trust["keyIds"]["witness"],
        },
        "nonce authority assurance issuer key crossed or reused a trust role",
    )
    require(
        len(
            {
                assurance_evidence_key_id,
                state_store_attestation_key_id,
                verifier_state_key_id,
                nonce_store_key_id,
                tls_scope_key_id,
                witness_store_key_id,
                trust["keyIds"]["completion"],
                trust["keyIds"]["witness"],
            }
        )
        == 8,
        "public attestation signing roles are not pairwise key-distinct",
    )
    verifier_state_store_administrative_domain_sha256 = (
        require_sha256(
            config[
                "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
            ],
            "nonce authority verifier-state administrative domain",
        )
    )
    require(
        verifier_state_store_administrative_domain_sha256
        != nonce_authority_assurance[
            "administrativeDomainSha256"
        ],
        "nonce authority and verifier-state store share an administrative domain",
    )
    verifier_state_store_identity_sha256 = require_sha256(
        config["nonceAuthorityVerifierStateStoreIdentitySha256"],
        "nonce authority verifier-state store identity",
    )
    verifier_state_store_assurance_evidence_sha256 = require_sha256(
        config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ],
        "nonce authority verifier-state store assurance evidence",
    )
    require_sha256(
        config[
            "nonceAuthorityVerifierStateStoreConfigurationSha256"
        ],
        "nonce authority verifier-state store configuration",
    )
    require_sha256(
        config[
            "nonceAuthorityVerifierStateStoreCredentialIdentitySha256"
        ],
        "nonce authority verifier-state store credential identity",
    )
    for field in (
        "nonceAuthorityVerifierStateStoreAssuranceIssuerAdministrativeDomainSha256",
        "nonceAuthorityVerifierStateStoreAssuranceIssuerCredentialIdentitySha256",
        "nonceAuthorityVerifierStateStoreAssuranceIssuerIdentitySha256",
    ):
        require_sha256(config[field], field)
    require_positive_uint(
        config["nonceAuthorityVerifierStateStoreMinimumGeneration"],
        "nonce authority verifier-state store minimum generation",
    )
    require_positive_uint(
        config["nonceAuthorityVerifierStateStoreMinimumCommitIndex"],
        "nonce authority verifier-state store minimum commit index",
    )
    require(
        isinstance(
            config["nonceAuthorityVerifierStateStoreRollbackMechanism"],
            str,
        )
        and 1
        <= len(
            config[
                "nonceAuthorityVerifierStateStoreRollbackMechanism"
            ]
        )
        <= 256,
        "nonce authority verifier-state rollback mechanism is invalid",
    )
    store_and_role_assurance = (
        verify_verifier_state_store_and_role_assurance(
            config,
            assurance=nonce_authority_assurance,
            nonce_store_key_id=nonce_store_key_id,
            verifier_state_key_id=verifier_state_key_id,
            store_attestation_key_id=state_store_attestation_key_id,
            service=verifier_state_service,
            now=int(time.time()),
        )
    )
    global_role_key_ids = {
        **store_and_role_assurance["roleKeyIdsByRole"],
        "release": release_identity["configuration"][
            "releaseKeySpkiSha256"
        ],
        "releaseCa": release_identity["configuration"]["caSpkiSha256"],
        "responseKey": release_identity["configuration"][
            "responseKeySpkiSha256"
        ],
        "tlsScope": release_identity["configuration"][
            "tlsScopeSigningKeySpkiSha256"
        ],
        "witness": release_identity["configuration"][
            "witnessKeySpkiSha256"
        ],
        "witnessStore": witness_store_key_id,
        **{
            f"trustRoot:{name}": trust["keyIds"][name]
            for name in sorted(trust["keyIds"])
            if name not in {"completion", "witness"}
        },
    }
    global_role_key_ids = (
        validate_global_attestation_key_role_separation(
            global_role_key_ids
        )
    )
    return {
        "globalRoleKeyIds": global_role_key_ids,
        "nonceAuthorityAssurance": nonce_authority_assurance,
        "nonceAuthorityAssuranceEvidence":
        config["nonceAuthorityAssuranceEvidence"],
        "nonceAuthorityAssuranceEvidenceKey":
        assurance_evidence_key,
        "nonceAuthorityAssuranceEvidenceKeyId":
        assurance_evidence_key_id,
        "nonceAuthorityAssuranceSha256":
        nonce_authority_assurance_sha256,
        "nonceAuthorityVerifierStateKey": verifier_state_key,
        "nonceAuthorityVerifierStateKeyId":
        verifier_state_key_id,
        "nonceAuthorityVerifierStateStoreIdentitySha256":
        verifier_state_store_identity_sha256,
        "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256":
        verifier_state_store_administrative_domain_sha256,
        "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256":
        verifier_state_store_assurance_evidence_sha256,
        "nonceAuthorityVerifierStateStoreAssuranceEvidence":
        config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidence"
        ],
        "nonceAuthorityVerifierStateRoleSeparationEvidence":
        config[
            "nonceAuthorityVerifierStateRoleSeparationEvidence"
        ],
        "nonceAuthorityVerifierStateRoleSeparationEvidenceSha256":
        store_and_role_assurance["roleEvidenceSha256"],
        "nonceAuthorityVerifierStateStoreConfigurationSha256":
        config[
            "nonceAuthorityVerifierStateStoreConfigurationSha256"
        ],
        "nonceAuthorityVerifierStateStoreMinimumCommitIndex":
        config[
            "nonceAuthorityVerifierStateStoreMinimumCommitIndex"
        ],
        "nonceAuthorityVerifierStateStoreMinimumGeneration":
        config[
            "nonceAuthorityVerifierStateStoreMinimumGeneration"
        ],
        "nonceAuthorityVerifierStateStoreAttestationKey":
        state_store_attestation_key,
        "nonceAuthorityVerifierStateStoreAttestationKeyId":
        state_store_attestation_key_id,
        "nonceStoreKey": nonce_store_key,
        "nonceStoreKeyId": nonce_store_key_id,
        "minimumRollbackContinuityCommitmentSha256": config[
            "minimumRollbackContinuityCommitmentSha256"
        ],
        "nonceAuthorityVerifierStateService":
        verifier_state_service,
        "producerPolicy":
        release_identity["configuration"]["publicAttestation"],
        "releaseIdentity": release_identity,
        "releaseIdentitySha256": sha256_json(release_identity),
        "sha256": sha256(raw),
        "witnessStoreKey": witness_store_key,
        "witnessStoreKeyId": witness_store_key_id,
    }


def validate_public_attestation_nonce_consumption(
    document: Any,
    *,
    caller_nonce_sha256: str,
    request_body_sha256: str,
    tls_binding_sha256: str,
    expected_store_identity_sha256: str,
    consumed_at_unix: int,
    sequence: int,
) -> dict[str, Any]:
    consumption = exact_keys(
        document,
        {
            "apiVersion",
            "consumedAtUnix",
            "nonceSha256",
            "oneUse",
            "requestBodySha256",
            "sequence",
            "storeIdentitySha256",
            "tlsBindingSha256",
        },
        "durable public-attestation nonce consumption",
    )
    require(
        consumption["apiVersion"]
        == PUBLIC_ATTESTATION_NONCE_CONSUMPTION_VERSION
        and consumption["oneUse"] is True
        and require_positive_uint(
            consumption["consumedAtUnix"],
            "durable nonce consumption time",
        )
        == consumed_at_unix
        and require_positive_uint(
            consumption["sequence"],
            "durable nonce sequence",
        )
        == sequence
        and consumption["nonceSha256"]
        == require_sha256(
            caller_nonce_sha256,
            "expected durable nonce",
        )
        and consumption["requestBodySha256"]
        == require_sha256(
            request_body_sha256,
            "expected durable nonce request body",
        )
        and consumption["tlsBindingSha256"]
        == require_sha256(
            tls_binding_sha256,
            "expected durable nonce TLS binding",
        )
        and consumption["storeIdentitySha256"]
        == require_sha256(
            expected_store_identity_sha256,
            "expected durable nonce-store identity",
        ),
        "durable nonce consumption crossed its one-use request binding",
    )
    return consumption


def public_attestation_producer_invocation(
    *,
    caller_nonce_sha256: str,
    expires_at_unix: int,
    issued_at_unix: int,
    minimum_release_identity_sha256: str,
    minimum_rollback_continuity_commitment_sha256: str,
    nonce_authority_verifier_challenge_base64url: str,
    nonce_authority_verifier_state_operation_id_base64url: str,
    producer_channel_challenge_base64url: str,
    producer_ephemeral_key_spki_der_base64url: str,
    producer_ephemeral_key_spki_sha256: str,
    release_identity_sha256: str,
    request_body_sha256: str,
    static_pins: dict[str, str],
    tls_binding_sha256: str,
    witness_verifier_challenge_base64url: str,
) -> dict[str, Any]:
    return {
        "apiVersion":
        PUBLIC_ATTESTATION_PRODUCER_INVOCATION_VERSION,
        "callerNonceSha256": caller_nonce_sha256,
        "expiresAtUnix": expires_at_unix,
        "issuedAtUnix": issued_at_unix,
        "minimumReleaseIdentitySha256":
        minimum_release_identity_sha256,
        "minimumRollbackContinuityCommitmentSha256":
        minimum_rollback_continuity_commitment_sha256,
        "nonceAuthorityVerifierChallengeBase64url":
        nonce_authority_verifier_challenge_base64url,
        "nonceAuthorityVerifierStateOperationIdBase64url":
        nonce_authority_verifier_state_operation_id_base64url,
        "producerChannelChallengeBase64url":
        producer_channel_challenge_base64url,
        "producerEphemeralKeySpkiDerBase64url":
        producer_ephemeral_key_spki_der_base64url,
        "producerEphemeralKeySpkiSha256":
        producer_ephemeral_key_spki_sha256,
        "releaseIdentitySha256": release_identity_sha256,
        "requestBodySha256": request_body_sha256,
        "staticPins": static_pins,
        "tlsBindingSha256": tls_binding_sha256,
        "witnessVerifierChallengeBase64url":
        witness_verifier_challenge_base64url,
    }


def verify_public_attestation_nonce_receipt_envelope(
    document: Any,
    *,
    key: Ed25519PublicKey,
    key_id: str,
) -> dict[str, Any]:
    envelope = exact_keys(
        document,
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "signatureAlgorithm",
            "signatureBase64url",
            "signingKeyId",
            "signingKeySpkiSha256",
        },
        "signed public-attestation nonce receipt",
    )
    require(
        envelope["apiVersion"]
        == PUBLIC_ATTESTATION_SIGNED_NONCE_RECEIPT_VERSION
        and envelope["signatureAlgorithm"] == "Ed25519"
        and envelope["signingKeyId"] == key_id
        and envelope["signingKeySpkiSha256"] == key_id,
        "signed public-attestation nonce receipt crossed its pinned key",
    )
    payload = exact_keys(
        envelope["payload"],
        {
            "apiVersion",
            "consumeRequestSha256",
            "consumedAtUnix",
            "expiresAtUnix",
            "finalExternalVerifierChallengeConsumed",
            "finalExternalVerifierChallengeConsumptionRequired",
            "nonceAuthorityAssuranceSha256",
            "nonceAuthorityState",
            "nonceAuthorityStateSha256",
            "nonceAuthorityVerifierStateAuthorizationSha256",
            "nonceConsumption",
            "nonceConsumptionSha256",
            "nonceSha256",
            "previousReceiptSha256",
            "producerChannelChallengeBase64url",
            "producerEphemeralKeySha256",
            "producerInvocationSha256",
            "receiptIssuedAtUnix",
            "requestBodySha256",
            "sequence",
            "signerChannelBindingSha256",
            "storeIdentitySha256",
            "tlsBindingSha256",
            "transactionIdBase64url",
        },
        "signed public-attestation nonce receipt payload",
    )
    payload_sha256 = sha256_json(payload)
    require(
        envelope["payloadSha256"] == payload_sha256,
        "signed public-attestation nonce receipt payload digest is invalid",
    )
    signature = b64url_decode_exact(
        envelope["signatureBase64url"],
        "signed public-attestation nonce receipt signature",
        exact_bytes=64,
    )
    try:
        key.verify(
            signature,
            PUBLIC_ATTESTATION_NONCE_RECEIPT_DOMAIN
            + canonical_json_bytes(
                {
                    "payload": payload,
                    "payloadSha256": payload_sha256,
                }
            ),
        )
    except InvalidSignature as exc:
        raise VerificationError(
            "signed public-attestation nonce receipt signature is invalid"
        ) from exc
    return {
        "document": envelope,
        "payload": payload,
        "receiptSha256": sha256_json(envelope),
    }


def validate_public_attestation_nonce_receipt_bindings(
    verified: dict[str, Any],
    *,
    caller_nonce_sha256: str,
    request_body_sha256: str,
    tls_binding_sha256: str,
    expected_store_identity_sha256: str,
    producer_invocation: dict[str, Any],
    producer_invocation_sha256: str,
    issued_at_unix: int,
    expires_at_unix: int,
    nonce_authority_assurance: dict[str, Any],
    nonce_authority_assurance_sha256: str,
    prior_nonce_authority_verifier_state: dict[str, Any],
) -> dict[str, Any]:
    payload = verified["payload"]
    consumed_at = require_positive_uint(
        payload["consumedAtUnix"],
        "signed nonce receipt consumed time",
    )
    receipt_issued = require_positive_uint(
        payload["receiptIssuedAtUnix"],
        "signed nonce receipt issue time",
    )
    receipt_expires = require_positive_uint(
        payload["expiresAtUnix"],
        "signed nonce receipt expiry",
    )
    sequence = require_positive_uint(
        payload["sequence"],
        "signed nonce receipt sequence",
    )
    b64url_decode_exact(
        payload["transactionIdBase64url"],
        "signed nonce receipt transaction ID",
        exact_bytes=32,
    )
    b64url_decode_exact(
        payload["producerChannelChallengeBase64url"],
        "signed nonce receipt producer challenge",
        exact_bytes=32,
    )
    previous_receipt_sha256 = payload["previousReceiptSha256"]
    if sequence == 1:
        require(
            previous_receipt_sha256 is None,
            "first signed nonce receipt has a predecessor",
        )
    else:
        require_sha256(
            previous_receipt_sha256,
            "signed nonce receipt predecessor",
        )
    consumption = validate_public_attestation_nonce_consumption(
        payload["nonceConsumption"],
        caller_nonce_sha256=caller_nonce_sha256,
        request_body_sha256=request_body_sha256,
        tls_binding_sha256=tls_binding_sha256,
        expected_store_identity_sha256=expected_store_identity_sha256,
        consumed_at_unix=consumed_at,
        sequence=sequence,
    )
    consumption_sha256 = sha256_json(consumption)
    authority_state = validate_nonce_authority_state_transition(
        payload["nonceAuthorityState"],
        assurance=nonce_authority_assurance,
        assurance_sha256=nonce_authority_assurance_sha256,
        nonce_consumption_sha256=consumption_sha256,
        nonce_verifier_state_authorization_sha256=payload[
            "nonceAuthorityVerifierStateAuthorizationSha256"
        ],
        previous_receipt_sha256=previous_receipt_sha256,
        sequence=sequence,
        transaction_id_base64url=payload[
            "transactionIdBase64url"
        ],
        prior_verifier_state=prior_nonce_authority_verifier_state,
    )
    consume_request = {
        "apiVersion":
        PUBLIC_ATTESTATION_NONCE_CONSUME_ONCE_REQUEST_VERSION,
        "expiresAtUnix": receipt_expires,
        "nonceAuthorityVerifierStateAuthorizationSha256": payload[
            "nonceAuthorityVerifierStateAuthorizationSha256"
        ],
        "nonceSha256": caller_nonce_sha256,
        "producerChannelChallengeBase64url":
        producer_invocation["producerChannelChallengeBase64url"],
        "producerEphemeralKeySha256":
        producer_invocation["producerEphemeralKeySpkiSha256"],
        "producerInvocationSha256": producer_invocation_sha256,
        "requestBodySha256": request_body_sha256,
        "tlsBindingSha256": tls_binding_sha256,
        "transactionIdBase64url": payload["transactionIdBase64url"],
    }
    consume_request_sha256 = sha256(
        PUBLIC_ATTESTATION_NONCE_CONSUME_REQUEST_DIGEST_DOMAIN
        + canonical_json_bytes(consume_request)
    )
    require(
        payload["apiVersion"]
        == PUBLIC_ATTESTATION_NONCE_RECEIPT_PAYLOAD_VERSION
        and payload["consumeRequestSha256"]
        == consume_request_sha256
        and payload["nonceAuthorityAssuranceSha256"]
        == nonce_authority_assurance_sha256
        and payload["nonceAuthorityStateSha256"]
        == sha256_json(authority_state)
        and payload[
            "nonceAuthorityVerifierStateAuthorizationSha256"
        ]
        == prior_nonce_authority_verifier_state[
            "authorizationSha256"
        ]
        and payload["nonceConsumptionSha256"]
        == consumption_sha256
        and payload["nonceSha256"] == caller_nonce_sha256
        and payload["requestBodySha256"] == request_body_sha256
        and payload["tlsBindingSha256"] == tls_binding_sha256
        and payload["storeIdentitySha256"]
        == expected_store_identity_sha256
        and payload["producerChannelChallengeBase64url"]
        == producer_invocation["producerChannelChallengeBase64url"]
        and payload["producerEphemeralKeySha256"]
        == producer_invocation["producerEphemeralKeySpkiSha256"]
        and payload["producerInvocationSha256"]
        == producer_invocation_sha256
        and payload["finalExternalVerifierChallengeConsumptionRequired"]
        is True
        and payload["finalExternalVerifierChallengeConsumed"] is False
        and consumed_at == receipt_issued
        and consumed_at <= issued_at_unix < expires_at_unix
        <= receipt_expires
        and issued_at_unix - consumed_at <= 30,
        "signed nonce receipt crossed its exact invocation or validity window",
    )
    for field in (
        "consumeRequestSha256",
        "nonceAuthorityAssuranceSha256",
        "nonceAuthorityStateSha256",
        "nonceAuthorityVerifierStateAuthorizationSha256",
        "nonceConsumptionSha256",
        "nonceSha256",
        "producerEphemeralKeySha256",
        "producerInvocationSha256",
        "requestBodySha256",
        "signerChannelBindingSha256",
        "storeIdentitySha256",
        "tlsBindingSha256",
    ):
        require_sha256(payload[field], f"signed nonce receipt {field}")
    return {
        **verified,
        "authorityState": authority_state,
        "authorityStateSha256": sha256_json(authority_state),
        "consumption": consumption,
        "consumptionSha256": consumption_sha256,
    }


def verify_verifier_state_read_response(
    document: Any,
    *,
    signing_key: Ed25519PublicKey,
    signing_key_id: str,
    expected_state_store_identity_sha256: str,
    assurance: dict[str, Any],
    assurance_sha256: str,
    expected_state: dict[str, Any] | None,
    label: str,
) -> dict[str, Any]:
    response = exact_keys(
        document,
        {
            "apiVersion",
            "nonActionable",
            "state",
            "stateSha256",
        },
        label,
    )
    state = verify_nonce_authority_verifier_state(
        response["state"],
        signing_key=signing_key,
        signing_key_id=signing_key_id,
        expected_state_store_identity_sha256=(
            expected_state_store_identity_sha256
        ),
        assurance=assurance,
        assurance_sha256=assurance_sha256,
    )
    require(
        response["apiVersion"]
        == NONCE_AUTHORITY_VERIFIER_STATE_READ_RESPONSE_VERSION
        and response["nonActionable"] is True
        and response["stateSha256"] == state["envelopeSha256"]
        and (
            expected_state is None
            or state["document"] == expected_state["document"]
        ),
        f"{label} is substituted or crossed",
    )
    return {
        "document": response,
        "documentSha256": sha256_json(response),
        "state": state,
    }


def verify_public_attestation_verifier_state_transition(
    document: Any,
    *,
    assurance: dict[str, Any],
    assurance_evidence: dict[str, Any] | None,
    assurance_evidence_sha256: str | None,
    authorization: dict[str, Any],
    commit_request: dict[str, Any],
    commit_receipt: dict[str, Any],
    nonce_consumption_receipt: dict[str, Any],
    prior_state: dict[str, Any],
    verifier_state_service: dict[str, Any],
    verifier_state_key: Ed25519PublicKey,
    verifier_state_key_id: str,
    state_store_identity_sha256: str,
    state_store_administrative_domain_sha256: str,
    state_store_assurance_evidence_sha256: str | None,
    state_store_assurance_evidence: dict[str, Any],
    role_separation_evidence: dict[str, Any],
    role_separation_evidence_sha256: str,
    state_store_configuration_sha256: str,
    state_store_minimum_commit_index: int,
    state_store_minimum_generation: int,
    state_store_attestation_key_id: str,
    verifier_challenge: bytes,
    now: int,
) -> dict[str, Any]:
    transition = exact_keys(
        document,
        {
            "apiVersion",
            "assurance",
            "assuranceEvidence",
            "assuranceEvidenceSha256",
            "assuranceSha256",
            "authorization",
            "authorizationSha256",
            "commitRequest",
            "commitRequestSha256",
            "commitReceipt",
            "commitReceiptSha256",
            "committedState",
            "committedStateRead",
            "committedStateReadSha256",
            "committedStateSha256",
            "nonActionable",
            "nonceAuthorityState",
            "nonceAuthorityStateSha256",
            "nonceConsumptionReceipt",
            "nonceConsumptionReceiptSha256",
            "nonceConsumptionSha256",
            "operationIdBase64url",
            "preparedOperation",
            "preparedOperationSha256",
            "priorState",
            "priorStateRead",
            "priorStateReadSha256",
            "priorStateSha256",
            "roleSeparationEvidence",
            "roleSeparationEvidenceSha256",
            "recoveryIdentity",
            "recoveryIdentitySha256",
            "recoveryKeySha256",
            "requestBindingSha256",
            "serviceBinding",
            "signedStoreCommitProof",
            "signedStoreCommitProofSha256",
            "storeAssuranceEvidence",
            "storeAssuranceEvidenceSha256",
            "transactionIdBase64url",
            "verifierChallengeBase64url",
            "verifierChallengeSha256",
        },
        "public nonce-authority verifier-state transition",
    )
    assurance_sha256 = sha256_json(assurance)
    operation_id = b64url_decode_exact(
        transition["operationIdBase64url"],
        "public verifier-state transition operation ID",
        exact_bytes=32,
    )
    transaction_id = b64url_decode_exact(
        transition["transactionIdBase64url"],
        "public verifier-state transition transaction ID",
        exact_bytes=32,
    )
    transition_challenge = b64url_decode_exact(
        transition["verifierChallengeBase64url"],
        "public verifier-state transition challenge",
        exact_bytes=32,
    )
    prior_read = verify_verifier_state_read_response(
        transition["priorStateRead"],
        signing_key=verifier_state_key,
        signing_key_id=verifier_state_key_id,
        expected_state_store_identity_sha256=(
            state_store_identity_sha256
        ),
        assurance=assurance,
        assurance_sha256=sha256_json(assurance),
        expected_state=prior_state,
        label="public verifier-state prior read",
    )
    committed_read = verify_verifier_state_read_response(
        transition["committedStateRead"],
        signing_key=verifier_state_key,
        signing_key_id=verifier_state_key_id,
        expected_state_store_identity_sha256=(
            state_store_identity_sha256
        ),
        assurance=assurance,
        assurance_sha256=sha256_json(assurance),
        expected_state=None,
        label="public verifier-state committed read",
    )
    service_binding = exact_keys(
        transition["serviceBinding"],
        {
            "apiVersion",
            "clientCertificateSpkiSha256",
            "endpoint",
            "serverLeafSpkiSha256",
            "serviceConfigurationSha256",
            "signingKeySpkiSha256",
            "roleSeparationEvidenceSha256",
            "stateStoreAdministrativeDomainSha256",
            "stateStoreAssuranceEvidenceSha256",
            "stateStoreAttestationKeySpkiSha256",
            "stateStoreConfigurationSha256",
            "stateStoreIdentitySha256",
            "stateStoreMinimumCommitIndex",
            "stateStoreMinimumGeneration",
        },
        "public verifier-state transition service binding",
    )
    expected_service_binding = {
        "apiVersion":
        PUBLIC_ATTESTATION_VERIFIER_STATE_CLIENT_VERSION,
        "clientCertificateSpkiSha256":
        verifier_state_service["clientCertificateSpkiSha256"],
        "endpoint": verifier_state_service["endpoint"],
        "serverLeafSpkiSha256":
        verifier_state_service["serverLeafSpkiSha256"],
        "serviceConfigurationSha256":
        verifier_state_service["serviceConfigurationSha256"],
        "signingKeySpkiSha256": verifier_state_key_id,
        "roleSeparationEvidenceSha256":
        role_separation_evidence_sha256,
        "stateStoreAdministrativeDomainSha256":
        state_store_administrative_domain_sha256,
        "stateStoreAssuranceEvidenceSha256":
        state_store_assurance_evidence_sha256,
        "stateStoreAttestationKeySpkiSha256":
        state_store_attestation_key_id,
        "stateStoreConfigurationSha256":
        state_store_configuration_sha256,
        "stateStoreIdentitySha256": state_store_identity_sha256,
        "stateStoreMinimumCommitIndex":
        state_store_minimum_commit_index,
        "stateStoreMinimumGeneration":
        state_store_minimum_generation,
    }
    prepared_operation = exact_keys(
        transition["preparedOperation"],
        {
            "apiVersion",
            "authorization",
            "authorizationSha256",
            "nonceConsumeRequest",
            "nonceConsumeRequestSha256",
            "prepareRequest",
            "prepareRequestSha256",
            "recoveryBinding",
            "recoveryIdentity",
            "recoveryIdentitySha256",
            "recoveryKeySha256",
            "requestBinding",
            "requestBindingSha256",
            "successorIntent",
            "successorIntentSha256",
        },
        "public verifier-state prepared operation",
    )
    prepare_request = exact_keys(
        prepared_operation["prepareRequest"],
        {
            "apiVersion",
            "assuranceSha256",
            "challengeIssue",
            "challengeIssueSha256",
            "expectedVerifierStateSha256",
            "operationIdBase64url",
            "priorStateRead",
            "priorStateReadSha256",
            "producerInvocation",
            "producerInvocationBaseSha256",
            "producerInvocationSha256",
            "recoveryIdentity",
            "recoveryIdentitySha256",
            "recoveryKeySha256",
            "requestBinding",
            "requestBindingSha256",
            "verifierChallengeBase64url",
        },
        "public verifier-state prepare request",
    )
    recovery_identity = exact_keys(
        prepared_operation["recoveryIdentity"],
        {
            "apiVersion",
            "assuranceSha256",
            "callerNonceSha256",
            "immutableConfigSha256",
            "releaseIdentitySha256",
            "requestBodySha256",
        },
        "public verifier-state recovery identity",
    )
    request_binding = exact_keys(
        prepared_operation["requestBinding"],
        {
            "apiVersion",
            "expiresAtUnix",
            "nonceSha256",
            "producerChannelChallengeBase64url",
            "producerEphemeralKeySha256",
            "producerInvocationSha256",
            "requestBodySha256",
            "tlsBindingSha256",
            "transactionIdBase64url",
        },
        "public verifier-state request binding",
    )
    recovery_binding = exact_keys(
        prepared_operation["recoveryBinding"],
        {
            "apiVersion",
            "assuranceSha256",
            "expectedVerifierStateSha256",
            "operationIdBase64url",
            "requestBindingSha256",
            "verifierChallengeSha256",
        },
        "public verifier-state recovery binding",
    )
    nonce_consume_request = exact_keys(
        prepared_operation["nonceConsumeRequest"],
        {
            "apiVersion",
            "expiresAtUnix",
            "nonceAuthorityVerifierStateAuthorizationSha256",
            "nonceSha256",
            "producerChannelChallengeBase64url",
            "producerEphemeralKeySha256",
            "producerInvocationSha256",
            "requestBodySha256",
            "tlsBindingSha256",
            "transactionIdBase64url",
        },
        "public verifier-state prepared nonce request",
    )
    successor_intent = exact_keys(
        prepared_operation["successorIntent"],
        {
            "apiVersion",
            "authorizationSha256",
            "expectedHighWaterSequence",
            "expectedStateStoreGeneration",
            "expectedVerifierStateSha256",
            "nonceConsumeRequestSha256",
            "operationIdBase64url",
            "previousStateStoreHeadSha256",
            "requestBindingSha256",
            "transactionIdBase64url",
            "verifierChallengeSha256",
        },
        "public verifier-state successor intent",
    )
    request_binding_sha256 = sha256(
        VERIFIER_STATE_REQUEST_BINDING_DOMAIN
        + canonical_json_bytes(request_binding)
    )
    recovery_identity_sha256 = sha256_json(recovery_identity)
    deterministic_operation_id = b64url_encode(
        hashlib.sha256(
            VERIFIER_STATE_OPERATION_ID_DOMAIN
            + canonical_json_bytes(recovery_identity)
        ).digest()
    )
    recovery_key_sha256 = sha256(
        VERIFIER_STATE_RECOVERY_KEY_DOMAIN
        + canonical_json_bytes(recovery_identity)
    )
    nonce_consume_request_sha256 = sha256(
        PUBLIC_ATTESTATION_NONCE_CONSUME_REQUEST_DIGEST_DOMAIN
        + canonical_json_bytes(nonce_consume_request)
    )
    producer_invocation_base = {
        key: item
        for key, item in prepare_request["producerInvocation"].items()
        if key
        not in {
            "nonceAuthorityVerifierChallengeBase64url",
            "nonceAuthorityVerifierStateOperationIdBase64url",
        }
    }
    challenge_issue = exact_keys(
        prepare_request["challengeIssue"],
        {
            "apiVersion",
            "challengeBase64url",
            "challengeExpiresAtUnix",
            "challengeIssuedAtUnix",
            "challengeSha256",
            "expectedVerifierStateSha256",
            "issueRequestSha256",
            "nonActionable",
            "operationIdBase64url",
            "producerInvocationBaseSha256",
            "recoveryKeySha256",
            "replacementForbidden",
            "status",
        },
        "public verifier-state challenge issue response",
    )
    require(
        prepared_operation["apiVersion"]
        == VERIFIER_STATE_PREPARED_OPERATION_VERSION
        and transition["preparedOperationSha256"]
        == sha256_json(prepared_operation)
        and prepared_operation["authorization"]
        == authorization["document"]
        and prepared_operation["authorizationSha256"]
        == authorization["envelopeSha256"]
        and prepared_operation["prepareRequestSha256"]
        == sha256_json(prepare_request)
        == authorization["payload"]["prepareRequestSha256"]
        and prepared_operation["recoveryIdentity"]
        == recovery_identity
        and prepared_operation["recoveryIdentitySha256"]
        == recovery_identity_sha256
        == authorization["payload"]["recoveryIdentitySha256"]
        and prepared_operation["recoveryKeySha256"]
        == recovery_key_sha256
        == authorization["payload"]["recoveryKeySha256"]
        and prepared_operation["requestBinding"]
        == request_binding
        and prepared_operation["requestBindingSha256"]
        == request_binding_sha256
        == authorization["payload"]["requestBindingSha256"]
        and prepared_operation["nonceConsumeRequestSha256"]
        == nonce_consume_request_sha256
        and prepared_operation["successorIntentSha256"]
        == sha256_json(successor_intent)
        and prepare_request["apiVersion"]
        == VERIFIER_STATE_PREPARE_REQUEST_VERSION
        and prepare_request["assuranceSha256"] == assurance_sha256
        and prepare_request["expectedVerifierStateSha256"]
        == prior_state["envelopeSha256"]
        and prepare_request["operationIdBase64url"]
        == authorization["payload"]["operationIdBase64url"]
        == deterministic_operation_id
        and prepare_request["priorStateRead"]
        == transition["priorStateRead"]
        and prepare_request["priorStateReadSha256"]
        == transition["priorStateReadSha256"]
        and prepare_request["producerInvocationSha256"]
        == sha256_json(prepare_request["producerInvocation"])
        == request_binding["producerInvocationSha256"]
        and prepare_request["producerInvocationBaseSha256"]
        == sha256_json(producer_invocation_base)
        == challenge_issue["producerInvocationBaseSha256"]
        and prepare_request["challengeIssueSha256"]
        == sha256_json(challenge_issue)
        and challenge_issue["apiVersion"]
        == "serverware.attestationVerifierStateIssueChallengeResponse/v1"
        and challenge_issue["operationIdBase64url"]
        == deterministic_operation_id
        and challenge_issue["recoveryKeySha256"]
        == recovery_key_sha256
        and challenge_issue["challengeBase64url"]
        == prepare_request["verifierChallengeBase64url"]
        and challenge_issue["challengeSha256"]
        == sha256(verifier_challenge)
        and challenge_issue["expectedVerifierStateSha256"]
        == prior_state["envelopeSha256"]
        and challenge_issue["replacementForbidden"] is True
        and challenge_issue["nonActionable"] is True
        and challenge_issue["status"] == "issued"
        and prepare_request["recoveryIdentity"]
        == recovery_identity
        and prepare_request["recoveryIdentitySha256"]
        == recovery_identity_sha256
        and prepare_request["recoveryKeySha256"]
        == recovery_key_sha256
        and prepare_request["requestBinding"] == request_binding
        and prepare_request["requestBindingSha256"]
        == request_binding_sha256
        and prepare_request["verifierChallengeBase64url"]
        == transition["verifierChallengeBase64url"]
        and recovery_identity["apiVersion"]
        == VERIFIER_STATE_RECOVERY_IDENTITY_VERSION
        and recovery_identity["assuranceSha256"]
        == assurance_sha256
        and recovery_identity["callerNonceSha256"]
        == request_binding["nonceSha256"]
        and recovery_identity["requestBodySha256"]
        == request_binding["requestBodySha256"]
        and request_binding["apiVersion"]
        == VERIFIER_STATE_REQUEST_BINDING_VERSION
        and recovery_binding["apiVersion"]
        == VERIFIER_STATE_RECOVERY_BINDING_VERSION
        and recovery_binding["assuranceSha256"]
        == assurance_sha256
        and recovery_binding["expectedVerifierStateSha256"]
        == prior_state["envelopeSha256"]
        and recovery_binding["operationIdBase64url"]
        == authorization["payload"]["operationIdBase64url"]
        and recovery_binding["requestBindingSha256"]
        == request_binding_sha256
        and recovery_binding["verifierChallengeSha256"]
        == sha256(verifier_challenge)
        and nonce_consume_request[
            "apiVersion"
        ]
        == PUBLIC_ATTESTATION_NONCE_CONSUME_ONCE_REQUEST_VERSION
        and nonce_consume_request[
            "nonceAuthorityVerifierStateAuthorizationSha256"
        ]
        == authorization["envelopeSha256"]
        and all(
            nonce_consume_request[field] == request_binding[field]
            for field in (
                "expiresAtUnix",
                "nonceSha256",
                "producerChannelChallengeBase64url",
                "producerEphemeralKeySha256",
                "producerInvocationSha256",
                "requestBodySha256",
                "tlsBindingSha256",
                "transactionIdBase64url",
            )
        )
        and successor_intent["apiVersion"]
        == VERIFIER_STATE_SUCCESSOR_INTENT_VERSION
        and successor_intent["authorizationSha256"]
        == authorization["envelopeSha256"]
        and successor_intent["expectedHighWaterSequence"]
        == prior_state["payload"]["highWaterSequence"] + 1
        and successor_intent["expectedStateStoreGeneration"]
        == prior_state["payload"]["stateStoreGeneration"] + 1
        and successor_intent["expectedVerifierStateSha256"]
        == prior_state["envelopeSha256"]
        and successor_intent["nonceConsumeRequestSha256"]
        == nonce_consume_request_sha256
        and successor_intent["operationIdBase64url"]
        == authorization["payload"]["operationIdBase64url"]
        and successor_intent["previousStateStoreHeadSha256"]
        == prior_state["payload"]["stateStoreHeadSha256"]
        and successor_intent["requestBindingSha256"]
        == request_binding_sha256
        and successor_intent["transactionIdBase64url"]
        == request_binding["transactionIdBase64url"]
        and successor_intent["verifierChallengeSha256"]
        == sha256(verifier_challenge)
        and commit_request["preparedOperationSha256"]
        == transition["preparedOperationSha256"]
        and commit_request["recoveryKeySha256"]
        == recovery_key_sha256
        and commit_request["requestBindingSha256"]
        == request_binding_sha256,
        "public verifier-state transition did not bind its exact prepared saga",
    )
    nonce_payload = exact_keys(
        nonce_consumption_receipt["payload"],
        {
            "apiVersion",
            "consumeRequestSha256",
            "consumedAtUnix",
            "expiresAtUnix",
            "finalExternalVerifierChallengeConsumed",
            "finalExternalVerifierChallengeConsumptionRequired",
            "nonceAuthorityAssuranceSha256",
            "nonceAuthorityState",
            "nonceAuthorityStateSha256",
            "nonceAuthorityVerifierStateAuthorizationSha256",
            "nonceConsumption",
            "nonceConsumptionSha256",
            "nonceSha256",
            "previousReceiptSha256",
            "producerChannelChallengeBase64url",
            "producerEphemeralKeySha256",
            "producerInvocationSha256",
            "receiptIssuedAtUnix",
            "requestBodySha256",
            "sequence",
            "signerChannelBindingSha256",
            "storeIdentitySha256",
            "tlsBindingSha256",
            "transactionIdBase64url",
        },
        "public verifier-state transition nonce receipt payload",
    )
    expected_transition = {
        "apiVersion":
        NONCE_AUTHORITY_VERIFIER_STATE_TRANSITION_VERSION,
        "assurance": assurance,
        "assuranceEvidence": assurance_evidence,
        "assuranceEvidenceSha256": assurance_evidence_sha256,
        "assuranceSha256": sha256_json(assurance),
        "authorization": authorization["document"],
        "authorizationSha256": authorization["envelopeSha256"],
        "commitRequest": commit_request,
        "commitRequestSha256": sha256_json(commit_request),
        "commitReceipt": commit_receipt["document"],
        "commitReceiptSha256": commit_receipt["envelopeSha256"],
        "committedState": committed_read["state"]["document"],
        "committedStateRead": committed_read["document"],
        "committedStateReadSha256":
        committed_read["documentSha256"],
        "committedStateSha256":
        committed_read["state"]["envelopeSha256"],
        "nonActionable": True,
        "nonceAuthorityState": commit_receipt["nonceAuthorityState"],
        "nonceAuthorityStateSha256":
        commit_receipt["nonceAuthorityStateSha256"],
        "nonceConsumptionReceipt": nonce_consumption_receipt,
        "nonceConsumptionReceiptSha256":
        commit_receipt["nonceConsumptionReceiptSha256"],
        "nonceConsumptionSha256":
        commit_receipt["nonceConsumptionSha256"],
        "operationIdBase64url":
        authorization["payload"]["operationIdBase64url"],
        "preparedOperation": transition["preparedOperation"],
        "preparedOperationSha256":
        transition["preparedOperationSha256"],
        "priorState": prior_state["document"],
        "priorStateRead": prior_read["document"],
        "priorStateReadSha256": prior_read["documentSha256"],
        "priorStateSha256": prior_state["envelopeSha256"],
        "roleSeparationEvidence": role_separation_evidence,
        "roleSeparationEvidenceSha256":
        role_separation_evidence_sha256,
        "recoveryIdentity": transition["recoveryIdentity"],
        "recoveryIdentitySha256":
        transition["recoveryIdentitySha256"],
        "recoveryKeySha256": transition["recoveryKeySha256"],
        "requestBindingSha256":
        transition["requestBindingSha256"],
        "serviceBinding": expected_service_binding,
        "signedStoreCommitProof":
        commit_receipt["storeCommitProof"],
        "signedStoreCommitProofSha256":
        commit_receipt["storeCommitProofSha256"],
        "storeAssuranceEvidence": state_store_assurance_evidence,
        "storeAssuranceEvidenceSha256":
        state_store_assurance_evidence_sha256,
        "transactionIdBase64url":
        nonce_payload["transactionIdBase64url"],
        "verifierChallengeBase64url":
        b64url_encode(verifier_challenge),
        "verifierChallengeSha256": sha256(verifier_challenge),
    }
    require(
        transition == expected_transition
        and commit_request["apiVersion"]
        == VERIFIER_STATE_COMMIT_REQUEST_VERSION
        and committed_read["state"]["payload"]
        == commit_receipt["committedState"]
        and challenge_issue["challengeIssuedAtUnix"]
        <= authorization["payload"]["issuedAtUnix"]
        < authorization["payload"]["expiresAtUnix"]
        <= challenge_issue["challengeExpiresAtUnix"]
        and transition_challenge == verifier_challenge
        and operation_id
        == b64url_decode_exact(
            authorization["payload"]["operationIdBase64url"],
            "authorized public verifier-state operation",
            exact_bytes=32,
        )
        and transaction_id
        == b64url_decode_exact(
            nonce_payload["transactionIdBase64url"],
            "authorized public verifier-state transaction",
            exact_bytes=32,
        )
        == operation_id
        and operation_id != transition_challenge
        and service_binding == expected_service_binding,
        "public verifier-state transition omitted, substituted, or crossed a signed binding",
    )
    return {
        "document": transition,
        "documentSha256": sha256_json(transition),
        "serviceBinding": service_binding,
    }


def reconstruct_public_attestation_producer_request(
    *,
    caller_nonce: bytes,
    request_body: bytes,
    tls_binding: dict[str, Any],
    release_identity_sha256: str,
    static_pins: dict[str, str],
    nonce_consumption: dict[str, Any],
    nonce_consumption_receipt: dict[str, Any],
    nonce_authority_verifier_state_transition: dict[str, Any],
    producer_invocation: dict[str, Any],
    producer_invocation_sha256: str,
    issued_at_unix: int,
    expires_at_unix: int,
) -> tuple[dict[str, Any], bytes]:
    request = {
        "apiVersion": PUBLIC_ATTESTATION_PRODUCER_REQUEST_VERSION,
        "liveSessionRequest": {
            "apiVersion": PUBLIC_ATTESTATION_LIVE_REQUEST_VERSION,
            "callerNonceBase64url": b64url_encode(caller_nonce),
            "callerNonceSha256": sha256(caller_nonce),
            "expiresAtUnix": expires_at_unix,
            "httpRequest": {
                "bodySha256": sha256(request_body),
                "method": "POST",
                "path": "/attestation/public-evidence",
            },
            "issuedAtUnix": issued_at_unix,
            "nonceConsumption": nonce_consumption,
            "nonceConsumptionReceipt": nonce_consumption_receipt,
            "nonceConsumptionReceiptSha256":
            sha256_json(nonce_consumption_receipt),
            "nonceAuthorityVerifierStateTransition":
            nonce_authority_verifier_state_transition,
            "oneUse": True,
            "producerInvocation": producer_invocation,
            "producerInvocationSha256":
            producer_invocation_sha256,
            "tlsBinding": tls_binding,
            "tlsBindingSha256": require_sha256(
                tls_binding.get("bindingSha256"),
                "producer request TLS binding",
            ),
        },
        "releaseIdentitySha256": require_sha256(
            release_identity_sha256,
            "producer request stable release identity",
        ),
        "staticPins": static_pins,
    }
    raw = canonical_json_bytes(request) + b"\n"
    require(
        len(raw) <= 256 * 1024,
        "reconstructed producer request exceeds its schema bound",
    )
    return request, raw


def verify_public_attestation_producer_binding(
    document: Any,
    *,
    caller_nonce: bytes,
    request_body: bytes,
    tls_binding: dict[str, Any],
    nonce_consumption_receipt: Any,
    nonce_store_key: Ed25519PublicKey,
    nonce_store_key_id: str,
    nonce_authority_assurance: dict[str, Any],
    nonce_authority_assurance_sha256: str,
    prior_nonce_authority_verifier_state: dict[str, Any],
    nonce_authority_verifier_state_transition: dict[str, Any],
    minimum_release_identity_sha256: str,
    minimum_rollback_continuity_commitment_sha256: str,
    current_witness_invocation_binding: dict[str, Any],
    expected_witness_verifier_challenge: bytes,
    release_identity_sha256: str,
    release_config_sha256: str,
    global_role_key_ids: Mapping[str, str],
    signed_static_pins: dict[str, str],
    generated_at_unix: int,
    now: int,
) -> dict[str, Any]:
    envelope = exact_keys(
        document,
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "signatureAlgorithm",
            "signatureBase64url",
            "signingKeySpkiDerBase64url",
            "signingKeySpkiSha256",
        },
        "signed public v3 producer binding",
    )
    binding = exact_keys(
        envelope["payload"],
        {
            "apiVersion",
            "callerNonceSha256",
            "descriptorSha256",
            "executableSha256",
            "expiresAtUnix",
            "immutableConfigSha256",
            "issuedAtUnix",
            "nonceAuthorityAssuranceEvidenceSha256",
            "nonceAuthorityAssuranceSha256",
            "nonceAuthorityVerifierChallengeSha256",
            "nonceAuthorityVerifierStateAuthorizationSha256",
            "nonceAuthorityVerifierStateCommitReceiptSha256",
            "nonceAuthorityVerifierStateCommitRequestSha256",
            "nonceAuthorityVerifierStateCommittedStateReadSha256",
            "nonceAuthorityVerifierStateCommittedStateSha256",
            "nonceAuthorityVerifierStateOperationIdBase64url",
            "nonceAuthorityVerifierStatePriorStateReadSha256",
            "nonceAuthorityVerifierStatePriorStateSha256",
            "nonceAuthorityVerifierStateServiceConfigurationSha256",
            "nonceAuthorityVerifierStateSigningKeySpkiSha256",
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256",
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256",
            "nonceAuthorityVerifierStateRoleSeparationEvidenceSha256",
            "nonceAuthorityVerifierStateStoreAttestationKeySpkiSha256",
            "nonceAuthorityVerifierStateStoreCommitProofSha256",
            "nonceAuthorityVerifierStateStoreConfigurationSha256",
            "nonceAuthorityVerifierStateStoreIdentitySha256",
            "nonceAuthorityVerifierStateStoreMinimumCommitIndex",
            "nonceAuthorityVerifierStateStoreMinimumGeneration",
            "nonceAuthorityVerifierStateTransitionSha256",
            "nonceConsumptionReceiptSha256",
            "nonceConsumptionSha256",
            "nonceStoreIdentitySha256",
            "nonceStoreKeySpkiSha256",
            "producerEphemeralKeySpkiSha256",
            "producerInvocationSha256",
            "producerRequestSchemaSha256",
            "producerRequestSha256",
            "requestBodySha256",
            "sandboxDescriptorSha256",
            "sandboxLauncherSha256",
            "tlsBindingSha256",
            "transactionIdBase64url",
            "trustRootsSha256",
            "witnessCurrentRequestSha256",
            "witnessStoreIdentitySha256",
            "witnessStoreKeySpkiSha256",
        },
        "public v3 producer binding",
    )
    for field, value in binding.items():
        if field.endswith("Sha256"):
            require_sha256(value, f"public v3 producer {field}")
    issued = require_positive_uint(
        binding["issuedAtUnix"],
        "public v3 producer issue time",
    )
    expires = require_positive_uint(
        binding["expiresAtUnix"],
        "public v3 producer expiry",
    )
    require(
        envelope["apiVersion"]
        == PUBLIC_ATTESTATION_SIGNED_PRODUCER_BINDING_VERSION
        and envelope["signatureAlgorithm"] == "Ed25519"
        and binding["apiVersion"]
        == PUBLIC_ATTESTATION_PRODUCER_BINDING_VERSION
        and issued <= generated_at_unix <= now
        and 15 <= expires - issued <= 30,
        "public v3 producer binding is future-dated or overlong",
    )
    expected_static_pins = validate_public_attestation_statement_pins(
        signed_static_pins,
        label="signed producer request static pins",
    )
    require(
        expected_static_pins["immutableConfigSha256"]
        == require_sha256(
            release_config_sha256,
            "independently expected public attestation config",
        ),
        "signed producer pins crossed the independently expected release config",
    )
    caller_nonce_sha256 = sha256(caller_nonce)
    request_body_sha256 = sha256(request_body)
    tls_binding_sha256 = require_sha256(
        tls_binding.get("bindingSha256"),
        "independently authenticated TLS binding",
    )
    producer_public_key_der = b64url_decode_exact(
        envelope["signingKeySpkiDerBase64url"],
        "producer binding ephemeral public key",
        exact_bytes=44,
    )
    producer_public_key_sha256 = sha256(producer_public_key_der)
    producer_service_tls_key_id = require_sha256(
        tls_binding.get("leafSpkiSha256"),
        "producer request TLS leaf SPKI",
    )
    public_client_tls_key_id = require_sha256(
        tls_binding.get("peerSpkiSha256"),
        "producer request TLS peer SPKI",
    )
    require(
        envelope["signingKeySpkiSha256"]
        == producer_public_key_sha256,
        "producer binding ephemeral key crossed its signed envelope",
    )
    validate_global_attestation_key_role_separation(
        {
            **global_role_key_ids,
            "producer": producer_public_key_sha256,
            "producerServiceTls": producer_service_tls_key_id,
            "publicEvidenceCallerTls": public_client_tls_key_id,
        }
    )
    try:
        producer_public_key = serialization.load_der_public_key(
            producer_public_key_der
        )
    except (TypeError, ValueError) as exc:
        raise VerificationError(
            "producer binding ephemeral public key is invalid"
        ) from exc
    require(
        isinstance(producer_public_key, Ed25519PublicKey),
        "producer binding ephemeral public key is not Ed25519",
    )
    payload_sha256 = sha256_json(binding)
    require(
        envelope["payloadSha256"] == payload_sha256,
        "producer binding payload digest is invalid",
    )
    signature = b64url_decode_exact(
        envelope["signatureBase64url"],
        "producer binding possession signature",
        exact_bytes=64,
    )
    try:
        producer_public_key.verify(
            signature,
            PUBLIC_ATTESTATION_PRODUCER_BINDING_DOMAIN
            + canonical_json_bytes(
                {
                    "payload": binding,
                    "payloadSha256": payload_sha256,
                    "signingKeySpkiSha256":
                    producer_public_key_sha256,
                }
            ),
        )
    except InvalidSignature as exc:
        raise VerificationError(
            "producer did not prove possession of the request-bound ephemeral key"
        ) from exc
    witness_binding = validate_attestation_witness_invocation_binding(
        current_witness_invocation_binding,
        label="current witness invocation binding",
    )
    witness_challenge_base64url = b64url_encode(
        expected_witness_verifier_challenge
    )
    require(
        len(expected_witness_verifier_challenge) == 32
        and witness_binding["verifierChallengeBase64url"]
        == witness_challenge_base64url,
        "current witness response did not consume the expected fresh verifier challenge",
    )
    prior_release_identity_sha256 = require_sha256(
        minimum_release_identity_sha256,
        "producer invocation release floor",
    )
    prior_continuity_sha256 = require_sha256(
        minimum_rollback_continuity_commitment_sha256,
        "producer invocation continuity floor",
    )
    verified_receipt = (
        verify_public_attestation_nonce_receipt_envelope(
            nonce_consumption_receipt,
            key=nonce_store_key,
            key_id=nonce_store_key_id,
        )
    )
    receipt_payload = verified_receipt["payload"]
    transition = nonce_authority_verifier_state_transition[
        "document"
    ]
    transition_service = nonce_authority_verifier_state_transition[
        "serviceBinding"
    ]
    producer_invocation = public_attestation_producer_invocation(
        caller_nonce_sha256=caller_nonce_sha256,
        expires_at_unix=expires,
        issued_at_unix=issued,
        minimum_release_identity_sha256=(
            prior_release_identity_sha256
        ),
        minimum_rollback_continuity_commitment_sha256=(
            prior_continuity_sha256
        ),
        nonce_authority_verifier_challenge_base64url=transition[
            "verifierChallengeBase64url"
        ],
        nonce_authority_verifier_state_operation_id_base64url=transition[
            "operationIdBase64url"
        ],
        producer_channel_challenge_base64url=receipt_payload[
            "producerChannelChallengeBase64url"
        ],
        producer_ephemeral_key_spki_der_base64url=envelope[
            "signingKeySpkiDerBase64url"
        ],
        producer_ephemeral_key_spki_sha256=(
            producer_public_key_sha256
        ),
        release_identity_sha256=release_identity_sha256,
        request_body_sha256=request_body_sha256,
        static_pins=expected_static_pins,
        tls_binding_sha256=tls_binding_sha256,
        witness_verifier_challenge_base64url=(
            witness_challenge_base64url
        ),
    )
    producer_invocation_sha256 = sha256_json(producer_invocation)
    prepared_operation = transition["preparedOperation"]
    prepared_invocation = prepared_operation["prepareRequest"][
        "producerInvocation"
    ]
    prepared_recovery_identity = transition["recoveryIdentity"]
    prepared_request_binding = prepared_operation["requestBinding"]
    require(
        prepared_invocation == producer_invocation
        and prepared_operation["prepareRequest"][
            "producerInvocationSha256"
        ]
        == producer_invocation_sha256
        and prepared_recovery_identity["callerNonceSha256"]
        == caller_nonce_sha256
        and prepared_recovery_identity["requestBodySha256"]
        == request_body_sha256
        and prepared_recovery_identity["releaseIdentitySha256"]
        == release_identity_sha256
        and prepared_recovery_identity["immutableConfigSha256"]
        == expected_static_pins["immutableConfigSha256"]
        and prepared_request_binding["expiresAtUnix"] == expires
        and prepared_request_binding["nonceSha256"]
        == caller_nonce_sha256
        and prepared_request_binding[
            "producerChannelChallengeBase64url"
        ]
        == producer_invocation[
            "producerChannelChallengeBase64url"
        ]
        and prepared_request_binding["producerEphemeralKeySha256"]
        == producer_public_key_sha256
        and prepared_request_binding["producerInvocationSha256"]
        == producer_invocation_sha256
        and prepared_request_binding["requestBodySha256"]
        == request_body_sha256
        and prepared_request_binding["tlsBindingSha256"]
        == tls_binding_sha256
        and prepared_request_binding["transactionIdBase64url"]
        == transition["operationIdBase64url"],
        "producer response crossed its exact prepared verifier-state saga",
    )
    producer_randoms = {
        caller_nonce,
        b64url_decode_exact(
            transition["verifierChallengeBase64url"],
            "producer invocation verifier-state challenge",
            exact_bytes=32,
        ),
        b64url_decode_exact(
            transition["operationIdBase64url"],
            "producer invocation verifier-state operation",
            exact_bytes=32,
        ),
        b64url_decode_exact(
            receipt_payload["producerChannelChallengeBase64url"],
            "producer invocation producer challenge",
            exact_bytes=32,
        ),
        expected_witness_verifier_challenge,
    }
    require(
        len(caller_nonce) == 32
        and len(expected_witness_verifier_challenge) == 32
        and len(producer_randoms) == 5,
        "producer invocation one-use random bindings are not independent",
    )
    receipt = validate_public_attestation_nonce_receipt_bindings(
        verified_receipt,
        caller_nonce_sha256=caller_nonce_sha256,
        request_body_sha256=request_body_sha256,
        tls_binding_sha256=tls_binding_sha256,
        expected_store_identity_sha256=(
            expected_static_pins["nonceStoreIdentitySha256"]
        ),
        producer_invocation=producer_invocation,
        producer_invocation_sha256=producer_invocation_sha256,
        issued_at_unix=issued,
        expires_at_unix=expires,
        nonce_authority_assurance=nonce_authority_assurance,
        nonce_authority_assurance_sha256=(
            nonce_authority_assurance_sha256
        ),
        prior_nonce_authority_verifier_state=(
            prior_nonce_authority_verifier_state
        ),
    )
    _, producer_request_raw = (
        reconstruct_public_attestation_producer_request(
            caller_nonce=caller_nonce,
            request_body=request_body,
            tls_binding=tls_binding,
            release_identity_sha256=release_identity_sha256,
            static_pins=expected_static_pins,
            nonce_consumption=receipt["consumption"],
            nonce_consumption_receipt=receipt["document"],
            nonce_authority_verifier_state_transition=transition,
            producer_invocation=producer_invocation,
            producer_invocation_sha256=(
                producer_invocation_sha256
            ),
            issued_at_unix=issued,
            expires_at_unix=expires,
        )
    )
    producer_request_sha256 = sha256(producer_request_raw)
    witness_current_request = {
        "apiVersion":
        "serverware.attestationWitnessCurrentRequest/v2",
        "minimumReleaseIdentitySha256":
        prior_release_identity_sha256,
        "minimumRollbackContinuityCommitmentSha256":
        prior_continuity_sha256,
        "producerEphemeralKeySpkiSha256":
        producer_public_key_sha256,
        "producerInvocationSha256":
        producer_invocation_sha256,
        "producerRequestSha256": producer_request_sha256,
        "tlsBindingSha256": tls_binding_sha256,
        "verifierChallengeBase64url":
        witness_challenge_base64url,
    }
    witness_current_request_sha256 = sha256_json(
        witness_current_request
    )
    expected_witness_binding = {
        "apiVersion":
        ATTESTATION_WITNESS_INVOCATION_BINDING_VERSION,
        "currentRequestSha256":
        witness_current_request_sha256,
        "producerEphemeralKeySpkiSha256":
        producer_public_key_sha256,
        "producerInvocationSha256":
        producer_invocation_sha256,
        "producerRequestSha256": producer_request_sha256,
        "tlsBindingSha256": tls_binding_sha256,
        "verifierChallengeBase64url":
        witness_challenge_base64url,
    }
    require(
        witness_binding == expected_witness_binding,
        "signed witness invocation differs from the exact reconstructed current request",
    )
    expected_binding = {
        "apiVersion":
        PUBLIC_ATTESTATION_PRODUCER_BINDING_VERSION,
        "callerNonceSha256": caller_nonce_sha256,
        "descriptorSha256":
        expected_static_pins["descriptorSha256"],
        "executableSha256":
        expected_static_pins["executableSha256"],
        "expiresAtUnix": expires,
        "immutableConfigSha256":
        expected_static_pins["immutableConfigSha256"],
        "issuedAtUnix": issued,
        "nonceAuthorityAssuranceEvidenceSha256":
        transition["assuranceEvidenceSha256"],
        "nonceAuthorityAssuranceSha256":
        transition["assuranceSha256"],
        "nonceAuthorityVerifierChallengeSha256":
        transition["verifierChallengeSha256"],
        "nonceAuthorityVerifierStateAuthorizationSha256":
        transition["authorizationSha256"],
        "nonceAuthorityVerifierStateCommitReceiptSha256":
        transition["commitReceiptSha256"],
        "nonceAuthorityVerifierStateCommitRequestSha256":
        transition["commitRequestSha256"],
        "nonceAuthorityVerifierStateCommittedStateReadSha256":
        transition["committedStateReadSha256"],
        "nonceAuthorityVerifierStateCommittedStateSha256":
        transition["committedStateSha256"],
        "nonceAuthorityVerifierStateOperationIdBase64url":
        transition["operationIdBase64url"],
        "nonceAuthorityVerifierStatePriorStateReadSha256":
        transition["priorStateReadSha256"],
        "nonceAuthorityVerifierStatePriorStateSha256":
        transition["priorStateSha256"],
        "nonceAuthorityVerifierStateServiceConfigurationSha256":
        transition_service["serviceConfigurationSha256"],
        "nonceAuthorityVerifierStateSigningKeySpkiSha256":
        transition_service["signingKeySpkiSha256"],
        "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256":
        transition_service[
            "stateStoreAdministrativeDomainSha256"
        ],
        "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256":
        transition_service[
            "stateStoreAssuranceEvidenceSha256"
        ],
        "nonceAuthorityVerifierStateRoleSeparationEvidenceSha256":
        transition["roleSeparationEvidenceSha256"],
        "nonceAuthorityVerifierStateStoreAttestationKeySpkiSha256":
        transition_service[
            "stateStoreAttestationKeySpkiSha256"
        ],
        "nonceAuthorityVerifierStateStoreCommitProofSha256":
        transition["signedStoreCommitProofSha256"],
        "nonceAuthorityVerifierStateStoreConfigurationSha256":
        transition_service["stateStoreConfigurationSha256"],
        "nonceAuthorityVerifierStateStoreIdentitySha256":
        transition_service["stateStoreIdentitySha256"],
        "nonceAuthorityVerifierStateStoreMinimumCommitIndex":
        transition_service["stateStoreMinimumCommitIndex"],
        "nonceAuthorityVerifierStateStoreMinimumGeneration":
        transition_service["stateStoreMinimumGeneration"],
        "nonceAuthorityVerifierStateTransitionSha256":
        nonce_authority_verifier_state_transition[
            "documentSha256"
        ],
        "nonceConsumptionReceiptSha256":
        receipt["receiptSha256"],
        "nonceConsumptionSha256": receipt["consumptionSha256"],
        "producerEphemeralKeySpkiSha256":
        producer_public_key_sha256,
        "nonceStoreIdentitySha256":
        expected_static_pins["nonceStoreIdentitySha256"],
        "nonceStoreKeySpkiSha256":
        expected_static_pins["nonceStoreKeySpkiSha256"],
        "producerInvocationSha256":
        producer_invocation_sha256,
        "producerRequestSchemaSha256":
        expected_static_pins["producerRequestSchemaSha256"],
        "producerRequestSha256": producer_request_sha256,
        "requestBodySha256": request_body_sha256,
        "sandboxDescriptorSha256":
        expected_static_pins["sandboxDescriptorSha256"],
        "sandboxLauncherSha256":
        expected_static_pins["sandboxLauncherSha256"],
        "tlsBindingSha256": tls_binding_sha256,
        "transactionIdBase64url":
        transition["transactionIdBase64url"],
        "trustRootsSha256":
        expected_static_pins["trustRootsSha256"],
        "witnessCurrentRequestSha256":
        witness_current_request_sha256,
        "witnessStoreIdentitySha256":
        expected_static_pins["witnessStoreIdentitySha256"],
        "witnessStoreKeySpkiSha256":
        expected_static_pins["witnessStoreKeySpkiSha256"],
    }
    require(
        binding == expected_binding,
        "public v3 producer binding differs from exact reconstructed signed request pins",
    )
    return {
        "binding": binding,
        "bindingSha256": sha256_json(envelope),
        "nonceAuthorityState": receipt["authorityState"],
        "nonceAuthorityStateSha256":
        receipt["authorityStateSha256"],
        "nonceConsumptionReceiptSha256":
        receipt["receiptSha256"],
        "nonceConsumptionSha256": receipt["consumptionSha256"],
        "nonceAuthorityVerifierStateTransitionSha256":
        nonce_authority_verifier_state_transition[
            "documentSha256"
        ],
        "producerInvocationSha256":
        producer_invocation_sha256,
        "producerRequestSha256": producer_request_sha256,
        "witnessCurrentRequestSha256":
        witness_current_request_sha256,
        "witnessInvocationBinding": expected_witness_binding,
    }


def verify_public_v3_response(
    *,
    evidence_body: bytes,
    live_session_proof: Any,
    live_session_signature: str,
    response_signing_public_key_pem: str,
    caller_nonce: bytes,
    request_body: bytes,
    expected_tls_binding: dict[str, Any],
    delivery_rebind: Any | None = None,
    trust: dict[str, Any],
    expected_release_config_sha256: str,
    expected_nonce_authority_assurance_sha256: str,
    expected_nonce_authority_assurance_issuer_spki_sha256: str,
    expected_attestation_pins: dict[str, Any],
    protected_witness_state: dict[str, Any],
    protected_witness_state_raw: bytes,
    prior_protected_witness_state: dict[str, Any],
    nonce_consumption_receipt: dict[str, Any],
    nonce_authority_assurance_evidence: dict[str, Any],
    prior_nonce_authority_verifier_state: dict[str, Any],
    nonce_authority_state_authorization: dict[str, Any],
    nonce_authority_state_commit_receipt: dict[str, Any],
    nonce_authority_verifier_challenge: bytes,
    witness_verifier_challenge: bytes,
    now: int,
) -> dict[str, Any]:
    require(
        delivery_rebind is not None,
        "public live verification requires a signed current-connection delivery rebind",
    )
    require(
        type(evidence_body) is bytes
        and 1 <= len(evidence_body) <= 4 * 1024 * 1024,
        "public v3 evidence body is empty or oversized",
    )
    document = parse_json(evidence_body, "public v3 evidence body")
    require(
        evidence_body == canonical_json_bytes(document) + b"\n",
        "public v3 evidence body is not canonical JSON plus LF",
    )
    envelope = exact_keys(
        document,
        {
            "apiVersion",
            "bundle",
            "bundleSha256",
            "liveWitnessHead",
            "nonceAuthorityVerifierStateTransition",
            "producerBinding",
            "protectedLiveWitnessState",
        },
        "public v3 evidence envelope",
    )
    require(
        envelope["apiVersion"] == PUBLIC_ATTESTATION_BUNDLE_VERSION,
        "public v3 evidence version is invalid",
    )
    require(
        envelope["protectedLiveWitnessState"]
        == protected_witness_state,
        "embedded protected live-witness state differs from the independently fetched current state",
    )
    require(
        canonical_json_bytes(envelope["protectedLiveWitnessState"])
        + b"\n"
        == protected_witness_state_raw,
        "embedded protected live-witness state bytes differ from the independently fetched current state bytes",
    )
    bundle = exact_keys(
        envelope["bundle"],
        {
            "artifacts",
            "generatedAtUnix",
            "releaseGraph",
            "schemaVersions",
        },
        "public v3 evidence bundle",
    )
    require(
        envelope["bundleSha256"] == sha256_json(bundle),
        "public v3 bundle digest is invalid",
    )
    require(
        bundle["schemaVersions"]
        == {
            "endpointBundle": PUBLIC_ATTESTATION_BUNDLE_VERSION,
            "liveSessionProof": LIVE_SESSION_PROOF_VERSION,
            "liveWitnessHead": LIVE_WITNESS_HEAD_VERSION,
            "nonceAuthorityVerifierStateTransition":
            NONCE_AUTHORITY_VERIFIER_STATE_TRANSITION_VERSION,
            "protectedLiveWitnessState":
            PROTECTED_LIVE_WITNESS_STATE_VERSION,
            "releaseConfig": PUBLIC_ATTESTATION_CONFIG_VERSION,
            "releaseIdentity": RELEASE_IDENTITY_VERSION,
            "stableReleaseStatement": STABLE_RELEASE_STATEMENT_VERSION,
            "trustRoots": TRUST_ROOTS_VERSION,
        },
        "public v3 schema-version bridge is invalid",
    )
    generated_at = require_positive_uint(
        bundle["generatedAtUnix"], "public v3 generation time"
    )
    require(
        generated_at <= now,
        "public v3 generation time is in the future",
    )
    artifacts = bundle["artifacts"]
    require(
        isinstance(artifacts, list)
        and len(artifacts) == 3
        and [
            item.get("name") if isinstance(item, dict) else None
            for item in artifacts
        ]
        == [
            "nitro-trust-roots",
            "release-config",
            "stable-release-statement",
        ],
        "public v3 stable artifact inventory is incomplete or non-canonical",
    )
    raw_artifacts: dict[str, bytes] = {}
    documents: dict[str, Any] = {}
    for item in artifacts:
        artifact = exact_keys(
            item,
            {"contentBase64url", "mediaType", "name", "sha256"},
            "public v3 stable artifact",
        )
        name = artifact["name"]
        require(
            name
            in {
                "nitro-trust-roots",
                "release-config",
                "stable-release-statement",
            }
            and name not in documents
            and artifact["mediaType"] == "application/json",
            "public v3 stable artifact identity is invalid",
        )
        raw = b64url_decode(
            artifact["contentBase64url"],
            f"public v3 {name} artifact",
            max_bytes=4 * 1024 * 1024,
        )
        parsed = parse_json(raw, f"public v3 {name} artifact")
        require(
            raw == canonical_json_bytes(parsed) + b"\n"
            and artifact["sha256"] == sha256(raw),
            f"public v3 {name} artifact bytes are invalid",
        )
        raw_artifacts[name] = raw
        documents[name] = parsed
    require(
        set(documents)
        == {
            "nitro-trust-roots",
            "release-config",
            "stable-release-statement",
        }
        and sha256(raw_artifacts["nitro-trust-roots"])
        == trust["trustRootBundleSha256"],
        "public v3 stable artifacts crossed the pinned trust roots",
    )
    release_config = validate_public_attestation_config(
        documents["release-config"],
        raw_artifacts["release-config"],
        expected_sha256=expected_release_config_sha256,
        expected_nonce_authority_assurance_sha256=(
            expected_nonce_authority_assurance_sha256
        ),
        expected_nonce_authority_assurance_issuer_spki_sha256=(
            expected_nonce_authority_assurance_issuer_spki_sha256
        ),
        trust=trust,
    )
    nonce_authority_evidence = (
        verify_nonce_authority_assurance_evidence(
            release_config["nonceAuthorityAssuranceEvidence"],
            signing_key=release_config[
                "nonceAuthorityAssuranceEvidenceKey"
            ],
            signing_key_id=release_config[
                "nonceAuthorityAssuranceEvidenceKeyId"
            ],
            assurance=release_config["nonceAuthorityAssurance"],
            nonce_authority_state_signing_key_id=release_config[
                "nonceStoreKeyId"
            ],
            verifier_state_store_administrative_domain_sha256=release_config[
                "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
            ],
            verifier_state_store_identity_sha256=release_config[
                "nonceAuthorityVerifierStateStoreIdentitySha256"
            ],
            verifier_state_store_signing_key_id=release_config[
                "nonceAuthorityVerifierStateKeyId"
            ],
            now=now,
        )
    )
    require(
        nonce_authority_assurance_evidence
        == nonce_authority_evidence["document"],
        "independently supplied nonce assurance evidence differs from immutable config",
    )
    verified_release = verify_stable_release(
        documents["stable-release-statement"],
        trust=trust,
    )
    independently_expected_pins = (
        validate_public_attestation_statement_pins(
            expected_attestation_pins,
            label="independently expected public attestation pins",
        )
    )
    require(
        verified_release["releaseIdentity"]
        == release_config["releaseIdentity"]
        and verified_release["attestationPins"]
        == independently_expected_pins
        and verified_release["attestationPins"][
            "immutableConfigSha256"
        ]
        == release_config["sha256"]
        and verified_release["attestationPins"]["trustRootsSha256"]
        == trust["trustRootBundleSha256"]
        and component_pins_from_statement(
            verified_release["attestationPins"]
        )
        == release_config["producerPolicy"],
        "public v3 signed release differs from the independently pinned release config",
    )
    protected = verify_protected_live_witness_transition(
        envelope["protectedLiveWitnessState"],
        prior_protected_witness_state,
        expected_release_identity=verified_release["releaseIdentity"],
        signing_key=release_config["witnessStoreKey"],
        signing_key_id=release_config["witnessStoreKeyId"],
        expected_store_identity_sha256=release_config[
            "producerPolicy"
        ]["witnessStoreIdentitySha256"],
        expected_witness_signing_key_id=trust["keyIds"]["witness"],
        now=now,
    )
    prior_nonce_authority_state = (
        verify_nonce_authority_verifier_state(
            prior_nonce_authority_verifier_state,
            signing_key=release_config[
                "nonceAuthorityVerifierStateKey"
            ],
            signing_key_id=release_config[
                "nonceAuthorityVerifierStateKeyId"
            ],
            expected_state_store_identity_sha256=release_config[
                "nonceAuthorityVerifierStateStoreIdentitySha256"
            ],
            assurance=release_config["nonceAuthorityAssurance"],
            assurance_sha256=release_config[
                "nonceAuthorityAssuranceSha256"
            ],
        )
    )
    nonce_authority_authorization = (
        verify_nonce_authority_state_authorization(
            nonce_authority_state_authorization,
            signing_key=release_config[
                "nonceAuthorityVerifierStateKey"
            ],
            signing_key_id=release_config[
                "nonceAuthorityVerifierStateKeyId"
            ],
            expected_state_store_identity_sha256=release_config[
                "nonceAuthorityVerifierStateStoreIdentitySha256"
            ],
            expected_state_store_attestation_key_id=release_config[
                "nonceAuthorityVerifierStateStoreAttestationKeyId"
            ],
            expected_state_store_assurance_evidence_sha256=release_config[
                "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
            ],
            expected_state_store_configuration_sha256=release_config[
                "nonceAuthorityVerifierStateStoreConfigurationSha256"
            ],
            expected_nonce_receipt_signing_key_id=release_config[
                "nonceStoreKeyId"
            ],
            assurance=release_config["nonceAuthorityAssurance"],
            assurance_sha256=release_config[
                "nonceAuthorityAssuranceSha256"
            ],
            prior_verifier_state=prior_nonce_authority_state,
            verifier_challenge=nonce_authority_verifier_challenge,
            now=None,
        )
    )
    prior_nonce_authority_state = {
        **prior_nonce_authority_state,
        "authorizationSha256":
        nonce_authority_authorization["envelopeSha256"],
    }
    transition_document = envelope[
        "nonceAuthorityVerifierStateTransition"
    ]
    require(
        isinstance(transition_document, dict)
        and isinstance(
            transition_document.get("commitRequest"),
            dict,
        ),
        "public bundle omitted the verifier-state commit request",
    )
    nonce_authority_commit_request = dict(
        transition_document["commitRequest"]
    )
    nonce_authority_commit_request_sha256 = sha256_json(
        nonce_authority_commit_request
    )
    nonce_authority_commit = (
        verify_nonce_authority_state_commit_receipt(
            nonce_authority_state_commit_receipt,
            signing_key=release_config[
                "nonceAuthorityVerifierStateKey"
            ],
            signing_key_id=release_config[
                "nonceAuthorityVerifierStateKeyId"
            ],
            expected_state_store_identity_sha256=release_config[
                "nonceAuthorityVerifierStateStoreIdentitySha256"
            ],
            expected_state_store_administrative_domain_sha256=release_config[
                "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
            ],
            expected_state_store_assurance_evidence_sha256=release_config[
                "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
            ],
            expected_state_store_configuration_sha256=release_config[
                "nonceAuthorityVerifierStateStoreConfigurationSha256"
            ],
            minimum_state_store_generation=release_config[
                "nonceAuthorityVerifierStateStoreMinimumGeneration"
            ],
            minimum_state_store_commit_index=release_config[
                "nonceAuthorityVerifierStateStoreMinimumCommitIndex"
            ],
            expected_production_eligible=True,
            state_store_attestation_key=release_config[
                "nonceAuthorityVerifierStateStoreAttestationKey"
            ],
            state_store_attestation_key_id=release_config[
                "nonceAuthorityVerifierStateStoreAttestationKeyId"
            ],
            assurance=release_config["nonceAuthorityAssurance"],
            assurance_sha256=release_config[
                "nonceAuthorityAssuranceSha256"
            ],
            prior_verifier_state=prior_nonce_authority_state[
                "document"
            ],
            authorization=nonce_authority_state_authorization,
            commit_request=nonce_authority_commit_request,
            nonce_consumption_receipt=nonce_consumption_receipt,
            nonce_receipt_signing_key=release_config[
                "nonceStoreKey"
            ],
            nonce_receipt_signing_key_id=release_config[
                "nonceStoreKeyId"
            ],
            verifier_challenge=(
                nonce_authority_verifier_challenge
            ),
            now=now,
        )
    )
    verifier_state_transition = (
        verify_public_attestation_verifier_state_transition(
            envelope["nonceAuthorityVerifierStateTransition"],
            assurance=release_config["nonceAuthorityAssurance"],
            assurance_evidence=nonce_authority_evidence["document"],
            assurance_evidence_sha256=nonce_authority_evidence[
                "envelopeSha256"
            ],
            authorization=nonce_authority_authorization,
            commit_request=nonce_authority_commit_request,
            commit_receipt=nonce_authority_commit,
            nonce_consumption_receipt=nonce_consumption_receipt,
            prior_state=prior_nonce_authority_state,
            verifier_state_service=release_config[
                "nonceAuthorityVerifierStateService"
            ],
            verifier_state_key=release_config[
                "nonceAuthorityVerifierStateKey"
            ],
            verifier_state_key_id=release_config[
                "nonceAuthorityVerifierStateKeyId"
            ],
            state_store_identity_sha256=release_config[
                "nonceAuthorityVerifierStateStoreIdentitySha256"
            ],
            state_store_administrative_domain_sha256=release_config[
                "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
            ],
            state_store_assurance_evidence_sha256=release_config[
                "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
            ],
            state_store_assurance_evidence=release_config[
                "nonceAuthorityVerifierStateStoreAssuranceEvidence"
            ],
            role_separation_evidence=release_config[
                "nonceAuthorityVerifierStateRoleSeparationEvidence"
            ],
            role_separation_evidence_sha256=release_config[
                "nonceAuthorityVerifierStateRoleSeparationEvidenceSha256"
            ],
            state_store_configuration_sha256=release_config[
                "nonceAuthorityVerifierStateStoreConfigurationSha256"
            ],
            state_store_minimum_commit_index=release_config[
                "nonceAuthorityVerifierStateStoreMinimumCommitIndex"
            ],
            state_store_minimum_generation=release_config[
                "nonceAuthorityVerifierStateStoreMinimumGeneration"
            ],
            state_store_attestation_key_id=release_config[
                "nonceAuthorityVerifierStateStoreAttestationKeyId"
            ],
            verifier_challenge=nonce_authority_verifier_challenge,
            now=now,
        )
    )
    producer = verify_public_attestation_producer_binding(
        envelope["producerBinding"],
        caller_nonce=caller_nonce,
        request_body=request_body,
        tls_binding=live_session_proof["tlsBinding"],
        nonce_consumption_receipt=nonce_consumption_receipt,
        nonce_store_key=release_config["nonceStoreKey"],
        nonce_store_key_id=release_config["nonceStoreKeyId"],
        nonce_authority_assurance=release_config[
            "nonceAuthorityAssurance"
        ],
        nonce_authority_assurance_sha256=release_config[
            "nonceAuthorityAssuranceSha256"
        ],
        prior_nonce_authority_verifier_state=(
            prior_nonce_authority_state
        ),
        nonce_authority_verifier_state_transition=(
            verifier_state_transition
        ),
        minimum_release_identity_sha256=verified_release[
            "releaseIdentitySha256"
        ],
        minimum_rollback_continuity_commitment_sha256=release_config[
            "minimumRollbackContinuityCommitmentSha256"
        ],
        current_witness_invocation_binding=protected[
            "invocationBinding"
        ],
        expected_witness_verifier_challenge=(
            witness_verifier_challenge
        ),
        release_identity_sha256=(
            verified_release["releaseIdentitySha256"]
        ),
        release_config_sha256=release_config["sha256"],
        global_role_key_ids=release_config["globalRoleKeyIds"],
        signed_static_pins=verified_release["attestationPins"],
        generated_at_unix=generated_at,
        now=now,
    )
    require(
        protected["invocationBinding"]
        == producer["witnessInvocationBinding"],
        "producer binding and signed current witness disagree on the invocation",
    )
    require(
        nonce_authority_commit["nonceAuthorityStateSha256"]
        == producer["nonceAuthorityStateSha256"]
        and nonce_authority_commit["commitRequestSha256"]
        == nonce_authority_commit_request_sha256
        and nonce_authority_commit["nonceConsumptionReceiptSha256"]
        == producer["nonceConsumptionReceiptSha256"]
        and nonce_authority_commit["nonceConsumptionSha256"]
        == producer["nonceConsumptionSha256"],
        "producer binding and verifier-state receipt disagree on nonce evidence",
    )
    release_monotonic = verified_release["releaseIdentity"][
        "monotonicRelease"
    ]
    require(
        protected["current"]["generation"]
        == release_monotonic["releaseGeneration"]
        and protected["current"]["rollbackEpoch"]
        == release_monotonic["rollbackEpoch"],
        "signed protected witness crossed stable release coordinates",
    )
    graph = exact_keys(
        bundle["releaseGraph"],
        {
            "apiVersion",
            "releaseConfigSha256",
            "releaseIdentity",
            "releaseIdentitySha256",
            "stableReleaseStatementSha256",
            "trustRootBundleSha256",
        },
        "public v3 release graph",
    )
    require(
        graph["apiVersion"] == PUBLIC_RELEASE_GRAPH_VERSION
        and graph["releaseConfigSha256"] == release_config["sha256"]
        and graph["releaseIdentity"] == verified_release["releaseIdentity"]
        and graph["releaseIdentitySha256"]
        == verified_release["releaseIdentitySha256"]
        and graph["stableReleaseStatementSha256"]
        == sha256(raw_artifacts["stable-release-statement"])
        and graph["trustRootBundleSha256"]
        == trust["trustRootBundleSha256"],
        "public v3 release graph is not reconstructible",
    )
    layers = verify_release_then_live_session(
        stable_release_statement=documents["stable-release-statement"],
        live_witness_head=envelope["liveWitnessHead"],
        live_session_proof=live_session_proof,
        live_session_signature=live_session_signature,
        trust=trust,
        expected_witness=protected["current"],
        expected_witness_invocation_binding=protected[
            "invocationBinding"
        ],
        expected_live_witness_payload_sha256=protected["current"][
            "liveWitnessHeadPayloadSha256"
        ],
        response_signing_public_key_pem=(
            response_signing_public_key_pem
        ),
        evidence_body=evidence_body,
        caller_nonce=caller_nonce,
        request_body=request_body,
        expected_tls_binding=expected_tls_binding,
        delivery_rebind=delivery_rebind,
        now=now,
    )
    result = {
        "apiVersion": LIVE_ATTESTATION_RESULT_VERSION,
        "verificationOk": True,
        "finalCompletionVerified": True,
        "actionAuthorization": None,
        "okForAction": False,
        "committedNonceAuthorityVerifierState":
        nonce_authority_commit["committedState"],
        "evidence": {
            "committedNonceAuthorityVerifierStateSha256":
            nonce_authority_commit["committedStateSha256"],
            "evidenceBodySha256": sha256(evidence_body),
            "deliveryRebindSha256": sha256_json(
                delivery_rebind
            ),
            "liveSessionProofSha256": sha256_json(
                layers["liveSessionProof"]
            ),
            "liveSessionSignatureSha256": sha256(
                live_session_signature.encode("ascii")
            ),
            "liveWitnessHeadPayloadSha256": protected["current"][
                "liveWitnessHeadPayloadSha256"
            ],
            "nonceAuthorityAssuranceEvidenceSha256":
            nonce_authority_evidence["envelopeSha256"],
            "nonceAuthorityAssuranceSha256": release_config[
                "nonceAuthorityAssuranceSha256"
            ],
            "nonceAuthorityEpoch": producer[
                "nonceAuthorityState"
            ]["authorityEpoch"],
            "nonceAuthorityGeneration": producer[
                "nonceAuthorityState"
            ]["authorityGeneration"],
            "nonceAuthorityHighWaterCommitmentSha256": producer[
                "nonceAuthorityState"
            ]["highWaterCommitmentSha256"],
            "nonceAuthoritySequence": producer[
                "nonceAuthorityState"
            ]["highWaterSequence"],
            "nonceAuthorityStateSha256": producer[
                "nonceAuthorityStateSha256"
            ],
            "nonceAuthorityVerifierChallengeSha256": sha256(
                nonce_authority_verifier_challenge
            ),
            "nonceAuthorityVerifierStateAuthorizationSha256":
            nonce_authority_authorization["envelopeSha256"],
            "nonceAuthorityVerifierStateCommitReceiptSha256":
            nonce_authority_commit["envelopeSha256"],
            "nonceAuthorityVerifierStateSigningKeySpkiSha256":
            release_config["nonceAuthorityVerifierStateKeyId"],
            "nonceAuthorityVerifierStateStoreGeneration":
            nonce_authority_commit["committedState"][
                "stateStoreGeneration"
            ],
            "nonceAuthorityVerifierStateStoreIdentitySha256":
            release_config[
                "nonceAuthorityVerifierStateStoreIdentitySha256"
            ],
            "nonceConsumptionSha256": producer[
                "nonceConsumptionSha256"
            ],
            "nonceConsumptionReceiptSha256": producer[
                "nonceConsumptionReceiptSha256"
            ],
            "nonceStoreKeySpkiSha256": release_config[
                "nonceStoreKeyId"
            ],
            "priorProtectedLiveWitnessStateSha256": protected[
                "priorEnvelopeSha256"
            ],
            "priorNonceAuthorityVerifierStateSha256":
            prior_nonce_authority_state["envelopeSha256"],
            "producerBindingSha256": producer["bindingSha256"],
            "producerEphemeralKeySpkiSha256": producer[
                "producerEphemeralKeySpkiSha256"
            ],
            "producerInvocationSha256": producer[
                "producerInvocationSha256"
            ],
            "producerRequestSha256": producer[
                "producerRequestSha256"
            ],
            "protectedLiveWitnessStateSha256": protected[
                "envelopeSha256"
            ],
            "releaseConfigSha256": release_config["sha256"],
            "releaseIdentitySha256": verified_release[
                "releaseIdentitySha256"
            ],
            "stableReleaseStatementSha256": verified_release[
                "statementSha256"
            ],
            "witnessGeneration": layers["witness"]["generation"],
            "witnessCurrentRequestSha256": producer[
                "witnessCurrentRequestSha256"
            ],
            "witnessSequence": layers["witness"]["sequence"],
            "witnessStoreIdentitySha256": release_config[
                "producerPolicy"
            ]["witnessStoreIdentitySha256"],
            "witnessVerifierChallengeSha256": sha256(
                witness_verifier_challenge
            ),
        },
    }
    return validate_non_actionable_live_result(result)


def reject_completion_bindings(value: Any, *, label: str) -> None:
    if isinstance(value, dict):
        forbidden = COMPLETION_BINDING_FIELD_NAMES.intersection(value)
        require(
            not forbidden,
            f"{label} contains forbidden completion binding fields: "
            + ", ".join(sorted(forbidden)),
        )
        for key, item in value.items():
            reject_completion_bindings(item, label=f"{label}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            reject_completion_bindings(item, label=f"{label}[{index}]")


def without_completion_bindings(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: without_completion_bindings(item)
            for key, item in value.items()
            if key not in COMPLETION_BINDING_FIELD_NAMES
        }
    if isinstance(value, list):
        return [without_completion_bindings(item) for item in value]
    return value


def builder_transcript_core_payload(
    transcript: dict[str, Any],
) -> dict[str, Any]:
    outer_events = transcript.get("events")
    require(
        isinstance(outer_events, list),
        "builder transcript core requires an event list",
    )
    previous_core_event_sha256 = sha256(b"")
    core_events: list[dict[str, Any]] = []
    for sequence, outer_record in enumerate(outer_events, start=1):
        require(
            isinstance(outer_record, dict),
            "builder transcript core event is malformed",
        )
        outer_sequence = require_uint(
            outer_record.get("sequence"),
            "builder transcript core event sequence",
        )
        require(
            outer_sequence == sequence
            and isinstance(outer_record.get("event"), dict),
            "builder transcript core event is malformed",
        )
        core_event_payload = {
            "event": without_completion_bindings(outer_record["event"]),
            "previousEventSha256": previous_core_event_sha256,
            "sequence": sequence,
        }
        core_event_sha256 = sha256_json(core_event_payload)
        core_events.append(
            {
                **core_event_payload,
                "eventSha256": core_event_sha256,
            }
        )
        previous_core_event_sha256 = core_event_sha256
    core_payload = {
        key: without_completion_bindings(value)
        for key, value in transcript.items()
        if key
        not in {
            "completionIdentity",
            "completionIdentitySha256",
            "eventHeadSha256",
            "events",
            "transcriptSha256",
        }
    }
    core_payload["eventHeadSha256"] = previous_core_event_sha256
    core_payload["events"] = core_events
    reject_completion_bindings(
        core_payload,
        label="builder transcript completion core",
    )
    return core_payload


def completion_core(
    name: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    require(
        name in COMPLETION_CORE_VERSIONS,
        f"unknown completion core {name}",
    )
    core = {
        "apiVersion": COMPLETION_CORE_VERSIONS[name],
        "pipeline": PIPELINE,
        "payload": payload,
    }
    reject_completion_bindings(core, label=f"{name} completion core")
    return core


def reconstruct_completion_identity(
    *,
    core_digests: dict[str, Any],
    challenge_nonce_sha256: str,
    release_generation: int,
    rollback_epoch: int,
) -> dict[str, Any]:
    verified_core_digests = exact_keys(
        core_digests,
        COMPLETION_CORE_DIGEST_FIELDS,
        "reconstructed completion core digests",
    )
    for name, digest in verified_core_digests.items():
        require_sha256(digest, f"reconstructed {name} core digest")
    return validate_completion_identity(
        {
            "apiVersion": COMPLETION_IDENTITY_VERSION,
            "challengeNonceSha256": require_sha256(
                challenge_nonce_sha256,
                "reconstructed completion challenge",
            ),
            "coreDigests": dict(verified_core_digests),
            "pipeline": PIPELINE,
            "releaseGeneration": require_uint(
                release_generation,
                "reconstructed completion release generation",
            ),
            "rollbackEpoch": require_uint(
                rollback_epoch,
                "reconstructed completion rollback epoch",
            ),
        },
        label="reconstructed completion identity",
    )


def reconstruct_continuity_core_digest(
    *,
    core_digests: dict[str, str],
    challenge_nonce_sha256: str,
    release_generation: int,
    rollback_epoch: int,
) -> str:
    constituent_names = COMPLETION_CORE_DIGEST_FIELDS - {"continuity"}
    constituents = exact_keys(
        core_digests,
        constituent_names,
        "continuity core constituent digests",
    )
    for name, digest in constituents.items():
        require_sha256(digest, f"continuity {name} core digest")
    continuity_core = {
        "apiVersion": "serverware.completionContinuityCore/v1",
        "challengeNonceSha256": require_sha256(
            challenge_nonce_sha256,
            "continuity challenge",
        ),
        "coreDigests": dict(constituents),
        "pipeline": PIPELINE,
        "releaseGeneration": require_uint(
            release_generation,
            "continuity release generation",
        ),
        "rollbackEpoch": require_uint(
            rollback_epoch,
            "continuity rollback epoch",
        ),
    }
    reject_completion_bindings(
        continuity_core,
        label="completion continuity core",
    )
    return sha256_json(continuity_core)


def verify_reconstructed_completion_identity(
    reconstructed: dict[str, Any],
    occurrences: list[tuple[str, Any, Any]],
) -> str:
    reconstructed_sha256 = sha256_json(reconstructed)
    for label, value, digest in occurrences:
        occurrence = verify_completion_identity(
            value,
            digest,
            label=label,
        )
        require(
            occurrence == reconstructed
            and hmac.compare_digest(digest, reconstructed_sha256),
            f"{label} does not bind the independently reconstructed core digests",
        )
    return reconstructed_sha256


def verify_completion_identity(
    document: Any,
    digest: Any,
    *,
    label: str,
) -> dict[str, Any]:
    identity = validate_completion_identity(document, label=label)
    require_sha256(digest, f"{label} digest")
    require(
        digest == sha256_json(identity),
        f"{label} digest does not match its canonical object",
    )
    return identity


def verify_custody_completion_binding(
    custody: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    identity = verify_completion_identity(
        custody.get("completionIdentity"),
        custody.get("completionIdentitySha256"),
        label="runtime custody completion identity",
    )
    custody_core = {
        key: value
        for key, value in custody.items()
        if key not in {"completionIdentity", "completionIdentitySha256"}
    }
    core_digest = sha256_json(completion_core("custody", custody_core))
    require(
        identity["coreDigests"]["custody"] == core_digest,
        "completion identity does not bind the reconstructed custody core",
    )
    return identity, core_digest


def load_expectations(document: Any) -> dict[str, Any]:
    document = exact_keys(
        document,
        {
            "apiVersion",
            "pipeline",
            "trustRootBundleSha256",
            "trustRootKeyIds",
            "candidateManifestFileSha256",
            "candidateManifestPayloadSha256",
            "sourceInputManifestFileSha256",
            "sourceInputManifestPayloadSha256",
            "sourceClosureSha256",
            "buildWatchdogReceiptFileSha256",
            "buildWatchdogReceiptPayloadSha256",
            "promotionReceiptFileSha256",
            "promotionReceiptPayloadSha256",
            "promotedManifestFileSha256",
            "promotedManifestPayloadSha256",
            "manifestV6EifBuildStatementFileSha256",
            "manifestV6EifBuildStatementPayloadSha256",
            "productionIdentitySha256",
            "completionIdentity",
            "completionIdentitySha256",
            "monotonicWitnessSha256",
            "productionContinuitySha256",
            "productionReleaseIdentitySha256",
            "runtimeStateFileSha256",
            "runtimeKeyCustodyFileSha256",
            "dependencyClosureSha256",
            "importedImageMappingsSha256",
            "eifSha384",
            "pcrs",
            "nitroModuleId",
            "policyHash",
            "policySequence",
            "caSpkiSha256",
            "liveTlsExporterSha256",
            "liveTlsLeafSpkiSha256",
            "liveTlsPeerSpkiSha256",
            "tlsStackMeasurementSha256",
            "attestationRequestSha256",
            "releaseGeneration",
            "rollbackEpoch",
            "maxQuoteAgeSeconds",
            "maxFutureSkewSeconds",
        },
        "independent production expectations",
    )
    require(document["apiVersion"] == EXPECTATIONS_VERSION, "expectations apiVersion mismatch")
    require(document["pipeline"] == PIPELINE, "expectations select an unsupported pipeline")
    verify_completion_identity(
        document["completionIdentity"],
        document["completionIdentitySha256"],
        label="expected completion identity",
    )
    for field in (
        "trustRootBundleSha256",
        "candidateManifestFileSha256",
        "candidateManifestPayloadSha256",
        "sourceInputManifestFileSha256",
        "sourceInputManifestPayloadSha256",
        "sourceClosureSha256",
        "buildWatchdogReceiptFileSha256",
        "buildWatchdogReceiptPayloadSha256",
        "promotionReceiptFileSha256",
        "promotionReceiptPayloadSha256",
        "promotedManifestFileSha256",
        "promotedManifestPayloadSha256",
        "manifestV6EifBuildStatementFileSha256",
        "manifestV6EifBuildStatementPayloadSha256",
        "productionIdentitySha256",
        "completionIdentitySha256",
        "monotonicWitnessSha256",
        "productionContinuitySha256",
        "productionReleaseIdentitySha256",
        "runtimeStateFileSha256",
        "runtimeKeyCustodyFileSha256",
        "dependencyClosureSha256",
        "importedImageMappingsSha256",
        "policyHash",
        "caSpkiSha256",
        "liveTlsExporterSha256",
        "liveTlsLeafSpkiSha256",
        "liveTlsPeerSpkiSha256",
        "tlsStackMeasurementSha256",
        "attestationRequestSha256",
    ):
        require_sha256(document[field], f"expectations {field}")
    trust_key_ids = exact_keys(
        document["trustRootKeyIds"],
        TRUST_KEY_ROLES,
        "expected trust-root role key IDs",
    )
    for role in TRUST_KEY_ROLES:
        require_sha256(trust_key_ids[role], f"expected {role} trust-root key ID")
    require(
        len(set(trust_key_ids.values())) == len(trust_key_ids),
        "expected trust-root roles reuse a key",
    )
    require_identifier(document["nitroModuleId"], "expected Nitro module ID")
    require_sha384(document["eifSha384"], "expected EIF digest")
    pcrs = exact_keys(document["pcrs"], {"PCR0", "PCR1", "PCR2"}, "expected PCRs")
    for name in ("PCR0", "PCR1", "PCR2"):
        require_sha384(pcrs[name], f"expected {name}")
    require(
        pcrs["PCR0"] == document["eifSha384"],
        "independently expected EIF digest must map exactly to PCR0",
    )
    require_uint(document["releaseGeneration"], "expected release generation")
    require_uint(document["rollbackEpoch"], "expected rollback epoch")
    require_uint(document["policySequence"], "expected policy sequence")
    max_age = require_uint(document["maxQuoteAgeSeconds"], "maximum quote age", maximum=MAX_VALIDITY_SECONDS)
    skew = require_uint(document["maxFutureSkewSeconds"], "maximum quote future skew", maximum=120)
    require(1 <= max_age <= MAX_VALIDITY_SECONDS, "maximum quote age is invalid")
    return document


def load_client_state(document: Any) -> dict[str, Any]:
    document = exact_keys(
        document,
        {
            "apiVersion",
            "challengeConsumptionSha256",
            "checkpointSha256",
            "logId",
            "provider",
            "releaseGeneration",
            "rollbackEpoch",
            "rootHash",
            "sequence",
            "stateSha256",
            "treeSize",
            "witnessKeyId",
        },
        "durable prior witness state",
    )
    require(document["apiVersion"] == CLIENT_STATE_VERSION, "client-state apiVersion mismatch")
    state_payload = dict(document)
    state_sha256 = state_payload.pop("stateSha256")
    require(
        state_sha256 == sha256_json(state_payload),
        "prior witness state digest mismatch",
    )
    require(
        isinstance(document["provider"], str)
        and 1 <= len(document["provider"]) <= 128,
        "prior witness provider is invalid",
    )
    for field in (
        "checkpointSha256",
        "challengeConsumptionSha256",
        "logId",
        "rootHash",
        "stateSha256",
        "witnessKeyId",
    ):
        require_sha256(document[field], f"prior witness {field}")
    for field in (
        "releaseGeneration",
        "rollbackEpoch",
        "sequence",
        "treeSize",
    ):
        require_uint(document[field], f"prior witness {field}")
    require(
        document["releaseGeneration"] >= 1
        and document["sequence"] >= 1
        and document["treeSize"] >= 1,
        "prior witness high-water values are invalid",
    )
    return document


def verify_indexed_merkle_inclusion(
    *,
    leaf_sha256: str,
    leaf_index: int,
    tree_size: int,
    proof: Any,
    root_sha256: str,
    label: str,
) -> None:
    require(
        0 <= leaf_index < tree_size,
        f"{label} leaf index is outside the tree",
    )
    require(
        isinstance(proof, list) and len(proof) <= 256,
        f"{label} proof is invalid",
    )
    cursor = bytes.fromhex(require_sha256(leaf_sha256, f"{label} leaf")[7:])
    index = leaf_index
    last = tree_size - 1
    for item in proof:
        sibling = bytes.fromhex(require_sha256(item, f"{label} sibling")[7:])
        if index == last or index & 1:
            cursor = hashlib.sha256(b"\x01" + sibling + cursor).digest()
            while index != 0 and not index & 1:
                index >>= 1
                last >>= 1
        else:
            cursor = hashlib.sha256(b"\x01" + cursor + sibling).digest()
        index >>= 1
        last >>= 1
    require(
        last == 0 and "sha256:" + cursor.hex() == root_sha256,
        f"{label} proof does not reach the indexed root",
    )


def verify_protected_client_state(
    document: Any,
    checkpoint_document: Any,
    *,
    trust: dict[str, Any],
    now: int,
) -> tuple[dict[str, Any], dict[str, str]]:
    payload, envelope_sha256 = verify_standard_envelope(
        document,
        api_version=PROTECTED_STATE_VERSION,
        domain=PROTECTED_STATE_DOMAIN,
        key=trust["keys"]["clientState"],
        key_id=trust["keyIds"]["clientState"],
        label="protected prior client state",
    )
    payload = exact_keys(
        payload,
        {
            "canonicalProfile",
            "clientState",
            "clientStateSha256",
            "expiresAtUnix",
            "issuedAtUnix",
            "protectedClientStateId",
            "provenanceBoundary",
            "trustRootBundleSha256",
            "trustRootPinId",
        },
        "protected prior client-state payload",
    )
    require(
        payload["canonicalProfile"] == CANONICAL_PROFILE
        and payload["provenanceBoundary"] == PROTECTED_STATE_PROVENANCE
        and payload["trustRootBundleSha256"]
        == trust["trustRootBundleSha256"],
        "protected state profile, provenance, or trust-root binding mismatch",
    )
    require_identifier(
        payload["protectedClientStateId"], "protected client-state ID"
    )
    require_identifier(payload["trustRootPinId"], "trust-root pin ID")
    issued = require_uint(payload["issuedAtUnix"], "protected state issue time")
    expires = require_uint(payload["expiresAtUnix"], "protected state expiry")
    require(
        issued <= now <= expires and expires - issued <= MAX_RELEASE_VALIDITY_SECONDS,
        "protected prior state is stale or overlong",
    )
    prior = load_client_state(payload["clientState"])
    require(
        payload["clientStateSha256"] == prior["stateSha256"],
        "protected state does not bind its exact client state",
    )
    checkpoint, checkpoint_sha256 = verify_standard_envelope(
        checkpoint_document,
        api_version=PROTECTED_STATE_CHECKPOINT_VERSION,
        domain=PROTECTED_STATE_CHECKPOINT_DOMAIN,
        key=trust["keys"]["clientStateCheckpoint"],
        key_id=trust["keyIds"]["clientStateCheckpoint"],
        label="protected prior-state checkpoint",
    )
    checkpoint = exact_keys(
        checkpoint,
        {
            "canonicalProfile",
            "clientStateSha256",
            "expiresAtUnix",
            "inclusionProof",
            "issuedAtUnix",
            "leafIndex",
            "leafSha256",
            "logId",
            "protectedClientStateId",
            "protectedClientStatePayloadSha256",
            "provider",
            "rootHashSha256",
            "treeSize",
            "trustRootBundleSha256",
            "trustRootPinId",
        },
        "protected prior-state checkpoint payload",
    )
    require(
        checkpoint["canonicalProfile"] == CANONICAL_PROFILE
        and checkpoint["clientStateSha256"] == prior["stateSha256"]
        and checkpoint["protectedClientStateId"]
        == payload["protectedClientStateId"]
        and checkpoint["protectedClientStatePayloadSha256"]
        == document["payloadSha256"]
        and checkpoint["trustRootBundleSha256"]
        == trust["trustRootBundleSha256"]
        and checkpoint["trustRootPinId"] == payload["trustRootPinId"],
        "protected state checkpoint crossed state, payload, or trust roots",
    )
    checkpoint_issued = require_uint(
        checkpoint["issuedAtUnix"], "protected checkpoint issue time"
    )
    checkpoint_expires = require_uint(
        checkpoint["expiresAtUnix"], "protected checkpoint expiry"
    )
    require(
        checkpoint_issued <= now <= checkpoint_expires
        and checkpoint_expires - checkpoint_issued
        <= MAX_RELEASE_VALIDITY_SECONDS,
        "protected state checkpoint is stale or overlong",
    )
    leaf = {
        "apiVersion": "serverware.protectedNitroClientStateLeaf/v1",
        "clientStateSha256": prior["stateSha256"],
        "protectedClientStateId": payload["protectedClientStateId"],
        "protectedClientStatePayloadSha256": document["payloadSha256"],
        "trustRootBundleSha256": trust["trustRootBundleSha256"],
    }
    leaf_sha256 = sha256(b"\x00" + canonical_json_bytes(leaf))
    require(
        checkpoint["leafSha256"] == leaf_sha256,
        "protected state checkpoint leaf mismatch",
    )
    verify_indexed_merkle_inclusion(
        leaf_sha256=leaf_sha256,
        leaf_index=require_uint(
            checkpoint["leafIndex"], "protected checkpoint leaf index"
        ),
        tree_size=require_uint(
            checkpoint["treeSize"], "protected checkpoint tree size"
        ),
        proof=checkpoint["inclusionProof"],
        root_sha256=require_sha256(
            checkpoint["rootHashSha256"], "protected checkpoint root"
        ),
        label="protected state checkpoint inclusion",
    )
    return prior, {
        "protectedStateEnvelopeSha256": envelope_sha256,
        "protectedStateCheckpointSha256": checkpoint_sha256,
    }


def decode_canonical_json_file_b64(value: Any, label: str) -> tuple[dict[str, Any], bytes]:
    raw = b64url_decode(value, label, max_bytes=MAX_JSON_BYTES)
    document = parse_json(raw, label)
    require(isinstance(document, dict), f"{label} must contain a JSON object")
    require(raw == canonical_json_bytes(document) + b"\n", f"{label} is not canonical JSON plus LF")
    return document, raw


def safe_source_path(value: Any, label: str) -> str:
    require(isinstance(value, str) and value and len(value.encode("utf-8")) <= 4096, f"{label} is invalid")
    path = PurePosixPath(value)
    require(
        not path.is_absolute()
        and value == path.as_posix()
        and all(part not in {"", ".", ".."} for part in path.parts),
        f"{label} is not a canonical relative path",
    )
    return value


def validate_source_entry(entry: Any, *, label: str) -> tuple[str, dict[str, Any]]:
    require(isinstance(entry, dict), f"{label} is invalid")
    path = safe_source_path(entry.get("path"), f"{label} path")
    kind = entry.get("type")
    if kind == "file":
        exact_keys(
            entry,
            {"path", "type", "mode", "size", "sha256", "classification", "provenance"},
            label,
        )
        require(entry["mode"] in {0o400, 0o500}, f"{label} mode is invalid")
        require_uint(entry["size"], f"{label} size", maximum=8 * 1024 * 1024 * 1024)
        require_sha256(entry["sha256"], f"{label} digest")
    elif kind == "symlink":
        exact_keys(
            entry,
            {"path", "type", "mode", "target", "classification", "provenance"},
            label,
        )
        require(entry["mode"] == 0o777, f"{label} mode is invalid")
        target = entry["target"]
        require(isinstance(target, str) and target and "\x00" not in target, f"{label} target is invalid")
        resolved = PurePosixPath(path).parent.joinpath(target)
        depth = 0
        for part in resolved.parts:
            if part == "..":
                depth -= 1
            elif part not in {"", "."}:
                depth += 1
            require(depth >= 0, f"{label} symlink escapes source root")
    else:
        raise VerificationError(f"{label} type is unsupported")
    require(entry["classification"] in {"source", "build-input"}, f"{label} classification is invalid")
    require(
        entry["provenance"] in {"tracked", "required-untracked"},
        f"{label} provenance is invalid",
    )
    return path, entry


def reconstruct_git_index_tree(
    entries: list[dict[str, Any]],
    *,
    object_format: str,
) -> str:
    digest_factory = hashlib.sha1 if object_format == "sha1" else hashlib.sha256
    root: dict[str, Any] = {}
    for entry in entries:
        cursor = root
        parts = PurePosixPath(entry["path"]).parts
        for component in parts[:-1]:
            require(
                component not in cursor or isinstance(cursor[component], dict),
                "Git index contains a file/directory collision",
            )
            cursor = cursor.setdefault(component, {})
        require(parts[-1] not in cursor, "Git index contains a duplicate path")
        cursor[parts[-1]] = entry

    def tree_id(directory: dict[str, Any]) -> bytes:
        records: list[tuple[bytes, bytes]] = []
        for name, value in directory.items():
            raw_name = name.encode("utf-8")
            require(b"/" not in raw_name and b"\x00" not in raw_name, "Git tree name is invalid")
            if isinstance(value, dict):
                mode = b"40000"
                object_id = tree_id(value)
                sort_name = raw_name + b"/"
            else:
                mode = value["gitMode"].encode("ascii")
                object_id = bytes.fromhex(value["objectId"].split(":", 1)[1])
                sort_name = raw_name
            records.append((sort_name, mode + b" " + raw_name + b"\x00" + object_id))
        body = b"".join(record for _, record in sorted(records, key=lambda item: item[0]))
        return digest_factory(b"tree " + str(len(body)).encode("ascii") + b"\x00" + body).digest()

    return f"{object_format}:{tree_id(root).hex()}"


def verify_source_evidence(
    source: dict[str, Any],
    raw: bytes,
    *,
    trust: dict[str, Any],
) -> dict[str, Any]:
    required = {
        "aggregateBytes",
        "apiVersion",
        "entries",
        "entryCount",
        "fileCount",
        "gitInventory",
        "gitInventoryPayloadSha256",
        "pathListSha256",
        "payloadSha256",
        "requiredUntrackedInventorySha256",
        "requiredUntrackedPaths",
        "selectionModel",
        "sourceEvidence",
        "sourceEvidenceSha256",
        "symlinkCount",
        "trackedInventorySha256",
        "trackedPaths",
        "untrackedApproval",
        "untrackedApprovalPayloadSha256",
    }
    exact_keys(source, required, "source-input manifest")
    require(source["apiVersion"] == SOURCE_INPUT_VERSION, "source-input apiVersion mismatch")
    require(source["selectionModel"] == SOURCE_SELECTION_MODEL, "source selection model mismatch")
    payload = dict(source)
    payload_digest = payload.pop("payloadSha256")
    require(payload_digest == sha256_json(payload), "source-input payload digest mismatch")
    git, git_document_sha256 = verify_existing_envelope(
        source["gitInventory"],
        api_version=GIT_INVENTORY_VERSION,
        domain=GIT_INVENTORY_DOMAIN,
        key=trust["keys"]["sourceGitInventory"],
        key_id=trust["keyIds"]["sourceGitInventory"],
        key_file_sha256=trust["keyFileSha256s"]["sourceGitInventory"],
        raw_key_sha256=trust["rawKeySha256s"]["sourceGitInventory"],
        label="signed Git inventory",
    )
    approval, approval_document_sha256 = verify_existing_envelope(
        source["untrackedApproval"],
        api_version=UNTRACKED_APPROVAL_VERSION,
        domain=UNTRACKED_APPROVAL_DOMAIN,
        key=trust["keys"]["sourceUntrackedApproval"],
        key_id=trust["keyIds"]["sourceUntrackedApproval"],
        key_file_sha256=trust["keyFileSha256s"]["sourceUntrackedApproval"],
        raw_key_sha256=trust["rawKeySha256s"]["sourceUntrackedApproval"],
        label="signed untracked-source approval",
    )
    require(source["gitInventoryPayloadSha256"] == source["gitInventory"]["payloadSha256"], "Git inventory binding mismatch")
    require(source["untrackedApprovalPayloadSha256"] == source["untrackedApproval"]["payloadSha256"], "untracked approval binding mismatch")
    git = exact_keys(
        git,
        {
            "headTree",
            "indexEntries",
            "indexEntriesSha256",
            "indexInventoryRawSha256",
            "indexTree",
            "objectFormat",
            "rawEvidence",
            "repositoryIdSha256",
            "status",
            "treeEntries",
            "treeEntriesSha256",
            "worktreeEntries",
            "worktreeEntriesSha256",
        },
        "Git inventory payload",
    )
    object_format = git["objectFormat"]
    object_length = 40 if object_format == "sha1" else 64 if object_format == "sha256" else 0
    require(object_length != 0, "Git object format is unsupported")
    require(
        isinstance(git["headTree"], str)
        and re.fullmatch(rf"{object_format}:[0-9a-f]{{{object_length}}}", git["headTree"]) is not None,
        "Git head tree is invalid",
    )
    require_sha256(git["indexInventoryRawSha256"], "raw Git index inventory digest")
    require_sha256(git["repositoryIdSha256"], "Git repository identity")
    require(git["indexTree"] == git["headTree"], "Git index tree differs from HEAD")
    raw_evidence = exact_keys(git["rawEvidence"], {"index", "status", "tree"}, "raw Git evidence")
    raw_commands = {
        "index": ["git", "ls-files", "--stage", "-z"],
        "tree": ["git", "ls-tree", "-rz", "--full-tree", "HEAD"],
        "status": [
            "git",
            "status",
            "--porcelain=v1",
            "-z",
            "--ignored=matching",
            "--untracked-files=all",
        ],
    }
    raw_git_evidence: dict[str, bytes] = {}
    for name, evidence in raw_evidence.items():
        evidence = exact_keys(evidence, {"bytesBase64", "command", "sha256"}, f"raw Git {name} evidence")
        require(evidence["command"] == raw_commands[name], f"raw Git {name} command mismatch")
        raw_git = strict_b64_decode(evidence["bytesBase64"], f"raw Git {name} bytes", max_bytes=MAX_JSON_BYTES)
        raw_git_evidence[name] = raw_git
        require(evidence["sha256"] == sha256(raw_git), f"raw Git {name} digest mismatch")
        if name == "index":
            require(git["indexInventoryRawSha256"] == sha256(raw_git), "raw Git index inventory digest mismatch")
    index_entries = git["indexEntries"]
    tree_entries = git["treeEntries"]
    worktree_entries = git["worktreeEntries"]
    require(isinstance(index_entries, list) and index_entries, "Git index inventory is empty")
    require(isinstance(tree_entries, list), "Git tree inventory is invalid")
    require(isinstance(worktree_entries, list), "Git worktree inventory is invalid")
    require(git["indexEntriesSha256"] == sha256_json(index_entries), "Git index inventory digest mismatch")
    require(git["treeEntriesSha256"] == sha256_json(tree_entries), "Git tree inventory digest mismatch")
    require(git["worktreeEntriesSha256"] == sha256_json(worktree_entries), "Git worktree inventory digest mismatch")
    indexed: list[str] = []
    for entry in index_entries:
        exact_keys(entry, {"gitMode", "objectId", "path", "stage"}, "Git index entry")
        path = safe_source_path(entry["path"], "Git index path")
        require(entry["gitMode"] in {"100644", "100755", "120000"} and entry["stage"] == 0, "Git index mode/stage is invalid")
        require(
            isinstance(entry["objectId"], str)
            and re.fullmatch(rf"{object_format}:[0-9a-f]{{{object_length}}}", entry["objectId"]) is not None,
            "Git object identity is invalid",
        )
        indexed.append(path)
    require(indexed == sorted(set(indexed)), "Git index inventory is not sorted and unique")
    raw_index_records = raw_git_evidence["index"].split(b"\x00")
    require(
        raw_index_records[-1] == b"",
        "raw git ls-files output is not NUL terminated",
    )
    parsed_index: list[dict[str, Any]] = []
    for raw_record in raw_index_records[:-1]:
        try:
            metadata, raw_path = raw_record.split(b"\t", 1)
            mode, object_id, stage = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
            stage_value = int(stage, 10)
        except (UnicodeDecodeError, ValueError) as exc:
            raise VerificationError(
                "raw git ls-files record is malformed"
            ) from exc
        safe_source_path(path, "raw git index path")
        require(
            mode in {"100644", "100755", "120000"}
            and re.fullmatch(rf"[0-9a-f]{{{object_length}}}", object_id)
            and stage_value == 0,
            "raw git ls-files mode, object, or stage is invalid",
        )
        parsed_index.append(
            {
                "gitMode": mode,
                "objectId": f"{object_format}:{object_id}",
                "path": path,
                "stage": stage_value,
            }
        )
    require(
        parsed_index == index_entries,
        "structured Git index inventory differs from raw git ls-files",
    )
    require(
        reconstruct_git_index_tree(index_entries, object_format=object_format)
        == git["indexTree"],
        "Git indexTree is not the tree reconstructed from the signed stage-0 index",
    )
    projected_tree = [
        {
            "gitMode": entry["gitMode"],
            "objectId": entry["objectId"],
            "objectType": "blob",
            "path": entry["path"],
        }
        for entry in index_entries
    ]
    require(tree_entries == projected_tree, "Git recursive tree does not equal the complete index")
    raw_tree_records = raw_git_evidence["tree"].split(b"\x00")
    require(
        raw_tree_records[-1] == b"",
        "raw git ls-tree output is not NUL terminated",
    )
    parsed_tree: list[dict[str, Any]] = []
    for raw_record in raw_tree_records[:-1]:
        try:
            metadata, raw_path = raw_record.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split(" ")
            path = raw_path.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise VerificationError(
                "raw git ls-tree record is malformed"
            ) from exc
        safe_source_path(path, "raw git tree path")
        require(
            mode in {"100644", "100755", "120000"}
            and object_type == "blob"
            and re.fullmatch(rf"[0-9a-f]{{{object_length}}}", object_id),
            "raw git ls-tree mode, type, or object is invalid",
        )
        parsed_tree.append(
            {
                "gitMode": mode,
                "objectId": f"{object_format}:{object_id}",
                "objectType": object_type,
                "path": path,
            }
        )
    require(
        parsed_tree == tree_entries,
        "structured Git tree inventory differs from raw git ls-tree",
    )
    indexed_by_path = {entry["path"]: entry for entry in index_entries}
    worktree_paths: list[str] = []
    worktree_by_path: dict[str, dict[str, Any]] = {}
    for entry in worktree_entries:
        require(isinstance(entry, dict), "Git worktree entry is invalid")
        path = safe_source_path(entry.get("path"), "Git worktree path")
        indexed_entry = indexed_by_path.get(path)
        require(indexed_entry is not None, "Git worktree names a non-indexed path")
        common = {
            "classification",
            "gitMode",
            "indexObjectId",
            "mode",
            "path",
            "type",
            "worktreeObjectId",
        }
        if entry.get("type") == "file":
            exact_keys(entry, common | {"sha256", "size"}, "Git worktree file")
            require_uint(entry["size"], "Git worktree file size", maximum=8 * 1024 * 1024 * 1024)
            require_sha256(entry["sha256"], "Git worktree file digest")
        elif entry.get("type") == "symlink":
            exact_keys(entry, common | {"target"}, "Git worktree symlink")
            require(isinstance(entry["target"], str), "Git worktree symlink target is invalid")
        else:
            raise VerificationError("Git worktree entry type is unsupported")
        require(
            entry["classification"] in {"source", "build-input"}
            and entry["gitMode"] == indexed_entry["gitMode"]
            and entry["indexObjectId"] == indexed_entry["objectId"],
            "Git worktree provenance mismatch",
        )
        worktree_paths.append(path)
        worktree_by_path[path] = entry
    require(worktree_paths == indexed, "Git worktree does not equal the complete index")
    status = exact_keys(
        git["status"],
        {
            "ignoredPaths",
            "ignoredPathsSha256",
            "policy",
            "trackedChanges",
            "trackedChangesSha256",
            "untrackedPaths",
            "untrackedPathsSha256",
        },
        "Git status inventory",
    )
    require(status["policy"] == "git-status-v1-z-complete-with-ignored-separate/v2", "Git status policy mismatch")
    raw_status_records = raw_git_evidence["status"].split(b"\x00")
    require(
        raw_status_records[-1] == b"",
        "raw git status output is not NUL terminated",
    )
    parsed_ignored: list[str] = []
    parsed_untracked: list[str] = []
    parsed_changes: list[dict[str, str]] = []
    for raw_record in raw_status_records[:-1]:
        require(
            len(raw_record) >= 4 and raw_record[2:3] == b" ",
            "raw git status record is malformed",
        )
        try:
            status_code = raw_record[:2].decode("ascii")
            path = raw_record[3:].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VerificationError("raw git status record is not UTF-8") from exc
        safe_source_path(path, "raw git status path")
        if status_code == "!!":
            parsed_ignored.append(path)
        elif status_code == "??":
            parsed_untracked.append(path)
        elif (
            re.fullmatch(r"[ MADU?!]{2}", status_code)
            and "R" not in status_code
            and "C" not in status_code
        ):
            parsed_changes.append({"path": path, "status": status_code})
        else:
            raise VerificationError(
                "raw git status contains rename, copy, conflict, or unknown status"
            )
    parsed_status = {
        "ignoredPaths": sorted(parsed_ignored),
        "ignoredPathsSha256": sha256_json(sorted(parsed_ignored)),
        "policy": "git-status-v1-z-complete-with-ignored-separate/v2",
        "trackedChanges": sorted(
            parsed_changes, key=lambda item: item["path"]
        ),
        "trackedChangesSha256": sha256_json(
            sorted(parsed_changes, key=lambda item: item["path"])
        ),
        "untrackedPaths": sorted(parsed_untracked),
        "untrackedPathsSha256": sha256_json(sorted(parsed_untracked)),
    }
    require(
        len(parsed_ignored) == len(set(parsed_ignored))
        and len(parsed_untracked) == len(set(parsed_untracked))
        and len(parsed_changes)
        == len({item["path"] for item in parsed_changes})
        and parsed_status == status,
        "structured Git status inventory differs from raw git status",
    )
    for field, digest_field in (
        ("ignoredPaths", "ignoredPathsSha256"),
        ("untrackedPaths", "untrackedPathsSha256"),
        ("trackedChanges", "trackedChangesSha256"),
    ):
        require(isinstance(status[field], list), f"Git status {field} is invalid")
        require(status[digest_field] == sha256_json(status[field]), f"Git status {field} digest mismatch")
    tracked = source["trackedPaths"]
    untracked = source["requiredUntrackedPaths"]
    require(
        isinstance(tracked, list)
        and isinstance(untracked, list)
        and tracked == sorted(set(tracked))
        and untracked == sorted(set(untracked))
        and not set(tracked) & set(untracked),
        "source path inventories are invalid",
    )
    require(tracked == indexed, "tracked source paths differ from the signed Git index")
    require(set(untracked) <= set(status["untrackedPaths"]), "required untracked source is absent from signed status")
    require(not set(untracked) & set(status["ignoredPaths"]), "ignored source input is forbidden")
    for path in [*tracked, *untracked]:
        safe_source_path(path, "selected source path")
    require(source["trackedInventorySha256"] == sha256_json(tracked), "tracked source inventory digest mismatch")
    require(source["requiredUntrackedInventorySha256"] == sha256_json(untracked), "untracked source inventory digest mismatch")
    selected = sorted([*tracked, *untracked])
    require(source["pathListSha256"] == sha256_json(selected), "source path-list digest mismatch")
    approval = exact_keys(
        approval,
        {
            "challengeSha256",
            "decision",
            "entries",
            "gitInventoryPayloadSha256",
            "pathListSha256",
        },
        "untracked-source approval payload",
    )
    require(approval["decision"] == "approve-exact-required-untracked-for-source-freeze", "untracked source was not exactly approved")
    require_sha256(approval["challengeSha256"], "untracked approval challenge")
    require(approval["gitInventoryPayloadSha256"] == source["gitInventoryPayloadSha256"], "untracked approval crossed Git inventory")
    require(isinstance(approval["entries"], list), "untracked approval entries are invalid")
    approved_paths = [
        safe_source_path(item.get("path"), "approved untracked path")
        for item in approval["entries"]
        if isinstance(item, dict)
    ]
    require(approved_paths == untracked, "untracked approval is not exact")
    require(approval["pathListSha256"] == sha256_json(untracked), "untracked approval path digest mismatch")
    entries = source["entries"]
    require(isinstance(entries, list), "source entries are invalid")
    seen: list[str] = []
    aggregate = 0
    file_count = 0
    symlink_count = 0
    untracked_entries: list[dict[str, Any]] = []
    for entry in entries:
        path, normalized = validate_source_entry(entry, label="source entry")
        expected_provenance = "tracked" if path in set(tracked) else "required-untracked"
        require(
            normalized["provenance"] == expected_provenance,
            "source entry provenance mismatch",
        )
        if expected_provenance == "tracked":
            signed = worktree_by_path[path]
            expected = {
                key: value
                for key, value in signed.items()
                if key not in {"gitMode", "indexObjectId", "worktreeObjectId"}
            }
            expected["provenance"] = "tracked"
            require(normalized == expected, "tracked source differs from signed worktree evidence")
        else:
            untracked_entries.append(normalized)
        seen.append(path)
        if normalized["type"] == "file":
            aggregate += normalized["size"]
            file_count += 1
        else:
            symlink_count += 1
    require(seen == selected, "source entries do not equal selected paths in canonical order")
    require(source["entryCount"] == len(entries), "source entry count mismatch")
    require(source["fileCount"] == file_count, "source file count mismatch")
    require(source["symlinkCount"] == symlink_count, "source symlink count mismatch")
    require(source["aggregateBytes"] == aggregate, "source aggregate byte count mismatch")
    require(approval["entries"] == untracked_entries, "approved untracked source identities differ")
    git_signature = exact_keys(
        source["gitInventory"]["signature"],
        {"algorithm", "domain", "keyFileSha256", "rawKeySha256", "value"},
        "signed Git inventory signature",
    )
    approval_signature = exact_keys(
        source["untrackedApproval"]["signature"],
        {"algorithm", "domain", "keyFileSha256", "rawKeySha256", "value"},
        "signed untracked approval signature",
    )
    source_evidence = exact_keys(
        source["sourceEvidence"],
        {"apiVersion", "gitInventory", "identitySha256", "untrackedApproval"},
        "source evidence identity",
    )
    git_evidence = {
        "envelopeSha256": sha256(canonical_json_bytes(source["gitInventory"])),
        "headTree": git["headTree"],
        "indexEntriesSha256": git["indexEntriesSha256"],
        "indexRawSha256": git["indexInventoryRawSha256"],
        "indexTree": git["indexTree"],
        "keyRawSha256": trust["rawKeySha256s"]["sourceGitInventory"],
        "keySpkiSha256": trust["keyIds"]["sourceGitInventory"],
        "payloadSha256": source["gitInventoryPayloadSha256"],
        "signatureSha256": sha256(
            strict_b64_decode(
                git_signature["value"],
                "Git source evidence signature",
                max_bytes=64,
            )
        ),
        "statusRawSha256": git["rawEvidence"]["status"]["sha256"],
        "treeEntriesSha256": git["treeEntriesSha256"],
        "treeRawSha256": git["rawEvidence"]["tree"]["sha256"],
        "worktreeEntriesSha256": git["worktreeEntriesSha256"],
    }
    approval_evidence = {
        "challengeSha256": approval["challengeSha256"],
        "envelopeSha256": sha256(
            canonical_json_bytes(source["untrackedApproval"])
        ),
        "keyRawSha256": trust["rawKeySha256s"]["sourceUntrackedApproval"],
        "keySpkiSha256": trust["keyIds"]["sourceUntrackedApproval"],
        "pathListSha256": approval["pathListSha256"],
        "payloadSha256": source["untrackedApprovalPayloadSha256"],
        "signatureSha256": sha256(
            strict_b64_decode(
                approval_signature["value"],
                "untracked source evidence signature",
                max_bytes=64,
            )
        ),
    }
    source_evidence_payload = {
        "apiVersion": "serverware.sourceEvidenceIdentity/v1",
        "gitInventory": git_evidence,
        "untrackedApproval": approval_evidence,
    }
    source_evidence_digest = sha256_json(source_evidence_payload)
    require(
        source_evidence
        == {**source_evidence_payload, "identitySha256": source_evidence_digest}
        and source["sourceEvidenceSha256"] == source_evidence_digest,
        "source evidence identity does not match the directly verified envelopes",
    )
    return {
        "fileSha256": sha256(raw),
        "payloadSha256": payload_digest,
        "pathListSha256": source["pathListSha256"],
        "trackedInventorySha256": source["trackedInventorySha256"],
        "requiredUntrackedInventorySha256": source[
            "requiredUntrackedInventorySha256"
        ],
        "gitInventoryPayloadSha256": source["gitInventoryPayloadSha256"],
        "gitInventoryDocumentSha256": git_document_sha256,
        "untrackedApprovalPayloadSha256": source["untrackedApprovalPayloadSha256"],
        "untrackedApprovalDocumentSha256": approval_document_sha256,
        "sourceEvidence": source_evidence,
        "sourceEvidenceSha256": source_evidence_digest,
        "entries": entries,
    }


def validate_digest_document(value: Any, *, api_version: str, digest_field: str, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(value.get("apiVersion") == api_version, f"{label} apiVersion mismatch")
    supplied = require_sha256(value.get(digest_field), f"{label} digest")
    payload = {key: item for key, item in value.items() if key != digest_field}
    require(supplied == sha256_json(payload), f"{label} digest mismatch")
    return value


def validate_candidate_image(value: Any, role: str) -> dict[str, Any]:
    required = {
        "archive",
        "build",
        "capabilityAttestation",
        "capabilityCatalog",
        "capabilityCatalogSha256",
        "configDigest",
        "dependencyClosureSha256",
        "dependencyFileManifestSha256",
        "dependencyPackageInventorySha256",
        "dependencyRole",
        "executableInventorySha256",
        "fileManifest",
        "fixedToolIdentities",
        "indexDigest",
        "layerDigests",
        "manifestDigest",
        "platform",
        "role",
        "rootfsDiffIds",
        "rootfsDigest",
        "sbom",
        "semanticContract",
    }
    value = exact_keys(value, required, f"{role} candidate image")
    require(value["role"] == role, f"{role} candidate role mismatch")
    require(value["platform"] == {"architecture": "amd64", "os": "linux"}, f"{role} platform mismatch")
    archive = exact_keys(
        value["archive"],
        {"path", "sha256", "size"},
        f"{role} archive identity",
    )
    require(isinstance(archive["path"], str) and archive["path"], f"{role} archive path is invalid")
    require_sha256(archive["sha256"], f"{role} archive digest")
    require_uint(archive["size"], f"{role} archive size", maximum=16 * 1024 * 1024 * 1024)
    require(archive["size"] > 0, f"{role} archive is empty")
    for field in (
        "capabilityCatalogSha256",
        "configDigest",
        "dependencyClosureSha256",
        "dependencyFileManifestSha256",
        "dependencyPackageInventorySha256",
        "executableInventorySha256",
        "indexDigest",
        "manifestDigest",
        "rootfsDigest",
    ):
        require_sha256(value[field], f"{role} {field}")
    for field in ("fileManifest", "sbom"):
        record = exact_keys(value[field], {"path", "sha256"}, f"{role} {field}")
        require(isinstance(record["path"], str) and record["path"], f"{role} {field} path is invalid")
        require_sha256(record["sha256"], f"{role} {field} digest")
    for field in ("layerDigests", "rootfsDiffIds"):
        items = value[field]
        require(
            isinstance(items, list)
            and items
            and items == list(dict.fromkeys(items))
            and all(isinstance(item, str) and IMAGE_RE.fullmatch(item) for item in items),
            f"{role} {field} is invalid",
        )
    require(isinstance(value["build"], dict), f"{role} build identity is invalid")
    catalog = value["capabilityCatalog"]
    require(isinstance(catalog, dict), f"{role} capability catalog is invalid")
    catalog_payload = dict(catalog)
    catalog_digest = catalog_payload.pop("catalogSha256", None)
    require(
        catalog.get("apiVersion") == "serverware.dependencyCapabilityCatalog/v2"
        and catalog_digest == value["capabilityCatalogSha256"]
        and catalog_digest == sha256_json(catalog_payload),
        f"{role} capability catalog digest mismatch",
    )
    capability = exact_keys(
        value["capabilityAttestation"],
        {"apiVersion", "payload", "payloadSha256", "signature"},
        f"{role} capability attestation",
    )
    require(
        capability["apiVersion"]
        == "serverware.dependencyCapabilityAttestation/v1"
        and isinstance(capability["payload"], dict)
        and capability["payloadSha256"] == sha256_json(capability["payload"]),
        f"{role} capability attestation is invalid",
    )
    capability_signature = exact_keys(
        capability["signature"],
        {"algorithm", "domain", "keyFileSha256", "rawKeySha256", "value"},
        f"{role} capability signature",
    )
    require(
        capability_signature["algorithm"] == "Ed25519"
        and capability_signature["domain"]
        == "serverware.dependencyCapabilityAttestation/v1\x00Ed25519",
        f"{role} capability signature metadata is invalid",
    )
    require_sha256(capability_signature["keyFileSha256"], f"{role} capability key file")
    require_sha256(capability_signature["rawKeySha256"], f"{role} capability raw key")
    require(
        len(
            strict_b64_decode(
                capability_signature["value"],
                f"{role} capability signature",
                max_bytes=64,
            )
        )
        == 64,
        f"{role} capability signature length is invalid",
    )
    require_identifier(value["dependencyRole"], f"{role} dependency role")
    if role == "npm-publish-companion":
        tools = exact_keys(
            value["fixedToolIdentities"],
            {"node", "npmEntrypoint", "npmPackageManifest"},
            "npm fixed tool identities",
        )
        for name, tool in tools.items():
            tool = exact_keys(tool, {"path", "sha256", "size"}, f"npm {name}")
            require(
                isinstance(tool["path"], str)
                and tool["path"].startswith("/")
                and require_uint(tool["size"], f"npm {name} size") > 0,
                f"npm {name} identity is invalid",
            )
            require_sha256(tool["sha256"], f"npm {name} digest")
    else:
        require(value["fixedToolIdentities"] is None, f"{role} fixed tools are forbidden")
    return value


def verify_candidate(
    candidate: dict[str, Any],
    raw: bytes,
    *,
    source: dict[str, Any],
    source_raw: bytes,
) -> dict[str, Any]:
    candidate = exact_keys(
        candidate,
        {
            "apiVersion",
            "buildContinuity",
            "candidateManifestPayloadSha256",
            "companions",
            "images",
            "laneOrder",
            "lanes",
            "promotionContract",
            "sourceSnapshot",
        },
        "Candidate Manifest v6",
    )
    require(candidate["apiVersion"] == CANDIDATE_VERSION, "Candidate Manifest apiVersion mismatch")
    require(candidate["laneOrder"] == list(LANE_ORDER), "Candidate Manifest lane order mismatch")
    require(isinstance(candidate["lanes"], dict) and list(candidate["lanes"]) == list(LANE_ORDER), "Candidate Manifest lane inventory mismatch")
    require(isinstance(candidate["images"], dict) and list(candidate["images"]) == list(IMAGE_ORDER), "Candidate Manifest image inventory mismatch")
    payload = {key: value for key, value in candidate.items() if key != "candidateManifestPayloadSha256"}
    payload_digest = sha256_json(payload)
    require(candidate["candidateManifestPayloadSha256"] == payload_digest, "Candidate Manifest payload digest mismatch")
    images = {
        role: validate_candidate_image(candidate["images"][role], role)
        for role in IMAGE_ORDER
    }
    continuity = exact_keys(
        candidate["buildContinuity"],
        {
            "buildBundle",
            "buildPlan",
            "buildWatchdogReceipt",
            "dependencyBundle",
            "sourceSnapshot",
        },
        "Candidate Manifest build continuity",
    )
    watchdog_binding = exact_keys(
        continuity["buildWatchdogReceipt"],
        {"document", "receiptFileSha256", "resources"},
        "Candidate build-watchdog binding",
    )
    require(isinstance(watchdog_binding["document"], dict), "Candidate build-watchdog document is invalid")
    require_sha256(
        watchdog_binding["receiptFileSha256"],
        "Candidate build-watchdog receipt file",
    )
    require(isinstance(watchdog_binding["resources"], list), "Candidate build-watchdog resources are invalid")
    plan = continuity["buildPlan"]
    exact_keys(
        plan,
        {
            "apiVersion",
            "buildWatchdogContract",
            "dependencyBundle",
            "export",
            "imageOrder",
            "lanes",
            "npmCompanion",
            "planSha256",
            "securityProfiles",
            "sourceSnapshot",
        },
        "Candidate build plan",
    )
    validate_digest_document(
        plan,
        api_version=BUILD_PLAN_VERSION,
        digest_field="planSha256",
        label="Candidate build plan",
    )
    require(plan.get("imageOrder") == list(IMAGE_ORDER), "Candidate build-plan image order mismatch")
    require(isinstance(plan.get("lanes"), dict) and list(plan["lanes"]) == list(LANE_ORDER), "Candidate build-plan lane inventory mismatch")
    source_snapshot = plan.get("sourceSnapshot")
    require(isinstance(source_snapshot, dict), "Candidate source snapshot is invalid")
    source_manifest = source_snapshot.get("sourceManifest")
    require(isinstance(source_manifest, dict), "Candidate source manifest is missing")
    require(source_manifest.get("apiVersion") == SOURCE_SNAPSHOT_VERSION, "Candidate source snapshot version mismatch")
    snapshot_entries = source_manifest.get("entries")
    require(isinstance(snapshot_entries, list), "Candidate source snapshot entries are invalid")
    expected_content = [
        {
            key: value
            for key, value in entry.items()
            if key not in {"classification", "provenance"}
        }
        for entry in source["entries"]
    ]
    expected_directories: set[str] = set()
    for entry in source["entries"]:
        parts = PurePosixPath(entry["path"]).parts
        for end in range(1, len(parts)):
            expected_directories.add(PurePosixPath(*parts[:end]).as_posix())
    expected_snapshot_entries = [
        {"mode": 0o500, "path": path, "type": "directory"}
        for path in expected_directories
    ] + expected_content
    expected_snapshot_entries.sort(
        key=lambda item: (
            len(PurePosixPath(item["path"]).parts),
            item["path"],
            item["type"],
        )
    )
    require(
        snapshot_entries == expected_snapshot_entries,
        "Candidate source closure contains missing, extra, or changed entries",
    )
    closure_payload = {
        "aggregateBytes": source_manifest.get("aggregateBytes"),
        "entries": snapshot_entries,
        "entryCount": source_manifest.get("entryCount"),
        "fileCount": source_manifest.get("fileCount"),
        "symlinkCount": source_manifest.get("symlinkCount"),
    }
    closure_digest = sha256_json(closure_payload)
    require(source_manifest.get("closureSha256") == closure_digest, "source closure digest mismatch")
    require(
        source_manifest.get("aggregateBytes") == source["aggregateBytes"]
        and source_manifest.get("entryCount") == len(snapshot_entries)
        and source_manifest.get("fileCount") == source["fileCount"]
        and source_manifest.get("symlinkCount") == source["symlinkCount"],
        "Candidate source closure counts differ from signed source selection",
    )
    require(source_snapshot.get("sourceClosureSha256") == closure_digest, "build plan source closure mismatch")
    require(source_snapshot.get("sourceFileInventorySha256") == sha256_json(source_manifest.get("entries")), "source file inventory digest mismatch")
    require(source_snapshot.get("sourceManifestPayloadSha256") == sha256_json(source_manifest), "source manifest payload digest mismatch")
    require(
        source_snapshot.get("sourceManifestFileSha256")
        == sha256(canonical_json_bytes(source_manifest) + b"\n"),
        "source manifest file digest mismatch",
    )
    require(source_manifest.get("selection") == source, "source snapshot selection differs from signed source input")
    require(source_manifest.get("selectionManifestFileSha256") == sha256(source_raw), "source snapshot input-file digest mismatch")
    require(source_manifest.get("selectionManifestPayloadSha256") == source["payloadSha256"], "source snapshot input payload mismatch")
    require(source_snapshot.get("sourceSelectionManifestFileSha256") == sha256(source_raw), "build-plan source-selection file mismatch")
    require(source_snapshot.get("sourceSelectionManifestPayloadSha256") == source["payloadSha256"], "build-plan source-selection payload mismatch")
    require(source_snapshot.get("sourcePathListSha256") == source["pathListSha256"], "build-plan source path-list mismatch")
    require(source_snapshot.get("sourceGitInventoryPayloadSha256") == source["gitInventoryPayloadSha256"], "build-plan Git inventory mismatch")
    require(source_snapshot.get("sourceUntrackedApprovalPayloadSha256") == source["untrackedApprovalPayloadSha256"], "build-plan untracked approval mismatch")
    require(
        source_snapshot.get("sourceEvidence") == source["sourceEvidence"]
        and source_snapshot.get("sourceEvidenceSha256")
        == source["sourceEvidenceSha256"],
        "build-plan source evidence identity mismatch",
    )
    require(source_snapshot.get("sourceSelectionModel") == SOURCE_SELECTION_MODEL, "build-plan source model mismatch")
    require(continuity["sourceSnapshot"] == source_snapshot, "Candidate continuity source snapshot mismatch")
    require(candidate["sourceSnapshot"] == source_snapshot, "Candidate top-level source snapshot mismatch")
    dependency = continuity["dependencyBundle"]
    require(isinstance(dependency, dict), "Candidate dependency bundle is invalid")
    validate_digest_document(
        dependency,
        api_version=DEPENDENCY_BUNDLE_VERSION,
        digest_field="manifestSha256",
        label="Candidate dependency bundle",
    )
    require(plan.get("dependencyBundle") == dependency, "Candidate build plan crossed dependency bundle")
    bundles = dependency.get("bundles")
    require(isinstance(bundles, dict) and bundles, "Candidate dependency role inventory is invalid")
    role_closures: dict[str, str] = {}
    for role, bundle_record in bundles.items():
        require_identifier(role, "dependency role")
        require(isinstance(bundle_record, dict), f"{role} dependency closure is invalid")
        closure = require_sha256(bundle_record.get("closureSha256"), f"{role} dependency closure")
        closure_payload = {
            "baseImageDigest": bundle_record.get("baseImageDigest"),
            "capabilities": bundle_record.get("capabilities"),
            "files": bundle_record.get("files"),
            "packages": bundle_record.get("packages"),
        }
        require(closure == sha256_json(closure_payload), f"{role} dependency closure digest mismatch")
        role_closures[role] = closure
    bundle = continuity["buildBundle"]
    exact_keys(
        bundle,
        {
            "apiVersion",
            "buildLeaseId",
            "bundleSha256",
            "candidateRequestSha256",
            "images",
            "planSha256",
        },
        "Candidate OCI build bundle",
    )
    validate_digest_document(
        bundle,
        api_version=BUILD_BUNDLE_VERSION,
        digest_field="bundleSha256",
        label="Candidate OCI build bundle",
    )
    require(bundle.get("planSha256") == plan["planSha256"], "Candidate build bundle crossed build plan")
    promotion_contract = candidate["promotionContract"]
    require(isinstance(promotion_contract, dict), "Candidate promotion contract is invalid")
    require(promotion_contract.get("apiVersion") == "serverware.verificationPromotionContract/v6", "promotion contract version mismatch")
    contract_payload = {
        key: value for key, value in promotion_contract.items() if key != "contractSha256"
    }
    require(promotion_contract.get("contractSha256") == sha256_json(contract_payload), "promotion contract digest mismatch")
    candidate_without_promotion = {
        key: value
        for key, value in candidate.items()
        if key not in {"candidateManifestPayloadSha256", "promotionContract"}
    }
    require(
        promotion_contract.get("candidatePayloadSha256")
        == sha256_json(candidate_without_promotion),
        "promotion contract candidate payload mismatch",
    )
    mappings = promotion_contract.get("imageMappings")
    require(isinstance(mappings, list) and [item.get("role") for item in mappings if isinstance(item, dict)] == list(IMAGE_ORDER), "promotion contract image mapping inventory mismatch")
    for mapping in mappings:
        role = mapping["role"]
        required_candidate = {
            "archiveSha256": images[role]["archive"]["sha256"],
            "archiveSize": images[role]["archive"]["size"],
            "capabilityAttestation": images[role]["capabilityAttestation"],
            "capabilityCatalog": images[role]["capabilityCatalog"],
            "capabilityCatalogSha256": images[role]["capabilityCatalogSha256"],
            "configDigest": images[role]["configDigest"],
            "dependencyClosureSha256": images[role]["dependencyClosureSha256"],
            "dependencyFileManifestSha256": images[role]["dependencyFileManifestSha256"],
            "dependencyPackageInventorySha256": images[role]["dependencyPackageInventorySha256"],
            "dependencyRole": images[role]["dependencyRole"],
            "executableInventorySha256": images[role]["executableInventorySha256"],
            "fileManifestSha256": images[role]["fileManifest"]["sha256"],
            "fixedToolIdentities": images[role]["fixedToolIdentities"],
            "indexDigest": images[role]["indexDigest"],
            "layerDigests": images[role]["layerDigests"],
            "manifestDigest": images[role]["manifestDigest"],
            "rootfsDiffIds": images[role]["rootfsDiffIds"],
            "rootfsDigest": images[role]["rootfsDigest"],
            "sbomSha256": images[role]["sbom"]["sha256"],
            "semanticContract": images[role]["semanticContract"],
        }
        require(mapping.get("candidate") == required_candidate, f"{role} promotion candidate mapping mismatch")
    return {
        "fileSha256": sha256(raw),
        "payloadSha256": payload_digest,
        "sourceClosureSha256": closure_digest,
        "sourceSnapshot": source_snapshot,
        "buildPlanSha256": plan["planSha256"],
        "buildBundleSha256": bundle["bundleSha256"],
        "dependencyBundleSha256": dependency["manifestSha256"],
        "dependencyClosureSha256": sha256_json(role_closures),
        "dependencyManifestFileSha256": sha256(
            canonical_json_bytes(dependency) + b"\n"
        ),
        "dependencyRoleClosuresSha256": sha256_json(role_closures),
        "dependencyRoleClosures": role_closures,
        "promotionContractSha256": promotion_contract["contractSha256"],
        "images": images,
        "watchdogBinding": watchdog_binding,
        "candidateImagesSha256": sha256_json(
            {
                role: {
                    "archiveSha256": images[role]["archive"]["sha256"],
                    "archiveSize": images[role]["archive"]["size"],
                    "capabilityAttestation": images[role]["capabilityAttestation"],
                    "capabilityCatalog": images[role]["capabilityCatalog"],
                    "capabilityCatalogSha256": images[role]["capabilityCatalogSha256"],
                    "configDigest": images[role]["configDigest"],
                    "dependencyClosureSha256": images[role]["dependencyClosureSha256"],
                    "dependencyFileManifestSha256": images[role]["dependencyFileManifestSha256"],
                    "dependencyPackageInventorySha256": images[role]["dependencyPackageInventorySha256"],
                    "dependencyRole": images[role]["dependencyRole"],
                    "executableInventorySha256": images[role]["executableInventorySha256"],
                    "fileManifestSha256": images[role]["fileManifest"]["sha256"],
                    "fixedToolIdentities": images[role]["fixedToolIdentities"],
                    "indexDigest": images[role]["indexDigest"],
                    "layerDigests": images[role]["layerDigests"],
                    "manifestDigest": images[role]["manifestDigest"],
                    "rootfsDiffIds": images[role]["rootfsDiffIds"],
                    "rootfsDigest": images[role]["rootfsDigest"],
                    "sbomSha256": images[role]["sbom"]["sha256"],
                    "semanticContract": images[role]["semanticContract"],
                }
                for role in IMAGE_ORDER
            }
        ),
        "buildContinuity": continuity,
        "promotionContract": promotion_contract,
    }


def verify_event_chain(events: Any, *, label: str, maximum: int = MAX_TRANSCRIPT_EVENTS) -> str:
    require(isinstance(events, list) and 1 <= len(events) <= maximum, f"{label} events are invalid")
    previous = sha256(b"")
    for sequence, record in enumerate(events, start=1):
        record = exact_keys(
            record,
            {"event", "eventSha256", "previousEventSha256", "sequence"},
            f"{label} event",
        )
        require(
            require_uint(
                record["sequence"], f"{label} event sequence"
            )
            == sequence,
            f"{label} event sequence mismatch",
        )
        require(record["previousEventSha256"] == previous, f"{label} event chain mismatch")
        require(isinstance(record["event"], dict), f"{label} event payload is invalid")
        measured = sha256_json(
            {
                "event": record["event"],
                "previousEventSha256": previous,
                "sequence": sequence,
            }
        )
        require(record["eventSha256"] == measured, f"{label} event digest mismatch")
        previous = measured
    return previous


def verify_build_watchdog(
    document: dict[str, Any],
    raw: bytes,
    *,
    candidate: dict[str, Any],
    trust: dict[str, Any],
) -> dict[str, Any]:
    payload, measured_file = verify_existing_envelope(
        document,
        api_version=BUILD_WATCHDOG_VERSION,
        domain=BUILD_WATCHDOG_DOMAIN,
        key=trust["keys"]["buildWatchdog"],
        key_id=trust["keyIds"]["buildWatchdog"],
        key_file_sha256=trust["keyFileSha256s"]["buildWatchdog"],
        raw_key_sha256=trust["rawKeySha256s"]["buildWatchdog"],
        label="build-watchdog receipt",
    )
    require(measured_file == sha256(raw), "build-watchdog receipt canonical file digest mismatch")
    require(
        candidate["watchdogBinding"]["document"] == document
        and candidate["watchdogBinding"]["receiptFileSha256"] == sha256(raw),
        "Candidate Manifest does not bind the exact build-watchdog receipt",
    )
    payload = exact_keys(
        payload,
        {
            "bootId",
            "buildBundleSha256",
            "candidateRequest",
            "candidateRequestSha256",
            "daemonIdentity",
            "daemonIdentitySha256",
            "eventHeadSha256",
            "events",
            "lease",
            "planSha256",
            "request",
            "requestSha256",
            "serviceIdentity",
            "serviceIdentitySha256",
        },
        "build-watchdog payload",
    )
    require(isinstance(payload["bootId"], str) and UUID_RE.fullmatch(payload["bootId"]), "build-watchdog boot ID is invalid")
    require(payload["buildBundleSha256"] == candidate["buildBundleSha256"], "build-watchdog crossed build bundle")
    require(payload["planSha256"] == candidate["buildPlanSha256"], "build-watchdog crossed build plan")
    require(payload["candidateRequestSha256"] == sha256_json(payload["candidateRequest"]), "build-watchdog candidate request digest mismatch")
    require(payload["requestSha256"] == sha256_json(payload["request"]), "build-watchdog request digest mismatch")
    lease = exact_keys(
        payload["lease"],
        {"capabilitySha256", "challengeSha256", "id"},
        "build-watchdog lease",
    )
    require_identifier(lease["id"], "build-watchdog lease ID")
    require_sha256(lease["capabilitySha256"], "build-watchdog lease capability")
    require_sha256(lease["challengeSha256"], "build-watchdog lease challenge")
    plan = candidate["buildContinuity"]["buildPlan"]
    build_bundle = candidate["buildContinuity"]["buildBundle"]
    source_snapshot = candidate["sourceSnapshot"]
    expected_candidate_request = {
        "dependencyBundleSha256": candidate["dependencyBundleSha256"],
        "imageRoles": list(IMAGE_ORDER),
        "network": "none",
        "outputIdentitiesSha256": sha256_json(
            candidate_image_identities(candidate)
        ),
        "planSha256": candidate["buildPlanSha256"],
        "platform": {"architecture": "amd64", "os": "linux"},
        "sourceClosureSha256": candidate["sourceClosureSha256"],
        "sourceEvidence": source_snapshot["sourceEvidence"],
        "sourceEvidenceSha256": source_snapshot["sourceEvidenceSha256"],
        "sourceGitInventoryPayloadSha256": source_snapshot[
            "sourceGitInventoryPayloadSha256"
        ],
        "sourceManifestFileSha256": source_snapshot[
            "sourceManifestFileSha256"
        ],
        "sourceSelectionManifestFileSha256": source_snapshot[
            "sourceSelectionManifestFileSha256"
        ],
        "sourceSelectionManifestPayloadSha256": source_snapshot[
            "sourceSelectionManifestPayloadSha256"
        ],
        "sourceUntrackedApprovalPayloadSha256": source_snapshot[
            "sourceUntrackedApprovalPayloadSha256"
        ],
    }
    require(
        payload["candidateRequest"] == expected_candidate_request
        and payload["candidateRequestSha256"]
        == sha256_json(expected_candidate_request)
        and build_bundle["candidateRequestSha256"]
        == payload["candidateRequestSha256"],
        "build-watchdog candidate request is not exactly rederived",
    )
    require(payload["request"].get("operation") == "build-all-oci-v3", "build-watchdog operation mismatch")
    watchdog_contract = plan["buildWatchdogContract"]
    expected_request = {
        "buildBundleSha256": candidate["buildBundleSha256"],
        "candidateRequestSha256": payload["candidateRequestSha256"],
        "challengeSha256": lease["challengeSha256"],
        "contractSha256": watchdog_contract["contractSha256"],
        "leaseCapabilitySha256": lease["capabilitySha256"],
        "leaseId": lease["id"],
        "operation": "build-all-oci-v3",
    }
    require(
        payload["request"] == expected_request
        and payload["requestSha256"] == sha256_json(expected_request)
        and lease["id"] == build_bundle["buildLeaseId"],
        "build-watchdog request/lease differs from the fixed v4 contract",
    )
    require(payload["eventHeadSha256"] == verify_event_chain(payload["events"], label="build-watchdog"), "build-watchdog event head mismatch")
    resources: dict[tuple[str, str], dict[str, Any]] = {}
    actions: dict[tuple[str, str], set[str]] = {}
    absence = 0
    absence_records: list[dict[str, Any]] = []
    phase = "initial"
    for record in payload["events"]:
        event = record["event"]
        event_type = event.get("type")
        if event_type == "lease-begin":
            require(phase == "initial", "build-watchdog lease begins out of order")
            require(
                event
                == {
                    "leaseId": lease["id"],
                    "requestSha256": payload["requestSha256"],
                    "type": "lease-begin",
                },
                "build-watchdog lease-begin event mismatch",
            )
            phase = "build"
        elif event_type == "resource-created":
            require(phase == "build", "build-watchdog resource created outside build")
            exact_keys(event, {"resource", "type"}, "build-watchdog resource-created event")
            resource = event.get("resource")
            resource = exact_keys(
                resource,
                {"id", "kind", "labels", "name", "role"},
                "build-watchdog resource",
            )
            require(resource.get("kind") != "network", "network resource exists in a network-none build")
            key = (str(resource.get("kind")), str(resource.get("id")))
            require(key not in resources, "build-watchdog resource identity is duplicated")
            require(resource.get("role") in IMAGE_ORDER, "build-watchdog resource role is invalid")
            require_identifier(resource["id"], "build-watchdog resource ID")
            require_identifier(resource["name"], "build-watchdog resource name")
            require(
                resource["kind"]
                in {"builder", "container", "content", "image", "snapshot", "task"},
                "build-watchdog resource kind is invalid",
            )
            require(
                resource["labels"]
                == {
                    "org.serverware.build-lease": lease["id"],
                    "org.serverware.build-plan": candidate["buildPlanSha256"],
                    "org.serverware.image-role": resource["role"],
                    "org.serverware.resource-kind": resource["kind"],
                },
                "build-watchdog resource labels mismatch",
            )
            resources[key] = resource
        elif event_type == "cleanup-started":
            require(phase == "build", "build-watchdog cleanup starts out of order")
            require(
                event == {"leaseId": lease["id"], "type": "cleanup-started"},
                "build-watchdog cleanup-started event mismatch",
            )
            phase = "cleanup"
        elif event_type == "cleanup-action":
            require(phase == "cleanup" and absence == 0, "build-watchdog cleanup action is out of order")
            exact_keys(
                event,
                {"action", "resource", "result", "type"},
                "build-watchdog cleanup event",
            )
            ref = event.get("resource")
            require(isinstance(ref, dict) and set(ref) == {"id", "kind"}, "build-watchdog cleanup reference is invalid")
            key = (str(ref["kind"]), str(ref["id"]))
            require(key in resources, "build-watchdog cleanup references an unknown resource")
            action = event.get("action")
            require(action in {"inspect", "kill", "remove"}, "build-watchdog cleanup action is invalid")
            expected_result = {
                "inspect": "present-or-already-absent",
                "kill": "killed-reaped-or-already-absent",
                "remove": "removed-or-already-absent",
            }[action]
            require(event["result"] == expected_result, "build-watchdog cleanup result mismatch")
            require(action not in actions.setdefault(key, set()), "build-watchdog cleanup action is duplicated")
            actions[key].add(action)
        elif event_type == "daemon-inventory-absence":
            require(phase == "cleanup", "build-watchdog absence inventory is out of order")
            exact_keys(
                event,
                {
                    "absentResources",
                    "labelledAlternates",
                    "ordinal",
                    "presentResources",
                    "type",
                },
                "build-watchdog absence inventory",
            )
            absence += 1
            require(
                require_uint(
                    event.get("ordinal"),
                    "build-watchdog absence ordinal",
                )
                == absence,
                "build-watchdog absence ordinal mismatch",
            )
            require(event.get("presentResources") == [] and event.get("labelledAlternates") == [], "build-watchdog cleanup left resources")
            absence_records.append(event)
        elif event_type == "lease-finished":
            require(phase == "cleanup" and absence == 3, "build-watchdog lease finished before three absence inventories")
            exact_keys(
                event,
                {"eventHeadBeforeFinishSha256", "leaseId", "type"},
                "build-watchdog lease-finished event",
            )
            require(
                event["leaseId"] == lease["id"]
                and event["eventHeadBeforeFinishSha256"]
                == record["previousEventSha256"],
                "build-watchdog lease-finished identity mismatch",
            )
            phase = "terminal"
        else:
            raise VerificationError("build-watchdog contains an unsupported event")
    require(phase == "terminal", "build-watchdog receipt is not terminal")
    for key, resource in resources.items():
        expected_actions = {"inspect", "remove"}
        if resource.get("kind") in {"builder", "container", "task"}:
            expected_actions.add("kill")
        require(actions.get(key) == expected_actions, "build-watchdog resource cleanup is incomplete")
    expected_refs = sorted(
        ({"id": resource["id"], "kind": resource["kind"]} for resource in resources.values()),
        key=lambda item: (item["kind"], item["id"]),
    )
    for ordinal, observation in enumerate(absence_records, start=1):
        require(
            observation
            == {
                "absentResources": expected_refs,
                "labelledAlternates": [],
                "ordinal": ordinal,
                "presentResources": [],
                "type": "daemon-inventory-absence",
            },
            "build-watchdog absence inventory is incomplete",
        )
    for role in IMAGE_ORDER:
        kinds = {resource.get("kind") for resource in resources.values() if resource.get("role") == role}
        require(
            {"builder", "container", "content", "image", "snapshot", "task"} <= kinds,
            f"build-watchdog resource inventory is incomplete for {role}",
        )
    return {
        "fileSha256": sha256(raw),
        "payloadSha256": document["payloadSha256"],
        "eventHeadSha256": payload["eventHeadSha256"],
        "payload": payload,
    }


def validate_imported_image(value: Any, role: str) -> dict[str, Any]:
    required = {
        "capabilityAttestation",
        "capabilityCatalog",
        "capabilityCatalogSha256",
        "configDigest",
        "containerdImageId",
        "dependencyClosureSha256",
        "dependencyFileManifestSha256",
        "dependencyPackageInventorySha256",
        "dependencyRole",
        "executableInventorySha256",
        "fileManifestSha256",
        "fixedToolIdentities",
        "independentInspectionSha256",
        "manifestDigest",
        "platform",
        "role",
        "rootfsDiffIds",
        "rootfsDigest",
        "sbomSha256",
        "semanticContract",
    }
    value = exact_keys(value, required, f"{role} imported image")
    require(value["role"] == role and value["platform"] == {"architecture": "amd64", "os": "linux"}, f"{role} imported image identity mismatch")
    for field in (
        "capabilityCatalogSha256",
        "configDigest",
        "containerdImageId",
        "dependencyClosureSha256",
        "dependencyFileManifestSha256",
        "dependencyPackageInventorySha256",
        "executableInventorySha256",
        "fileManifestSha256",
        "independentInspectionSha256",
        "manifestDigest",
        "rootfsDigest",
        "sbomSha256",
    ):
        require_sha256(value[field], f"{role} imported {field}")
    require(value["containerdImageId"] == value["manifestDigest"], f"{role} containerd image ID mismatch")
    require(
        isinstance(value["rootfsDiffIds"], list)
        and value["rootfsDiffIds"]
        and all(isinstance(item, str) and SHA256_RE.fullmatch(item) for item in value["rootfsDiffIds"]),
        f"{role} imported diff IDs are invalid",
    )
    catalog = value["capabilityCatalog"]
    require(isinstance(catalog, dict), f"{role} imported capability catalog is invalid")
    catalog_payload = dict(catalog)
    require(
        catalog.get("apiVersion") == "serverware.dependencyCapabilityCatalog/v2"
        and catalog_payload.pop("catalogSha256", None)
        == value["capabilityCatalogSha256"]
        and value["capabilityCatalogSha256"] == sha256_json(catalog_payload),
        f"{role} imported capability catalog digest mismatch",
    )
    capability = exact_keys(
        value["capabilityAttestation"],
        {"apiVersion", "payload", "payloadSha256", "signature"},
        f"{role} imported capability attestation",
    )
    require(
        capability["apiVersion"]
        == "serverware.dependencyCapabilityAttestation/v1"
        and isinstance(capability["payload"], dict)
        and capability["payloadSha256"] == sha256_json(capability["payload"]),
        f"{role} imported capability attestation is invalid",
    )
    require_identifier(value["dependencyRole"], f"{role} imported dependency role")
    if role == "npm-publish-companion":
        exact_keys(
            value["fixedToolIdentities"],
            {"node", "npmEntrypoint", "npmPackageManifest"},
            "imported npm fixed tool identities",
        )
    else:
        require(value["fixedToolIdentities"] is None, f"{role} imported fixed tools are forbidden")
    return value


def verify_promotion(
    document: dict[str, Any],
    raw: bytes,
    *,
    candidate: dict[str, Any],
    trust: dict[str, Any],
) -> dict[str, Any]:
    payload, measured_file = verify_existing_envelope(
        document,
        api_version=PROMOTION_VERSION,
        domain=PROMOTION_DOMAIN,
        key=trust["keys"]["promotion"],
        key_id=trust["keyIds"]["promotion"],
        key_file_sha256=trust["keyFileSha256s"]["promotion"],
        raw_key_sha256=trust["rawKeySha256s"]["promotion"],
        label="promotion receipt",
    )
    require(measured_file == sha256(raw), "promotion receipt canonical file digest mismatch")
    required_payload = {
        "candidateIndexSha256",
        "candidateManifestFileSha256",
        "candidateManifestPayloadSha256",
        "candidatePromotionContractSha256",
        "daemon",
        "finalManifestSha256",
        "imageMappings",
        "images",
        "launcherRuntime",
        "manifest",
        "promotionAcceptanceSha256",
        "promotionPublicKey",
        "receiptStorage",
        "sourceEvidence",
        "sourceEvidenceSha256",
        "watchdog",
    }
    exact_keys(payload, required_payload, "promotion receipt payload")
    require_sha256(payload["candidateIndexSha256"], "promotion candidate index")
    require(payload["candidateManifestFileSha256"] == candidate["fileSha256"], "promotion crossed Candidate Manifest file")
    require(payload["candidateManifestPayloadSha256"] == candidate["payloadSha256"], "promotion crossed Candidate Manifest payload")
    require(payload["candidatePromotionContractSha256"] == candidate["promotionContractSha256"], "promotion crossed candidate contract")
    require(
        payload["sourceEvidence"] == candidate["sourceSnapshot"]["sourceEvidence"]
        and payload["sourceEvidenceSha256"]
        == candidate["sourceSnapshot"]["sourceEvidenceSha256"],
        "promotion crossed the signed source-evidence identity",
    )
    acceptance_payload = {
        "apiVersion": PROMOTION_ACCEPTANCE_VERSION,
        "candidatePromotionContractSha256": candidate[
            "promotionContractSha256"
        ],
    }
    require(
        payload["promotionAcceptanceSha256"]
        == sha256_json(acceptance_payload),
        "promotion receipt does not use the single canonical acceptance payload",
    )
    promotion_key = exact_keys(
        payload["promotionPublicKey"],
        {"identity", "mount", "rawKeySha256"},
        "promotion public-key evidence",
    )
    promotion_key_identity = exact_keys(
        promotion_key["identity"],
        {"device", "gid", "inode", "mode", "nlink", "path", "sha256", "size", "uid"},
        "promotion public-key file identity",
    )
    require(
        promotion_key_identity["sha256"]
        == trust["keyFileSha256s"]["promotion"]
        and promotion_key["rawKeySha256"]
        == trust["rawKeySha256s"]["promotion"],
        "promotion receipt key-file/raw-key identities differ from trust roots",
    )
    for field in ("device", "gid", "inode", "mode", "nlink", "size", "uid"):
        require_uint(promotion_key_identity[field], f"promotion key identity {field}")
    require(
        promotion_key_identity["nlink"] == 1
        and promotion_key_identity["mode"] & 0o222 == 0
        and isinstance(promotion_key_identity["path"], str)
        and promotion_key_identity["path"].startswith("/"),
        "promotion public-key file identity is not immutable",
    )
    receipt_storage = exact_keys(
        payload["receiptStorage"],
        {"mount", "path"},
        "promotion receipt storage",
    )
    require(
        isinstance(receipt_storage["path"], str)
        and receipt_storage["path"].startswith("/"),
        "promotion receipt storage path is not absolute",
    )
    manifest_record = exact_keys(
        payload["manifest"], {"identity", "mount"}, "promoted manifest artifact"
    )
    manifest_identity = exact_keys(
        manifest_record["identity"],
        {"device", "gid", "inode", "mode", "nlink", "path", "sha256", "size", "uid"},
        "promoted manifest file identity",
    )
    require_sha256(manifest_identity["sha256"], "promoted manifest file")
    require(
        manifest_identity["nlink"] == 1
        and manifest_identity["mode"] & 0o222 == 0
        and isinstance(manifest_identity["path"], str)
        and manifest_identity["path"].startswith("/"),
        "promoted manifest artifact identity is not immutable",
    )
    require(isinstance(payload["images"], dict) and list(payload["images"]) == list(IMAGE_ORDER), "promotion imported image inventory mismatch")
    require(isinstance(payload["imageMappings"], dict) and list(payload["imageMappings"]) == list(IMAGE_ORDER), "promotion mapping inventory mismatch")
    imported: dict[str, dict[str, Any]] = {}
    for role in IMAGE_ORDER:
        image = validate_imported_image(payload["images"][role], role)
        imported[role] = image
        mapping = exact_keys(
            payload["imageMappings"][role],
            {"candidate", "imported", "mappingSha256", "role"},
            f"{role} image mapping",
        )
        require(mapping["role"] == role and mapping["imported"] == image, f"{role} imported mapping mismatch")
        candidate_mapping = mapping["candidate"]
        expected = {
            "archiveSha256": candidate["images"][role]["archive"]["sha256"],
            "archiveSize": candidate["images"][role]["archive"]["size"],
            "capabilityAttestation": candidate["images"][role]["capabilityAttestation"],
            "capabilityCatalog": candidate["images"][role]["capabilityCatalog"],
            "capabilityCatalogSha256": candidate["images"][role]["capabilityCatalogSha256"],
            "configDigest": candidate["images"][role]["configDigest"],
            "dependencyClosureSha256": candidate["images"][role]["dependencyClosureSha256"],
            "dependencyFileManifestSha256": candidate["images"][role]["dependencyFileManifestSha256"],
            "dependencyPackageInventorySha256": candidate["images"][role]["dependencyPackageInventorySha256"],
            "dependencyRole": candidate["images"][role]["dependencyRole"],
            "executableInventorySha256": candidate["images"][role]["executableInventorySha256"],
            "fileManifestSha256": candidate["images"][role]["fileManifest"]["sha256"],
            "fixedToolIdentities": candidate["images"][role]["fixedToolIdentities"],
            "indexDigest": candidate["images"][role]["indexDigest"],
            "layerDigests": candidate["images"][role]["layerDigests"],
            "manifestDigest": candidate["images"][role]["manifestDigest"],
            "rootfsDiffIds": candidate["images"][role]["rootfsDiffIds"],
            "rootfsDigest": candidate["images"][role]["rootfsDigest"],
            "sbomSha256": candidate["images"][role]["sbom"]["sha256"],
            "semanticContract": candidate["images"][role]["semanticContract"],
        }
        require(candidate_mapping == expected, f"{role} candidate/imported mapping mismatch")
        for candidate_field, imported_field in (
            ("configDigest", "configDigest"),
            ("capabilityAttestation", "capabilityAttestation"),
            ("capabilityCatalog", "capabilityCatalog"),
            ("capabilityCatalogSha256", "capabilityCatalogSha256"),
            ("dependencyClosureSha256", "dependencyClosureSha256"),
            ("dependencyFileManifestSha256", "dependencyFileManifestSha256"),
            ("dependencyPackageInventorySha256", "dependencyPackageInventorySha256"),
            ("dependencyRole", "dependencyRole"),
            ("executableInventorySha256", "executableInventorySha256"),
            ("fileManifestSha256", "fileManifestSha256"),
            ("fixedToolIdentities", "fixedToolIdentities"),
            ("manifestDigest", "manifestDigest"),
            ("rootfsDiffIds", "rootfsDiffIds"),
            ("rootfsDigest", "rootfsDigest"),
            ("sbomSha256", "sbomSha256"),
            ("semanticContract", "semanticContract"),
        ):
            require(candidate_mapping[candidate_field] == image[imported_field], f"{role} promotion changed {candidate_field}")
        mapping_payload = {"candidate": candidate_mapping, "imported": image, "role": role}
        require(mapping["mappingSha256"] == sha256_json(mapping_payload), f"{role} mapping digest mismatch")
    return {
        "fileSha256": sha256(raw),
        "payloadSha256": document["payloadSha256"],
        "finalManifestSha256": require_sha256(payload["finalManifestSha256"], "promoted final manifest"),
        "importedImageMappingsSha256": sha256_json(payload["imageMappings"]),
        "imageMappings": payload["imageMappings"],
        "promotionAcceptanceSha256": require_sha256(
            payload["promotionAcceptanceSha256"],
            "promotion acceptance",
        ),
        "images": imported,
        "payload": payload,
    }


def candidate_output_records(candidate: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            "role": role,
            "manifestDigest": candidate["images"][role]["manifestDigest"],
            "configDigest": candidate["images"][role]["configDigest"],
            "rootfsDigest": candidate["images"][role]["rootfsDigest"],
            "sbomSha256": candidate["images"][role]["sbom"]["sha256"],
            "fileManifestSha256": candidate["images"][role]["fileManifest"]["sha256"],
        }
        for role in IMAGE_ORDER
    ]


def candidate_image_identities(candidate: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        role: {
            "archiveSha256": candidate["images"][role]["archive"]["sha256"],
            "archiveSize": candidate["images"][role]["archive"]["size"],
            "configDigest": candidate["images"][role]["configDigest"],
            "fileManifestSha256": candidate["images"][role]["fileManifest"]["sha256"],
            "indexDigest": candidate["images"][role]["indexDigest"],
            "layerDigests": candidate["images"][role]["layerDigests"],
            "manifestDigest": candidate["images"][role]["manifestDigest"],
            "rootfsDiffIds": candidate["images"][role]["rootfsDiffIds"],
            "rootfsDigest": candidate["images"][role]["rootfsDigest"],
            "sbomSha256": candidate["images"][role]["sbom"]["sha256"],
        }
        for role in IMAGE_ORDER
    }


def verify_builder(
    document: Any,
    *,
    role: str,
    candidate: dict[str, Any],
    source: dict[str, Any],
    watchdog: dict[str, Any],
    expectations: dict[str, Any],
    trust: dict[str, Any],
) -> dict[str, Any]:
    wrapper = exact_keys(document, {"statement", "transcript"}, f"{role} raw builder evidence")
    payload, statement_file_sha256 = verify_existing_envelope(
        wrapper["statement"],
        api_version=BUILDER_STATEMENT_VERSION,
        domain=BUILDER_STATEMENT_DOMAIN,
        key=trust["keys"][role],
        key_id=trust["keyIds"][role],
        key_file_sha256=trust["keyFileSha256s"][role],
        raw_key_sha256=trust["rawKeySha256s"][role],
        label=f"{role} builder statement",
    )
    payload = exact_keys(
        payload,
        {
            "builderId",
            "candidateManifestFileSha256",
            "candidateManifestPayloadSha256",
            "completionIdentity",
            "completionIdentitySha256",
            "dependencyManifestFileSha256",
            "dependencyManifestPayloadSha256",
            "environmentSha256",
            "expiresAtUnix",
            "imageOutputsSha256",
            "invocationId",
            "issuedAtUnix",
            "operatorId",
            "pipeline",
            "sourceInputManifestFileSha256",
            "sourceInputManifestPayloadSha256",
            "sourceClosureSha256",
            "toolchainSha256",
            "transcriptFileSha256",
            "transcriptPayloadSha256",
        },
        f"{role} builder payload",
    )
    builder_id = require_identifier(payload["builderId"], f"{role} builder ID")
    invocation_id = require_identifier(payload["invocationId"], f"{role} invocation ID")
    operator_id = require_identifier(payload["operatorId"], f"{role} operator ID")
    issued = require_uint(payload["issuedAtUnix"], f"{role} builder issue time")
    expires = require_uint(payload["expiresAtUnix"], f"{role} builder expiry")
    require(issued < expires and expires - issued <= MAX_RELEASE_VALIDITY_SECONDS, f"{role} builder validity is overlong")
    require(payload["pipeline"] == PIPELINE, f"{role} builder pipeline mismatch")
    completion_identity = validate_completion_identity(
        payload["completionIdentity"],
        label=f"{role} builder completion identity",
    )
    require(
        payload["completionIdentitySha256"]
        == sha256_json(completion_identity),
        f"{role} builder completion identity digest mismatch",
    )
    expected_bindings = {
        "candidateManifestFileSha256": candidate["fileSha256"],
        "candidateManifestPayloadSha256": candidate["payloadSha256"],
        "sourceInputManifestFileSha256": source["fileSha256"],
        "sourceInputManifestPayloadSha256": source["payloadSha256"],
        "sourceClosureSha256": candidate["sourceClosureSha256"],
        "dependencyManifestFileSha256": candidate["dependencyManifestFileSha256"],
        "dependencyManifestPayloadSha256": candidate["dependencyBundleSha256"],
        "imageOutputsSha256": candidate["candidateImagesSha256"],
    }
    for field, expected in expected_bindings.items():
        require(payload[field] == expected, f"{role} builder {field} mismatch")
    require_sha256(payload["environmentSha256"], f"{role} environment")
    require_sha256(payload["toolchainSha256"], f"{role} toolchain")
    transcript = exact_keys(
        wrapper["transcript"],
        {
            "apiVersion",
            "builderId",
            "candidate",
            "completedAtUnix",
            "completionIdentity",
            "completionIdentitySha256",
            "dependencies",
            "events",
            "eventHeadSha256",
            "imageOutputs",
            "invocationId",
            "kind",
            "network",
            "pipeline",
            "sandbox",
            "source",
            "startedAtUnix",
            "transcriptSha256",
        },
        f"{role} builder transcript",
    )
    require(transcript["apiVersion"] == BUILDER_TRANSCRIPT_VERSION, f"{role} transcript apiVersion mismatch")
    require(
        transcript["kind"] == "HermeticBuilderTranscript"
        and transcript["pipeline"] == PIPELINE,
        f"{role} transcript kind or pipeline mismatch",
    )
    require(
        transcript["builderId"] == builder_id
        and transcript["invocationId"] == invocation_id,
        f"{role} transcript builder/invocation identity mismatch",
    )
    transcript_completion_identity = validate_completion_identity(
        transcript["completionIdentity"],
        label=f"{role} transcript completion identity",
    )
    require(
        transcript_completion_identity == completion_identity
        and transcript["completionIdentitySha256"]
        == sha256_json(transcript_completion_identity)
        == payload["completionIdentitySha256"],
        f"{role} transcript crossed completion identity",
    )
    started = require_uint(transcript["startedAtUnix"], f"{role} transcript start")
    completed = require_uint(transcript["completedAtUnix"], f"{role} transcript completion")
    require(started <= completed <= issued, f"{role} transcript timing is invalid")
    require(
        transcript["network"] == {"mode": "none", "observedEndpoints": []},
        f"{role} transcript recorded build network",
    )
    sandbox = exact_keys(
        transcript["sandbox"],
        {
            "environmentSha256",
            "filesystemInputSha256",
            "kind",
            "profileSha256",
            "toolchainSha256",
        },
        f"{role} builder sandbox",
    )
    require(
        sandbox["kind"] == "independently-measured-hermetic-builder",
        f"{role} builder sandbox is not independently measured",
    )
    for field in (
        "environmentSha256",
        "filesystemInputSha256",
        "profileSha256",
        "toolchainSha256",
    ):
        require_sha256(sandbox[field], f"{role} sandbox {field}")
    require(
        payload["environmentSha256"] == sandbox["environmentSha256"]
        and payload["toolchainSha256"] == sandbox["toolchainSha256"],
        f"{role} statement crossed sandbox measurements",
    )
    require(
        transcript["source"]
        == {
            "sourceClosureSha256": candidate["sourceClosureSha256"],
            "sourceInputManifestFileSha256": source["fileSha256"],
            "sourceInputManifestPayloadSha256": source["payloadSha256"],
            "gitInventoryPayloadSha256": source["gitInventoryPayloadSha256"],
            "untrackedApprovalPayloadSha256": source[
                "untrackedApprovalPayloadSha256"
            ],
        },
        f"{role} transcript source binding mismatch",
    )
    require(
        transcript["candidate"]
        == {
            "candidateManifestFileSha256": candidate["fileSha256"],
            "candidateManifestPayloadSha256": candidate["payloadSha256"],
            "candidateImagesSha256": candidate["candidateImagesSha256"],
            "promotionContractSha256": candidate["promotionContractSha256"],
        },
        f"{role} transcript candidate binding mismatch",
    )
    require(
        transcript["dependencies"]
        == {
            "dependencyManifestFileSha256": candidate[
                "dependencyManifestFileSha256"
            ],
            "dependencyManifestPayloadSha256": candidate[
                "dependencyBundleSha256"
            ],
            "roleClosuresSha256": candidate["dependencyRoleClosuresSha256"],
        },
        f"{role} transcript dependency binding mismatch",
    )
    require(
        transcript["imageOutputs"] == candidate_image_identities(candidate),
        f"{role} transcript image outputs mismatch",
    )
    event_head = verify_event_chain(transcript["events"], label=f"{role} builder transcript")
    require(transcript["eventHeadSha256"] == event_head, f"{role} transcript event head mismatch")
    transcript_payload = {
        key: value for key, value in transcript.items() if key != "transcriptSha256"
    }
    transcript_digest = sha256_json(transcript_payload)
    require(transcript["transcriptSha256"] == transcript_digest, f"{role} transcript digest mismatch")
    transcript_file_sha256 = sha256(
        canonical_json_bytes(wrapper["transcript"]) + b"\n"
    )
    require(
        payload["transcriptFileSha256"] == transcript_file_sha256
        and payload["transcriptPayloadSha256"] == transcript_digest,
        f"{role} statement crossed transcript",
    )
    events = [record["event"] for record in transcript["events"]]
    require(
        len(events) == 7 + len(IMAGE_ORDER),
        f"{role} transcript event count is not the fixed 15-output grammar",
    )
    command_event = exact_keys(
        events[1],
        {"commandContractSha256", "type"},
        f"{role} command event",
    )
    require(
        command_event["type"] == "command-measured",
        f"{role} command event type mismatch",
    )
    command_contract_sha256 = require_sha256(
        command_event["commandContractSha256"],
        f"{role} command contract",
    )
    expected_events = [
        {
            "builderId": transcript["builderId"],
            "candidateManifestFileSha256": candidate["fileSha256"],
            "candidateManifestPayloadSha256": candidate["payloadSha256"],
            "candidateImagesSha256": candidate["candidateImagesSha256"],
            "completionIdentity": completion_identity,
            "completionIdentitySha256": payload["completionIdentitySha256"],
            "dependencyManifestFileSha256": candidate[
                "dependencyManifestFileSha256"
            ],
            "dependencyManifestPayloadSha256": candidate[
                "dependencyBundleSha256"
            ],
            "dependencyRoleClosuresSha256": candidate[
                "dependencyRoleClosuresSha256"
            ],
            "gitInventoryPayloadSha256": source[
                "gitInventoryPayloadSha256"
            ],
            "invocationId": transcript["invocationId"],
            "planSha256": candidate["buildPlanSha256"],
            "sourceClosureSha256": candidate["sourceClosureSha256"],
            "sourceInputManifestFileSha256": source["fileSha256"],
            "sourceInputManifestPayloadSha256": source["payloadSha256"],
            "startedAtUnix": transcript["startedAtUnix"],
            "type": "build-started",
            "untrackedApprovalPayloadSha256": source[
                "untrackedApprovalPayloadSha256"
            ],
        },
        {
            "commandContractSha256": command_contract_sha256,
            "type": "command-measured",
        },
        {
            "environmentSha256": transcript["sandbox"][
                "environmentSha256"
            ],
            "type": "environment-measured",
        },
        {
            "sandboxSha256": sha256_json(transcript["sandbox"]),
            "type": "sandbox-measured",
        },
        {
            "networkSha256": sha256_json(
                {"mode": "none", "observedEndpoints": []}
            ),
            "type": "network-measured",
        },
        *[
            {
                "ordinal": ordinal,
                "outputSha256": sha256_json(
                    transcript["imageOutputs"][image_role]
                ),
                "role": image_role,
                "type": "output-measured",
            }
            for ordinal, image_role in enumerate(IMAGE_ORDER, start=1)
        ],
        {"exitCode": 0, "success": True, "type": "process-exited"},
        {
            "completedAtUnix": transcript["completedAtUnix"],
            "imageOutputsSha256": sha256_json(transcript["imageOutputs"]),
            "type": "build-completed",
        },
    ]
    require(
        events == expected_events,
        f"{role} transcript does not use the exact measured command, environment, sandbox, no-network, 15-output, successful-exit grammar",
    )
    statement_core_payload = {
        key: value
        for key, value in payload.items()
        if key
        not in {
            "completionIdentity",
            "completionIdentitySha256",
            "transcriptFileSha256",
            "transcriptPayloadSha256",
        }
    }
    transcript_core_payload = builder_transcript_core_payload(transcript)
    builder_core = completion_core(
        role,
        {
            "signingKeyId": trust["keyIds"][role],
            "statement": statement_core_payload,
            "transcript": transcript_core_payload,
        },
    )
    return {
        "builderId": builder_id,
        "operatorId": operator_id,
        "buildId": invocation_id,
        "statementSha256": statement_file_sha256,
        "statementFileSha256": statement_file_sha256,
        "statementPayloadSha256": wrapper["statement"]["payloadSha256"],
        "signingKeyId": trust["keyIds"][role],
        "transcriptSha256": transcript_digest,
        "transcriptFileSha256": transcript_file_sha256,
        "outputsSha256": candidate["candidateImagesSha256"],
        "commandContractSha256": command_contract_sha256,
        "eventGrammarSha256": sha256_json(events),
        "completionIdentity": completion_identity,
        "completionIdentitySha256": payload["completionIdentitySha256"],
        "core": builder_core,
        "coreSha256": sha256_json(builder_core),
        "issuedAtUnix": issued,
        "expiresAtUnix": expires,
    }


def verify_candidate_to_eif(
    document: dict[str, Any],
    raw: bytes,
    *,
    candidate: dict[str, Any],
    source: dict[str, Any],
    watchdog: dict[str, Any],
    promotion: dict[str, Any],
    promoted: dict[str, Any],
    builders: list[dict[str, Any]],
    expectations: dict[str, Any],
    trust: dict[str, Any],
) -> dict[str, Any]:
    payload, measured_file_sha256 = verify_existing_envelope(
        document,
        api_version=EIF_BUILD_VERSION,
        domain=EIF_BUILD_DOMAIN,
        key=trust["keys"]["manifestV6EifBuilder"],
        key_id=trust["keyIds"]["manifestV6EifBuilder"],
        key_file_sha256=trust["keyFileSha256s"]["manifestV6EifBuilder"],
        raw_key_sha256=trust["rawKeySha256s"]["manifestV6EifBuilder"],
        label="Manifest v6 candidate-to-EIF build statement",
    )
    require(
        measured_file_sha256 == sha256(raw),
        "candidate-to-EIF statement canonical file digest mismatch",
    )
    payload = exact_keys(
        payload,
        {
            "builderStatementsSha256",
            "candidateManifestFileSha256",
            "candidateManifestPayloadSha256",
            "completionIdentity",
            "completionIdentitySha256",
            "dependencyClosureSha256",
            "eifFileSha384",
            "importedImageMappingsSha256",
            "legacyDockerNsmAccepted",
            "pcrs",
            "pipeline",
            "promotionReceiptFileSha256",
            "promotionReceiptPayloadSha256",
            "releaseGeneration",
            "rollbackEpoch",
            "sourceClosureSha256",
            "sourceInputManifestFileSha256",
            "sourceInputManifestPayloadSha256",
            "watchdogReceiptFileSha256",
            "watchdogReceiptPayloadSha256",
        },
        "Manifest v6 candidate-to-EIF payload",
    )
    require(
        payload["pipeline"] == PIPELINE
        and payload["legacyDockerNsmAccepted"] is False,
        "candidate-to-EIF statement accepts a non-production or legacy pipeline",
    )
    require_uint(
        payload["releaseGeneration"],
        "candidate-to-EIF release generation",
    )
    require_uint(
        payload["rollbackEpoch"],
        "candidate-to-EIF rollback epoch",
    )
    builder_summaries = {
        side: {
            "file_sha256": builder["statementFileSha256"],
            "payload_sha256": builder["statementPayloadSha256"],
            "signing_key_id": builder["signingKeyId"],
            "builder_id": builder["builderId"],
            "operator_id": builder["operatorId"],
            "invocation_id": builder["buildId"],
            "transcript_file_sha256": builder["transcriptFileSha256"],
            "transcript_payload_sha256": builder["transcriptSha256"],
            "completion_identity": builder["completionIdentity"],
            "completion_identity_sha256": builder[
                "completionIdentitySha256"
            ],
            "issued_at_unix": builder["issuedAtUnix"],
            "expires_at_unix": builder["expiresAtUnix"],
        }
        for side, builder in zip(("left", "right"), builders, strict=True)
    }
    completion_identity = verify_completion_identity(
        payload["completionIdentity"],
        payload["completionIdentitySha256"],
        label="candidate-to-EIF completion identity",
    )
    dependency_role_closures = candidate["dependencyRoleClosures"]
    expected = {
        "builderStatementsSha256": sha256_json(builder_summaries),
        "candidateManifestFileSha256": candidate["fileSha256"],
        "candidateManifestPayloadSha256": candidate["payloadSha256"],
        "dependencyClosureSha256": sha256_json(dependency_role_closures),
        "eifFileSha384": expectations["eifSha384"],
        "importedImageMappingsSha256": promoted["imageMappingsSha256"],
        "pcrs": expectations["pcrs"],
        "promotionReceiptFileSha256": promotion["fileSha256"],
        "promotionReceiptPayloadSha256": promotion["payloadSha256"],
        "releaseGeneration": expectations["releaseGeneration"],
        "rollbackEpoch": expectations["rollbackEpoch"],
        "sourceClosureSha256": candidate["sourceClosureSha256"],
        "sourceInputManifestFileSha256": source["fileSha256"],
        "sourceInputManifestPayloadSha256": source["payloadSha256"],
        "watchdogReceiptFileSha256": watchdog["fileSha256"],
        "watchdogReceiptPayloadSha256": watchdog["payloadSha256"],
    }
    for field, expected_value in expected.items():
        require(
            payload[field] == expected_value,
            f"candidate-to-EIF {field} crossed the verified release closure",
        )
    require(
        payload["pcrs"]["PCR0"] == payload["eifFileSha384"],
        "candidate-to-EIF statement does not map EIF digest exactly to PCR0",
    )
    require(
        measured_file_sha256
        == expectations["manifestV6EifBuildStatementFileSha256"]
        and document["payloadSha256"]
        == expectations["manifestV6EifBuildStatementPayloadSha256"],
        "candidate-to-EIF statement differs from independent expectations",
    )
    eif_core_payload = {
        key: value
        for key, value in payload.items()
        if key
        not in {
            "builderStatementsSha256",
            "completionIdentity",
            "completionIdentitySha256",
        }
    }
    eif_core_payload["builderCoreSha256s"] = [
        builder["coreSha256"] for builder in builders
    ]
    eif_core = completion_core("eif", eif_core_payload)
    return {
        "fileSha256": measured_file_sha256,
        "payloadSha256": document["payloadSha256"],
        "builderStatementsSha256": payload["builderStatementsSha256"],
        "completionIdentity": completion_identity,
        "completionIdentitySha256": payload["completionIdentitySha256"],
        "core": eif_core,
        "coreSha256": sha256_json(eif_core),
        "dependencyClosureSha256": payload["dependencyClosureSha256"],
        "importedImageMappingsSha256": payload["importedImageMappingsSha256"],
        "eifSha384": payload["eifFileSha384"],
        "pcrs": payload["pcrs"],
    }


def manifest_dependency_role(name: str) -> str:
    if name in {
        "browser-python-compatibility",
        "chromium-compatibility",
        "portal-browser-oauth",
    }:
        return "browser-runtime"
    if name == "clean-room":
        return "clean-room-runtime"
    if name == "rust-decision-gate-tests":
        return "rust-runtime"
    if name == "npm-publish-companion":
        return "npm-11.8-runtime"
    return "python-runtime"


def expected_manifest_process(name: str) -> dict[str, Any]:
    if name == "npm-publish-companion":
        return {
            "argv": [],
            "cwd": "/work",
            "dynamicEnvironment": [],
            "entrypoint": [
                "/opt/serverware/node/bin/node",
                "/opt/serverware/src/scripts/npm_publish_companion.js",
            ],
            "environment": {
                "CI": "true",
                "HOME": "/work/home",
                "LANG": "C",
                "LC_ALL": "C",
                "NO_PROXY": "",
                "TMPDIR": "/work/tmp",
                "XDG_RUNTIME_DIR": "/run/serverware-runtime",
                "npm_config_audit": "false",
                "npm_config_fund": "false",
                "npm_config_update_notifier": "false",
            },
            "gid": 65532,
            "uid": 65532,
        }
    if name == "rust-decision-gate-tests":
        entrypoint = ["/opt/serverware/bin/serverware-decision-gate-tests"]
        argv = ["--test-threads=1"]
    else:
        entrypoint = [
            "/opt/serverware/python/bin/python3",
            "-I",
            "/opt/serverware/src/scripts/oci_lane_entrypoint.py",
        ]
        argv = ["--role", name]
    return {
        "argv": argv,
        "cwd": "/work",
        "dynamicEnvironment": (
            PORTAL_DYNAMIC_ENVIRONMENT if name == "portal-browser-oauth" else []
        ),
        "entrypoint": entrypoint,
        "environment": BASE_LANE_ENVIRONMENT,
        "gid": 65532,
        "uid": 65532,
    }


def verify_fixed_manifest_isolation(value: Any, *, name: str) -> None:
    value = exact_keys(
        value,
        {
            "apparmorProfileSha256",
            "capDrop",
            "cpuQuotaMicros",
            "memoryBytes",
            "mounts",
            "noNewPrivileges",
            "outputStderrBytes",
            "outputStdoutBytes",
            "pidsLimit",
            "readOnlyRootfs",
            "seccompProfileSha256",
            "tmpfs",
            "timeoutSeconds",
        },
        f"{name} isolation",
    )
    require_sha256(value["apparmorProfileSha256"], f"{name} AppArmor profile")
    require_sha256(value["seccompProfileSha256"], f"{name} seccomp profile")
    expected_mounts = [
        {
            "destination": "/dev",
            "gid": 0,
            "mode": 0o755,
            "options": ["nosuid", "strictatime"],
            "sizeBytes": 16 * 1024 * 1024,
            "source": "tmpfs",
            "type": "tmpfs",
            "uid": 0,
        },
        {
            "destination": "/proc",
            "options": ["nosuid", "noexec", "nodev"],
            "source": "proc",
            "type": "proc",
        },
    ]
    expected_tmpfs = [
        {
            "destination": "/run/serverware-runtime",
            "gid": 65532,
            "mode": 0o700,
            "options": ["nodev", "noexec", "nosuid", "strictatime"],
            "sizeBytes": 16 * 1024 * 1024,
            "uid": 65532,
        },
        {
            "destination": "/tmp",
            "gid": 65532,
            "mode": 0o700,
            "options": ["nodev", "noexec", "nosuid", "strictatime"],
            "sizeBytes": 256 * 1024 * 1024,
            "uid": 65532,
        },
        {
            "destination": "/work",
            "gid": 65532,
            "mode": 0o700,
            "options": ["nodev", "nosuid", "strictatime"],
            "sizeBytes": 256 * 1024 * 1024,
            "uid": 65532,
        },
    ]
    expected = {
        "capDrop": ["ALL"],
        "cpuQuotaMicros": 1_000_000,
        "memoryBytes": (
            1024 * 1024 * 1024
            if name == "portal-browser-oauth"
            else 512 * 1024 * 1024
        ),
        "mounts": expected_mounts,
        "noNewPrivileges": True,
        "outputStderrBytes": 16 * 1024 * 1024,
        "outputStdoutBytes": 32 * 1024 * 1024,
        "pidsLimit": 256,
        "readOnlyRootfs": True,
        "tmpfs": expected_tmpfs,
        "timeoutSeconds": (
            900
            if name == "portal-browser-oauth"
            else 120
            if name == "npm-publish-companion"
            else 300
        ),
    }
    require(
        all(value[field] == expected_value for field, expected_value in expected.items()),
        f"{name} isolation differs from the fixed v6 contract",
    )


def verify_fixed_manifest_network(value: Any, *, name: str) -> None:
    value = exact_keys(value, {"egress", "mode", "namespace", "role"}, f"{name} network")
    if name == "portal-browser-oauth":
        expected = {"egress": "none", "mode": "internal", "namespace": "private-anchor", "role": "portal-npm-private"}
    elif name == "npm-publish-companion":
        expected = {"egress": "none", "mode": "join", "namespace": "lane:portal-browser-oauth", "role": "portal-npm-private"}
    else:
        expected = {"egress": "none", "mode": "none", "namespace": "private", "role": None}
    require(value == expected, f"{name} network differs from the fixed v6 contract")


def verify_fixed_runtime(value: Any, *, name: str, image: dict[str, Any]) -> None:
    value = exact_keys(
        value,
        {
            "dependencyCapabilityCatalogSha256",
            "dependencyCapabilities",
            "dependencyClosureSha256",
            "dependencyFileManifestSha256",
            "dependencyRole",
            "semanticContractSha256",
        },
        f"{name} runtime",
    )
    role = manifest_dependency_role(name)
    expected_semantic = (
        image["semanticContract"]["contractSha256"]
        if name == "clean-room" and isinstance(image["semanticContract"], dict)
        else None
    )
    require(
        value
        == {
            "dependencyCapabilityCatalogSha256": image["capabilityCatalogSha256"],
            "dependencyCapabilities": DEPENDENCY_CAPABILITIES[role],
            "dependencyClosureSha256": image["dependencyClosureSha256"],
            "dependencyFileManifestSha256": image["dependencyFileManifestSha256"],
            "dependencyRole": role,
            "semanticContractSha256": expected_semantic,
        },
        f"{name} runtime crossed its fixed dependency image",
    )


def verify_promoted_manifest(
    document: Any,
    raw: bytes,
    *,
    candidate: dict[str, Any],
    promotion: dict[str, Any],
) -> dict[str, Any]:
    document = exact_keys(
        document,
        {
            "apiVersion",
            "candidate",
            "companions",
            "imageMappings",
            "images",
            "laneOrder",
            "lanes",
            "manifestSha256",
            "platform",
            "promotion",
            "sourceSnapshot",
            "watchdog",
        },
        "promoted Manifest v6",
    )
    require(
        document["apiVersion"] == PROMOTED_MANIFEST_VERSION
        and document["platform"] == {"architecture": "amd64", "os": "linux"},
        "promoted manifest is not the exact Manifest v6 production artifact",
    )
    payload = dict(document)
    manifest_sha256 = require_sha256(
        payload.pop("manifestSha256"), "promoted Manifest v6 payload"
    )
    require(
        manifest_sha256 == sha256_json(payload)
        and manifest_sha256 == promotion["finalManifestSha256"],
        "promoted Manifest v6 digest differs from the promotion receipt",
    )
    require(
        promotion["payload"]["manifest"]["identity"]["sha256"] == sha256(raw),
        "promotion receipt manifest artifact does not bind the exact promoted file bytes",
    )
    manifest_candidate = exact_keys(
        document["candidate"],
        {"fileSha256", "indexSha256", "payloadSha256", "promotionContractSha256"},
        "promoted candidate identity",
    )
    require_sha256(manifest_candidate["indexSha256"], "candidate index")
    require(
        manifest_candidate["fileSha256"] == candidate["fileSha256"]
        and manifest_candidate["payloadSha256"] == candidate["payloadSha256"]
        and manifest_candidate["promotionContractSha256"]
        == candidate["promotionContractSha256"],
        "promoted manifest crossed the Candidate Manifest",
    )
    require(
        manifest_candidate["indexSha256"]
        == promotion["payload"]["candidateIndexSha256"],
        "promotion receipt candidate index differs from the promoted manifest",
    )
    require(
        document["sourceSnapshot"]
        == {
            key: value
            for key, value in candidate["sourceSnapshot"].items()
            if key != "sourceManifest"
        },
        "promoted manifest crossed the source closure",
    )
    require(
        document["images"] == promotion["images"]
        and document["imageMappings"] == promotion["imageMappings"],
        "promoted manifest crossed the imported-image one-to-one mapping",
    )
    promotion_acceptance = exact_keys(
        document["promotion"],
        {"acceptanceSha256", "apiVersion", "candidatePromotionContractSha256"},
        "promoted manifest acceptance",
    )
    require(
        promotion_acceptance["apiVersion"]
        == "serverware.verificationPromotionAcceptance/v2"
        and promotion_acceptance["acceptanceSha256"]
        == sha256_json(
            {
                key: value
                for key, value in promotion_acceptance.items()
                if key != "acceptanceSha256"
            }
        )
        and promotion_acceptance["acceptanceSha256"]
        == promotion["promotionAcceptanceSha256"]
        and promotion_acceptance["candidatePromotionContractSha256"]
        == candidate["promotionContractSha256"],
        "promoted manifest acceptance crossed the promotion receipt",
    )
    require(
        document["laneOrder"] == list(LANE_ORDER)
        and isinstance(document["lanes"], dict)
        and list(document["lanes"]) == list(LANE_ORDER)
        and isinstance(document["companions"], dict)
        and set(document["companions"]) == {"npmPublish"},
        "promoted manifest lane/companion inventory is not exact",
    )
    expected_probes = {
        "browser-python-compatibility": [
            "dns-nss-local-bounded",
            "multiprocessing-spawn-bounded",
            "openssl-provider-load",
            "sqlite-memory-and-file",
        ],
        "host-python-compatibility": [
            "dns-nss-local-bounded",
            "multiprocessing-spawn-bounded",
            "openssl-provider-load",
            "sqlite-memory-and-file",
        ],
        "proxy-python-compatibility": [
            "dns-nss-local-bounded",
            "multiprocessing-spawn-bounded",
            "openssl-provider-load",
            "sqlite-memory-and-file",
        ],
        "chromium-compatibility": ["chromium-startup-no-network"],
    }
    for name in LANE_ORDER:
        lane = exact_keys(
            document["lanes"][name],
            {
                "capabilityProbes",
                "imageRole",
                "isolation",
                "name",
                "network",
                "process",
                "runtime",
                "sourceSet",
            },
            f"{name} promoted lane",
        )
        require(
            lane["name"] == name
            and lane["imageRole"] == f"lane-{name}"
            and lane["capabilityProbes"] == expected_probes.get(name, [])
            and lane["process"] == expected_manifest_process(name)
            and lane["sourceSet"] == SOURCE_CONTRACTS[name],
            f"{name} is not the fixed Manifest v6 lane",
        )
        verify_fixed_manifest_isolation(lane["isolation"], name=name)
        verify_fixed_manifest_network(lane["network"], name=name)
        verify_fixed_runtime(
            lane["runtime"], name=name, image=document["images"][f"lane-{name}"]
        )
    npm = exact_keys(
        document["companions"]["npmPublish"],
        {
            "imageRole",
            "inputProtocol",
            "isolation",
            "network",
            "npmVersion",
            "operation",
            "operationCount",
            "process",
            "retryEquality",
            "runtime",
            "sourceSet",
        },
        "npm publish companion",
    )
    require(
        npm["imageRole"] == "npm-publish-companion"
        and npm["npmVersion"] == "11.8.0"
        and npm["operation"] == "npm.publish.fixture"
        and npm["operationCount"] == 2
        and npm["inputProtocol"]
        == "one-canonical-json-frame-on-stdin-no-generic-command"
        and npm["retryEquality"]
        == {
            "canonicalHttpRequestBytes": "identical",
            "operationInputBytes": "identical",
            "rawHttpRequestBytes": "different-only-by-npm-session",
            "requestBodyBytes": "identical",
        }
        and npm["process"] == expected_manifest_process("npm-publish-companion")
        and npm["sourceSet"]
        == {"exact": ["scripts/npm_publish_companion.js"], "prefixes": []},
        "npm companion is not the fixed two-operation no-egress contract",
    )
    verify_fixed_manifest_isolation(
        npm["isolation"], name="npm-publish-companion"
    )
    verify_fixed_manifest_network(npm["network"], name="npm-publish-companion")
    verify_fixed_runtime(
        npm["runtime"],
        name="npm-publish-companion",
        image=document["images"]["npm-publish-companion"],
    )
    watchdog_manifest = exact_keys(
        document["watchdog"],
        {
            "bootCleanupContractSha256",
            "protocolVersion",
            "resourceLabelNames",
            "selectionMode",
        },
        "promoted manifest watchdog",
    )
    require(
        watchdog_manifest["protocolVersion"]
        == "serverware.ociVerificationWatchdog/v4"
        and watchdog_manifest["selectionMode"]
        == "exact-kind-id-pairs-and-complete-label-set"
        and watchdog_manifest["resourceLabelNames"]
        == [
            "org.serverware.attempt",
            "org.serverware.kind",
            "org.serverware.lane",
            "org.serverware.lane-sequence",
            "org.serverware.lease",
            "org.serverware.manifest",
            "org.serverware.promotion-receipt",
            "org.serverware.role",
        ],
        "promoted manifest watchdog contract is not exact v4",
    )
    require_sha256(
        watchdog_manifest["bootCleanupContractSha256"],
        "promoted watchdog cleanup contract",
    )
    return {
        "fileSha256": sha256(raw),
        "manifestSha256": manifest_sha256,
        "imageMappingsSha256": sha256_json(document["imageMappings"]),
        "promotionAcceptanceSha256": promotion_acceptance["acceptanceSha256"],
        "document": document,
    }


def verify_production_identity(
    document: Any,
    raw: bytes,
    runtime_document: Any,
    runtime_raw: bytes,
    custody_document: Any,
    custody_raw: bytes,
    *,
    promoted: dict[str, Any],
    candidate: dict[str, Any],
    source: dict[str, Any],
    watchdog: dict[str, Any],
    promotion: dict[str, Any],
    builders: list[dict[str, Any]],
    candidate_to_eif: dict[str, Any],
    expectations: dict[str, Any],
    trust: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    identity = exact_keys(
        document,
        {
            "apiVersion",
            "builderStatementSha256s",
            "buildWatchdogReceiptSha256",
            "candidateManifestFileSha256",
            "candidateManifestPayloadSha256",
            "completionIdentity",
            "completionIdentitySha256",
            "dependencyClosureSha256",
            "eifImageSha384",
            "importedImageMappingsSha256",
            "monotonicWitnessSha256",
            "pipeline",
            "pcrs",
            "promotedManifestSha256",
            "promotionReceiptSha256",
            "productionContinuitySha256",
            "productionReleaseIdentitySha256",
            "releaseGeneration",
            "sourceClosureSha256",
            "sourceInputApprovalSha256",
            "sourceInputManifestFileSha256",
            "sourceInputManifestPayloadSha256",
        },
        "production attestation identity",
    )
    require(
        identity["apiVersion"] == PRODUCTION_IDENTITY_VERSION
        and identity["pipeline"] == PIPELINE,
        "production identity is not the promoted OCI Nitro pipeline",
    )
    production_completion_identity = verify_completion_identity(
        identity["completionIdentity"],
        identity["completionIdentitySha256"],
        label="production identity completion identity",
    )
    require_uint(
        identity["releaseGeneration"],
        "production identity release generation",
    )
    expected_identity = {
        "builderStatementSha256s": sorted(
            builder["statementFileSha256"] for builder in builders
        ),
        "buildWatchdogReceiptSha256": watchdog["fileSha256"],
        "candidateManifestFileSha256": candidate["fileSha256"],
        "candidateManifestPayloadSha256": candidate["payloadSha256"],
        "completionIdentity": production_completion_identity,
        "completionIdentitySha256": identity["completionIdentitySha256"],
        "dependencyClosureSha256": candidate["dependencyClosureSha256"],
        "eifImageSha384": expectations["eifSha384"],
        "importedImageMappingsSha256": promotion["importedImageMappingsSha256"],
        "monotonicWitnessSha256": expectations["monotonicWitnessSha256"],
        "pcrs": expectations["pcrs"],
        "promotedManifestSha256": promoted["fileSha256"],
        "promotionReceiptSha256": promotion["fileSha256"],
        "productionContinuitySha256": expectations[
            "productionContinuitySha256"
        ],
        "productionReleaseIdentitySha256": expectations[
            "productionReleaseIdentitySha256"
        ],
        "releaseGeneration": expectations["releaseGeneration"],
        "sourceClosureSha256": candidate["sourceClosureSha256"],
        "sourceInputApprovalSha256": source[
            "untrackedApprovalPayloadSha256"
        ],
        "sourceInputManifestFileSha256": source["fileSha256"],
        "sourceInputManifestPayloadSha256": source["payloadSha256"],
    }
    for field, expected in expected_identity.items():
        require(
            identity[field] == expected,
            f"production identity {field} binding mismatch",
        )
    runtime = exact_keys(
        runtime_document,
        {
            "activeTlsConnection",
            "apiVersion",
            "caSpkiSha256",
            "completionIdentity",
            "completionIdentitySha256",
            "custodyEvidenceSha256",
            "enclaveBootId",
            "enclaveInstanceId",
            "keyGenerations",
            "pipeline",
            "policyHash",
            "policySequence",
            "productionIdentitySha256",
            "promotedManifestSha256",
            "releaseGeneration",
            "rollbackEpoch",
            "tlsScopeSigningKeySpkiSha256",
        },
        "production runtime state",
    )
    identity_file_sha256 = sha256(raw)
    runtime_file_sha256 = sha256(runtime_raw)
    custody_file_sha256 = sha256(custody_raw)
    require(
        runtime_file_sha256 == expectations["runtimeStateFileSha256"]
        and custody_file_sha256
        == expectations["runtimeKeyCustodyFileSha256"],
        "runtime state or custody differs from independent expectations",
    )
    require(
        runtime["apiVersion"] == PRODUCTION_RUNTIME_VERSION
        and runtime["pipeline"] == PIPELINE,
        "runtime state is not the promoted OCI Nitro pipeline",
    )
    require(
        runtime["productionIdentitySha256"] == identity_file_sha256
        and runtime["promotedManifestSha256"] == promoted["fileSha256"]
        and runtime["custodyEvidenceSha256"] == custody_file_sha256,
        "runtime state crossed remeasured production files",
    )
    runtime_completion_identity = validate_completion_identity(
        runtime["completionIdentity"],
        label="runtime completion identity",
    )
    require(
        runtime_completion_identity == production_completion_identity
        and runtime["completionIdentitySha256"]
        == sha256_json(runtime_completion_identity)
        == identity["completionIdentitySha256"],
        "runtime state crossed completion identity",
    )
    for field in (
        "caSpkiSha256",
        "policyHash",
        "productionIdentitySha256",
        "promotedManifestSha256",
        "custodyEvidenceSha256",
        "tlsScopeSigningKeySpkiSha256",
    ):
        require_sha256(runtime[field], f"runtime {field}")
    require_identifier(runtime["enclaveInstanceId"], "enclave instance")
    require_identifier(runtime["enclaveBootId"], "enclave boot")
    require_uint(runtime["policySequence"], "policy sequence")
    require_uint(runtime["releaseGeneration"], "runtime release generation")
    require_uint(runtime["rollbackEpoch"], "runtime rollback epoch")
    require(
        runtime["rollbackEpoch"] == expectations["rollbackEpoch"]
        and runtime["releaseGeneration"] == expectations["releaseGeneration"]
        and runtime["policyHash"] == expectations["policyHash"]
        and runtime["policySequence"] == expectations["policySequence"]
        and runtime["caSpkiSha256"] == expectations["caSpkiSha256"],
        "runtime policy, CA, epoch, or release differs from independent expectations",
    )
    generation_names = {
        "brokerKek",
        "ca",
        "credentialRelease",
        "policy",
        "release",
        "response",
        "tls",
        "tlsScope",
    }
    generations = exact_keys(
        runtime["keyGenerations"], generation_names, "runtime key generations"
    )
    for name, value in generations.items():
        require_uint(value, f"{name} key generation")
    active_tls = exact_keys(
        runtime["activeTlsConnection"],
        {
            "connectionId",
            "connectionNonceSha256",
            "envelopeSha256",
            "expiresAtUnix",
            "exporterSha256",
            "issuedAtUnix",
            "leafCertificateSha256",
            "leafSpkiSha256",
            "peerCertificateSha256",
            "peerIdentity",
            "peerSpkiSha256",
            "tlsStackMeasurementSha256",
        },
        "runtime active TLS connection",
    )
    require_identifier(active_tls["connectionId"], "active TLS connection ID")
    require(
        isinstance(active_tls["peerIdentity"], str)
        and 1 <= len(active_tls["peerIdentity"]) <= 256,
        "active TLS peer identity is invalid",
    )
    for field in (
        "connectionNonceSha256",
        "envelopeSha256",
        "exporterSha256",
        "leafCertificateSha256",
        "leafSpkiSha256",
        "peerCertificateSha256",
        "peerSpkiSha256",
        "tlsStackMeasurementSha256",
    ):
        require_sha256(active_tls[field], f"active TLS {field}")
    active_tls_issued = require_uint(active_tls["issuedAtUnix"], "active TLS issue time")
    active_tls_expires = require_uint(active_tls["expiresAtUnix"], "active TLS expiry")
    require(
        active_tls_issued <= now <= active_tls_expires
        and active_tls_expires - active_tls_issued <= MAX_VALIDITY_SECONDS,
        "runtime active TLS scope is stale or overlong",
    )

    custody = exact_keys(
        custody_document,
        {
            "apiVersion",
            "completionIdentity",
            "completionIdentitySha256",
            "eifImageSha384",
            "generationSignerPublicKeySpkiDerBase64url",
            "generationSignerPublicKeySpkiSha256",
            "materials",
            "pcrs",
            "pipeline",
            "policyHash",
            "recipientPublicKeySpkiDerBase64url",
            "recipientPublicKeySpkiSha256",
            "releaseGeneration",
            "rollbackEpoch",
        },
        "remeasured runtime key custody",
    )
    require_uint(
        custody["releaseGeneration"],
        "runtime custody release generation",
    )
    require_uint(
        custody["rollbackEpoch"],
        "runtime custody rollback epoch",
    )
    require(
        custody["apiVersion"] == RUNTIME_CUSTODY_VERSION
        and custody["pipeline"] == PIPELINE
        and custody["eifImageSha384"] == expectations["eifSha384"]
        and custody["pcrs"] == expectations["pcrs"]
        and custody["policyHash"] == runtime["policyHash"]
        and custody["rollbackEpoch"] == runtime["rollbackEpoch"]
        and custody["releaseGeneration"] == runtime["releaseGeneration"]
        and custody["completionIdentitySha256"]
        == identity["completionIdentitySha256"],
        "runtime custody crossed EIF, PCR, policy, epoch, release, or completion state",
    )
    custody_completion_identity, custody_core_sha256 = (
        verify_custody_completion_binding(custody)
    )
    require(
        custody_completion_identity == production_completion_identity,
        "runtime custody crossed production completion identity",
    )
    recipient_der = b64url_decode(
        custody["recipientPublicKeySpkiDerBase64url"],
        "runtime custody recipient SPKI",
        max_bytes=8192,
    )
    recipient_spki = require_sha256(
        custody["recipientPublicKeySpkiSha256"],
        "runtime custody Nitro recipient key",
    )
    require(recipient_spki == sha256(recipient_der), "runtime custody recipient SPKI digest mismatch")
    try:
        recipient_key = serialization.load_der_public_key(recipient_der)
    except ValueError as exc:
        raise VerificationError("runtime custody recipient SPKI is invalid DER") from exc
    require(
        isinstance(recipient_key, rsa.RSAPublicKey)
        and 2048 <= recipient_key.key_size <= 4096
        and recipient_key.public_numbers().e == 65537,
        "runtime custody recipient key is not RSA OAEP compatible",
    )
    generation_signer_der = b64url_decode(
        custody["generationSignerPublicKeySpkiDerBase64url"],
        "custody generation signer SPKI",
        max_bytes=8192,
    )
    require(
        custody["generationSignerPublicKeySpkiSha256"]
        == sha256(generation_signer_der),
        "custody generation signer SPKI digest mismatch",
    )
    try:
        generation_signer = serialization.load_der_public_key(
            generation_signer_der
        )
    except ValueError as exc:
        raise VerificationError("custody generation signer is invalid DER") from exc
    require(
        isinstance(generation_signer, Ed25519PublicKey),
        "custody generation signer is not Ed25519",
    )
    generation_signer_id = sha256(generation_signer_der)
    material_names = MATERIALS
    materials = custody["materials"]
    require(
        isinstance(materials, list)
        and [item.get("name") for item in materials if isinstance(item, dict)]
        == list(material_names),
        "runtime custody material inventory is not exact and ordered",
    )
    generation_binding = {
        "broker-kek": "brokerKek",
        "ca": "ca",
        "credentials": "credentialRelease",
        "release": "release",
        "response": "response",
        "tls": "tls",
    }
    normalized_materials: dict[str, dict[str, Any]] = {}
    for raw_material in materials:
        material = exact_keys(
            raw_material,
            {
                "generationStatement",
                "identityPublicKeySpkiDerBase64url",
                "identitySpkiSha256",
                "keyGeneration",
                "kmsEncryptionContextSha256",
                "kmsRecipientRelease",
                "name",
                "scopeSigningKey",
            },
            "runtime custody material",
        )
        name = material["name"]
        identity_der = b64url_decode(
            material["identityPublicKeySpkiDerBase64url"],
            f"{name} identity SPKI",
            max_bytes=8192,
        )
        require(
            material["identitySpkiSha256"] == sha256(identity_der),
            f"{name} identity SPKI digest mismatch",
        )
        require_sha256(material["kmsEncryptionContextSha256"], f"{name} KMS context")
        require_uint(
            material["keyGeneration"],
            f"{name} runtime custody key generation",
        )
        require(
            material["keyGeneration"]
            == generations[generation_binding[name]],
            f"{name} runtime custody generation mismatch",
        )
        generation_statement = exact_keys(
            material["generationStatement"],
            {
                "apiVersion",
                "nitroDocumentBase64url",
                "nitroDocumentSha256",
                "payload",
                "payloadSha256",
                "signature",
                "signingKeyId",
            },
            f"{name} generation statement",
        )
        generation_payload = exact_keys(
            generation_statement["payload"],
            {
                "challengeNonce",
                "identitySpkiSha256",
                "keyGeneration",
                "pcrs",
                "policyHash",
                "recipientSpkiSha256",
                "releaseGeneration",
                "role",
                "rollbackEpoch",
            },
            f"{name} generation payload",
        )
        expected_generation = {
            "identitySpkiSha256": material["identitySpkiSha256"],
            "keyGeneration": material["keyGeneration"],
            "pcrs": expectations["pcrs"],
            "policyHash": runtime["policyHash"],
            "recipientSpkiSha256": recipient_spki,
            "releaseGeneration": runtime["releaseGeneration"],
            "role": name,
            "rollbackEpoch": runtime["rollbackEpoch"],
        }
        require_uint(
            generation_payload["keyGeneration"],
            f"{name} generation payload key generation",
        )
        require_uint(
            generation_payload["releaseGeneration"],
            f"{name} generation payload release generation",
        )
        require_uint(
            generation_payload["rollbackEpoch"],
            f"{name} generation payload rollback epoch",
        )
        for field, expected_value in expected_generation.items():
            require(
                generation_payload[field] == expected_value,
                f"{name} generation payload {field} mismatch",
            )
        generation_payload_sha256 = sha256_json(generation_payload)
        require(
            generation_statement["apiVersion"] == KEY_GENERATION_VERSION
            and generation_statement["payloadSha256"]
            == generation_payload_sha256
            and generation_statement["signingKeyId"] == generation_signer_id,
            f"{name} generation statement metadata mismatch",
        )
        generation_signature = generation_statement["signature"]
        require(
            isinstance(generation_signature, str)
            and generation_signature.startswith("ed25519:"),
            f"{name} generation signature encoding is invalid",
        )
        verify_ed25519(
            generation_signer,
            generation_signature.split(":", 1)[1],
            KEY_GENERATION_DOMAIN
            + canonical_json_bytes(
                {
                    "payload": generation_payload,
                    "payloadSha256": generation_payload_sha256,
                }
            ),
            f"{name} generation statement",
        )
        generation_nonce = b64url_decode(
            generation_payload["challengeNonce"],
            f"{name} generation challenge",
            max_bytes=32,
        )
        require(len(generation_nonce) == 32, f"{name} generation challenge is not 32 bytes")
        generation_nitro_raw = b64url_decode(
            generation_statement["nitroDocumentBase64url"],
            f"{name} generation Nitro document",
            max_bytes=MAX_NITRO_BYTES,
        )
        require(
            generation_statement["nitroDocumentSha256"]
            == sha256(generation_nitro_raw),
            f"{name} generation Nitro document digest mismatch",
        )
        generation_nitro = verify_nitro_document(
            generation_nitro_raw,
            claims=None,
            expected_user_data_bytes=(
                KEY_GENERATION_USER_DATA_PREFIX
                + bytes.fromhex(generation_payload_sha256[7:])
            ),
            challenge=generation_nonce,
            expected_pcrs=expectations["pcrs"],
            expected_eif=expectations["eifSha384"],
            roots=trust["awsRoots"],
            crls=trust["awsCrls"],
            certificate_profile=trust["certificateProfile"],
            expected_module_id=runtime["enclaveInstanceId"],
            now=now,
            max_age=expectations["maxQuoteAgeSeconds"],
            future_skew=expectations["maxFutureSkewSeconds"],
        )
        require(
            generation_nitro["recipientPublicKeySha256"] == recipient_spki,
            f"{name} generation quote crossed the enclave recipient key",
        )
        release = exact_keys(
            material["kmsRecipientRelease"],
            {
                "conditions",
                "encryptionContext",
                "encryptionContextSha256",
                "generationNitroDocumentSha256",
                "kmsKeyIdSha256",
                "rawResponseBase64url",
                "rawResponseSha256",
            },
            f"{name} KMS Recipient release",
        )
        conditions = exact_keys(
            release["conditions"],
            {
                "eifImageSha384",
                "identitySpkiSha256",
                "keyGeneration",
                "pcrs",
                "pipeline",
                "policyHash",
                "recipientSpkiSha256",
                "releaseGeneration",
                "role",
                "rollbackEpoch",
            },
            f"{name} KMS release conditions",
        )
        require_uint(
            conditions["keyGeneration"],
            f"{name} KMS condition key generation",
        )
        require_uint(
            conditions["releaseGeneration"],
            f"{name} KMS condition release generation",
        )
        require_uint(
            conditions["rollbackEpoch"],
            f"{name} KMS condition rollback epoch",
        )
        require(
            conditions
            == {
                "eifImageSha384": expectations["eifSha384"],
                "identitySpkiSha256": material["identitySpkiSha256"],
                "keyGeneration": material["keyGeneration"],
                "pcrs": expectations["pcrs"],
                "pipeline": PIPELINE,
                "policyHash": runtime["policyHash"],
                "recipientSpkiSha256": recipient_spki,
                "releaseGeneration": runtime["releaseGeneration"],
                "role": name,
                "rollbackEpoch": runtime["rollbackEpoch"],
            },
            f"{name} KMS release conditions mismatch",
        )
        context = exact_keys(
            release["encryptionContext"],
            {
                "identitySpkiSha256",
                "pipeline",
                "policyHash",
                "recipientSpkiSha256",
                "releaseGeneration",
                "role",
                "rollbackEpoch",
            },
            f"{name} KMS encryption context",
        )
        require_uint(
            context["releaseGeneration"],
            f"{name} KMS context release generation",
        )
        require_uint(
            context["rollbackEpoch"],
            f"{name} KMS context rollback epoch",
        )
        require(
            release["encryptionContextSha256"] == sha256_json(context)
            and release["encryptionContextSha256"]
            == material["kmsEncryptionContextSha256"]
            and release["generationNitroDocumentSha256"]
            == generation_statement["nitroDocumentSha256"],
            f"{name} KMS context or generation quote binding mismatch",
        )
        raw_response = b64url_decode(
            release["rawResponseBase64url"],
            f"{name} raw KMS response",
            max_bytes=MAX_CIPHERTEXT_BYTES * 2,
        )
        require(release["rawResponseSha256"] == sha256(raw_response), f"{name} raw KMS response digest mismatch")
        response_document = parse_json(raw_response, f"{name} raw KMS response")
        require(
            canonical_json_bytes(response_document) == raw_response,
            f"{name} raw KMS response is not canonical JSON",
        )
        response_document = exact_keys(
            response_document,
            {"CiphertextForRecipient", "KeyId"},
            f"{name} raw KMS response",
        )
        ciphertext = strict_b64_decode(
            response_document["CiphertextForRecipient"],
            f"{name} CiphertextForRecipient",
            max_bytes=MAX_CIPHERTEXT_BYTES,
        )
        require(ciphertext, f"{name} CiphertextForRecipient is empty")
        require_sha256(release["kmsKeyIdSha256"], f"{name} KMS key ID")
        require(
            release["kmsKeyIdSha256"]
            == sha256(response_document["KeyId"].encode("utf-8")),
            f"{name} KMS key ID digest mismatch",
        )
        scope_signing_key = material["scopeSigningKey"]
        if name == "tls":
            scope_signing_key = exact_keys(
                scope_signing_key,
                {
                    "keyGeneration",
                    "publicKeySpkiDerBase64url",
                    "publicKeySpkiSha256",
                },
                "TLS scope signing key",
            )
            scope_der = b64url_decode(
                scope_signing_key["publicKeySpkiDerBase64url"],
                "TLS scope signing SPKI",
                max_bytes=8192,
            )
            require(
                require_uint(
                    scope_signing_key["keyGeneration"],
                    "TLS scope signing key generation",
                )
                == generations["tlsScope"]
                and scope_signing_key["publicKeySpkiSha256"] == sha256(scope_der)
                and runtime["tlsScopeSigningKeySpkiSha256"] == sha256(scope_der),
                "TLS scope signing key crossed runtime custody",
            )
            try:
                scope_key = serialization.load_der_public_key(scope_der)
            except ValueError as exc:
                raise VerificationError("TLS scope signing key is invalid DER") from exc
            require(isinstance(scope_key, Ed25519PublicKey), "TLS scope signing key is not Ed25519")
        else:
            require(scope_signing_key is None, f"{name} has an unauthorized TLS scope key")
        normalized_materials[name] = material
    require(
        normalized_materials["ca"]["identitySpkiSha256"]
        == runtime["caSpkiSha256"],
        "runtime CA identity crossed key custody",
    )
    release_core_payload = {
        key: value
        for key, value in identity.items()
        if key
        not in {
            "builderStatementSha256s",
            "completionIdentity",
            "completionIdentitySha256",
            "monotonicWitnessSha256",
            "productionContinuitySha256",
            "productionReleaseIdentitySha256",
        }
    }
    release_core_payload["builderCoreSha256s"] = sorted(
        builder["coreSha256"] for builder in builders
    )
    release_core_payload["eifCoreSha256"] = candidate_to_eif["coreSha256"]
    release_core = completion_core("release", release_core_payload)
    runtime_core_payload = {
        key: value
        for key, value in runtime.items()
        if key
        not in {
            "completionIdentity",
            "completionIdentitySha256",
            "custodyEvidenceSha256",
            "productionIdentitySha256",
        }
    }
    runtime_core_payload["custodyCoreSha256"] = custody_core_sha256
    runtime_core_payload["releaseCoreSha256"] = sha256_json(release_core)
    runtime_core = completion_core("runtime", runtime_core_payload)
    return {
        "documentSha256": identity_file_sha256,
        "runtimeStateSha256": runtime_file_sha256,
        "runtimeCustodySha256": custody_file_sha256,
        "completionIdentity": production_completion_identity,
        "completionIdentitySha256": identity["completionIdentitySha256"],
        "releaseCore": release_core,
        "releaseCoreSha256": sha256_json(release_core),
        "runtimeCore": runtime_core,
        "runtimeCoreSha256": sha256_json(runtime_core),
        "custodyCoreSha256": custody_core_sha256,
        "payload": identity,
        "runtime": runtime,
        "custodyState": custody,
        "custodyMaterials": normalized_materials,
        "recipientPublicKeySha256": recipient_spki,
        "recipientPublicKeyDer": recipient_der,
        "tlsScopeKey": scope_key,
        "eif": {"sha384": identity["eifImageSha384"], "pcrs": identity["pcrs"]},
    }

def verify_kms_audit_proofs(
    documents: Any,
    *,
    identity: dict[str, Any],
    now: int,
    trust: dict[str, Any],
) -> dict[str, str]:
    documents = exact_keys(documents, MATERIALS, "KMS audit proof inventory")
    results: dict[str, str] = {}
    runtime = identity["runtime"]
    for name in MATERIALS:
        material = identity["custodyMaterials"][name]
        release = material["kmsRecipientRelease"]
        raw_response = b64url_decode(
            release["rawResponseBase64url"],
            f"{name} raw KMS response",
            max_bytes=MAX_CIPHERTEXT_BYTES * 2,
        )
        response_document = parse_json(raw_response, f"{name} raw KMS response")
        ciphertext = strict_b64_decode(
            response_document["CiphertextForRecipient"],
            f"{name} CiphertextForRecipient",
            max_bytes=MAX_CIPHERTEXT_BYTES,
        )
        payload, proof_sha256 = verify_standard_envelope(
            documents[name],
            api_version=KMS_AUDIT_VERSION,
            domain=KMS_AUDIT_DOMAIN,
            key=trust["keys"]["kmsAudit"],
            key_id=trust["keyIds"]["kmsAudit"],
            label=f"{name} independently authenticated AWS KMS audit proof",
        )
        payload = exact_keys(
            payload,
            {
                "accountId",
                "authentication",
                "conditionsSha256",
                "encryptionContextSha256",
                "eventId",
                "expiresAtUnix",
                "generationNitroDocumentSha256",
                "identitySpkiSha256",
                "issuedAtUnix",
                "keyGeneration",
                "kmsKeyIdSha256",
                "material",
                "pcrs",
                "policyHash",
                "provider",
                "rawResponseSha256",
                "recipientCiphertextSha256",
                "recipientSpkiSha256",
                "region",
                "releaseGeneration",
                "request",
                "requestSha256",
                "rollbackEpoch",
            },
            f"{name} AWS KMS audit payload",
        )
        authentication = exact_keys(
            payload["authentication"],
            {"evidenceSha256", "kind", "verifierInstanceSha256"},
            f"{name} AWS audit authentication",
        )
        require(
            authentication["kind"]
            in {
                "signed-cloudtrail-validation/v1",
                "attested-aws-kms-proxy/v1",
            },
            f"{name} AWS audit proof is not an authenticated closed subproof",
        )
        require_sha256(authentication["evidenceSha256"], f"{name} AWS audit evidence")
        require_sha256(authentication["verifierInstanceSha256"], f"{name} AWS verifier instance")
        request = exact_keys(
            payload["request"],
            {
                "ciphertextBlobSha256",
                "encryptionAlgorithm",
                "encryptionContext",
                "grantTokensSha256",
                "keyIdSha256",
                "recipientAttestationDocumentSha256",
                "recipientKeyEncryptionAlgorithm",
            },
            f"{name} authenticated AWS KMS request",
        )
        require(
            request["encryptionAlgorithm"] == "SYMMETRIC_DEFAULT"
            and request["recipientKeyEncryptionAlgorithm"] == "RSAES_OAEP_SHA_256"
            and request["encryptionContext"] == release["encryptionContext"]
            and request["keyIdSha256"] == release["kmsKeyIdSha256"]
            and request["recipientAttestationDocumentSha256"]
            == release["generationNitroDocumentSha256"],
            f"{name} authenticated AWS KMS request crossed the custody release",
        )
        for field in ("ciphertextBlobSha256", "grantTokensSha256"):
            require_sha256(request[field], f"{name} KMS request {field}")
        issued = require_uint(payload["issuedAtUnix"], f"{name} AWS audit issue time")
        expires = require_uint(payload["expiresAtUnix"], f"{name} AWS audit expiry")
        require_uint(
            payload["keyGeneration"],
            f"{name} AWS audit key generation",
        )
        require_uint(
            payload["releaseGeneration"],
            f"{name} AWS audit release generation",
        )
        require_uint(
            payload["rollbackEpoch"],
            f"{name} AWS audit rollback epoch",
        )
        require(
            issued <= now <= expires
            and expires - issued <= MAX_RELEASE_VALIDITY_SECONDS,
            f"{name} AWS KMS audit proof is stale or overlong",
        )
        require(
            payload["provider"] == "aws-kms-recipient-offline-audit/v1"
            and isinstance(payload["accountId"], str)
            and re.fullmatch(r"[0-9]{12}", payload["accountId"]) is not None
            and isinstance(payload["region"], str)
            and re.fullmatch(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]", payload["region"]) is not None,
            f"{name} AWS KMS audit provider/account/region is invalid",
        )
        require_identifier(payload["eventId"], f"{name} AWS KMS event ID")
        expected = {
            "conditionsSha256": sha256_json(release["conditions"]),
            "encryptionContextSha256": release["encryptionContextSha256"],
            "generationNitroDocumentSha256": release[
                "generationNitroDocumentSha256"
            ],
            "identitySpkiSha256": material["identitySpkiSha256"],
            "keyGeneration": material["keyGeneration"],
            "kmsKeyIdSha256": release["kmsKeyIdSha256"],
            "material": name,
            "pcrs": identity["eif"]["pcrs"],
            "policyHash": runtime["policyHash"],
            "rawResponseSha256": release["rawResponseSha256"],
            "recipientCiphertextSha256": sha256(ciphertext),
            "recipientSpkiSha256": identity["recipientPublicKeySha256"],
            "releaseGeneration": runtime["releaseGeneration"],
            "requestSha256": sha256_json(request),
            "rollbackEpoch": runtime["rollbackEpoch"],
        }
        for field, expected_value in expected.items():
            require(
                payload[field] == expected_value,
                f"{name} AWS KMS audit {field} mismatch",
            )
        results[name] = proof_sha256
    return results


def verify_claims(
    claims: Any,
    *,
    candidate: dict[str, Any],
    source: dict[str, Any],
    watchdog: dict[str, Any],
    promotion: dict[str, Any],
    builders: list[dict[str, Any]],
    identity: dict[str, Any],
    expectations: dict[str, Any],
    challenge: bytes,
    now: int,
) -> dict[str, Any]:
    claims = exact_keys(
        claims,
        {
            "apiVersion",
            "candidate",
            "challenge",
            "completion",
            "eif",
            "keyCustodySha256",
            "keyGenerations",
            "pipeline",
            "productionIdentitySha256",
            "promotedManifestSha256",
            "policy",
            "release",
            "requestSha256",
            "runtimeStateSha256",
            "tlsBinding",
        },
        "Nitro production claims",
    )
    require(claims["apiVersion"] == CLAIMS_VERSION, "Nitro production claims apiVersion mismatch")
    require(claims["pipeline"] == PIPELINE, "Nitro claims select an unsupported pipeline")
    runtime = identity["runtime"]
    candidate_claim = exact_keys(
        claims["candidate"],
        {
            "builderStatementSha256s",
            "buildWatchdogReceiptSha256",
            "candidateManifestFileSha256",
            "candidateManifestPayloadSha256",
            "dependencyClosureSha256",
            "importedImageMappingsSha256",
            "promotionReceiptSha256",
            "sourceClosureSha256",
            "sourceInputApprovalSha256",
            "sourceInputManifestFileSha256",
            "sourceInputManifestPayloadSha256",
        },
        "Nitro candidate claims",
    )
    require(
        candidate_claim
        == {
            "builderStatementSha256s": sorted(
                builder["statementFileSha256"] for builder in builders
            ),
            "buildWatchdogReceiptSha256": watchdog["fileSha256"],
            "candidateManifestFileSha256": candidate["fileSha256"],
            "candidateManifestPayloadSha256": candidate["payloadSha256"],
            "dependencyClosureSha256": candidate["dependencyClosureSha256"],
            "importedImageMappingsSha256": promotion[
                "importedImageMappingsSha256"
            ],
            "promotionReceiptSha256": promotion["fileSha256"],
            "sourceClosureSha256": candidate["sourceClosureSha256"],
            "sourceInputApprovalSha256": source[
                "untrackedApprovalPayloadSha256"
            ],
            "sourceInputManifestFileSha256": source["fileSha256"],
            "sourceInputManifestPayloadSha256": source["payloadSha256"],
        },
        "Nitro candidate claims crossed production release inputs",
    )
    challenge_claim = exact_keys(
        claims["challenge"],
        {
            "challengeId",
            "connectionId",
            "expiresAtUnix",
            "issuedAtUnix",
            "peerSpkiSha256",
            "value",
            "valueSha256",
        },
        "Nitro challenge claim",
    )
    challenge_value = b64url_decode(
        challenge_claim["value"], "Nitro challenge value", max_bytes=64
    )
    require(
        challenge_value == challenge
        and challenge_claim["valueSha256"] == sha256(challenge)
        and isinstance(challenge_claim["challengeId"], str)
        and UUID_RE.fullmatch(challenge_claim["challengeId"]) is not None,
        "Nitro challenge claim does not bind the exact one-use challenge",
    )
    challenge_issued = require_uint(
        challenge_claim["issuedAtUnix"], "Nitro challenge issue time"
    )
    challenge_expires = require_uint(
        challenge_claim["expiresAtUnix"], "Nitro challenge expiry"
    )
    require(
        challenge_issued <= now < challenge_expires
        and 15 <= challenge_expires - challenge_issued <= 300,
        "Nitro challenge is stale or has an unbounded validity window",
    )
    completion_claim = exact_keys(
        claims["completion"],
        {
            "completionIdentity",
            "completionIdentitySha256",
            "keyCustodyEvidenceSha256",
            "monotonicWitnessSha256",
            "productionContinuitySha256",
            "productionReleaseIdentitySha256",
        },
        "Nitro completion claim",
    )
    require(
        completion_claim
        == {
            "completionIdentity": identity["completionIdentity"],
            "completionIdentitySha256": identity["payload"]["completionIdentitySha256"],
            "keyCustodyEvidenceSha256": identity["runtimeCustodySha256"],
            "monotonicWitnessSha256": identity["payload"]["monotonicWitnessSha256"],
            "productionContinuitySha256": identity["payload"]["productionContinuitySha256"],
            "productionReleaseIdentitySha256": identity["payload"]["productionReleaseIdentitySha256"],
        },
        "Nitro completion claim crossed production identity",
    )
    require(
        exact_keys(claims["eif"], {"imageSha384", "pcrs"}, "Nitro EIF claim")
        == {
            "imageSha384": expectations["eifSha384"],
            "pcrs": expectations["pcrs"],
        },
        "Nitro EIF claims differ from independent expectations",
    )
    policy = exact_keys(
        claims["policy"], {"hash", "rollbackEpoch", "sequence"}, "Nitro policy claim"
    )
    require_uint(policy["rollbackEpoch"], "Nitro policy rollback epoch")
    require_uint(policy["sequence"], "Nitro policy sequence")
    require(
        policy
        == {
            "hash": runtime["policyHash"],
            "rollbackEpoch": runtime["rollbackEpoch"],
            "sequence": runtime["policySequence"],
        },
        "Nitro policy claim crossed runtime state",
    )
    release = exact_keys(
        claims["release"],
        {
            "caSpkiSha256",
            "generation",
            "releaseKeySpkiSha256",
            "responseKeySpkiSha256",
        },
        "Nitro release claim",
    )
    for field in (
        "caSpkiSha256",
        "releaseKeySpkiSha256",
        "responseKeySpkiSha256",
    ):
        require_sha256(release[field], f"Nitro release {field}")
    require_uint(release["generation"], "Nitro release generation")
    custody_materials = identity["custodyMaterials"]
    require(
        release
        == {
            "caSpkiSha256": runtime["caSpkiSha256"],
            "generation": runtime["releaseGeneration"],
            "releaseKeySpkiSha256": custody_materials["release"][
                "identitySpkiSha256"
            ],
            "responseKeySpkiSha256": custody_materials["response"][
                "identitySpkiSha256"
            ],
        },
        "Nitro release claim crossed runtime custody",
    )
    tls_binding = exact_keys(
        claims["tlsBinding"],
        {
            "apiVersion",
            "bindingSha256",
            "connectionId",
            "connectionNonceSha256",
            "enclaveBootId",
            "enclaveInstanceId",
            "expiresAtUnix",
            "exporterLabel",
            "exporterSha256",
            "issuedAtUnix",
            "leafCertificateSha256",
            "leafSpkiSha256",
            "peerCertificateSha256",
            "peerIdentity",
            "peerSpkiSha256",
            "provider",
            "tlsKeyGeneration",
            "tlsScopeEnvelopeSha256",
            "tlsScopeKeyGeneration",
            "tlsScopeKeySpkiSha256",
            "tlsStackMeasurementSha256",
        },
        "Nitro TLS scope claim",
    )
    binding_payload = dict(tls_binding)
    binding_sha256 = binding_payload.pop("bindingSha256")
    require(
        binding_sha256 == sha256_json(binding_payload)
        and tls_binding["apiVersion"] == TLS_BINDING_VERSION
        and isinstance(tls_binding["provider"], str)
        and tls_binding["provider"].startswith("enclave-")
        and tls_binding["exporterLabel"]
        == "EXPORTER-Serverware-Attestation-v1",
        "Nitro TLS scope is not the enclave-owned typed contract",
    )
    for field in (
        "exporterSha256",
        "connectionNonceSha256",
        "leafCertificateSha256",
        "leafSpkiSha256",
        "peerCertificateSha256",
        "peerSpkiSha256",
        "tlsScopeEnvelopeSha256",
        "tlsScopeKeySpkiSha256",
        "tlsStackMeasurementSha256",
    ):
        require_sha256(tls_binding[field], f"Nitro TLS {field}")
    require_uint(
        tls_binding["tlsKeyGeneration"],
        "Nitro TLS key generation",
    )
    require_uint(
        tls_binding["tlsScopeKeyGeneration"],
        "Nitro TLS scope key generation",
    )
    claim_generations = exact_keys(
        claims["keyGenerations"],
        runtime["keyGenerations"].keys(),
        "Nitro key generations",
    )
    for name, value in claim_generations.items():
        require_uint(value, f"Nitro {name} key generation")
    require(
        tls_binding["enclaveInstanceId"] == runtime["enclaveInstanceId"]
        and tls_binding["enclaveBootId"] == runtime["enclaveBootId"]
        and tls_binding["tlsKeyGeneration"] == runtime["keyGenerations"]["tls"]
        and tls_binding["tlsScopeKeyGeneration"]
        == runtime["keyGenerations"]["tlsScope"]
        and tls_binding["tlsScopeKeySpkiSha256"]
        == runtime["tlsScopeSigningKeySpkiSha256"]
        and tls_binding["leafSpkiSha256"]
        == custody_materials["tls"]["identitySpkiSha256"],
        "Nitro TLS scope crossed enclave runtime or TLS custody",
    )
    require(
        challenge_claim["connectionId"] == tls_binding["connectionId"]
        and challenge_claim["peerSpkiSha256"] == tls_binding["peerSpkiSha256"],
        "Nitro challenge was not issued for this exact TLS connection and peer",
    )
    require(
        claims["productionIdentitySha256"] == identity["documentSha256"]
        and claims["promotedManifestSha256"]
        == runtime["promotedManifestSha256"]
        and claims["runtimeStateSha256"] == identity["runtimeStateSha256"]
        and claims["keyCustodySha256"] == identity["runtimeCustodySha256"]
        and claim_generations == runtime["keyGenerations"],
        "Nitro state claims crossed remeasured production files",
    )
    require_sha256(claims["requestSha256"], "Nitro attestation request")
    return claims


def verify_tls_evidence(
    document: Any,
    *,
    identity: dict[str, Any],
    nitro: dict[str, Any],
    claims: dict[str, Any],
    expectations: dict[str, Any],
    challenge: bytes,
    now: int,
) -> dict[str, Any]:
    document = exact_keys(
        document,
        {
            "apiVersion",
            "exporterB64",
            "leafCertificateDerB64",
            "peerCertificateDerB64",
            "request",
            "trustedScopeEnvelope",
        },
        "live enclave TLS evidence",
    )
    require(
        document["apiVersion"] == TLS_EVIDENCE_VERSION,
        "live TLS evidence apiVersion mismatch",
    )
    scope_payload, scope_envelope_sha256 = verify_tls_scope_envelope(
        document["trustedScopeEnvelope"],
        key=identity["tlsScopeKey"],
        key_id=identity["runtime"]["tlsScopeSigningKeySpkiSha256"],
    )
    scope_payload = exact_keys(
        scope_payload,
        {
            "apiVersion",
            "connectionId",
            "connectionNonce",
            "enclaveBootId",
            "enclaveInstanceId",
            "expiresAtUnix",
            "exporter",
            "exporterLabel",
            "issuedAtUnix",
            "leafCertificateSha256",
            "leafSpkiSha256",
            "peerCertificateSha256",
            "peerIdentity",
            "peerSpkiSha256",
            "provider",
            "tlsKeyGeneration",
            "tlsScopeKeyGeneration",
            "tlsStackMeasurementSha256",
        },
        "live trusted TLS scope payload",
    )
    require_uint(
        scope_payload["tlsKeyGeneration"],
        "live TLS key generation",
    )
    require_uint(
        scope_payload["tlsScopeKeyGeneration"],
        "live TLS scope key generation",
    )
    connection_nonce = b64url_decode(
        scope_payload["connectionNonce"], "TLS connection nonce", max_bytes=32
    )
    scope_exporter = b64url_decode(
        scope_payload["exporter"], "TLS scope exporter", max_bytes=64
    )
    require(
        len(connection_nonce) == 32 and 32 <= len(scope_exporter) <= 64,
        "TLS scope nonce/exporter length is invalid",
    )
    binding_payload = {
        "apiVersion": TLS_BINDING_VERSION,
        "connectionId": scope_payload["connectionId"],
        "connectionNonceSha256": sha256(connection_nonce),
        "enclaveBootId": scope_payload["enclaveBootId"],
        "enclaveInstanceId": scope_payload["enclaveInstanceId"],
        "expiresAtUnix": scope_payload["expiresAtUnix"],
        "exporterLabel": scope_payload["exporterLabel"],
        "exporterSha256": sha256(scope_exporter),
        "issuedAtUnix": scope_payload["issuedAtUnix"],
        "leafCertificateSha256": scope_payload["leafCertificateSha256"],
        "leafSpkiSha256": scope_payload["leafSpkiSha256"],
        "peerCertificateSha256": scope_payload["peerCertificateSha256"],
        "peerIdentity": scope_payload["peerIdentity"],
        "peerSpkiSha256": scope_payload["peerSpkiSha256"],
        "provider": scope_payload["provider"],
        "tlsKeyGeneration": scope_payload["tlsKeyGeneration"],
        "tlsScopeEnvelopeSha256": scope_envelope_sha256,
        "tlsScopeKeyGeneration": scope_payload["tlsScopeKeyGeneration"],
        "tlsScopeKeySpkiSha256": identity["runtime"][
            "tlsScopeSigningKeySpkiSha256"
        ],
        "tlsStackMeasurementSha256": scope_payload[
            "tlsStackMeasurementSha256"
        ],
    }
    scope = {**binding_payload, "bindingSha256": sha256_json(binding_payload)}
    require(
        scope == claims["tlsBinding"],
        "live TLS scope differs from the Nitro-signed typed scope",
    )
    require(
        scope["exporterSha256"] == expectations["liveTlsExporterSha256"]
        and scope["leafSpkiSha256"]
        == expectations["liveTlsLeafSpkiSha256"]
        and scope["peerSpkiSha256"]
        == expectations["liveTlsPeerSpkiSha256"]
        and scope["tlsStackMeasurementSha256"]
        == expectations["tlsStackMeasurementSha256"],
        "Nitro TLS scope differs from independently observed live TLS evidence",
    )
    exporter = b64url_decode(
        document["exporterB64"], "TLS exporter", max_bytes=64
    )
    require(
        32 <= len(exporter) <= 64
        and exporter == scope_exporter
        and scope["exporterSha256"] == sha256(exporter),
        "TLS exporter bytes differ from the Nitro-signed exporter digest",
    )
    leaf_der = b64url_decode(
        document["leafCertificateDerB64"],
        "TLS leaf certificate",
        max_bytes=MAX_CERT_BYTES,
    )
    peer_der = b64url_decode(
        document["peerCertificateDerB64"],
        "TLS peer certificate",
        max_bytes=MAX_CERT_BYTES,
    )
    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
        peer = x509.load_der_x509_certificate(peer_der)
    except ValueError as exc:
        raise VerificationError("live TLS certificate evidence is invalid DER") from exc
    leaf_spki = leaf.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    peer_spki = peer.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    require(
        scope["leafCertificateSha256"] == sha256(leaf_der)
        and scope["leafSpkiSha256"] == sha256(leaf_spki)
        and scope["peerCertificateSha256"] == sha256(peer_der)
        and scope["peerSpkiSha256"] == sha256(peer_spki),
        "live TLS certificates or SPKIs differ from the Nitro-signed scope",
    )
    active_tls = identity["runtime"]["activeTlsConnection"]
    require(
        active_tls
        == {
            "connectionId": scope["connectionId"],
            "connectionNonceSha256": scope["connectionNonceSha256"],
            "envelopeSha256": scope["tlsScopeEnvelopeSha256"],
            "expiresAtUnix": scope["expiresAtUnix"],
            "exporterSha256": scope["exporterSha256"],
            "issuedAtUnix": scope["issuedAtUnix"],
            "leafCertificateSha256": scope["leafCertificateSha256"],
            "leafSpkiSha256": scope["leafSpkiSha256"],
            "peerCertificateSha256": scope["peerCertificateSha256"],
            "peerIdentity": scope["peerIdentity"],
            "peerSpkiSha256": scope["peerSpkiSha256"],
            "tlsStackMeasurementSha256": scope["tlsStackMeasurementSha256"],
        },
        "runtime active TLS connection differs from the signed TLS scope",
    )
    request = exact_keys(
        document["request"],
        {
            "apiVersion",
            "challengeId",
            "challengeSha256",
            "method",
            "path",
            "querySha256",
            "tlsBindingSha256",
        },
        "attestation request binding",
    )
    require(
        request["apiVersion"] == "serverware.attestationRequestBinding/v1"
        and request["challengeId"] == claims["challenge"]["challengeId"]
        and request["challengeSha256"] == sha256(challenge)
        and request["method"] == "GET"
        and request["path"] == "/attestation"
        and request["tlsBindingSha256"] == scope["bindingSha256"],
        "attestation request preimage is not the exact challenged TLS request",
    )
    require_sha256(request["querySha256"], "attestation query")
    request_sha256 = sha256_json(request)
    require(
        request_sha256 == claims["requestSha256"]
        and request_sha256 == expectations["attestationRequestSha256"],
        "live TLS evidence crossed the independently expected request digest",
    )
    return {
        "documentSha256": sha256(canonical_json_bytes(document) + b"\n"),
        "payload": {
            "exporterSha256": scope["exporterSha256"],
            "tlsSpkiSha256": scope["leafSpkiSha256"],
            "tlsPeerSpkiSha256": scope["peerSpkiSha256"],
            "tlsStackMeasurementSha256": scope[
                "tlsStackMeasurementSha256"
            ],
            "requestSha256": request_sha256,
            "bindingSha256": scope["bindingSha256"],
        },
        "exporter": exporter,
        "request": request,
    }


def verify_response_proof(
    proof: Any,
    *,
    identity: dict[str, Any],
    nitro: dict[str, Any],
    tls: dict[str, Any],
    claims: dict[str, Any],
    challenge: bytes,
    now: int,
) -> dict[str, Any]:
    proof = exact_keys(
        proof,
        {
            "orderedHeaders",
            "request",
            "responseBodyB64",
            "responseSigningPublicKeyPem",
            "signature",
            "statement",
            "status",
        },
        "exact response proof",
    )
    require(
        proof["request"] == tls["request"],
        "response proof request differs from live TLS request",
    )
    request_digest = tls["payload"]["requestSha256"]
    response_bytes = b64url_decode(
        proof["responseBodyB64"],
        "exact response bytes",
        max_bytes=MAX_RESPONSE_BYTES,
    )
    response_document = parse_json(
        response_bytes, "exact production attestation response body"
    )
    require(
        canonical_json_bytes(response_document) == response_bytes,
        "production attestation response body is not exact canonical JSON",
    )
    response_document = exact_keys(
        response_document,
        {
            "apiVersion",
            "assurance",
            "claims",
            "quote",
            "responseSigningPublicKeyPem",
        },
        "production attestation response body",
    )
    require(
        response_document["apiVersion"] == "serverware.productionAttestation/v2"
        and response_document["claims"] == claims
        and response_document["responseSigningPublicKeyPem"]
        == proof["responseSigningPublicKeyPem"],
        "production attestation response crossed claims or response key",
    )
    assurance = exact_keys(
        response_document["assurance"],
        {
            "class",
            "completionEligible",
            "externalVerificationRequired",
            "hostTlsAccepted",
            "reason",
        },
        "production attestation assurance",
    )
    require(
        assurance["class"] == "production-nitro-evidence"
        and assurance["completionEligible"] is False
        and assurance["externalVerificationRequired"] is True
        and assurance["hostTlsAccepted"] is False,
        "server response improperly claims self-verification or host-TLS assurance",
    )
    quote = exact_keys(
        response_document["quote"],
        {
            "attestation_document_b64",
            "attestation_document_sha256",
            "claims",
            "debug",
            "provider",
            "request_digest",
            "tee_platform",
            "user_data_sha256",
            "version",
        },
        "production Nitro quote wrapper",
    )
    raw_quote = b64url_decode(
        quote["attestation_document_b64"],
        "response Nitro document",
        max_bytes=MAX_NITRO_BYTES,
    )
    nitro_request_without_digest = {
        "apiVersion": "serverware.nitroAttestationRequest/v2",
        "binding": {
            "challenge": claims["challenge"],
            "requestSha256": claims["requestSha256"],
            "tlsBinding": claims["tlsBinding"],
        },
        "expectedRemeasurements": {
            "keyCustodySha256": identity["runtimeCustodySha256"],
            "productionIdentitySha256": identity["documentSha256"],
            "promotedManifestSha256": identity["runtime"][
                "promotedManifestSha256"
            ],
            "runtimeStateSha256": identity["runtimeStateSha256"],
        },
        "kind": "ProductionWorkloadRemeasurement",
        "provider": "aws-nitro-enclaves",
        "tee_platform": "aws-nitro",
    }
    require(
        raw_quote == nitro["raw"]
        and quote["attestation_document_sha256"]
        == nitro["attestationDocumentSha256"]
        and quote["claims"] == claims
        and quote["debug"] is False
        and "ok" not in quote
        and quote["provider"] == "aws-nitro-nsm"
        and quote["tee_platform"] == "aws-nitro"
        and quote["version"] == 2
        and quote["request_digest"] == sha256_json(nitro_request_without_digest)
        and quote["user_data_sha256"] == sha256(expected_user_data(claims)),
        "response quote wrapper differs from directly verified Nitro evidence",
    )
    key, response_key_id = load_ed25519_key(
        proof["responseSigningPublicKeyPem"], "response signing public key"
    )
    require(
        response_key_id == claims["release"]["responseKeySpkiSha256"],
        "response signing key differs from Nitro-signed runtime custody",
    )
    statement = exact_keys(
        proof["statement"],
        {
            "apiVersion",
            "bodySha256",
            "challengeId",
            "challengeSha256",
            "issuedAtUnix",
            "keyGenerations",
            "policy",
            "httpResponse",
            "quoteSha256",
            "release",
            "requestSha256",
            "responseSigningKeyId",
            "tlsBindingSha256",
        },
        "attestation response statement",
    )
    response_generations = exact_keys(
        statement["keyGenerations"],
        identity["runtime"]["keyGenerations"].keys(),
        "response statement key generations",
    )
    for name, value in response_generations.items():
        require_uint(value, f"response statement {name} key generation")
    response_policy = exact_keys(
        statement["policy"],
        {"hash", "rollbackEpoch", "sequence"},
        "response statement policy",
    )
    require_uint(
        response_policy["rollbackEpoch"],
        "response statement rollback epoch",
    )
    require_uint(
        response_policy["sequence"],
        "response statement policy sequence",
    )
    response_release = exact_keys(
        statement["release"],
        {
            "caSpkiSha256",
            "generation",
            "releaseKeySpkiSha256",
            "responseKeySpkiSha256",
        },
        "response statement release",
    )
    require_uint(
        response_release["generation"],
        "response statement release generation",
    )
    statement_issued = require_uint(
        statement["issuedAtUnix"], "response statement issue time"
    )
    require(
        nitro["issuedAtUnix"] <= statement_issued <= now
        and claims["challenge"]["issuedAtUnix"]
        <= statement_issued
        <= claims["challenge"]["expiresAtUnix"],
        "response statement is stale or future",
    )
    expected_statement = {
        "apiVersion": RESPONSE_STATEMENT_VERSION,
        "bodySha256": sha256(response_bytes),
        "challengeId": claims["challenge"]["challengeId"],
        "challengeSha256": sha256(challenge),
        "issuedAtUnix": statement_issued,
        "keyGenerations": claims["keyGenerations"],
        "policy": claims["policy"],
        "httpResponse": statement["httpResponse"],
        "quoteSha256": sha256_json(quote),
        "release": claims["release"],
        "requestSha256": request_digest,
        "responseSigningKeyId": response_key_id,
        "tlsBindingSha256": claims["tlsBinding"]["bindingSha256"],
    }
    require(
        statement == expected_statement,
        "attestation response statement does not bind the exact response",
    )
    status = require_uint(proof["status"], "attestation HTTP status", maximum=599)
    require(status == 200, "attestation HTTP status is not 200")
    core_headers = [
        {"name": "cache-control", "value": "no-store"},
        {"name": "pragma", "value": "no-cache"},
        {"name": "content-type", "value": "application/json"},
        {"name": "content-length", "value": str(len(response_bytes))},
        {
            "name": "x-serverware-attestation-body-sha256",
            "value": sha256(response_bytes),
        },
        {
            "name": "x-serverware-attestation-key-id",
            "value": response_key_id,
        },
        {
            "name": "x-serverware-attestation-request-sha256",
            "value": request_digest,
        },
        {
            "name": "x-serverware-attestation-tls-binding-sha256",
            "value": claims["tlsBinding"]["bindingSha256"],
        },
        {
            "name": "x-serverware-attestation-quote-sha256",
            "value": sha256_json(quote),
        },
    ]
    signature = proof["signature"]
    require(
        isinstance(signature, str) and signature.startswith("ed25519:"),
        "response statement signature encoding is invalid",
    )
    verify_ed25519(
        key,
        signature.split(":", 1)[1],
        canonical_json_bytes(statement),
        "response statement",
    )
    statement_sha256 = sha256(canonical_json_bytes(statement))
    detached_headers = [
        {
            "name": "x-serverware-attestation-statement-b64",
            "value": b64url_encode(canonical_json_bytes(statement)),
        },
        {
            "name": "x-serverware-attestation-statement-sha256",
            "value": statement_sha256,
        },
        {
            "name": "x-serverware-attestation-signature",
            "value": signature,
        },
    ]
    ordered_headers = proof["orderedHeaders"]
    require(
        ordered_headers == [*core_headers, *detached_headers],
        "attestation HTTP headers are not the exact closed ordered v2 envelope",
    )
    http_response = exact_keys(
        statement["httpResponse"],
        {
            "apiVersion",
            "bodyLength",
            "bodySha256",
            "coreHeaders",
            "detachedProofHeaders",
            "ordinaryHostTlsAccepted",
            "status",
            "transport",
        },
        "signed attestation HTTP response",
    )
    verify_detached_proof_headers(http_response["detachedProofHeaders"])
    require(
        http_response
        == {
            "apiVersion": HTTP_RESPONSE_VERSION,
            "bodyLength": len(response_bytes),
            "bodySha256": sha256(response_bytes),
            "coreHeaders": core_headers,
            "detachedProofHeaders": DETACHED_PROOF_HEADERS,
            "ordinaryHostTlsAccepted": False,
            "status": 200,
            "transport": "enclave-owned-tls-stack-with-authenticated-asgi-extension",
        },
        "response statement does not bind exact status, headers, length, and body",
    )
    response_core = completion_core(
        "response",
        {
            "challengeId": statement["challengeId"],
            "challengeSha256": statement["challengeSha256"],
            "exporterSha256": tls["payload"]["exporterSha256"],
            "httpStatus": status,
            "issuedAtUnix": statement_issued,
            "keyGenerations": statement["keyGenerations"],
            "leafSpkiSha256": claims["tlsBinding"]["leafSpkiSha256"],
            "peerSpkiSha256": claims["tlsBinding"]["peerSpkiSha256"],
            "policy": statement["policy"],
            "release": statement["release"],
            "requestSha256": request_digest,
            "responseSigningKeyId": response_key_id,
            "tlsBindingSha256": statement["tlsBindingSha256"],
        },
    )
    return {
        "statementSha256": statement_sha256,
        "requestSha256": request_digest,
        "responseBytesSha256": sha256(response_bytes),
        "key": key,
        "keyId": response_key_id,
        "quoteSha256": sha256_json(quote),
        "core": response_core,
        "coreSha256": sha256_json(response_core),
    }


def verify_kms_release(
    document: Any,
    *,
    material: str,
    generation: int,
    key_identity: str,
    identity: dict[str, Any],
    nitro: dict[str, Any],
    now: int,
    trust: dict[str, Any],
) -> dict[str, Any]:
    raise VerificationError(
        "legacy KMS release wrappers are incompatible with custody v3 and are rejected"
    )
    payload, document_digest = verify_standard_envelope(
        document,
        api_version=KMS_RELEASE_VERSION,
        domain=KMS_RELEASE_DOMAIN,
        key=trust["keys"]["kmsRelease"],
        key_id=trust["keyIds"]["kmsRelease"],
        label=f"{material} KMS Recipient release",
    )
    payload = exact_keys(
        payload,
        {
            "provider",
            "kmsKeyArn",
            "material",
            "keyIdentitySha256",
            "keyGeneration",
            "attestationDocumentSha256",
            "recipientPublicKeySha256",
            "recipientCiphertextB64",
            "recipientCiphertextSha256",
            "encryptionAlgorithm",
            "encryptionContext",
            "issuedAtUnix",
            "expiresAtUnix",
            "kmsRequestB64",
            "kmsRequestSha256",
            "kmsResponseB64",
            "kmsResponseSha256",
        },
        f"{material} KMS release payload",
    )
    require(payload["provider"] == "aws-kms-recipient", f"{material} release provider mismatch")
    require(
        isinstance(payload["kmsKeyArn"], str)
        and re.fullmatch(r"arn:aws(?:-[a-z]+)?:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9-]+", payload["kmsKeyArn"]),
        f"{material} KMS key ARN is invalid",
    )
    require(payload["material"] == material, f"{material} release material mismatch")
    require(payload["keyIdentitySha256"] == key_identity, f"{material} key identity mismatch")
    require(payload["keyGeneration"] == generation, f"{material} key generation mismatch")
    require(payload["attestationDocumentSha256"] == nitro["attestationDocumentSha256"], f"{material} KMS release crossed quote")
    require(payload["recipientPublicKeySha256"] == nitro["recipientPublicKeySha256"], f"{material} KMS recipient key mismatch")
    ciphertext = b64url_decode(
        payload["recipientCiphertextB64"],
        f"{material} recipient ciphertext",
        max_bytes=MAX_CIPHERTEXT_BYTES,
    )
    require(ciphertext, f"{material} recipient ciphertext is empty")
    require(payload["recipientCiphertextSha256"] == sha256(ciphertext), f"{material} recipient ciphertext digest mismatch")
    require(payload["encryptionAlgorithm"] == "RSAES_OAEP_SHA_256", f"{material} recipient encryption algorithm mismatch")
    runtime = identity["runtime"]
    release_roles = {
        "broker-kek": "broker-kek",
        "credential-store": "credentials",
        "decision-gate-ca": "ca",
        "tls-private-key": "tls",
        "response-signing-key": "response",
        "release-signing-key": "release",
        "policy-signing-key": "policy",
    }
    expected_context = {
        "keyRole": release_roles[material],
        "eifFileSha384": identity["eif"]["sha384"],
        "pcrs": identity["eif"]["pcrs"],
        "policyHash": runtime["policyHash"],
        "rollbackEpoch": runtime["rollbackEpoch"],
        "releaseGeneration": runtime["releaseGeneration"],
        "recipientPublicKeySpkiSha256": nitro["recipientPublicKeySha256"],
    }
    require(
        payload["encryptionContext"] == expected_context,
        f"{material} KMS encryption context mismatch",
    )
    issued = require_uint(payload["issuedAtUnix"], f"{material} KMS release time")
    expires = require_uint(payload["expiresAtUnix"], f"{material} KMS release expiry")
    require(issued <= now <= expires and expires - issued <= MAX_VALIDITY_SECONDS, f"{material} KMS release is stale or overlong")
    request_raw = b64url_decode(
        payload["kmsRequestB64"],
        f"{material} raw KMS request",
        max_bytes=MAX_CIPHERTEXT_BYTES * 2,
    )
    response_raw = b64url_decode(
        payload["kmsResponseB64"],
        f"{material} raw KMS response",
        max_bytes=MAX_CIPHERTEXT_BYTES * 2,
    )
    require(
        payload["kmsRequestSha256"] == sha256(request_raw)
        and payload["kmsResponseSha256"] == sha256(response_raw)
        and request_raw != response_raw,
        f"{material} raw KMS transcript digest mismatch",
    )
    kms_request = parse_json(request_raw, f"{material} raw KMS request")
    kms_response = parse_json(response_raw, f"{material} raw KMS response")
    require(
        canonical_json_bytes(kms_request) == request_raw
        and canonical_json_bytes(kms_response) == response_raw,
        f"{material} raw KMS transcript is not canonical JSON",
    )
    kms_request = exact_keys(
        kms_request,
        {
            "apiVersion",
            "ciphertextBlobSha256",
            "encryptionContext",
            "keyId",
            "recipient",
        },
        f"{material} KMS request transcript",
    )
    recipient_request = exact_keys(
        kms_request["recipient"],
        {
            "attestationDocumentSha256",
            "keyEncryptionAlgorithm",
            "publicKeySha256",
        },
        f"{material} KMS Recipient request",
    )
    require_sha256(
        kms_request["ciphertextBlobSha256"],
        f"{material} source KMS ciphertext",
    )
    require(
        kms_request["apiVersion"]
        == "serverware.awsKmsRecipientDecryptRequest/v1"
        and kms_request["keyId"] == payload["kmsKeyArn"]
        and kms_request["encryptionContext"] == expected_context
        and recipient_request
        == {
            "attestationDocumentSha256": nitro[
                "attestationDocumentSha256"
            ],
            "keyEncryptionAlgorithm": "RSAES_OAEP_SHA_256",
            "publicKeySha256": nitro["recipientPublicKeySha256"],
        },
        f"{material} KMS request did not bind the verified Recipient quote",
    )
    kms_response = exact_keys(
        kms_response,
        {
            "apiVersion",
            "ciphertextForRecipientB64",
            "keyEncryptionAlgorithm",
            "keyId",
        },
        f"{material} KMS response transcript",
    )
    transcript_ciphertext = b64url_decode(
        kms_response["ciphertextForRecipientB64"],
        f"{material} KMS response ciphertext",
        max_bytes=MAX_CIPHERTEXT_BYTES,
    )
    require(
        kms_response["apiVersion"]
        == "serverware.awsKmsRecipientDecryptResponse/v1"
        and kms_response["keyId"] == payload["kmsKeyArn"]
        and kms_response["keyEncryptionAlgorithm"]
        == "RSAES_OAEP_SHA_256"
        and transcript_ciphertext == ciphertext,
        f"{material} KMS response crossed key, algorithm, or ciphertext",
    )
    return {
        "documentSha256": document_digest,
        "recipientCiphertextSha256": payload["recipientCiphertextSha256"],
        "encryptionContextSha256": sha256_json(payload["encryptionContext"]),
        "kmsKeyArn": payload["kmsKeyArn"],
    }


def verify_release_custody(
    document: Any,
    *,
    identity: dict[str, Any],
    expectations: dict[str, Any],
    now: int,
    trust: dict[str, Any],
) -> dict[str, Any]:
    raise VerificationError(
        "legacy release-custody wrappers are incompatible with custody v3 and are rejected"
    )
    payload, file_sha256 = verify_existing_envelope(
        document,
        api_version=RELEASE_CUSTODY_VERSION,
        domain=RELEASE_CUSTODY_DOMAIN,
        key=trust["keys"]["releaseKeyCustody"],
        key_id=trust["keyIds"]["releaseKeyCustody"],
        label="release-completion key custody",
    )
    payload = exact_keys(
        payload,
        {
            "eifFileSha384",
            "enclaveBootId",
            "enclaveInstanceId",
            "expiresAtUnix",
            "issuedAtUnix",
            "keys",
            "pcrs",
            "pipeline",
            "policyHash",
            "releaseCoreIdentitySha256",
            "releaseGeneration",
            "rollbackEpoch",
        },
        "release-completion key-custody payload",
    )
    runtime = identity["runtime"]
    require(
        payload["pipeline"] == PIPELINE
        and payload["eifFileSha384"] == expectations["eifSha384"]
        and payload["pcrs"] == expectations["pcrs"]
        and payload["policyHash"] == runtime["policyHash"]
        and payload["releaseGeneration"] == runtime["releaseGeneration"]
        and payload["rollbackEpoch"] == runtime["rollbackEpoch"]
        and payload["enclaveBootId"] == runtime["enclaveBootId"]
        and payload["enclaveInstanceId"] == runtime["enclaveInstanceId"],
        "release-completion custody crossed runtime identity",
    )
    require_sha256(
        payload["releaseCoreIdentitySha256"],
        "release custody core identity",
    )
    issued = require_uint(payload["issuedAtUnix"], "release custody issue time")
    expires = require_uint(payload["expiresAtUnix"], "release custody expiry")
    require(
        issued <= now <= expires
        and issued < expires
        and expires - issued <= MAX_RELEASE_VALIDITY_SECONDS,
        "release-completion custody is stale, future, or overlong",
    )
    role_order = ("broker-kek", "credentials", "ca", "tls", "response", "release")
    keys = payload["keys"]
    require(
        isinstance(keys, list)
        and [item.get("role") for item in keys if isinstance(item, dict)]
        == list(role_order),
        "release-completion custody role inventory is not exact and ordered",
    )
    normalized: dict[str, dict[str, Any]] = {}
    runtime_materials = identity["custodyMaterials"]
    recipient_ids: set[str] = set()
    for item in keys:
        item = exact_keys(
            item,
            {
                "enclaveGenerationEvidenceSha256",
                "identitySpkiSha256",
                "kmsAttestationDocumentSha256",
                "kmsCiphertextForRecipientSha256",
                "kmsEncryptionContext",
                "kmsEncryptionContextSha256",
                "kmsKeyArnSha256",
                "plaintextExported",
                "recipientAlgorithm",
                "recipientKeyGeneration",
                "recipientPublicKeySpkiSha256",
                "releaseConditions",
                "role",
            },
            "release-completion custody key",
        )
        role = item["role"]
        require(
            item["plaintextExported"] is False
            and item["recipientAlgorithm"]
            == "RSAES_OAEP_SHA_256_CiphertextForRecipient",
            f"{role} release custody permits plaintext or a non-Recipient algorithm",
        )
        for field in (
            "enclaveGenerationEvidenceSha256",
            "identitySpkiSha256",
            "kmsAttestationDocumentSha256",
            "kmsCiphertextForRecipientSha256",
            "kmsEncryptionContextSha256",
            "kmsKeyArnSha256",
            "recipientPublicKeySpkiSha256",
        ):
            require_sha256(item[field], f"{role} release custody {field}")
        require(
            item["identitySpkiSha256"]
            == runtime_materials[role]["identitySpkiSha256"],
            f"{role} release custody identity crossed runtime custody",
        )
        recipient = item["recipientPublicKeySpkiSha256"]
        require(
            recipient not in recipient_ids,
            "release custody reuses a recipient key across roles",
        )
        recipient_ids.add(recipient)
        require_uint(
            item["recipientKeyGeneration"],
            f"{role} recipient key generation",
        )
        conditions = {
            "eifFileSha384": expectations["eifSha384"],
            "pcrs": expectations["pcrs"],
            "policyHash": runtime["policyHash"],
            "recipientPublicKeySpkiSha256": recipient,
            "releaseGeneration": runtime["releaseGeneration"],
            "rollbackEpoch": runtime["rollbackEpoch"],
        }
        require(
            item["releaseConditions"] == conditions
            and item["kmsEncryptionContext"] == {"keyRole": role, **conditions}
            and item["kmsEncryptionContextSha256"]
            == sha256_json(item["kmsEncryptionContext"]),
            f"{role} release custody conditions are not exact",
        )
        normalized[role] = {
            "identitySpkiSha256": item["identitySpkiSha256"],
            "recipientPublicKeySpkiSha256": item[
                "recipientPublicKeySpkiSha256"
            ],
            "recipientKeyGeneration": item["recipientKeyGeneration"],
            "kmsCiphertextForRecipientSha256": item[
                "kmsCiphertextForRecipientSha256"
            ],
            "kmsAttestationDocumentSha256": item[
                "kmsAttestationDocumentSha256"
            ],
            "enclaveGenerationEvidenceSha256": item[
                "enclaveGenerationEvidenceSha256"
            ],
            "kmsKeyArnSha256": item["kmsKeyArnSha256"],
            "kmsEncryptionContextSha256": item[
                "kmsEncryptionContextSha256"
            ],
        }
    return {
        "documentSha256": file_sha256,
        "payloadSha256": document["payloadSha256"],
        "signingKeyId": trust["keyIds"]["releaseKeyCustody"],
        "payload": payload,
        "keys": normalized,
        "keysSha256": sha256_json(normalized),
    }


def verify_key_custody(
    document: Any,
    *,
    identity: dict[str, Any],
    nitro: dict[str, Any],
    expectations: dict[str, Any],
    now: int,
    trust: dict[str, Any],
) -> dict[str, Any]:
    raise VerificationError(
        "legacy direct-custody transcripts are incompatible with custody v3 and are rejected"
    )
    payload, document_digest = verify_standard_envelope(
        document,
        api_version=CUSTODY_VERSION,
        domain=CUSTODY_DOMAIN,
        key=trust["keys"]["directKeyCustody"],
        key_id=trust["keyIds"]["directKeyCustody"],
        label="enclave key-custody evidence",
    )
    payload = exact_keys(
        payload,
        {
            "scope",
            "attestationDocumentSha256",
            "productionIdentitySha256",
            "enclaveInstanceId",
            "bootId",
            "materials",
            "transcriptSha256",
        },
        "enclave key-custody payload",
    )
    require(payload["scope"] == "inside-attested-eif-key-custody/v1", "key custody is not scoped to the attested EIF")
    require(payload["attestationDocumentSha256"] == nitro["attestationDocumentSha256"], "key custody crossed Nitro quote")
    require(payload["productionIdentitySha256"] == identity["documentSha256"], "key custody crossed production identity")
    runtime = identity["runtime"]
    require(
        payload["enclaveInstanceId"] == runtime["enclaveInstanceId"]
        and payload["bootId"] == runtime["enclaveBootId"],
        "key custody enclave instance/boot mismatch",
    )
    materials = payload["materials"]
    require(isinstance(materials, list) and [item.get("material") for item in materials if isinstance(item, dict)] == list(MATERIALS), "key-custody material inventory mismatch")
    summaries: list[dict[str, Any]] = []
    runtime_material_names = {
        "broker-kek": "broker-kek",
        "credential-store": "credentials",
        "decision-gate-ca": "ca",
        "tls-private-key": "tls",
        "response-signing-key": "response",
        "release-signing-key": "release",
    }
    runtime_generation_names = {
        "broker-kek": "brokerKek",
        "credential-store": "credentialRelease",
        "decision-gate-ca": "ca",
        "tls-private-key": "tls",
        "response-signing-key": "response",
        "release-signing-key": "release",
        "policy-signing-key": "policy",
    }
    observed_recipient_keys: set[str] = set()
    for record in materials:
        record = exact_keys(
            record,
            {
                "material",
                "keyIdentitySha256",
                "keyGeneration",
                "generation",
                "recipientAttestationClaims",
                "recipientAttestationDocumentB64",
                "recipientChallengeB64",
                "kmsRelease",
            },
            "key-custody material",
        )
        material = record["material"]
        key_identity = require_sha256(record["keyIdentitySha256"], f"{material} key identity")
        generation = require_uint(record["keyGeneration"], f"{material} key generation")
        require(
            generation
            == runtime["keyGenerations"][runtime_generation_names[material]],
            f"{material} runtime generation mismatch",
        )
        if material in runtime_material_names:
            require(
                key_identity
                == identity["custodyMaterials"][
                    runtime_material_names[material]
                ]["identitySpkiSha256"],
                f"{material} runtime key identity mismatch",
            )
        generation_event = exact_keys(
            record["generation"],
            {
                "scope",
                "algorithm",
                "keyIdentitySha256",
                "recipientPublicKeySha256",
                "generationNonceSha256",
                "generatedAtUnix",
                "privateKeyPolicy",
            },
            f"{material} generation event",
        )
        require(generation_event["scope"] == "inside-attested-nitro-enclave-csprng/v1", f"{material} was not generated in the attested enclave")
        require(
            generation_event["privateKeyPolicy"] == "non-exportable-recipient-only",
            f"{material} private-key custody policy permits export",
        )
        require(
            generation_event["keyIdentitySha256"] == key_identity,
            f"{material} generated key identity mismatch",
        )
        require_sha256(generation_event["generationNonceSha256"], f"{material} generation nonce")
        require_sha256(
            generation_event["recipientPublicKeySha256"],
            f"{material} Recipient public key",
        )
        generated = require_uint(generation_event["generatedAtUnix"], f"{material} generation time")
        require(
            isinstance(generation_event["algorithm"], str)
            and generation_event["algorithm"]
            in {"AES-256-GCM", "Ed25519", "ECDSA-P256", "RSA-3072"},
            f"{material} generation algorithm is unsupported",
        )
        recipient_claims = exact_keys(
            record["recipientAttestationClaims"],
            {
                "apiVersion",
                "bootId",
                "eif",
                "enclaveInstanceId",
                "keyGeneration",
                "keyIdentitySha256",
                "material",
                "pipeline",
                "policy",
                "productionIdentitySha256",
                "recipientPublicKeySha256",
                "recipientGenerationNonceSha256",
                "releaseGeneration",
            },
            f"{material} Recipient attestation claims",
        )
        require(
            recipient_claims
            == {
                "apiVersion": "serverware.kmsRecipientKeyClaims/v1",
                "bootId": runtime["enclaveBootId"],
                "eif": {
                    "imageSha384": expectations["eifSha384"],
                    "pcrs": expectations["pcrs"],
                },
                "enclaveInstanceId": runtime["enclaveInstanceId"],
                "keyGeneration": generation,
                "keyIdentitySha256": key_identity,
                "material": material,
                "pipeline": PIPELINE,
                "policy": {
                    "hash": runtime["policyHash"],
                    "rollbackEpoch": runtime["rollbackEpoch"],
                    "sequence": runtime["policySequence"],
                },
                "productionIdentitySha256": identity["documentSha256"],
                "recipientPublicKeySha256": recipient_claims[
                    "recipientPublicKeySha256"
                ],
                "recipientGenerationNonceSha256": generation_event[
                    "generationNonceSha256"
                ],
                "releaseGeneration": runtime["releaseGeneration"],
            },
            f"{material} Recipient claims crossed production state",
        )
        require_sha256(
            recipient_claims["recipientPublicKeySha256"],
            f"{material} Recipient claim public key",
        )
        recipient_challenge = b64url_decode(
            record["recipientChallengeB64"],
            f"{material} Recipient challenge",
            max_bytes=32,
        )
        require(
            len(recipient_challenge) == 32,
            f"{material} Recipient challenge must be exactly 32 bytes",
        )
        recipient_raw = b64url_decode(
            record["recipientAttestationDocumentB64"],
            f"{material} Recipient Nitro document",
            max_bytes=MAX_NITRO_BYTES,
        )
        recipient_nitro = verify_nitro_document(
            recipient_raw,
            claims=recipient_claims,
            challenge=recipient_challenge,
            expected_pcrs=expectations["pcrs"],
            expected_eif=expectations["eifSha384"],
            roots=trust["awsRoots"],
            now=now,
            max_age=expectations["maxQuoteAgeSeconds"],
            future_skew=expectations["maxFutureSkewSeconds"],
        )
        require(
            generation_event["recipientPublicKeySha256"]
            == recipient_nitro["recipientPublicKeySha256"]
            and recipient_claims["recipientPublicKeySha256"]
            == recipient_nitro["recipientPublicKeySha256"]
            and recipient_nitro["recipientPublicKeySha256"]
            not in observed_recipient_keys,
            f"{material} Recipient key is unbound or reused",
        )
        observed_recipient_keys.add(
            recipient_nitro["recipientPublicKeySha256"]
        )
        require(
            abs(generated - recipient_nitro["issuedAtUnix"])
            <= MAX_VALIDITY_SECONDS,
            f"{material} generation is not Recipient-quote-adjacent",
        )
        kms = verify_kms_release(
            record["kmsRelease"],
            material=material,
            generation=generation,
            key_identity=key_identity,
            identity=identity,
            nitro=recipient_nitro,
            now=now,
            trust=trust,
        )
        if material in runtime_material_names:
            runtime_material = identity["custodyMaterials"][
                runtime_material_names[material]
            ]
            require(
                kms["recipientCiphertextSha256"]
                == runtime_material["kmsCiphertextSha256"]
                and kms["encryptionContextSha256"]
                == runtime_material["kmsEncryptionContextSha256"],
                f"{material} direct KMS evidence crossed runtime custody",
            )
        summaries.append(
            {
                "material": material,
                "keyIdentitySha256": key_identity,
                "keyGeneration": generation,
                "kmsReleaseSha256": kms["documentSha256"],
                "recipientCiphertextSha256": kms["recipientCiphertextSha256"],
                "recipientPublicKeySha256": recipient_nitro[
                    "recipientPublicKeySha256"
                ],
                "recipientAttestationDocumentSha256": recipient_nitro[
                    "attestationDocumentSha256"
                ],
                "generationEvidenceSha256": sha256_json(generation_event),
                "kmsKeyArnSha256": sha256(
                    kms["kmsKeyArn"].encode("utf-8")
                ),
                "kmsEncryptionContextSha256": kms[
                    "encryptionContextSha256"
                ],
            }
        )
    require(payload["transcriptSha256"] == sha256_json(summaries), "key-custody transcript digest mismatch")
    return {
        "documentSha256": document_digest,
        "transcriptSha256": payload["transcriptSha256"],
        "materials": summaries,
    }


def verify_custody_bridge(
    release_custody: dict[str, Any],
    direct_custody: dict[str, Any],
) -> None:
    raise VerificationError(
        "legacy custody bridges are incompatible with custody v3 and are rejected"
    )
    direct_by_role = {
        {
            "broker-kek": "broker-kek",
            "credential-store": "credentials",
            "decision-gate-ca": "ca",
            "tls-private-key": "tls",
            "response-signing-key": "response",
            "release-signing-key": "release",
        }[item["material"]]: item
        for item in direct_custody["materials"]
        if item["material"] != "policy-signing-key"
    }
    require(
        set(direct_by_role) == set(release_custody["keys"]),
        "direct and release custody role inventories differ",
    )
    for role, release in release_custody["keys"].items():
        direct = direct_by_role[role]
        require(
            direct["keyIdentitySha256"] == release["identitySpkiSha256"]
            and direct["recipientPublicKeySha256"]
            == release["recipientPublicKeySpkiSha256"]
            and direct["recipientCiphertextSha256"]
            == release["kmsCiphertextForRecipientSha256"]
            and direct["recipientAttestationDocumentSha256"]
            == release["kmsAttestationDocumentSha256"]
            and direct["generationEvidenceSha256"]
            == release["enclaveGenerationEvidenceSha256"]
            and direct["kmsKeyArnSha256"] == release["kmsKeyArnSha256"]
            and direct["kmsEncryptionContextSha256"]
            == release["kmsEncryptionContextSha256"],
            f"{role} direct KMS evidence crossed release-completion custody",
        )


def verify_completion_release_identity(
    value: Any,
    *,
    candidate: dict[str, Any],
    source: dict[str, Any],
    watchdog: dict[str, Any],
    promotion: dict[str, Any],
    builders: list[dict[str, Any]],
    identity: dict[str, Any],
    release_custody: dict[str, Any],
) -> dict[str, Any]:
    raise VerificationError(
        "legacy release identity wrappers are incompatible with the public v2 bridge"
    )
    value = exact_keys(
        value,
        {
            "apiVersion",
            "buildWatchdog",
            "builders",
            "candidate",
            "completionIdentity",
            "completionIdentitySha256",
            "dependencies",
            "eif",
            "keyCustody",
            "pipeline",
            "productionReleaseIdentitySha256",
            "releaseCoreIdentitySha256",
            "releaseGeneration",
            "rollbackEpoch",
            "promotion",
            "source",
        },
        "completion production release identity",
    )
    require(
        value["apiVersion"] == "serverware.productionReleaseIdentity/v2"
        and value["pipeline"] == PIPELINE
        and value["releaseGeneration"] == identity["runtime"]["releaseGeneration"]
        and value["rollbackEpoch"] == identity["runtime"]["rollbackEpoch"],
        "completion production identity selected another pipeline or release",
    )
    release_completion_identity = verify_completion_identity(
        value["completionIdentity"],
        value["completionIdentitySha256"],
        label="completion production release identity",
    )
    require(
        release_completion_identity == identity["completionIdentity"]
        and value["completionIdentitySha256"]
        == identity["completionIdentitySha256"],
        "completion production release identity crossed completion identity",
    )
    production_payload = dict(value)
    production_digest = production_payload.pop("productionReleaseIdentitySha256")
    require(
        production_digest == sha256_json(production_payload),
        "completion production release identity digest is invalid",
    )
    release_core = {
        key: item
        for key, item in production_payload.items()
        if key not in {"keyCustody", "releaseCoreIdentitySha256"}
    }
    require(
        production_payload["releaseCoreIdentitySha256"] == sha256_json(release_core)
        and production_payload["releaseCoreIdentitySha256"]
        == release_custody["payload"]["releaseCoreIdentitySha256"],
        "completion release core crossed signed custody",
    )
    candidate_identity = exact_keys(
        value["candidate"],
        {
            "fileSha256",
            "imagesSha256",
            "payloadSha256",
            "promotionContractSha256",
        },
        "completion candidate identity",
    )
    require(
        candidate_identity
        == {
            "fileSha256": candidate["fileSha256"],
            "imagesSha256": candidate["candidateImagesSha256"],
            "payloadSha256": candidate["payloadSha256"],
            "promotionContractSha256": candidate["promotionContractSha256"],
        },
        "completion release identity crossed Candidate Manifest v6",
    )
    source_identity = exact_keys(
        value["source"],
        {
            "closureSha256",
            "gitInventoryKeyId",
            "gitInventoryPayloadSha256",
            "requiredUntrackedInventorySha256",
            "sourceInputManifestFileSha256",
            "sourceInputManifestPayloadSha256",
            "sourceManifestFileSha256",
            "sourceManifestPayloadSha256",
            "trackedInventorySha256",
            "untrackedApprovalKeyId",
            "untrackedApprovalPayloadSha256",
        },
        "completion source identity",
    )
    source_snapshot = candidate["sourceSnapshot"]
    require(
        source_identity["closureSha256"] == candidate["sourceClosureSha256"]
        and source_identity["sourceInputManifestFileSha256"]
        == source["fileSha256"]
        and source_identity["sourceInputManifestPayloadSha256"]
        == source["payloadSha256"]
        and source_identity["sourceManifestFileSha256"]
        == source_snapshot["sourceManifestFileSha256"]
        and source_identity["sourceManifestPayloadSha256"]
        == source_snapshot["sourceManifestPayloadSha256"]
        and source_identity["trackedInventorySha256"]
        == source["trackedInventorySha256"]
        and source_identity["requiredUntrackedInventorySha256"]
        == source["requiredUntrackedInventorySha256"]
        and source_identity["gitInventoryPayloadSha256"]
        == source["gitInventoryPayloadSha256"]
        and source_identity["untrackedApprovalPayloadSha256"]
        == source["untrackedApprovalPayloadSha256"],
        "completion release identity crossed source selection or closure",
    )
    require(
        source_identity["gitInventoryKeyId"]
        == source_snapshot["sourceGitInventoryKeySpkiSha256"]
        and source_identity["untrackedApprovalKeyId"]
        == source_snapshot["sourceUntrackedApprovalKeySpkiSha256"],
        "completion release identity crossed source-approval trust keys",
    )
    watchdog_identity = value["buildWatchdog"]
    require(
        isinstance(watchdog_identity, dict)
        and watchdog_identity.get("fileSha256") == watchdog["fileSha256"]
        and watchdog_identity.get("payloadSha256") == watchdog["payloadSha256"]
        and watchdog_identity.get("eventHeadSha256")
        == watchdog["eventHeadSha256"],
        "completion release identity crossed build-watchdog evidence",
    )
    promotion_identity = value["promotion"]
    require(
        isinstance(promotion_identity, dict)
        and promotion_identity.get("fileSha256") == promotion["fileSha256"]
        and promotion_identity.get("payloadSha256") == promotion["payloadSha256"]
        and promotion_identity.get("finalManifestSha256")
        == promotion["finalManifestSha256"]
        and promotion_identity.get("acceptanceSha256")
        == promotion["promotionAcceptanceSha256"]
        and promotion_identity.get("imageMappingsSha256")
        == promotion["importedImageMappingsSha256"]
        and promotion_identity.get("importedImages") == promotion["images"],
        "completion release identity crossed promotion or imported images",
    )
    builder_identity = value["builders"]
    left, right = builders
    require(
        isinstance(builder_identity, dict)
        and builder_identity.get("leftStatementSha256")
        == left["statementFileSha256"]
        and builder_identity.get("leftStatementPayloadSha256")
        == left["statementPayloadSha256"]
        and builder_identity.get("leftTranscriptSha256")
        == left["transcriptFileSha256"]
        and builder_identity.get("leftTranscriptPayloadSha256")
        == left["transcriptSha256"]
        and builder_identity.get("leftKeyId") == left["signingKeyId"]
        and builder_identity.get("rightStatementSha256")
        == right["statementFileSha256"]
        and builder_identity.get("rightStatementPayloadSha256")
        == right["statementPayloadSha256"]
        and builder_identity.get("rightTranscriptSha256")
        == right["transcriptFileSha256"]
        and builder_identity.get("rightTranscriptPayloadSha256")
        == right["transcriptSha256"]
        and builder_identity.get("rightKeyId") == right["signingKeyId"],
        "completion release identity crossed raw builder statements/transcripts",
    )
    dependencies = value["dependencies"]
    require(
        isinstance(dependencies, dict)
        and dependencies.get("fileSha256")
        == candidate["dependencyManifestFileSha256"]
        and dependencies.get("manifestSha256")
        == candidate["dependencyBundleSha256"]
        and dependencies.get("roleClosures")
        == candidate["dependencyRoleClosures"]
        and dependencies.get("roleClosuresSha256")
        == candidate["dependencyRoleClosuresSha256"],
        "completion release identity crossed dependency closure",
    )
    eif = value["eif"]
    require(
        isinstance(eif, dict)
        and eif.get("eifFileSha384") == identity["eif"]["sha384"]
        and eif.get("pcrs") == identity["eif"]["pcrs"],
        "completion release identity crossed independently expected EIF/PCRs",
    )
    for field in (
        "buildStatementFileSha256",
        "buildStatementPayloadSha256",
        "buildStatementKeyId",
    ):
        require_sha256(eif.get(field), f"completion EIF {field}")
    custody_identity = exact_keys(
        value["keyCustody"],
        {
            "evidenceFileSha256",
            "evidencePayloadSha256",
            "identityAndCustodyDistinguished",
            "keys",
            "keysSha256",
            "kmsCiphertextForRecipientBound",
            "verifierKeyId",
        },
        "completion release custody identity",
    )
    require(
        custody_identity["evidenceFileSha256"]
        == release_custody["documentSha256"]
        and custody_identity["evidencePayloadSha256"]
        == release_custody["payloadSha256"]
        and custody_identity["verifierKeyId"]
        == identity_key_id(release_custody, "release custody")
        and custody_identity["keys"] == release_custody["keys"]
        and custody_identity["keysSha256"] == release_custody["keysSha256"]
        and custody_identity["identityAndCustodyDistinguished"] is True
        and custody_identity["kmsCiphertextForRecipientBound"] is True,
        "completion release identity crossed release custody evidence",
    )
    return {
        "productionReleaseIdentitySha256": production_digest,
        "releaseCoreIdentitySha256": production_payload[
            "releaseCoreIdentitySha256"
        ],
    }


def identity_key_id(document: dict[str, Any], label: str) -> str:
    key_id = document.get("signingKeyId")
    return require_sha256(key_id, f"{label} signing key")


def validate_completion_v6_contract_shape(
    document: Any,
) -> dict[str, Any]:
    readiness_fields = {
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
    validate_json_shape(document, label="completionProof/v6")
    require(
        isinstance(document, dict)
        and set(document) == readiness_fields
        and document["apiVersion"] == COMPLETION_PROOF_VERSION
        and document["kind"] == "ServerwarePreEnclaveReadiness"
        and document["verificationOk"] is True
        and document["finalCompletionVerified"] is False
        and document["actionAuthorization"] is None
        and document["okForAction"] is False
        and document["verification_passed"] is True
        and document["verification_mode"] == "readiness"
        and document["result_scope"] == "readiness-only"
        and document["readiness_only"] is True
        and document["readiness_ok"] is True
        and document["completion_status"] == "pre-enclave-readiness"
        and document["release_completion"] == "not-final"
        and document["hardware_proof"] is False
        and document["independently_authenticated"] is False
        and document["final_challenge_consumption"]
        == {"required": False, "consumed": False}
        and document["aggregate_authentication"]
        == {
            "required": False,
            "independently_authenticated": False,
            "scope": "readiness-only",
        },
        "completionProof/v6 is strictly optional, non-authoritative host readiness context",
    )
    require_sha256(
        document["proof_core_sha256"],
        "completionProof/v6 readiness core",
    )
    integrity = exact_keys(
        document["integrity_metadata"],
        {
            "apiVersion",
            "authenticity_requires_external_signature_or_checkpoint",
            "detached_sha256_path",
            "publicationToken",
            "independently_authenticated",
            "scope",
        },
        "completionProof/v6 readiness integrity metadata",
    )
    require(
        integrity["apiVersion"] == READINESS_CHECKSUM_API_VERSION
        and isinstance(integrity["publicationToken"], str)
        and re.fullmatch(r"[0-9a-f]{32}", integrity["publicationToken"]) is not None
        and isinstance(integrity["detached_sha256_path"], str)
        and 1 <= len(integrity["detached_sha256_path"]) <= 4096
        and "\x00" not in integrity["detached_sha256_path"]
        and re.search(r"(^|/)\.{1,2}(/|$)|//", integrity["detached_sha256_path"]) is None,
        "completionProof/v6 integrity metadata is not the closed readinessChecksum/v1 contract",
    )
    require(
        integrity["scope"] == "checksum-only"
        and integrity["independently_authenticated"] is False
        and integrity[
            "authenticity_requires_external_signature_or_checkpoint"
        ]
        is True
        and "public_verifier_bridge"
        not in canonical_json_bytes(document).decode("utf-8")
        and "completionProofFileB64"
        not in canonical_json_bytes(document).decode("utf-8"),
        "completionProof/v6 cannot carry final or public-verifier bridge authority",
    )
    return document


def merkle_leaf_hash(value: Any) -> bytes:
    return hashlib.sha256(b"\x00" + canonical_json_bytes(value)).digest()


def merkle_node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def digest_bytes(value: str, label: str) -> bytes:
    require_sha256(value, label)
    return bytes.fromhex(value[7:])


def verify_inclusion(
    *,
    leaf: Any,
    leaf_index: int,
    tree_size: int,
    proof: list[str],
    expected_root: str,
) -> None:
    verify_indexed_merkle_inclusion(
        leaf_sha256="sha256:" + merkle_leaf_hash(leaf).hex(),
        leaf_index=leaf_index,
        tree_size=tree_size,
        proof=proof,
        root_sha256=expected_root,
        label="witness release inclusion",
    )


def verify_consistency(
    *,
    old_size: int,
    new_size: int,
    old_root: str,
    new_root: str,
    proof: list[str],
) -> None:
    require(0 <= old_size <= new_size, "witness consistency sizes are invalid")
    require(len(proof) <= 64, "witness consistency proof is too long")
    if old_size == 0:
        require(proof == [], "genesis consistency proof must be empty")
        return
    if old_size == new_size:
        require(proof == [] and old_root == new_root, "equal-size witness roots differ")
        return
    nodes = [digest_bytes(item, "witness consistency node") for item in proof]
    require(nodes, "witness consistency proof is missing")
    fn = old_size - 1
    sn = new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if fn == 0:
        first = digest_bytes(old_root, "prior witness root")
        old_hash = first
        new_hash = first
        offset = 0
    else:
        old_hash = nodes[0]
        new_hash = nodes[0]
        offset = 1
    for node in nodes[offset:]:
        if fn & 1 or fn == sn:
            old_hash = merkle_node_hash(node, old_hash)
            new_hash = merkle_node_hash(node, new_hash)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            new_hash = merkle_node_hash(new_hash, node)
        fn >>= 1
        sn >>= 1
    require(
        fn == 0
        and sn == 0
        and "sha256:" + old_hash.hex() == old_root
        and "sha256:" + new_hash.hex() == new_root,
        "witness consistency proof is invalid",
    )


def verify_witness(
    document: Any,
    *,
    prior: dict[str, Any],
    completion: dict[str, Any],
    identity: dict[str, Any],
    candidate: dict[str, Any],
    promotion: dict[str, Any],
    response: dict[str, Any],
    challenge: bytes,
    now: int,
    trust: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    payload, checkpoint_digest = verify_standard_envelope(
        document,
        api_version=WITNESS_VERSION,
        domain=WITNESS_DOMAIN,
        key=trust["keys"]["witness"],
        key_id=trust["keyIds"]["witness"],
        label="off-host monotonic witness",
    )
    payload = exact_keys(
        payload,
        {
            "challengeConsumption",
            "completionIdentity",
            "completionIdentitySha256",
            "consistencyProof",
            "expiresAtUnix",
            "inclusion",
            "issuedAtUnix",
            "logId",
            "priorStateSha256",
            "provider",
            "releaseGeneration",
            "releaseCoreSha256",
            "revocation",
            "rollbackEpoch",
            "sequence",
            "treeSize",
            "rootHash",
        },
        "off-host witness payload",
    )
    require(
        trust["keyIds"]["witness"] == prior["witnessKeyId"]
        and payload["provider"] == prior["provider"]
        and payload["logId"] == prior["logId"]
        and payload["priorStateSha256"] == prior["stateSha256"],
        "witness key, provider, log, or prior durable state changed",
    )
    issued = require_uint(payload["issuedAtUnix"], "witness issue time")
    expires = require_uint(payload["expiresAtUnix"], "witness expiry")
    require(
        issued <= now <= expires
        and expires - issued <= MAX_RELEASE_VALIDITY_SECONDS,
        "witness checkpoint is stale or overlong",
    )
    sequence = require_uint(payload["sequence"], "witness sequence")
    tree_size = require_uint(payload["treeSize"], "witness tree size")
    generation = require_uint(
        payload["releaseGeneration"], "witness release generation"
    )
    epoch = require_uint(payload["rollbackEpoch"], "witness rollback epoch")
    root = require_sha256(payload["rootHash"], "witness root hash")
    witness_completion_identity = verify_completion_identity(
        payload["completionIdentity"],
        payload["completionIdentitySha256"],
        label="witness completion identity",
    )
    require(
        payload["releaseCoreSha256"]
        == identity["releaseCoreSha256"]
        and witness_completion_identity == completion["completionIdentity"]
        and payload["completionIdentitySha256"]
        == completion["completionIdentitySha256"]
        and generation == identity["runtime"]["releaseGeneration"]
        and epoch == identity["runtime"]["rollbackEpoch"],
        "witness crossed the completion release identity",
    )
    require(
        sequence > prior["sequence"]
        and tree_size > prior["treeSize"]
        and (
            epoch > prior["rollbackEpoch"]
            or (
                epoch == prior["rollbackEpoch"]
                and generation >= prior["releaseGeneration"]
            )
        ),
        "witness high-water did not advance from durable state",
    )
    consistency = payload["consistencyProof"]
    require(isinstance(consistency, list), "witness consistency proof is invalid")
    verify_consistency(
        old_size=prior["treeSize"],
        new_size=tree_size,
        old_root=prior["rootHash"],
        new_root=root,
        proof=consistency,
    )
    leaf = {
        "releaseGeneration": generation,
        "releaseCoreSha256": identity["releaseCoreSha256"],
        "rollbackEpoch": epoch,
    }
    expected_leaf = sha256(b"\x00" + canonical_json_bytes(leaf))
    inclusion = exact_keys(
        payload["inclusion"],
        {
            "leafIndex",
            "leafSha256",
            "proof",
            "rootHash",
            "treeSize",
        },
        "witness release inclusion",
    )
    proof = inclusion["proof"]
    inclusion_tree_size = require_uint(
        inclusion["treeSize"],
        "witness inclusion tree size",
    )
    require(
        inclusion["leafSha256"] == expected_leaf
        and inclusion["rootHash"] == root
        and inclusion_tree_size == tree_size,
        "witness release inclusion proof is invalid",
    )
    leaf_index = require_uint(
        inclusion["leafIndex"],
        "witness leaf index",
    )
    verify_indexed_merkle_inclusion(
        leaf_sha256=expected_leaf,
        leaf_index=leaf_index,
        tree_size=tree_size,
        proof=proof,
        root_sha256=root,
        label="witness release inclusion",
    )
    revocation = exact_keys(
        payload["revocation"],
        {
            "asOfUnix",
            "completionIdentity",
            "completionIdentitySha256",
            "releaseCoreSha256",
            "revocationListSha256",
            "revokedIdentities",
            "status",
        },
        "witness current revocation",
    )
    revoked = revocation["revokedIdentities"]
    require(
        isinstance(revoked, list)
        and revoked == sorted(set(revoked))
        and all(isinstance(item, str) and SHA256_RE.fullmatch(item) for item in revoked)
        and revocation["revocationListSha256"] == sha256_json(revoked)
        and revocation["releaseCoreSha256"]
        == identity["releaseCoreSha256"]
        and revocation["completionIdentity"] == completion["completionIdentity"]
        and revocation["completionIdentitySha256"]
        == completion["completionIdentitySha256"]
        and revocation["status"] == "active"
        and revocation["asOfUnix"] == issued
        and identity["releaseCoreSha256"] not in revoked,
        "witness revocation data is stale, malformed, or revokes this release",
    )
    consumption = exact_keys(
        payload["challengeConsumption"],
        {
            "challengeNonceSha256",
            "consumedAtUnix",
            "consumptionId",
            "expiresAtUnix",
            "oneUse",
            "status",
        },
        "witness challenge consumption",
    )
    require_identifier(consumption["consumptionId"], "challenge consumption ID")
    require(
        consumption["challengeNonceSha256"] == sha256(challenge)
        and consumption["status"] == "consumed"
        and consumption["oneUse"] is True
        and consumption["consumedAtUnix"] == issued
        and consumption["expiresAtUnix"] == expires,
        "witness did not atomically consume the exact one-use challenge",
    )
    challenge_consumption_sha256 = sha256_json(consumption)
    require(
        challenge_consumption_sha256
        != prior["challengeConsumptionSha256"],
        "witness reused a prior challenge-consumption record",
    )
    next_state_payload = {
        "apiVersion": CLIENT_STATE_VERSION,
        "challengeConsumptionSha256": challenge_consumption_sha256,
        "checkpointSha256": checkpoint_digest,
        "logId": prior["logId"],
        "provider": prior["provider"],
        "releaseGeneration": generation,
        "rollbackEpoch": epoch,
        "rootHash": root,
        "sequence": sequence,
        "treeSize": tree_size,
        "witnessKeyId": trust["keyIds"]["witness"],
    }
    next_state = {
        **next_state_payload,
        "stateSha256": sha256_json(next_state_payload),
    }
    witness_core_payload = without_completion_bindings(payload)
    witness_core = completion_core("witness", witness_core_payload)
    return {
        "checkpointSha256": checkpoint_digest,
        "completionIdentity": completion["completionIdentity"],
        "completionIdentitySha256": completion["completionIdentitySha256"],
        "core": witness_core,
        "coreSha256": sha256_json(witness_core),
        "productionReleaseIdentitySha256": completion[
            "productionReleaseIdentitySha256"
        ],
        "releaseGeneration": generation,
        "rollbackEpoch": epoch,
        "sequence": sequence,
        "treeSize": tree_size,
        "rootHash": root,
        "leafIndex": leaf_index,
        "consumptionId": consumption["consumptionId"],
        "challengeConsumptionSha256": challenge_consumption_sha256,
        "revocationChecked": True,
    }, next_state


def verify_bundle(
    bundle: Any,
    *,
    expectations: dict[str, Any],
    trust: dict[str, Any],
    prior_state: dict[str, Any],
    challenge: bytes,
    now: int,
) -> dict[str, Any]:
    reject_public_secret_fields(bundle)
    required_bundle_fields = {
            "apiVersion",
            "kind",
            "pipeline",
            "rawNitroAttestationDocumentB64",
            "claims",
            "candidateManifestFileB64",
            "sourceInputManifestFileB64",
            "buildWatchdogReceiptFileB64",
            "promotionReceiptFileB64",
            "promotedManifestFileB64",
            "builders",
            "candidateToEifBuildStatementFileB64",
            "productionIdentityFileB64",
            "runtimeStateFileB64",
            "runtimeKeyCustodyFileB64",
            "kmsAuditProofs",
            "tlsEvidence",
            "responseProof",
            "witness",
    }
    readiness_bundle_fields = {
        "completionProofFileB64",
        "completionProofAuthentication",
        "completionProofCheckpoint",
    }
    require(
        isinstance(bundle, dict)
        and required_bundle_fields <= set(bundle)
        and set(bundle) <= required_bundle_fields | readiness_bundle_fields
        and (
            not readiness_bundle_fields.intersection(bundle)
            or readiness_bundle_fields <= set(bundle)
        ),
        "public Nitro verification bundle fields are missing, unknown, or contain a partial readiness context",
    )
    require(bundle["apiVersion"] == BUNDLE_VERSION, "public evidence bundle apiVersion mismatch")
    require(bundle["kind"] == "ServerwarePublicNitroVerificationBundle", "public evidence bundle kind mismatch")
    require(bundle["pipeline"] == PIPELINE, "development or legacy Docker /dev/nsm evidence is not accepted")
    require(expectations["pipeline"] == PIPELINE, "independent expectations do not select production Manifest v6 Nitro")
    require(
        expectations["trustRootBundleSha256"] == trust["trustRootBundleSha256"]
        and expectations["trustRootKeyIds"] == trust["keyIds"],
        "expectations do not pin the exact trust-root bundle and every role key",
    )
    require(len(challenge) == 32, "caller challenge must be exactly 32 bytes")

    source_doc, source_raw = decode_canonical_json_file_b64(
        bundle["sourceInputManifestFileB64"],
        "source-input manifest file",
    )
    require(sha256(source_raw) == expectations["sourceInputManifestFileSha256"], "source-input file differs from independent expectation")
    source = verify_source_evidence(source_doc, source_raw, trust=trust)
    require(
        source["payloadSha256"]
        == expectations["sourceInputManifestPayloadSha256"],
        "source-input payload differs from independent expectation",
    )

    candidate_doc, candidate_raw = decode_canonical_json_file_b64(
        bundle["candidateManifestFileB64"],
        "Candidate Manifest v6 file",
    )
    require(sha256(candidate_raw) == expectations["candidateManifestFileSha256"], "Candidate Manifest file differs from independent expectation")
    candidate = verify_candidate(
        candidate_doc,
        candidate_raw,
        source=source_doc,
        source_raw=source_raw,
    )
    require(candidate["payloadSha256"] == expectations["candidateManifestPayloadSha256"], "Candidate Manifest payload differs from independent expectation")
    require(
        candidate["sourceClosureSha256"] == expectations["sourceClosureSha256"]
        and candidate["dependencyRoleClosuresSha256"]
        == expectations["dependencyClosureSha256"],
        "candidate source/dependency closure differs from independent expectation",
    )

    watchdog_doc, watchdog_raw = decode_canonical_json_file_b64(
        bundle["buildWatchdogReceiptFileB64"],
        "build-watchdog receipt file",
    )
    require(sha256(watchdog_raw) == expectations["buildWatchdogReceiptFileSha256"], "build-watchdog receipt differs from independent expectation")
    watchdog = verify_build_watchdog(
        watchdog_doc,
        watchdog_raw,
        candidate=candidate,
        trust=trust,
    )
    require(
        watchdog["payloadSha256"]
        == expectations["buildWatchdogReceiptPayloadSha256"],
        "build-watchdog payload differs from independent expectation",
    )

    promotion_doc, promotion_raw = decode_canonical_json_file_b64(
        bundle["promotionReceiptFileB64"],
        "promotion receipt file",
    )
    require(sha256(promotion_raw) == expectations["promotionReceiptFileSha256"], "promotion receipt differs from independent expectation")
    promotion = verify_promotion(
        promotion_doc,
        promotion_raw,
        candidate=candidate,
        trust=trust,
    )
    require(
        promotion["payloadSha256"]
        == expectations["promotionReceiptPayloadSha256"],
        "promotion payload differs from independent expectation",
    )
    promoted_doc, promoted_raw = decode_canonical_json_file_b64(
        bundle["promotedManifestFileB64"],
        "promoted Manifest v6 file",
    )
    promoted = verify_promoted_manifest(
        promoted_doc,
        promoted_raw,
        candidate=candidate,
        promotion=promotion,
    )
    require(
        promoted["fileSha256"] == expectations["promotedManifestFileSha256"],
        "promoted Manifest v6 differs from independent expectation",
    )
    require(
        promoted["manifestSha256"]
        == expectations["promotedManifestPayloadSha256"]
        and promoted["imageMappingsSha256"]
        == expectations["importedImageMappingsSha256"],
        "promoted manifest payload or mappings differ from independent expectation",
    )
    source_core = completion_core(
        "source",
        {
            "buildWatchdogReceiptFileSha256": watchdog["fileSha256"],
            "buildWatchdogReceiptPayloadSha256": watchdog["payloadSha256"],
            "candidateManifestFileSha256": candidate["fileSha256"],
            "candidateManifestPayloadSha256": candidate["payloadSha256"],
            "dependencyClosureSha256": candidate[
                "dependencyRoleClosuresSha256"
            ],
            "sourceClosureSha256": candidate["sourceClosureSha256"],
            "sourceInputManifestFileSha256": source["fileSha256"],
            "sourceInputManifestPayloadSha256": source["payloadSha256"],
        },
    )
    promotion_core = completion_core(
        "promotion",
        {
            "importedImageMappingsSha256": promoted["imageMappingsSha256"],
            "promotedManifestFileSha256": promoted["fileSha256"],
            "promotedManifestPayloadSha256": promoted["manifestSha256"],
            "promotionReceiptFileSha256": promotion["fileSha256"],
            "promotionReceiptPayloadSha256": promotion["payloadSha256"],
        },
    )
    trust_core = completion_core(
        "trust",
        {
            "roleKeyIds": trust["keyIds"],
            "trustRootBundleSha256": trust["trustRootBundleSha256"],
        },
    )

    builders_doc = bundle["builders"]
    require(
        isinstance(builders_doc, list) and len(builders_doc) == 2,
        "exactly two raw builder statements/transcripts are required",
    )
    builders = [
        verify_builder(
            builders_doc[index],
            role=role,
            candidate=candidate,
            source=source,
            watchdog=watchdog,
            expectations=expectations,
            trust=trust,
        )
        for index, role in enumerate(("builderA", "builderB"))
    ]
    require(builders[0]["builderId"] != builders[1]["builderId"], "builder identities are not independent")
    require(builders[0]["buildId"] != builders[1]["buildId"], "builder executions are not independent")
    require(builders[0]["operatorId"] != builders[1]["operatorId"], "builder operators are not independent")
    for builder in builders:
        require(
            builder["issuedAtUnix"] <= now <= builder["expiresAtUnix"],
            "builder statement is stale or future",
        )
    require(builders[0]["outputsSha256"] == builders[1]["outputsSha256"], "independent builders produced different outputs")
    require(
        builders[0]["commandContractSha256"]
        == builders[1]["commandContractSha256"],
        "independent builders measured different command contracts",
    )
    eif_statement_doc, eif_statement_raw = decode_canonical_json_file_b64(
        bundle["candidateToEifBuildStatementFileB64"],
        "Manifest v6 candidate-to-EIF build statement",
    )
    candidate_to_eif = verify_candidate_to_eif(
        eif_statement_doc,
        eif_statement_raw,
        candidate=candidate,
        source=source,
        watchdog=watchdog,
        promotion=promotion,
        promoted=promoted,
        builders=builders,
        expectations=expectations,
        trust=trust,
    )

    identity_doc, identity_raw = decode_canonical_json_file_b64(
        bundle["productionIdentityFileB64"],
        "production attestation identity file",
    )
    runtime_doc, runtime_raw = decode_canonical_json_file_b64(
        bundle["runtimeStateFileB64"],
        "production runtime state file",
    )
    runtime_custody_doc, runtime_custody_raw = decode_canonical_json_file_b64(
        bundle["runtimeKeyCustodyFileB64"],
        "runtime key-custody file",
    )
    identity = verify_production_identity(
        identity_doc,
        identity_raw,
        runtime_doc,
        runtime_raw,
        runtime_custody_doc,
        runtime_custody_raw,
        promoted=promoted,
        candidate=candidate,
        source=source,
        watchdog=watchdog,
        promotion=promotion,
        builders=builders,
        candidate_to_eif=candidate_to_eif,
        expectations=expectations,
        trust=trust,
        now=now,
    )
    require(identity["documentSha256"] == expectations["productionIdentitySha256"], "production identity differs from independent expectation")
    kms_audits = verify_kms_audit_proofs(
        bundle["kmsAuditProofs"],
        identity=identity,
        now=now,
        trust=trust,
    )

    claims = verify_claims(
        bundle["claims"],
        candidate=candidate,
        source=source,
        watchdog=watchdog,
        promotion=promotion,
        builders=builders,
        identity=identity,
        expectations=expectations,
        challenge=challenge,
        now=now,
    )
    raw_nitro = b64url_decode(
        bundle["rawNitroAttestationDocumentB64"],
        "raw Nitro attestation document",
        max_bytes=MAX_NITRO_BYTES,
    )
    nitro = verify_nitro_document(
        raw_nitro,
        claims=claims,
        challenge=challenge,
        expected_pcrs=expectations["pcrs"],
        expected_eif=expectations["eifSha384"],
        roots=trust["awsRoots"],
        crls=trust["awsCrls"],
        certificate_profile=trust["certificateProfile"],
        expected_module_id=expectations["nitroModuleId"],
        now=now,
        max_age=expectations["maxQuoteAgeSeconds"],
        future_skew=expectations["maxFutureSkewSeconds"],
    )
    require(
        identity["recipientPublicKeySha256"]
        == nitro["recipientPublicKeySha256"],
        "runtime custody recipient key differs from the Nitro-attested key",
    )
    require(
        nitro["moduleId"] == identity["runtime"]["enclaveInstanceId"],
        "Nitro module_id differs from the remeasured enclave instance",
    )
    hardware_core = completion_core(
        "hardware",
        {
            "eifSha384": expectations["eifSha384"],
            "moduleId": nitro["moduleId"],
            "pcrs": nitro["pcrs"],
            "recipientPublicKeySha256": nitro["recipientPublicKeySha256"],
        },
    )

    tls = verify_tls_evidence(
        bundle["tlsEvidence"],
        identity=identity,
        nitro=nitro,
        claims=claims,
        expectations=expectations,
        challenge=challenge,
        now=now,
    )
    response = verify_response_proof(
        bundle["responseProof"],
        identity=identity,
        nitro=nitro,
        tls=tls,
        claims=claims,
        challenge=challenge,
        now=now,
    )
    readiness_sha256 = None
    if readiness_bundle_fields <= set(bundle):
        completion_doc, completion_raw = decode_canonical_json_file_b64(
            bundle["completionProofFileB64"],
            "optional completionProof/v6 readiness file",
        )
        validate_completion_v6_contract_shape(completion_doc)
        require(
            bundle["completionProofAuthentication"] is None
            and bundle["completionProofCheckpoint"] is None,
            "completionProof/v6 readiness context cannot carry final authentication artifacts",
        )
        readiness_sha256 = sha256(completion_raw)
    release_identity = reconstruct_release_identity(
        identity=identity,
        candidate_to_eif=candidate_to_eif,
        trust=trust,
    )
    completion = {
        "completionIdentity": expectations["completionIdentity"],
        "completionIdentitySha256": expectations[
            "completionIdentitySha256"
        ],
        "productionReleaseIdentitySha256": sha256_json(
            release_identity
        ),
        "readinessContextSha256": readiness_sha256,
    }
    witness, next_state = verify_witness(
        bundle["witness"],
        prior=prior_state,
        completion=completion,
        identity=identity,
        candidate=candidate,
        promotion=promotion,
        response=response,
        challenge=challenge,
        now=now,
        trust=trust,
    )
    core_digests = {
        "builderA": builders[0]["coreSha256"],
        "builderB": builders[1]["coreSha256"],
        "custody": identity["custodyCoreSha256"],
        "eif": candidate_to_eif["coreSha256"],
        "hardware": sha256_json(hardware_core),
        "promotion": sha256_json(promotion_core),
        "release": identity["releaseCoreSha256"],
        "response": response["coreSha256"],
        "runtime": identity["runtimeCoreSha256"],
        "source": sha256_json(source_core),
        "trust": sha256_json(trust_core),
        "witness": witness["coreSha256"],
    }
    core_digests["continuity"] = reconstruct_continuity_core_digest(
        core_digests=core_digests,
        challenge_nonce_sha256=sha256(challenge),
        release_generation=identity["runtime"]["releaseGeneration"],
        rollback_epoch=identity["runtime"]["rollbackEpoch"],
    )
    reconstructed_completion_identity = reconstruct_completion_identity(
        core_digests=core_digests,
        challenge_nonce_sha256=sha256(challenge),
        release_generation=identity["runtime"]["releaseGeneration"],
        rollback_epoch=identity["runtime"]["rollbackEpoch"],
    )
    completion_identity_sha256 = verify_reconstructed_completion_identity(
        reconstructed_completion_identity,
        [
            (
                "independent expectations completion identity",
                expectations["completionIdentity"],
                expectations["completionIdentitySha256"],
            ),
            *[
                (
                    f"builder {index} completion identity",
                    builder["completionIdentity"],
                    builder["completionIdentitySha256"],
                )
                for index, builder in enumerate(builders)
            ],
            (
                "candidate-to-EIF completion identity",
                candidate_to_eif["completionIdentity"],
                candidate_to_eif["completionIdentitySha256"],
            ),
            (
                "production completion identity",
                identity["completionIdentity"],
                identity["completionIdentitySha256"],
            ),
            (
                "runtime completion identity",
                identity["runtime"]["completionIdentity"],
                identity["runtime"]["completionIdentitySha256"],
            ),
            (
                "custody completion identity",
                identity["custodyState"]["completionIdentity"],
                identity["custodyState"]["completionIdentitySha256"],
            ),
            (
                "Nitro claims completion identity",
                claims["completion"]["completionIdentity"],
                claims["completion"]["completionIdentitySha256"],
            ),
            (
                "completion proof identity",
                completion["completionIdentity"],
                completion["completionIdentitySha256"],
            ),
            (
                "witness completion identity",
                witness["completionIdentity"],
                witness["completionIdentitySha256"],
            ),
        ],
    )
    release_identity_sha256 = sha256_json(release_identity)
    return {
        "okForAction": False,
        "status": "pending-state-commit",
        "apiVersion": RESULT_VERSION,
        "pipeline": PIPELINE,
        "canonicalProfile": CANONICAL_PROFILE,
        "verifiedAtUnix": now,
        "evidenceBundleFileSha256": sha256(
            canonical_json_bytes(bundle) + b"\n"
        ),
        "expectationsFileSha256": sha256(
            canonical_json_bytes(expectations) + b"\n"
        ),
        "trustRootBundleFileSha256": trust[
            "trustRootBundleSha256"
        ],
        "productionIdentitySha256": identity["documentSha256"],
        "candidateManifestFileSha256": candidate["fileSha256"],
        "candidateManifestPayloadSha256": candidate["payloadSha256"],
        "sourceInputManifestFileSha256": source["fileSha256"],
        "sourceClosureSha256": candidate["sourceClosureSha256"],
        "buildWatchdogReceiptFileSha256": watchdog["fileSha256"],
        "promotionReceiptFileSha256": promotion["fileSha256"],
        "promotedManifestFileSha256": promoted["fileSha256"],
        "nitroAttestationDocumentSha256": nitro["attestationDocumentSha256"],
        "attestationRequestSha256": expectations[
            "attestationRequestSha256"
        ],
        "eifSha384": expectations["eifSha384"],
        "pcrs": expectations["pcrs"],
        "tlsExporterSha256": tls["payload"]["exporterSha256"],
        "tlsSpkiSha256": claims["tlsBinding"]["leafSpkiSha256"],
        "tlsPeerSpkiSha256": tls["payload"]["tlsPeerSpkiSha256"],
        "tlsStackMeasurementSha256": tls["payload"][
            "tlsStackMeasurementSha256"
        ],
        "requestSha256": response["requestSha256"],
        "responseBytesSha256": response["responseBytesSha256"],
        "completionIdentity": reconstructed_completion_identity,
        "completionIdentitySha256": completion_identity_sha256,
        "completionCoreDigests": core_digests,
        "releaseIdentity": release_identity,
        "releaseIdentitySha256": release_identity_sha256,
        "hostReadinessContextSha256": readiness_sha256,
        "runtimeKeyCustodyFileSha256": identity["runtimeCustodySha256"],
        "runtimeStateFileSha256": identity["runtimeStateSha256"],
        "candidateToEifBuildStatementFileSha256": candidate_to_eif["fileSha256"],
        "kmsAuditProofSha256s": kms_audits,
        "witness": witness,
        "nextClientState": next_state,
        "challengeConsumptionSha256": witness[
            "challengeConsumptionSha256"
        ],
        "stateTransition": {
            "oldStateSha256": prior_state["stateSha256"],
            "newStateSha256": next_state["stateSha256"],
            "transitionSha256": sha256_json(
                {
                    "oldStateSha256": prior_state["stateSha256"],
                    "newStateSha256": next_state["stateSha256"],
                }
            ),
        },
        "stateCommitRequired": (
            "persist nextClientState with durable compare-and-swap before "
            "accepting or acting on the response"
        ),
        "externalBoundary": (
            "AWS Nitro EIF/KMS, enclave TLS exporter extension, off-host "
            "witness, CAS/current-head reservation and atomic redemption "
            "store, independent builders/promoter, and their trust roots must "
            "be provisioned outside this verifier"
        ),
    }


def finalize_state_commit(
    pending: dict[str, Any],
    document: Any,
    *,
    trust: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    require(
        pending.get("status") == "pending-state-commit"
        and "ok" not in pending
        and pending.get("okForAction") is False,
        "only a pending verification result can be finalized",
    )
    payload, receipt_sha256 = verify_standard_envelope(
        document,
        api_version=STATE_COMMIT_VERSION,
        domain=STATE_COMMIT_DOMAIN,
        key=trust["keys"]["stateCommit"],
        key_id=trust["keyIds"]["stateCommit"],
        label="external compare-and-swap state commit",
    )
    payload = exact_keys(
        payload,
        {
            "commitId",
            "committedAtUnix",
            "compareAndSwap",
            "expiresAtUnix",
            "newStateSha256",
            "newRedemptionSequence",
            "newStoreGeneration",
            "oldHeadSha256",
            "oldRedemptionSequence",
            "oldStateSha256",
            "oldStoreGeneration",
            "storeId",
            "transitionSha256",
            "trustRootBundleSha256",
        },
        "external state commit payload",
    )
    transition = pending["stateTransition"]
    require(
        payload["compareAndSwap"] is True
        and payload["oldStateSha256"] == transition["oldStateSha256"]
        and payload["newStateSha256"] == transition["newStateSha256"]
        and payload["transitionSha256"] == transition["transitionSha256"]
        and payload["trustRootBundleSha256"]
        == trust["trustRootBundleSha256"],
        "state commit does not prove compare-and-swap of the exact old/new state",
    )
    old_store_generation = require_uint(
        payload["oldStoreGeneration"],
        "old state-store generation",
    )
    new_store_generation = require_uint(
        payload["newStoreGeneration"],
        "new state-store generation",
    )
    old_redemption_sequence = require_uint(
        payload["oldRedemptionSequence"],
        "old state-store redemption sequence",
    )
    new_redemption_sequence = require_uint(
        payload["newRedemptionSequence"],
        "new state-store redemption sequence",
    )
    require(
        new_store_generation == old_store_generation + 1,
        "state commit did not advance the monotonic store generation exactly once",
    )
    require(
        new_redemption_sequence == old_redemption_sequence,
        "state commit changed the one-use redemption sequence",
    )
    require_sha256(payload["oldHeadSha256"], "prior state-store head")
    require_identifier(payload["commitId"], "state commit ID")
    require_identifier(payload["storeId"], "state store ID")
    committed = require_uint(payload["committedAtUnix"], "state commit time")
    expires = require_uint(payload["expiresAtUnix"], "state commit expiry")
    require(
        committed <= now <= expires
        and expires - committed <= MAX_VALIDITY_SECONDS,
        "state commit receipt is stale or overlong",
    )
    receipt_identity = {
        "apiVersion": STATE_COMMIT_RECEIPT_IDENTITY_VERSION,
        "commitId": payload["commitId"],
        "receiptFileSha256": receipt_sha256,
        "receiptPayloadSha256": require_sha256(
            document.get("payloadSha256"),
            "state commit receipt payload",
        ),
        "signingKeyId": trust["keyIds"]["stateCommit"],
        "storeId": payload["storeId"],
    }
    pre_authorization_core = {
        "apiVersion": PRE_AUTHORIZATION_RESULT_CORE_VERSION,
        "canonicalProfile": CANONICAL_PROFILE,
        "challengeConsumptionSha256": pending[
            "challengeConsumptionSha256"
        ],
        "challengeNonceSha256": pending["completionIdentity"][
            "challengeNonceSha256"
        ],
        "completionIdentitySha256": pending["completionIdentitySha256"],
        "newStateSha256": transition["newStateSha256"],
        "oldStateSha256": transition["oldStateSha256"],
        "pendingResultSha256": sha256_json(pending),
        "pipeline": PIPELINE,
        "requestSha256": pending["requestSha256"],
        "responseBytesSha256": pending["responseBytesSha256"],
        "transitionSha256": transition["transitionSha256"],
    }
    pre_authorization_core_sha256 = sha256_json(pre_authorization_core)
    post_commit = {
        key: value
        for key, value in pending.items()
        if key != "stateCommitRequired"
    }
    return {
        **post_commit,
        "okForAction": False,
        "status": "pending-current-head-authorization",
        "preAuthorizationResultCore": pre_authorization_core,
        "preAuthorizationResultCoreSha256": pre_authorization_core_sha256,
        "stateCommitReceiptSha256": receipt_sha256,
        "stateCommitReceiptIdentity": receipt_identity,
        "stateCommitId": payload["commitId"],
        "stateCommitCommittedAtUnix": committed,
        "stateCommitExpiresAtUnix": expires,
        "stateStoreId": payload["storeId"],
        "stateStoreGeneration": new_store_generation,
        "stateStoreRedemptionSequence": new_redemption_sequence,
        "stateCommitPhase": "committed-awaiting-current-head-authorization",
        "currentHeadAuthorizationRequired": (
            "obtain a fresh one-use authorization from the external store for "
            "this exact committed state, current head, verifier nonce, "
            "challenge consumption, and pre-authorization result"
        ),
        "rollbackResistanceBoundary": (
            "the CAS receipt is historical transition evidence only and is "
            "not current-head authority"
        ),
    }


def authorize_current_head(
    pending: dict[str, Any],
    document: Any,
    *,
    verifier_nonce: bytes,
    trust: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    require(
        pending.get("status") == "pending-current-head-authorization"
        and "ok" not in pending
        and pending.get("okForAction") is False,
        "current-head authorization requires a verified post-CAS result",
    )
    require(
        len(verifier_nonce) == 32,
        "current-head verifier nonce must be exactly 32 fresh bytes",
    )
    payload, authorization_file_sha256 = verify_standard_envelope(
        document,
        api_version=CURRENT_HEAD_AUTHORIZATION_VERSION,
        domain=CURRENT_HEAD_AUTHORIZATION_DOMAIN,
        key=trust["keys"]["currentHeadAuthorization"],
        key_id=trust["keyIds"]["currentHeadAuthorization"],
        label="external current-head authorization",
    )
    payload = exact_keys(
        payload,
        {
            "authorizationId",
            "canonicalProfile",
            "challengeConsumptionSha256",
            "committedNewStateSha256",
            "completionIdentitySha256",
            "completionResultSha256",
            "currentHead",
            "currentHeadSha256",
            "expectedOldStateSha256",
            "expiresAtUnix",
            "headReservation",
            "issuedAtUnix",
            "oneUse",
            "preAuthorizationResultCoreSha256",
            "stateCommitReceiptIdentity",
            "status",
            "storeGeneration",
            "storeId",
            "transitionSha256",
            "trustRootBundleSha256",
            "verifierNonceConsumption",
        },
        "current-head authorization payload",
    )
    require_identifier(payload["authorizationId"], "current-head authorization ID")
    require(
        payload["canonicalProfile"] == CANONICAL_PROFILE
        and payload["status"] == "active"
        and payload["oneUse"] is True,
        "current-head authorization is not an active one-use canonical grant",
    )
    store_generation = require_uint(
        payload["storeGeneration"],
        "current-head authorization store generation",
    )
    pending_store_generation = require_uint(
        pending.get("stateStoreGeneration"),
        "pending current-head store generation",
    )
    pending_redemption_sequence = require_uint(
        pending.get("stateStoreRedemptionSequence"),
        "pending current-head redemption sequence",
    )
    transition = pending["stateTransition"]
    receipt_identity = exact_keys(
        payload["stateCommitReceiptIdentity"],
        {
            "apiVersion",
            "commitId",
            "receiptFileSha256",
            "receiptPayloadSha256",
            "signingKeyId",
            "storeId",
        },
        "current-head state-commit receipt identity",
    )
    for field in (
        "receiptFileSha256",
        "receiptPayloadSha256",
        "signingKeyId",
    ):
        require_sha256(
            receipt_identity[field],
            f"current-head receipt identity {field}",
        )
    require(
        receipt_identity == pending["stateCommitReceiptIdentity"],
        "current-head authorization substituted the authenticated CAS receipt",
    )
    completion_result_sha256 = sha256_json(pending)
    require(
        payload["storeId"] == pending["stateStoreId"]
        and store_generation == pending_store_generation
        and payload["expectedOldStateSha256"] == transition["oldStateSha256"]
        and payload["committedNewStateSha256"] == transition["newStateSha256"]
        and payload["transitionSha256"] == transition["transitionSha256"]
        and payload["challengeConsumptionSha256"]
        == pending["challengeConsumptionSha256"]
        and payload["completionIdentitySha256"]
        == pending["completionIdentitySha256"]
        and payload["preAuthorizationResultCoreSha256"]
        == pending["preAuthorizationResultCoreSha256"]
        and payload["completionResultSha256"] == completion_result_sha256
        and payload["trustRootBundleSha256"]
        == trust["trustRootBundleSha256"],
        "current-head authorization crossed the committed state or completion result",
    )
    current_head = exact_keys(
        payload["currentHead"],
        {
            "apiVersion",
            "challengeConsumptionSha256",
            "commitId",
            "generation",
            "redemptionSequence",
            "stateCommitReceiptSha256",
            "stateSha256",
            "storeId",
        },
        "current state-store head",
    )
    current_head_generation = require_uint(
        current_head["generation"],
        "current state-store head generation",
    )
    current_redemption_sequence = require_uint(
        current_head["redemptionSequence"],
        "current state-store redemption sequence",
    )
    require(
        current_head
        == {
            "apiVersion": STATE_STORE_HEAD_VERSION,
            "challengeConsumptionSha256": pending[
                "challengeConsumptionSha256"
            ],
            "commitId": pending["stateCommitId"],
            "generation": pending_store_generation,
            "redemptionSequence": pending_redemption_sequence,
            "stateCommitReceiptSha256": pending[
                "stateCommitReceiptSha256"
            ],
            "stateSha256": transition["newStateSha256"],
            "storeId": pending["stateStoreId"],
        }
        and payload["currentHeadSha256"] == sha256_json(current_head),
        "current-head authorization does not prove the exact committed head",
    )
    nonce_consumption = exact_keys(
        payload["verifierNonceConsumption"],
        {
            "consumedAtUnix",
            "consumptionId",
            "expiresAtUnix",
            "oneUse",
            "status",
            "verifierNonceSha256",
        },
        "current-head verifier nonce consumption",
    )
    require_identifier(
        nonce_consumption["consumptionId"],
        "current-head verifier nonce consumption ID",
    )
    reservation = exact_keys(
        payload["headReservation"],
        {
            "apiVersion",
            "authorizationId",
            "challengeConsumptionSha256",
            "completionResultSha256",
            "currentRedemptionSequence",
            "expectedFinalGeneration",
            "expectedOneUseSequence",
            "expiresAtUnix",
            "generation",
            "headSha256",
            "oneUse",
            "receiptIdentitySha256",
            "reservationId",
            "status",
            "storeId",
            "verifierNonceConsumptionSha256",
        },
        "current-head reservation",
    )
    require_identifier(
        reservation["reservationId"],
        "current-head reservation ID",
    )
    reservation_generation = require_uint(
        reservation["generation"],
        "current-head reservation generation",
    )
    reservation_current_sequence = require_uint(
        reservation["currentRedemptionSequence"],
        "current-head reservation current redemption sequence",
    )
    reservation_final_generation = require_uint(
        reservation["expectedFinalGeneration"],
        "current-head reservation expected final generation",
    )
    reservation_one_use_sequence = require_uint(
        reservation["expectedOneUseSequence"],
        "current-head reservation expected one-use sequence",
    )
    for field in (
        "challengeConsumptionSha256",
        "completionResultSha256",
        "headSha256",
        "receiptIdentitySha256",
        "verifierNonceConsumptionSha256",
    ):
        require_sha256(
            reservation[field],
            f"current-head reservation {field}",
        )
    require(
        len(
            {
                payload["authorizationId"],
                nonce_consumption["consumptionId"],
                reservation["reservationId"],
                pending["stateCommitId"],
            }
        )
        == 4,
        "current-head authorization, nonce, reservation, and CAS receipt identities are not distinct",
    )
    issued = require_uint(payload["issuedAtUnix"], "current-head issue time")
    expires = require_uint(payload["expiresAtUnix"], "current-head expiry")
    consumed = require_uint(
        nonce_consumption["consumedAtUnix"],
        "current-head verifier nonce consumption time",
    )
    nonce_expires = require_uint(
        nonce_consumption["expiresAtUnix"],
        "current-head verifier nonce expiry",
    )
    reservation_expires = require_uint(
        reservation["expiresAtUnix"],
        "current-head reservation expiry",
    )
    receipt_identity_sha256 = sha256_json(receipt_identity)
    verifier_nonce_consumption_sha256 = sha256_json(nonce_consumption)
    require(
        nonce_consumption["verifierNonceSha256"] == sha256(verifier_nonce)
        and nonce_consumption["status"] == "consumed"
        and nonce_consumption["oneUse"] is True
        and store_generation == pending_store_generation
        and current_head_generation == pending_store_generation
        and current_redemption_sequence
        == pending_redemption_sequence
        and reservation["apiVersion"]
        == CURRENT_HEAD_RESERVATION_IDENTITY_VERSION
        and reservation["authorizationId"] == payload["authorizationId"]
        and reservation["challengeConsumptionSha256"]
        == pending["challengeConsumptionSha256"]
        and reservation["completionResultSha256"]
        == completion_result_sha256
        and reservation_generation == pending_store_generation
        and reservation_current_sequence == current_redemption_sequence
        and reservation_final_generation == current_head_generation + 1
        and reservation_one_use_sequence
        == current_redemption_sequence + 1
        and reservation["headSha256"] == payload["currentHeadSha256"]
        and reservation["status"] == "reserved"
        and reservation["oneUse"] is True
        and reservation["receiptIdentitySha256"]
        == receipt_identity_sha256
        and reservation["storeId"] == pending["stateStoreId"]
        and reservation["verifierNonceConsumptionSha256"]
        == verifier_nonce_consumption_sha256
        and pending["stateCommitCommittedAtUnix"]
        <= consumed
        <= issued
        <= now
        < expires
        <= pending["stateCommitExpiresAtUnix"]
        and now < nonce_expires
        and now < reservation_expires
        and expires - issued <= MAX_CURRENT_HEAD_AUTHORIZATION_SECONDS
        and nonce_expires == expires
        and reservation_expires == expires,
        "current-head authorization is stale, reused, advanced, or not reserved for the fresh verifier nonce",
    )
    reservation_identity = dict(reservation)
    reservation_identity_sha256 = sha256_json(reservation_identity)
    authorization_identity = {
        "apiVersion": CURRENT_HEAD_AUTHORIZATION_IDENTITY_VERSION,
        "authorizationFileSha256": authorization_file_sha256,
        "authorizationId": payload["authorizationId"],
        "authorizationPayloadSha256": require_sha256(
            document.get("payloadSha256"),
            "current-head authorization payload",
        ),
        "currentHeadSha256": payload["currentHeadSha256"],
        "reservationIdentitySha256": reservation_identity_sha256,
        "signingKeyId": trust["keyIds"]["currentHeadAuthorization"],
        "storeId": pending["stateStoreId"],
    }
    return {
        **pending,
        "okForAction": False,
        "status": "pending-current-head-redemption",
        "currentHeadAuthorizationFileSha256": authorization_file_sha256,
        "currentHeadAuthorizationId": payload["authorizationId"],
        "currentHeadAuthorizationIdentity": authorization_identity,
        "currentHeadAuthorizationIdentitySha256": sha256_json(
            authorization_identity
        ),
        "currentHeadAuthorizationIssuedAtUnix": issued,
        "currentHeadAuthorizationExpiresAtUnix": expires,
        "currentHead": current_head,
        "currentHeadSha256": payload["currentHeadSha256"],
        "currentHeadVerifierNonceSha256": sha256(verifier_nonce),
        "currentHeadReservationId": reservation["reservationId"],
        "currentHeadReservationIdentity": reservation_identity,
        "currentHeadReservationIdentitySha256": (
            reservation_identity_sha256
        ),
        "currentHeadExpectedFinalGeneration": (
            reservation_final_generation
        ),
        "currentHeadExpectedOneUseSequence": (
            reservation_one_use_sequence
        ),
        "currentHeadAuthorizationRequired": False,
        "currentHeadRedemptionRequired": (
            "atomically compare the reserved current head, consume the "
            "authorization and reservation, advance generation and one-use "
            "sequence exactly once, and return a signed redemption receipt "
            "bound to a fresh post-authorization verifier nonce"
        ),
        "rollbackResistanceBoundary": (
            "authorization is a non-actionable reservation; a separately "
            "signed atomic redemption receipt establishes only historical "
            "redemption evidence, while a live stateful action gate must "
            "consume that receipt identity once"
        ),
    }


def finalize_current_head_redemption(
    pending: dict[str, Any],
    document: Any,
    *,
    verifier_nonce: bytes,
    trust: dict[str, Any],
    now: int,
) -> dict[str, Any]:
    require(
        pending.get("status") == "pending-current-head-redemption"
        and "ok" not in pending
        and pending.get("okForAction") is False,
        "current-head redemption requires a non-actionable authorization result",
    )
    require(
        len(verifier_nonce) == 32,
        "redemption verifier nonce must be exactly 32 fresh bytes",
    )
    require(
        sha256(verifier_nonce)
        != pending.get("currentHeadVerifierNonceSha256"),
        "redemption verifier nonce must be fresh after authorization",
    )
    pending_store_generation = require_uint(
        pending.get("stateStoreGeneration"),
        "pending redemption store generation",
    )
    pending_redemption_sequence = require_uint(
        pending.get("stateStoreRedemptionSequence"),
        "pending redemption one-use sequence",
    )
    pending_final_generation = require_uint(
        pending.get("currentHeadExpectedFinalGeneration"),
        "pending redemption expected final generation",
    )
    pending_one_use_sequence = require_uint(
        pending.get("currentHeadExpectedOneUseSequence"),
        "pending redemption expected one-use sequence",
    )
    pending_head = exact_keys(
        pending.get("currentHead"),
        {
            "apiVersion",
            "challengeConsumptionSha256",
            "commitId",
            "generation",
            "redemptionSequence",
            "stateCommitReceiptSha256",
            "stateSha256",
            "storeId",
        },
        "pending redemption current head",
    )
    pending_head_generation = require_uint(
        pending_head["generation"],
        "pending redemption current-head generation",
    )
    pending_head_redemption_sequence = require_uint(
        pending_head["redemptionSequence"],
        "pending redemption current-head one-use sequence",
    )
    pending_reservation_identity = exact_keys(
        pending.get("currentHeadReservationIdentity"),
        {
            "apiVersion",
            "authorizationId",
            "challengeConsumptionSha256",
            "completionResultSha256",
            "currentRedemptionSequence",
            "expectedFinalGeneration",
            "expectedOneUseSequence",
            "expiresAtUnix",
            "generation",
            "headSha256",
            "oneUse",
            "receiptIdentitySha256",
            "reservationId",
            "status",
            "storeId",
            "verifierNonceConsumptionSha256",
        },
        "pending redemption reservation identity",
    )
    pending_reservation_generation = require_uint(
        pending_reservation_identity["generation"],
        "pending redemption reservation generation",
    )
    pending_reservation_sequence = require_uint(
        pending_reservation_identity["currentRedemptionSequence"],
        "pending redemption reservation current one-use sequence",
    )
    pending_reservation_final_generation = require_uint(
        pending_reservation_identity["expectedFinalGeneration"],
        "pending redemption reservation expected final generation",
    )
    pending_reservation_one_use_sequence = require_uint(
        pending_reservation_identity["expectedOneUseSequence"],
        "pending redemption reservation expected one-use sequence",
    )
    require(
        pending_head_generation == pending_store_generation
        and pending_head_redemption_sequence
        == pending_redemption_sequence
        and pending_reservation_generation == pending_store_generation
        and pending_reservation_sequence == pending_redemption_sequence
        and pending_reservation_final_generation
        == pending_final_generation
        and pending_reservation_one_use_sequence
        == pending_one_use_sequence,
        "pending redemption generation aliases are inconsistent",
    )
    payload, redemption_file_sha256 = verify_standard_envelope(
        document,
        api_version=CURRENT_HEAD_REDEMPTION_VERSION,
        domain=CURRENT_HEAD_REDEMPTION_DOMAIN,
        key=trust["keys"]["currentHeadRedemption"],
        key_id=trust["keyIds"]["currentHeadRedemption"],
        label="atomic current-head redemption receipt",
    )
    payload = exact_keys(
        payload,
        {
            "authorizationIdentity",
            "authorizationIdentitySha256",
            "authorizationVerifierNonceSha256",
            "challengeConsumptionSha256",
            "committedNewStateSha256",
            "completionIdentitySha256",
            "completionResultSha256",
            "currentRedemptionSequence",
            "currentStoreGeneration",
            "expectedOldStateSha256",
            "expiresAtUnix",
            "finalHead",
            "finalHeadSha256",
            "finalStoreGeneration",
            "issuedAtUnix",
            "oneUse",
            "oneUseSequence",
            "operation",
            "preRedemptionHead",
            "preRedemptionHeadSha256",
            "preRedemptionResultSha256",
            "redeemedAtUnix",
            "redemptionId",
            "redemptionVerifierNonceConsumption",
            "reservationIdentity",
            "reservationIdentitySha256",
            "stateCommitReceiptIdentity",
            "stateCommitReceiptIdentitySha256",
            "status",
            "storeId",
            "transitionSha256",
            "trustRootBundleSha256",
        },
        "atomic current-head redemption payload",
    )
    require_identifier(payload["redemptionId"], "current-head redemption ID")
    authorization_identity = exact_keys(
        payload["authorizationIdentity"],
        {
            "apiVersion",
            "authorizationFileSha256",
            "authorizationId",
            "authorizationPayloadSha256",
            "currentHeadSha256",
            "reservationIdentitySha256",
            "signingKeyId",
            "storeId",
        },
        "redeemed current-head authorization identity",
    )
    reservation_identity = exact_keys(
        payload["reservationIdentity"],
        {
            "apiVersion",
            "authorizationId",
            "challengeConsumptionSha256",
            "completionResultSha256",
            "currentRedemptionSequence",
            "expectedFinalGeneration",
            "expectedOneUseSequence",
            "expiresAtUnix",
            "generation",
            "headSha256",
            "oneUse",
            "receiptIdentitySha256",
            "reservationId",
            "status",
            "storeId",
            "verifierNonceConsumptionSha256",
        },
        "redeemed current-head reservation identity",
    )
    redeemed_reservation_generation = require_uint(
        reservation_identity["generation"],
        "redeemed reservation generation",
    )
    redeemed_reservation_sequence = require_uint(
        reservation_identity["currentRedemptionSequence"],
        "redeemed reservation current one-use sequence",
    )
    redeemed_reservation_final_generation = require_uint(
        reservation_identity["expectedFinalGeneration"],
        "redeemed reservation expected final generation",
    )
    redeemed_reservation_one_use_sequence = require_uint(
        reservation_identity["expectedOneUseSequence"],
        "redeemed reservation expected one-use sequence",
    )
    state_commit_identity = exact_keys(
        payload["stateCommitReceiptIdentity"],
        {
            "apiVersion",
            "commitId",
            "receiptFileSha256",
            "receiptPayloadSha256",
            "signingKeyId",
            "storeId",
        },
        "redeemed state-commit receipt identity",
    )
    for label, identity, expected, supplied_digest in (
        (
            "authorization",
            authorization_identity,
            pending["currentHeadAuthorizationIdentity"],
            payload["authorizationIdentitySha256"],
        ),
        (
            "reservation",
            reservation_identity,
            pending["currentHeadReservationIdentity"],
            payload["reservationIdentitySha256"],
        ),
        (
            "state-commit receipt",
            state_commit_identity,
            pending["stateCommitReceiptIdentity"],
            payload["stateCommitReceiptIdentitySha256"],
        ),
    ):
        require_sha256(
            supplied_digest,
            f"current-head redemption {label} identity",
        )
        require(
            identity == expected
            and supplied_digest == sha256_json(identity),
            f"current-head redemption substituted the {label} identity",
        )
    current_store_generation = require_uint(
        payload["currentStoreGeneration"],
        "redemption current store generation",
    )
    final_store_generation = require_uint(
        payload["finalStoreGeneration"],
        "redemption final store generation",
    )
    current_redemption_sequence = require_uint(
        payload["currentRedemptionSequence"],
        "redemption current one-use sequence",
    )
    one_use_sequence = require_uint(
        payload["oneUseSequence"],
        "redemption one-use sequence",
    )
    transition = pending["stateTransition"]
    pre_redemption_result_sha256 = sha256_json(pending)
    pre_head = exact_keys(
        payload["preRedemptionHead"],
        {
            "apiVersion",
            "challengeConsumptionSha256",
            "commitId",
            "generation",
            "redemptionSequence",
            "stateCommitReceiptSha256",
            "stateSha256",
            "storeId",
        },
        "redemption pre-operation head",
    )
    pre_head_generation = require_uint(
        pre_head["generation"],
        "redemption pre-operation head generation",
    )
    pre_head_redemption_sequence = require_uint(
        pre_head["redemptionSequence"],
        "redemption pre-operation head one-use sequence",
    )
    final_head = exact_keys(
        payload["finalHead"],
        {
            "apiVersion",
            "authorizationId",
            "challengeConsumptionSha256",
            "commitId",
            "completionResultSha256",
            "generation",
            "previousHeadSha256",
            "redemptionId",
            "redemptionSequence",
            "redemptionVerifierNonceSha256",
            "reservationId",
            "stateCommitReceiptSha256",
            "stateSha256",
            "storeId",
        },
        "redemption final current head",
    )
    final_head_generation = require_uint(
        final_head["generation"],
        "redemption final head generation",
    )
    final_head_redemption_sequence = require_uint(
        final_head["redemptionSequence"],
        "redemption final head one-use sequence",
    )
    nonce_consumption = exact_keys(
        payload["redemptionVerifierNonceConsumption"],
        {
            "consumedAtUnix",
            "consumptionId",
            "expiresAtUnix",
            "oneUse",
            "status",
            "verifierNonceSha256",
        },
        "redemption verifier nonce consumption",
    )
    require_identifier(
        nonce_consumption["consumptionId"],
        "redemption verifier nonce consumption ID",
    )
    consumed = require_uint(
        nonce_consumption["consumedAtUnix"],
        "redemption verifier nonce consumption time",
    )
    nonce_expires = require_uint(
        nonce_consumption["expiresAtUnix"],
        "redemption verifier nonce expiry",
    )
    redeemed = require_uint(payload["redeemedAtUnix"], "redemption time")
    issued = require_uint(payload["issuedAtUnix"], "redemption receipt issue time")
    expires = require_uint(
        payload["expiresAtUnix"],
        "redemption receipt expiry",
    )
    operation = exact_keys(
        payload["operation"],
        {
            "authorizationConsumed",
            "compareCurrentHead",
            "finalHeadCommitted",
            "reservationConsumed",
        },
        "atomic current-head redemption operation",
    )
    require(
        operation
        == {
            "authorizationConsumed": True,
            "compareCurrentHead": True,
            "finalHeadCommitted": True,
            "reservationConsumed": True,
        }
        and payload["status"] == "redeemed"
        and payload["oneUse"] is True,
        "current-head redemption was not an atomic one-use operation",
    )
    expected_final_head = {
        "apiVersion": STATE_STORE_FINAL_HEAD_VERSION,
        "authorizationId": pending["currentHeadAuthorizationId"],
        "challengeConsumptionSha256": pending[
            "challengeConsumptionSha256"
        ],
        "commitId": pending["stateCommitId"],
        "completionResultSha256": pending[
            "currentHeadReservationIdentity"
        ]["completionResultSha256"],
        "generation": pending_final_generation,
        "previousHeadSha256": pending["currentHeadSha256"],
        "redemptionId": payload["redemptionId"],
        "redemptionSequence": pending_one_use_sequence,
        "redemptionVerifierNonceSha256": sha256(verifier_nonce),
        "reservationId": pending["currentHeadReservationId"],
        "stateCommitReceiptSha256": pending[
            "stateCommitReceiptSha256"
        ],
        "stateSha256": transition["newStateSha256"],
        "storeId": pending["stateStoreId"],
    }
    require(
        payload["storeId"] == pending["stateStoreId"]
        and payload["authorizationVerifierNonceSha256"]
        == pending["currentHeadVerifierNonceSha256"]
        and payload["challengeConsumptionSha256"]
        == pending["challengeConsumptionSha256"]
        and payload["completionIdentitySha256"]
        == pending["completionIdentitySha256"]
        and payload["completionResultSha256"]
        == pending["currentHeadReservationIdentity"][
            "completionResultSha256"
        ]
        and payload["preRedemptionResultSha256"]
        == pre_redemption_result_sha256
        and payload["expectedOldStateSha256"]
        == transition["oldStateSha256"]
        and payload["committedNewStateSha256"]
        == transition["newStateSha256"]
        and payload["transitionSha256"] == transition["transitionSha256"]
        and payload["trustRootBundleSha256"]
        == trust["trustRootBundleSha256"]
        and current_store_generation == pending_store_generation
        and final_store_generation == pending_final_generation
        and current_redemption_sequence == pending_redemption_sequence
        and one_use_sequence == pending_one_use_sequence
        and pre_head == pending_head
        and pre_head_generation == current_store_generation
        and pre_head_redemption_sequence == current_redemption_sequence
        and redeemed_reservation_generation == current_store_generation
        and redeemed_reservation_sequence == current_redemption_sequence
        and redeemed_reservation_final_generation == final_store_generation
        and redeemed_reservation_one_use_sequence == one_use_sequence
        and payload["preRedemptionHeadSha256"] == sha256_json(pre_head)
        and payload["preRedemptionHeadSha256"]
        == pending["currentHeadSha256"]
        and final_head == expected_final_head
        and final_head_generation == final_store_generation
        and final_head_redemption_sequence == one_use_sequence
        and payload["finalHeadSha256"] == sha256_json(final_head)
        and final_store_generation == current_store_generation + 1
        and one_use_sequence == current_redemption_sequence + 1,
        "current-head redemption crossed its authorization, state transition, or final monotonic head",
    )
    require(
        nonce_consumption["verifierNonceSha256"] == sha256(verifier_nonce)
        and nonce_consumption["status"] == "consumed"
        and nonce_consumption["oneUse"] is True
        and len(
            {
                pending["stateCommitId"],
                pending["currentHeadAuthorizationId"],
                pending["currentHeadReservationId"],
                payload["redemptionId"],
                nonce_consumption["consumptionId"],
            }
        )
        == 5
        and pending["currentHeadAuthorizationIssuedAtUnix"]
        <= consumed
        <= redeemed
        <= issued
        <= now
        < expires
        <= pending["stateCommitExpiresAtUnix"]
        and redeemed
        <= pending["currentHeadAuthorizationExpiresAtUnix"]
        and now < nonce_expires
        and nonce_expires == expires
        and expires - issued <= MAX_CURRENT_HEAD_REDEMPTION_SECONDS,
        "current-head redemption is stale or not bound to the fresh post-authorization verifier nonce",
    )
    receipt_identity = {
        "apiVersion": (
            CURRENT_HEAD_REDEMPTION_RECEIPT_IDENTITY_VERSION
        ),
        "oneUseSequence": one_use_sequence,
        "redemptionFileSha256": redemption_file_sha256,
        "redemptionId": payload["redemptionId"],
        "redemptionPayloadSha256": require_sha256(
            document.get("payloadSha256"),
            "current-head redemption payload",
        ),
        "signingKeyId": trust["keyIds"]["currentHeadRedemption"],
        "storeId": pending["stateStoreId"],
    }
    final_base = {
        key: value
        for key, value in pending.items()
        if key
        not in {
            "currentHeadAuthorizationRequired",
            "currentHeadRedemptionRequired",
            "finalCompletion",
            "ok",
            "stateCommitRequired",
        }
    }
    result = {
        **final_base,
        "verificationOk": True,
        "finalCompletionVerified": True,
        "actionAuthorization": None,
        "okForAction": False,
        "status": "redemption-verified-non-actionable",
        "currentFinalHead": final_head,
        "currentFinalHeadSha256": payload["finalHeadSha256"],
        "currentHeadRedemptionReceiptFileSha256": (
            redemption_file_sha256
        ),
        "currentHeadRedemptionReceiptIdentity": receipt_identity,
        "currentHeadRedemptionReceiptIdentitySha256": sha256_json(
            receipt_identity
        ),
        "currentHeadRedemptionId": payload["redemptionId"],
        "currentHeadRedemptionVerifierNonceSha256": sha256(
            verifier_nonce
        ),
        "currentHeadRedemptionVerified": True,
        "currentHeadOneUseSequence": one_use_sequence,
        "finalEvidenceIssuedAtUnix": issued,
        "stateStoreGeneration": final_store_generation,
        "stateStoreRedemptionSequence": one_use_sequence,
        "rollbackResistanceBoundary": (
            "this is durable historical evidence, never a reusable action "
            "capability; an action gate must atomically re-check this exact "
            "final head as live and consume the redemption receipt identity "
            "once while performing the action"
        ),
    }
    return validate_non_actionable_final_result(
        result,
        label="verified current-head redemption result",
    )


PUBLIC_NITRO_FINAL_ROLE_NAMES = frozenset(
    {
        "builderA",
        "builderB",
        "buildWatchdog",
        "clientState",
        "clientStateCheckpoint",
        "currentHeadAuthorization",
        "currentHeadRedemption",
        "keyCustody",
        "kmsAudit",
        "manifestV6EifBuilder",
        "nitroAttestationVerifier",
        "promotion",
        "publicNitroResult",
        "releaseCa",
        "remoteSignerServerTls",
        "remoteStoreServerTls",
        "responseKey",
        "sourceGitInventory",
        "sourceUntrackedApproval",
        "stateCommit",
        "stateStore",
        "storeAssurance",
        "tlsRelease",
        "verifierState",
        "witness",
        "witnessStore",
    }
)
PUBLIC_NITRO_RESULT_ROLE_NAMES = frozenset(
    PUBLIC_NITRO_FINAL_ROLE_NAMES
    - {
        "releaseCa",
        "remoteSignerServerTls",
        "remoteStoreServerTls",
        "responseKey",
    }
)


def validate_public_nitro_role_registry(
    document: Any,
    *,
    expected_sha256: str,
    result_signer_key_id: str,
    result_signer_server_tls_spki_sha256: str,
    state_store_server_tls_spki_sha256: str,
    tls_release_key_id: str,
    release_ca_key_id: str,
    response_key_id: str,
    trust: dict[str, Any],
) -> dict[str, str]:
    registry = exact_keys(
        document,
        {"apiVersion", "roles"},
        "public Nitro role registry",
    )
    roles = exact_keys(
        registry["roles"],
        PUBLIC_NITRO_FINAL_ROLE_NAMES,
        "public Nitro final role map",
    )
    normalized = {
        name: require_sha256(
            roles[name],
            f"public Nitro {name} role key",
        )
        for name in sorted(roles)
    }
    validate_global_attestation_key_role_separation(
        normalized,
        expected_roles=PUBLIC_NITRO_FINAL_ROLE_NAMES,
    )
    require(
        registry["apiVersion"] == PUBLIC_NITRO_ROLE_REGISTRY_VERSION
        and sha256_json(
            {
                "apiVersion": PUBLIC_NITRO_ROLE_REGISTRY_VERSION,
                "roles": normalized,
            }
        )
        == require_sha256(
            expected_sha256,
            "independently pinned public Nitro role registry",
        ),
        "public Nitro role registry is crossed, colliding, or not independently pinned",
    )
    known_trust_roles = {
        "builderA": "builderA",
        "builderB": "builderB",
        "buildWatchdog": "buildWatchdog",
        "clientState": "clientState",
        "clientStateCheckpoint": "clientStateCheckpoint",
        "currentHeadAuthorization": "currentHeadAuthorization",
        "currentHeadRedemption": "currentHeadRedemption",
        "kmsAudit": "kmsAudit",
        "manifestV6EifBuilder": "manifestV6EifBuilder",
        "promotion": "promotion",
        "sourceGitInventory": "sourceGitInventory",
        "sourceUntrackedApproval": "sourceUntrackedApproval",
        "stateCommit": "stateCommit",
        "witness": "witness",
    }
    require(
        all(
            normalized[result_role] == trust["keyIds"][trust_role]
            for result_role, trust_role in known_trust_roles.items()
        )
        and normalized["publicNitroResult"]
        == require_sha256(
            result_signer_key_id,
            "public Nitro result signer role",
        )
        and normalized["tlsRelease"]
        == require_sha256(
            tls_release_key_id,
            "public Nitro TLS release role",
        ),
        "public Nitro role registry crossed a verified trust, result signer, or TLS role",
    )
    require(
        normalized["releaseCa"]
        == require_sha256(
            release_ca_key_id,
            "public Nitro release CA role",
        )
        and normalized["responseKey"]
        == require_sha256(
            response_key_id,
            "public Nitro response-key role",
        )
        and normalized["remoteSignerServerTls"]
        == require_sha256(
            result_signer_server_tls_spki_sha256,
            "public Nitro remote signer server TLS role",
        )
        and normalized["remoteStoreServerTls"]
        == require_sha256(
            state_store_server_tls_spki_sha256,
            "public Nitro remote store server TLS role",
        ),
        "public Nitro role registry crossed a verified trust, result signer, or TLS role",
    )
    return normalized


def project_public_nitro_final_result(
    internal: dict[str, Any],
    *,
    roles: dict[str, str],
    witness_store_identity_sha256: str,
    witness_store_assurance_sha256: str,
    verified_at_unix: int,
) -> dict[str, Any]:
    validate_non_actionable_final_result(
        internal,
        label="internal public Nitro final result",
    )
    transition = exact_keys(
        internal["stateTransition"],
        {
            "newStateSha256",
            "oldStateSha256",
            "transitionSha256",
        },
        "public Nitro final state transition",
    )
    receipt_identity = exact_keys(
        internal["stateCommitReceiptIdentity"],
        {
            "apiVersion",
            "commitId",
            "receiptFileSha256",
            "receiptPayloadSha256",
            "signingKeyId",
            "storeId",
        },
        "public Nitro state-commit receipt identity",
    )
    result_roles = {
        name: roles[name]
        for name in sorted(PUBLIC_NITRO_RESULT_ROLE_NAMES)
    }
    state_commit = {
        "apiVersion": "serverware.publicNitroStateCommit/v1",
        "status": "redemption-verified-non-actionable",
        "actionable": False,
        "redemptionVerified": True,
        "commitId": internal["stateCommitId"],
        "storeId": internal["stateStoreId"],
        "signingKeyId": roles["stateCommit"],
        "stateStoreSigningKeyId": roles["stateStore"],
        "receiptFileSha256": receipt_identity[
            "receiptFileSha256"
        ],
        "receiptPayloadSha256": receipt_identity[
            "receiptPayloadSha256"
        ],
        "priorStateSha256": transition["oldStateSha256"],
        "currentStateSha256": transition["newStateSha256"],
        "transitionSha256": transition["transitionSha256"],
        "challengeConsumptionSha256": internal[
            "challengeConsumptionSha256"
        ],
        "currentHeadAuthorizationId": internal[
            "currentHeadAuthorizationId"
        ],
        "currentHeadAuthorizationFileSha256": internal[
            "currentHeadAuthorizationFileSha256"
        ],
        "currentHeadAuthorizationKeyId": roles[
            "currentHeadAuthorization"
        ],
        "currentHeadSha256": internal["currentHeadSha256"],
        "currentHeadVerifierNonceSha256": internal[
            "currentHeadVerifierNonceSha256"
        ],
        "currentHeadReservationId": internal[
            "currentHeadReservationId"
        ],
        "currentHeadRedemptionId": internal[
            "currentHeadRedemptionId"
        ],
        "currentHeadRedemptionReceiptFileSha256": internal[
            "currentHeadRedemptionReceiptFileSha256"
        ],
        "currentHeadRedemptionReceiptIdentitySha256": internal[
            "currentHeadRedemptionReceiptIdentitySha256"
        ],
        "currentHeadRedemptionVerifierNonceSha256": internal[
            "currentHeadRedemptionVerifierNonceSha256"
        ],
        "currentHeadRedemptionKeyId": roles[
            "currentHeadRedemption"
        ],
        "currentFinalHeadSha256": internal[
            "currentFinalHeadSha256"
        ],
        "currentHeadOneUseSequence": internal[
            "currentHeadOneUseSequence"
        ],
        "verifierStateKeyId": roles["verifierState"],
        "storeAssuranceKeyId": roles["storeAssurance"],
        "tlsReleaseKeyId": roles["tlsRelease"],
        "rollbackResistanceBoundary": internal[
            "rollbackResistanceBoundary"
        ],
    }
    internal_witness = internal["witness"]
    witness = {
        "checkpointSha256": internal_witness["checkpointSha256"],
        "challengeConsumptionSha256": internal_witness[
            "challengeConsumptionSha256"
        ],
        "leafIndex": internal_witness["leafIndex"],
        "releaseGeneration": internal_witness["releaseGeneration"],
        "rollbackEpoch": internal_witness["rollbackEpoch"],
        "sequence": internal_witness["sequence"],
        "treeSize": internal_witness["treeSize"],
        "rootHash": internal_witness["rootHash"],
        "witnessKeyId": roles["witness"],
        "witnessStoreKeyId": roles["witnessStore"],
        "witnessStoreIdentitySha256": require_sha256(
            witness_store_identity_sha256,
            "public Nitro witness-store identity",
        ),
        "witnessStoreAssuranceSha256": require_sha256(
            witness_store_assurance_sha256,
            "public Nitro witness-store assurance",
        ),
    }
    public_result = {
        "apiVersion": RESULT_VERSION,
        "verificationOk": True,
        "finalCompletionVerified": True,
        "actionAuthorization": None,
        "okForAction": False,
        "status": "redemption-verified-non-actionable",
        "pipeline": PIPELINE,
        "canonicalProfile": CANONICAL_PROFILE,
        "verifiedAtUnix": require_positive_uint(
            internal.get(
                "finalEvidenceIssuedAtUnix",
                verified_at_unix,
            ),
            "public Nitro final verification time",
        ),
        "evidenceBundleFileSha256": internal[
            "evidenceBundleFileSha256"
        ],
        "expectationsFileSha256": internal[
            "expectationsFileSha256"
        ],
        "trustRootBundleFileSha256": internal[
            "trustRootBundleFileSha256"
        ],
        "completionIdentity": internal["completionIdentity"],
        "completionIdentitySha256": internal[
            "completionIdentitySha256"
        ],
        "completionCoreDigests": internal[
            "completionCoreDigests"
        ],
        "candidateManifestFileSha256": internal[
            "candidateManifestFileSha256"
        ],
        "candidateManifestPayloadSha256": internal[
            "candidateManifestPayloadSha256"
        ],
        "sourceInputManifestFileSha256": internal[
            "sourceInputManifestFileSha256"
        ],
        "sourceClosureSha256": internal["sourceClosureSha256"],
        "buildWatchdogReceiptFileSha256": internal[
            "buildWatchdogReceiptFileSha256"
        ],
        "promotionReceiptFileSha256": internal[
            "promotionReceiptFileSha256"
        ],
        "promotedManifestFileSha256": internal[
            "promotedManifestFileSha256"
        ],
        "productionIdentitySha256": internal[
            "productionIdentitySha256"
        ],
        "runtimeStateFileSha256": internal["runtimeStateFileSha256"],
        "runtimeKeyCustodyFileSha256": internal[
            "runtimeKeyCustodyFileSha256"
        ],
        "candidateToEifBuildStatementFileSha256": internal[
            "candidateToEifBuildStatementFileSha256"
        ],
        "eifSha384": internal["eifSha384"],
        "pcrs": internal["pcrs"],
        "nitroAttestationDocumentSha256": internal[
            "nitroAttestationDocumentSha256"
        ],
        "attestationRequestSha256": internal[
            "attestationRequestSha256"
        ],
        "requestSha256": internal["requestSha256"],
        "responseBytesSha256": internal["responseBytesSha256"],
        "tlsExporterSha256": internal["tlsExporterSha256"],
        "tlsSpkiSha256": internal["tlsSpkiSha256"],
        "tlsPeerSpkiSha256": internal["tlsPeerSpkiSha256"],
        "tlsStackMeasurementSha256": internal[
            "tlsStackMeasurementSha256"
        ],
        "kmsAuditProofSha256s": internal["kmsAuditProofSha256s"],
        "witness": witness,
        "nextClientState": internal["nextClientState"],
        "stateTransition": transition,
        "stateCommit": state_commit,
        "roleKeyIds": result_roles,
        "roleRegistrySha256": sha256_json(
            {
                "apiVersion": PUBLIC_NITRO_ROLE_REGISTRY_VERSION,
                "roles": result_roles,
            }
        ),
    }
    return validate_non_actionable_final_result(
        public_result,
        label="public Nitro final result",
    )


def build_public_nitro_result_signing_request(
    result: dict[str, Any],
    *,
    provider: str,
    signing_key_id: str,
    signing_key_spki_sha256: str,
    signer_server_tls_spki_sha256: str,
) -> dict[str, Any]:
    validate_public_nitro_final_result_contract(result)
    require_public_nitro_provider(
        provider,
        "public Nitro result signer provider",
    )
    require(
        require_sha256(
            signing_key_id,
            "public Nitro result signer key ID",
        )
        == require_sha256(
            signing_key_spki_sha256,
            "public Nitro result signer SPKI digest",
        )
        == result["roleKeyIds"]["publicNitroResult"],
        "public Nitro result signer pins differ from the global role registry",
    )
    require_sha256(
        signer_server_tls_spki_sha256,
        "public Nitro result signer server TLS SPKI",
    )
    envelope_core = {
        "apiVersion": PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_VERSION,
        "provider": provider,
        "signingKeyId": signing_key_id,
        "signingKeySpkiSha256": signing_key_spki_sha256,
        "result": result,
        "resultSha256": sha256_json(result),
    }
    signing_message = (
        PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN
        + canonical_json_bytes(envelope_core)
    )
    request_core = {
        "apiVersion": PUBLIC_NITRO_RESULT_SIGNING_REQUEST_VERSION,
        "envelopeCore": envelope_core,
        "operation": "sign-public-nitro-live-verification-result",
        "retrySemantics": (
            "same-recovery-key-requires-byte-identical-request-and-response"
        ),
        "signingMessageSha256": sha256(signing_message),
        "transportPins": {
            "signerServerTlsSpkiSha256":
            signer_server_tls_spki_sha256,
        },
    }
    operation_id = sha256(
        PUBLIC_NITRO_RESULT_SIGNING_OPERATION_DOMAIN
        + canonical_json_bytes(request_core)
    )
    recovery_key = sha256(
        PUBLIC_NITRO_RESULT_SIGNING_RECOVERY_DOMAIN
        + operation_id.encode("ascii")
    )
    request = {
        **request_core,
        "operationIdSha256": operation_id,
        "recoveryKeySha256": recovery_key,
    }
    return {
        **request,
        "requestSha256": sha256_json(request),
    }


PUBLIC_NITRO_RESULT_FIELDS = frozenset(
    {
        "actionAuthorization",
        "apiVersion",
        "attestationRequestSha256",
        "buildWatchdogReceiptFileSha256",
        "candidateManifestFileSha256",
        "candidateManifestPayloadSha256",
        "candidateToEifBuildStatementFileSha256",
        "canonicalProfile",
        "completionCoreDigests",
        "completionIdentity",
        "completionIdentitySha256",
        "eifSha384",
        "evidenceBundleFileSha256",
        "expectationsFileSha256",
        "finalCompletionVerified",
        "kmsAuditProofSha256s",
        "nextClientState",
        "nitroAttestationDocumentSha256",
        "okForAction",
        "pcrs",
        "pipeline",
        "productionIdentitySha256",
        "promotedManifestFileSha256",
        "promotionReceiptFileSha256",
        "requestSha256",
        "responseBytesSha256",
        "roleKeyIds",
        "roleRegistrySha256",
        "runtimeKeyCustodyFileSha256",
        "runtimeStateFileSha256",
        "sourceClosureSha256",
        "sourceInputManifestFileSha256",
        "stateCommit",
        "stateTransition",
        "status",
        "tlsExporterSha256",
        "tlsPeerSpkiSha256",
        "tlsSpkiSha256",
        "tlsStackMeasurementSha256",
        "trustRootBundleFileSha256",
        "verificationOk",
        "verifiedAtUnix",
        "witness",
    }
)
PUBLIC_NITRO_WITNESS_FIELDS = frozenset(
    {
        "checkpointSha256",
        "challengeConsumptionSha256",
        "leafIndex",
        "releaseGeneration",
        "rollbackEpoch",
        "sequence",
        "treeSize",
        "rootHash",
        "witnessKeyId",
        "witnessStoreKeyId",
        "witnessStoreIdentitySha256",
        "witnessStoreAssuranceSha256",
    }
)
PUBLIC_NITRO_STATE_COMMIT_FIELDS = frozenset(
    {
        "actionable",
        "apiVersion",
        "challengeConsumptionSha256",
        "commitId",
        "currentFinalHeadSha256",
        "currentHeadAuthorizationFileSha256",
        "currentHeadAuthorizationId",
        "currentHeadAuthorizationKeyId",
        "currentHeadOneUseSequence",
        "currentHeadRedemptionId",
        "currentHeadRedemptionKeyId",
        "currentHeadRedemptionReceiptFileSha256",
        "currentHeadRedemptionReceiptIdentitySha256",
        "currentHeadRedemptionVerifierNonceSha256",
        "currentHeadReservationId",
        "currentHeadSha256",
        "currentHeadVerifierNonceSha256",
        "currentStateSha256",
        "priorStateSha256",
        "receiptFileSha256",
        "receiptPayloadSha256",
        "redemptionVerified",
        "rollbackResistanceBoundary",
        "signingKeyId",
        "stateStoreSigningKeyId",
        "status",
        "storeAssuranceKeyId",
        "storeId",
        "tlsReleaseKeyId",
        "transitionSha256",
        "verifierStateKeyId",
    }
)


def validate_public_nitro_final_result_contract(
    document: Any,
) -> dict[str, Any]:
    def validate_integer_domain(
        value: Any,
        *,
        label: str,
    ) -> None:
        if isinstance(value, Mapping):
            for field, child in value.items():
                validate_integer_domain(
                    child,
                    label=f"{label}.{field}",
                )
            return
        if isinstance(value, list):
            for index, child in enumerate(value):
                validate_integer_domain(
                    child,
                    label=f"{label}[{index}]",
                )
            return
        if type(value) is int:
            require(
                -(1 << 63)
                <= value
                <= PUBLIC_NITRO_CANONICAL_INTEGER_MAX,
                f"{label} is outside the canonical signed-64 integer domain",
            )

    validate_integer_domain(
        document,
        label="public Nitro final result",
    )
    require(
        isinstance(document, dict)
        and set(document) == PUBLIC_NITRO_RESULT_FIELDS
        and document["apiVersion"] == RESULT_VERSION
        and document["verificationOk"] is True
        and document["finalCompletionVerified"] is True
        and document["actionAuthorization"] is None
        and document["okForAction"] is False
        and document["status"] == "redemption-verified-non-actionable"
        and document["pipeline"] == PIPELINE
        and document["canonicalProfile"] == CANONICAL_PROFILE,
        "public Nitro final result does not match the closed non-actionable v2 contract",
    )
    identity = verify_completion_identity(
        document["completionIdentity"],
        document["completionIdentitySha256"],
        label="public Nitro final completion identity",
    )
    require(
        document["completionCoreDigests"] == identity["coreDigests"],
        "public Nitro final result crossed its completion core registry",
    )
    roles = exact_keys(
        document["roleKeyIds"],
        PUBLIC_NITRO_RESULT_ROLE_NAMES,
        "public Nitro final result role map",
    )
    for name, key_id in roles.items():
        require_sha256(key_id, f"public Nitro final {name} role")
    validate_global_attestation_key_role_separation(
        roles,
        expected_roles=PUBLIC_NITRO_RESULT_ROLE_NAMES,
    )
    require(
        document["roleRegistrySha256"]
        == sha256_json(
            {
                "apiVersion": PUBLIC_NITRO_ROLE_REGISTRY_VERSION,
                "roles": {
                    name: roles[name] for name in sorted(roles)
                },
            }
        ),
        "public Nitro final result role registry is colliding or crossed",
    )
    for field in (
        "attestationRequestSha256",
        "buildWatchdogReceiptFileSha256",
        "candidateManifestFileSha256",
        "candidateManifestPayloadSha256",
        "candidateToEifBuildStatementFileSha256",
        "completionIdentitySha256",
        "evidenceBundleFileSha256",
        "expectationsFileSha256",
        "nitroAttestationDocumentSha256",
        "productionIdentitySha256",
        "promotedManifestFileSha256",
        "promotionReceiptFileSha256",
        "requestSha256",
        "responseBytesSha256",
        "roleRegistrySha256",
        "runtimeKeyCustodyFileSha256",
        "runtimeStateFileSha256",
        "sourceClosureSha256",
        "sourceInputManifestFileSha256",
        "tlsExporterSha256",
        "tlsPeerSpkiSha256",
        "tlsSpkiSha256",
        "tlsStackMeasurementSha256",
        "trustRootBundleFileSha256",
    ):
        require_sha256(document[field], f"public Nitro final {field}")
    require_sha384(document["eifSha384"], "public Nitro final EIF")
    pcrs = exact_keys(
        document["pcrs"],
        {"PCR0", "PCR1", "PCR2"},
        "public Nitro final PCR map",
    )
    for name, digest in pcrs.items():
        require_sha384(digest, f"public Nitro final {name}")
    kms_digests = document["kmsAuditProofSha256s"]
    require(
        isinstance(kms_digests, dict)
        and 1 <= len(kms_digests) <= 64,
        "public Nitro final KMS digest map is invalid",
    )
    for name, digest in kms_digests.items():
        require(
            isinstance(name, str)
            and re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",
                name,
                re.ASCII,
            )
            is not None,
            "public Nitro final KMS digest name is invalid",
        )
        require_sha256(digest, f"public Nitro final KMS digest {name}")
    require_positive_uint(
        document["verifiedAtUnix"],
        "public Nitro final verification time",
    )
    witness = exact_keys(
        document["witness"],
        PUBLIC_NITRO_WITNESS_FIELDS,
        "public Nitro final witness",
    )
    for field in (
        "checkpointSha256",
        "challengeConsumptionSha256",
        "rootHash",
        "witnessKeyId",
        "witnessStoreKeyId",
        "witnessStoreIdentitySha256",
        "witnessStoreAssuranceSha256",
    ):
        require_sha256(witness[field], f"public Nitro final witness {field}")
    for field in (
        "leafIndex",
        "releaseGeneration",
        "rollbackEpoch",
        "sequence",
        "treeSize",
    ):
        require_uint(witness[field], f"public Nitro final witness {field}")
    next_state = load_client_state(document["nextClientState"])
    require_identifier(
        next_state["provider"],
        "public Nitro final next-state provider",
    )
    transition = exact_keys(
        document["stateTransition"],
        {"oldStateSha256", "newStateSha256", "transitionSha256"},
        "public Nitro final state transition",
    )
    for field in transition:
        require_sha256(
            transition[field],
            f"public Nitro final state transition {field}",
        )
    state_commit = exact_keys(
        document["stateCommit"],
        PUBLIC_NITRO_STATE_COMMIT_FIELDS,
        "public Nitro final state commit",
    )
    require(
        state_commit["apiVersion"]
        == "serverware.publicNitroStateCommit/v1"
        and state_commit["status"]
        == "redemption-verified-non-actionable"
        and state_commit["actionable"] is False
        and state_commit["redemptionVerified"] is True,
        "public Nitro final state commit is not closed and non-actionable",
    )
    for field in (
        "challengeConsumptionSha256",
        "currentFinalHeadSha256",
        "currentHeadAuthorizationFileSha256",
        "currentHeadAuthorizationKeyId",
        "currentHeadRedemptionKeyId",
        "currentHeadRedemptionReceiptFileSha256",
        "currentHeadRedemptionReceiptIdentitySha256",
        "currentHeadRedemptionVerifierNonceSha256",
        "currentHeadSha256",
        "currentHeadVerifierNonceSha256",
        "currentStateSha256",
        "priorStateSha256",
        "receiptFileSha256",
        "receiptPayloadSha256",
        "signingKeyId",
        "stateStoreSigningKeyId",
        "storeAssuranceKeyId",
        "tlsReleaseKeyId",
        "transitionSha256",
        "verifierStateKeyId",
    ):
        require_sha256(
            state_commit[field],
            f"public Nitro final state commit {field}",
        )
    for field in (
        "commitId",
        "currentHeadAuthorizationId",
        "currentHeadRedemptionId",
        "currentHeadReservationId",
        "storeId",
    ):
        require_identifier(
            state_commit[field],
            f"public Nitro final state commit {field}",
        )
    require_positive_uint(
        state_commit["currentHeadOneUseSequence"],
        "public Nitro final state commit one-use sequence",
    )
    rollback_boundary = state_commit["rollbackResistanceBoundary"]
    require(
        isinstance(rollback_boundary, str)
        and 1 <= len(rollback_boundary) <= 4096
        and not any(
            separator in rollback_boundary
            for separator in ("\r", "\n", "\u2028", "\u2029")
        ),
        "public Nitro final rollback-resistance boundary is invalid",
    )
    require(
        transition["newStateSha256"] == next_state["stateSha256"]
        and transition["transitionSha256"]
        == sha256_json(
            {
                "oldStateSha256": transition["oldStateSha256"],
                "newStateSha256": transition["newStateSha256"],
            }
        )
        and next_state["challengeConsumptionSha256"]
        == witness["challengeConsumptionSha256"]
        and state_commit["priorStateSha256"]
        == transition["oldStateSha256"]
        and state_commit["currentStateSha256"]
        == transition["newStateSha256"]
        and state_commit["transitionSha256"]
        == transition["transitionSha256"]
        and state_commit["challengeConsumptionSha256"]
        == witness["challengeConsumptionSha256"]
        and witness["witnessKeyId"] == roles["witness"]
        and witness["witnessStoreKeyId"]
        == roles["witnessStore"]
        and state_commit["signingKeyId"] == roles["stateCommit"]
        and state_commit["stateStoreSigningKeyId"]
        == roles["stateStore"]
        and state_commit["currentHeadAuthorizationKeyId"]
        == roles["currentHeadAuthorization"]
        and state_commit["currentHeadRedemptionKeyId"]
        == roles["currentHeadRedemption"]
        and state_commit["verifierStateKeyId"]
        == roles["verifierState"]
        and state_commit["storeAssuranceKeyId"]
        == roles["storeAssurance"]
        and state_commit["tlsReleaseKeyId"]
        == roles["tlsRelease"],
        "public Nitro final result crossed its witness, transition, or state roles",
    )
    return document


def validate_public_nitro_result_signing_request(
    document: Any,
) -> dict[str, Any]:
    request = exact_keys(
        document,
        {
            "apiVersion",
            "envelopeCore",
            "operation",
            "operationIdSha256",
            "recoveryKeySha256",
            "requestSha256",
            "retrySemantics",
            "signingMessageSha256",
            "transportPins",
        },
        "public Nitro result signing request",
    )
    envelope_core = exact_keys(
        request["envelopeCore"],
        {
            "apiVersion",
            "provider",
            "result",
            "resultSha256",
            "signingKeyId",
            "signingKeySpkiSha256",
        },
        "public Nitro result signing envelope core",
    )
    transport_pins = exact_keys(
        request["transportPins"],
        {"signerServerTlsSpkiSha256"},
        "public Nitro signer transport pins",
    )
    validate_public_nitro_final_result_contract(envelope_core["result"])
    require_public_nitro_provider(
        envelope_core["provider"],
        "public Nitro result signer provider",
    )
    require_sha256(
        transport_pins["signerServerTlsSpkiSha256"],
        "public Nitro signer server TLS SPKI",
    )
    require(
        request["apiVersion"]
        == PUBLIC_NITRO_RESULT_SIGNING_REQUEST_VERSION
        and request["operation"]
        == "sign-public-nitro-live-verification-result"
        and request["retrySemantics"]
        == "same-recovery-key-requires-byte-identical-request-and-response"
        and envelope_core["apiVersion"]
        == PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_VERSION
        and envelope_core["resultSha256"]
        == sha256_json(envelope_core["result"])
        and envelope_core["signingKeyId"]
        == envelope_core["signingKeySpkiSha256"]
        == envelope_core["result"]["roleKeyIds"][
            "publicNitroResult"
        ],
        "public Nitro signing request crossed its envelope, result, or signer role",
    )
    request_core = {
        "apiVersion": request["apiVersion"],
        "envelopeCore": envelope_core,
        "operation": request["operation"],
        "retrySemantics": request["retrySemantics"],
        "signingMessageSha256": request["signingMessageSha256"],
        "transportPins": transport_pins,
    }
    operation_id = sha256(
        PUBLIC_NITRO_RESULT_SIGNING_OPERATION_DOMAIN
        + canonical_json_bytes(request_core)
    )
    require(
        request["signingMessageSha256"]
        == sha256(
            PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN
            + canonical_json_bytes(envelope_core)
        )
        and request["operationIdSha256"] == operation_id
        and request["recoveryKeySha256"]
        == sha256(
            PUBLIC_NITRO_RESULT_SIGNING_RECOVERY_DOMAIN
            + operation_id.encode("ascii")
        )
        and request["requestSha256"]
        == sha256_json(
            {
                **request_core,
                "operationIdSha256": operation_id,
                "recoveryKeySha256": request[
                    "recoveryKeySha256"
                ],
            }
        ),
        "public Nitro signing request deterministic identity or digest is invalid",
    )
    return request


def verify_public_nitro_result_signing_response(
    request: dict[str, Any],
    response: Any,
    *,
    signing_key: Ed25519PublicKey,
) -> dict[str, Any]:
    request = validate_public_nitro_result_signing_request(request)
    response = exact_keys(
        response,
        {
            "apiVersion",
            "envelope",
            "operationIdSha256",
            "recoveryKeySha256",
            "requestSha256",
            "status",
            "transportPins",
        },
        "public Nitro result signing response",
    )
    require(
        response["apiVersion"]
        == PUBLIC_NITRO_RESULT_SIGNING_RESPONSE_VERSION
        and response["status"] == "signed"
        and response["operationIdSha256"]
        == request["operationIdSha256"]
        and response["recoveryKeySha256"]
        == request["recoveryKeySha256"]
        and response["requestSha256"] == request["requestSha256"],
        "public Nitro signer response crossed its deterministic request or recovery identity",
    )
    require(
        response["transportPins"] == request["transportPins"],
        "public Nitro signer response crossed its deterministic request or recovery identity",
    )
    envelope = exact_keys(
        response["envelope"],
        {
            "apiVersion",
            "provider",
            "result",
            "resultSha256",
            "signature",
            "signingKeyId",
            "signingKeySpkiSha256",
        },
        "public Nitro live result envelope",
    )
    require(
        {
            key: value
            for key, value in envelope.items()
            if key != "signature"
        }
        == request["envelopeCore"]
        and isinstance(envelope["signature"], str)
        and envelope["signature"].startswith("ed25519:"),
        "public Nitro signer changed the exact requested envelope core",
    )
    verify_ed25519(
        signing_key,
        envelope["signature"][len("ed25519:"):],
        PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN
        + canonical_json_bytes(request["envelopeCore"]),
        "public Nitro live result envelope",
    )
    return envelope


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Offline production verification for Serverware Manifest v6 on "
            "AWS Nitro Enclaves. No trust roots or evidence are fetched."
        )
    )
    parser.add_argument("--evidence-bundle")
    parser.add_argument("--expectations")
    parser.add_argument("--trust-roots")
    parser.add_argument(
        "--expected-trust-roots-sha256",
        required=False,
        help="independently obtained sha256:<hex> digest of the trust-root bundle",
    )
    parser.add_argument(
        "--mode",
        choices=("verify", "finalize", "finalize-signed", "live"),
        default="verify",
    )
    parser.add_argument(
        "--protected-client-state",
        required=False,
        help=(
            "durable prior off-host witness state; stateless production "
            "verification is intentionally unsupported"
        ),
    )
    parser.add_argument(
        "--protected-client-state-checkpoint",
        required=False,
        help="separately signed indexed checkpoint for protected prior state",
    )
    parser.add_argument(
        "--state-commit-receipt",
        help="required in finalize mode: signed external CAS commit receipt",
    )
    parser.add_argument(
        "--current-head-authorization",
        help=(
            "required in finalize mode: fresh signed one-use current-head "
            "authorization issued after the CAS receipt was verified"
        ),
    )
    parser.add_argument(
        "--current-head-verifier-nonce",
        help=(
            "required in finalize mode: independently generated fresh 32-byte "
            "unpadded base64url nonce supplied to the external state store "
            "only after CAS verification"
        ),
    )
    parser.add_argument(
        "--current-head-redemption-receipt",
        help=(
            "required in finalize mode: signed receipt from the atomic "
            "compare-current-head-and-redeem operation"
        ),
    )
    parser.add_argument(
        "--current-head-redemption-verifier-nonce",
        help=(
            "required in finalize mode: independently generated fresh "
            "32-byte unpadded base64url nonce created only after current-head "
            "authorization verification"
        ),
    )
    parser.add_argument(
        "--challenge",
        help="independently generated 32-byte unpadded base64url challenge",
    )
    parser.add_argument("--live-session-proof")
    parser.add_argument("--live-session-signature")
    parser.add_argument("--delivery-rebind")
    parser.add_argument("--response-signing-public-key")
    parser.add_argument("--request-body")
    parser.add_argument("--tls-binding")
    parser.add_argument("--protected-live-witness-state")
    parser.add_argument("--prior-protected-live-witness-state")
    parser.add_argument("--nonce-consumption-receipt")
    parser.add_argument("--nonce-authority-assurance-evidence")
    parser.add_argument("--prior-nonce-authority-verifier-state")
    parser.add_argument("--nonce-authority-state-authorization")
    parser.add_argument("--nonce-authority-state-commit-receipt")
    parser.add_argument(
        "--nonce-authority-verifier-challenge",
        help=(
            "fresh independently generated 32-byte unpadded base64url "
            "challenge bound to current-head authorization and CAS commit"
        ),
    )
    parser.add_argument("--caller-nonce")
    parser.add_argument(
        "--witness-verifier-challenge",
        help=(
            "fresh independently generated 32-byte unpadded base64url "
            "challenge used for the witness current request"
        ),
    )
    parser.add_argument("--expected-release-config-sha256")
    parser.add_argument(
        "--expected-nonce-authority-assurance-sha256"
    )
    parser.add_argument(
        "--expected-nonce-authority-assurance-issuer-spki-sha256"
    )
    parser.add_argument("--expected-attestation-pins")
    parser.add_argument("--public-nitro-role-registry")
    parser.add_argument(
        "--expected-public-nitro-role-registry-sha256"
    )
    parser.add_argument("--public-nitro-result-signer-provider")
    parser.add_argument("--public-nitro-result-signing-key-id")
    parser.add_argument(
        "--public-nitro-result-signing-key-spki-sha256"
    )
    parser.add_argument(
        "--public-nitro-result-signer-server-tls-spki-sha256"
    )
    parser.add_argument(
        "--public-nitro-state-store-server-tls-spki-sha256"
    )
    parser.add_argument("--public-nitro-result-signing-public-key")
    parser.add_argument("--public-nitro-result-signing-request")
    parser.add_argument("--public-nitro-result-signing-response")
    parser.add_argument("--witness-store-identity-sha256")
    parser.add_argument("--witness-store-assurance-sha256")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    file_argument_names = (
        "current_head_authorization",
        "current_head_redemption_receipt",
        "delivery_rebind",
        "evidence_bundle",
        "expected_attestation_pins",
        "expectations",
        "live_session_proof",
        "nonce_consumption_receipt",
        "nonce_authority_assurance_evidence",
        "nonce_authority_state_authorization",
        "nonce_authority_state_commit_receipt",
        "prior_nonce_authority_verifier_state",
        "prior_protected_live_witness_state",
        "protected_client_state",
        "protected_client_state_checkpoint",
        "protected_live_witness_state",
        "public_nitro_result_signing_public_key",
        "public_nitro_result_signing_request",
        "public_nitro_result_signing_response",
        "public_nitro_role_registry",
        "request_body",
        "response_signing_public_key",
        "state_commit_receipt",
        "tls_binding",
        "trust_roots",
    )
    for argument_name in file_argument_names:
        value = getattr(args, argument_name)
        if value is not None:
            require_normalized_absolute_path(
                value,
                f"--{argument_name.replace('_', '-')} value",
            )
    if args.mode == "finalize-signed":
        recovery_inputs = {
            "retained signing request":
            args.public_nitro_result_signing_request,
            "external signer response":
            args.public_nitro_result_signing_response,
            "signing public key":
            args.public_nitro_result_signing_public_key,
            "caller-pinned signer provider":
            args.public_nitro_result_signer_provider,
            "caller-pinned signing key ID":
            args.public_nitro_result_signing_key_id,
            "caller-pinned signing SPKI digest":
            args.public_nitro_result_signing_key_spki_sha256,
            "caller-pinned signer server TLS SPKI":
            args.public_nitro_result_signer_server_tls_spki_sha256,
        }
        for label, value in recovery_inputs.items():
            require(
                isinstance(value, str) and bool(value),
                f"finalize-signed mode requires {label}",
            )
        retained_request, retained_request_raw = load_json_file(
            Path(args.public_nitro_result_signing_request),
            "retained public Nitro result signing request",
        )
        signer_response, signer_response_raw = load_json_file(
            Path(args.public_nitro_result_signing_response),
            "external public Nitro result signing response",
        )
        require(
            retained_request_raw
            == canonical_json_bytes(retained_request) + b"\n"
            and signer_response_raw
            == canonical_json_bytes(signer_response) + b"\n",
            "finalize-signed recovery inputs are not canonical JSON plus LF",
        )
        terminal_request = None
        terminal_request_kind = None
        retained_version = (
            retained_request.get("apiVersion")
            if isinstance(retained_request, Mapping)
            else None
        )
        if retained_version == PUBLIC_NITRO_RESULT_RECOVERY_REQUEST_VERSION:
            terminal_request = (
                validate_public_nitro_result_recovery_request(
                    retained_request
                )
            )
            terminal_request_kind = "recovery"
            retained_request = terminal_request["signingRequest"]
        elif retained_version == PUBLIC_NITRO_RESULT_STATUS_REQUEST_VERSION:
            terminal_request = validate_public_nitro_result_status_request(
                retained_request
            )
            terminal_request_kind = "status"
            retained_request = terminal_request["signingRequest"]
        else:
            retained_request = (
                validate_public_nitro_result_signing_request(
                    retained_request
                )
            )
        envelope_core = retained_request["envelopeCore"]
        require(
            envelope_core["provider"]
            == args.public_nitro_result_signer_provider
            and envelope_core["signingKeyId"]
            == require_sha256(
                args.public_nitro_result_signing_key_id,
                "caller-pinned public Nitro signing key ID",
            )
            and envelope_core["signingKeySpkiSha256"]
            == require_sha256(
                args.public_nitro_result_signing_key_spki_sha256,
                "caller-pinned public Nitro signing SPKI digest",
            ),
            "retained public Nitro signing request differs from caller-pinned signer identity",
        )
        require(
            retained_request["transportPins"][
                "signerServerTlsSpkiSha256"
            ]
            == require_sha256(
                args.public_nitro_result_signer_server_tls_spki_sha256,
                "caller-pinned public Nitro signer server TLS SPKI",
            ),
            "retained public Nitro signing request differs from the caller-pinned signer transport",
        )
        signing_public_key_raw = read_regular(
            Path(args.public_nitro_result_signing_public_key),
            label="public Nitro result signing public key",
        )
        try:
            signing_public_key_pem = signing_public_key_raw.decode(
                "ascii"
            )
        except UnicodeDecodeError as exc:
            raise VerificationError(
                "public Nitro result signing public key is not ASCII PEM"
            ) from exc
        signing_public_key, calculated_signing_key_id = (
            load_ed25519_key(
                signing_public_key_pem,
                "public Nitro result signing public key",
            )
        )
        require(
            calculated_signing_key_id
            == envelope_core["signingKeyId"]
            == envelope_core["signingKeySpkiSha256"],
            "public Nitro signing public key differs from the retained request and caller pins",
        )
        if terminal_request is None:
            envelope = verify_public_nitro_result_signing_response(
                retained_request,
                signer_response,
                signing_key=signing_public_key,
            )
        elif terminal_request_kind == "recovery":
            envelope = (
                validate_public_nitro_result_recovered_response(
                    terminal_request,
                    signer_response,
                    signing_key=signing_public_key,
                )
            )
        else:
            envelope = validate_public_nitro_result_status_response(
                terminal_request,
                signer_response,
                signing_key=signing_public_key,
            )
        sys.stdout.buffer.write(canonical_json_bytes(envelope) + b"\n")
        return
    require(
        isinstance(args.evidence_bundle, str)
        and bool(args.evidence_bundle)
        and isinstance(args.trust_roots, str)
        and bool(args.trust_roots)
        and isinstance(args.expected_trust_roots_sha256, str)
        and bool(args.expected_trust_roots_sha256),
        "verify, finalize, and live modes require the evidence bundle, trust roots, and independent trust-root digest",
    )
    bundle, bundle_raw = load_json_file(
        Path(args.evidence_bundle),
        "public Nitro evidence bundle",
    )
    trust_doc, trust_raw = load_json_file(Path(args.trust_roots), "independent public trust roots")
    expected_trust_roots_sha256 = require_sha256(
        args.expected_trust_roots_sha256,
        "independently expected trust-root bundle",
    )
    trust = load_trust_roots(
        trust_doc,
        trust_raw,
        independently_expected_sha256=expected_trust_roots_sha256,
    )
    now = int(time.time())
    if args.mode == "live":
        live_inputs = {
            "caller nonce": args.caller_nonce,
            "expected release config": args.expected_release_config_sha256,
            "expected nonce authority assurance":
            args.expected_nonce_authority_assurance_sha256,
            "expected nonce authority assurance issuer key":
            args.expected_nonce_authority_assurance_issuer_spki_sha256,
            "expected attestation pins":
            args.expected_attestation_pins,
            "live session proof": args.live_session_proof,
            "live session signature": args.live_session_signature,
            "delivery rebind": args.delivery_rebind,
            "nonce consumption receipt":
            args.nonce_consumption_receipt,
            "nonce authority assurance evidence":
            args.nonce_authority_assurance_evidence,
            "nonce authority current-head authorization":
            args.nonce_authority_state_authorization,
            "nonce authority state commit receipt":
            args.nonce_authority_state_commit_receipt,
            "nonce authority verifier challenge":
            args.nonce_authority_verifier_challenge,
            "prior nonce authority verifier state":
            args.prior_nonce_authority_verifier_state,
            "prior protected live-witness state":
            args.prior_protected_live_witness_state,
            "protected live-witness state":
            args.protected_live_witness_state,
            "request body": args.request_body,
            "response signing public key":
            args.response_signing_public_key,
            "TLS binding": args.tls_binding,
            "witness verifier challenge":
            args.witness_verifier_challenge,
        }
        for label, value in live_inputs.items():
            require(
                isinstance(value, str) and bool(value),
                f"live mode requires {label}",
            )
        proof_document, proof_raw = load_json_file(
            Path(args.live_session_proof),
            "live session proof",
        )
        delivery_rebind, delivery_rebind_raw = load_json_file(
            Path(args.delivery_rebind),
            "signed current-connection delivery rebind",
        )
        tls_binding, tls_binding_raw = load_json_file(
            Path(args.tls_binding),
            "independently authenticated TLS binding",
        )
        protected_live_witness_state, protected_live_witness_raw = (
            load_json_file(
                Path(args.protected_live_witness_state),
                "signed protected current live-witness state",
            )
        )
        prior_protected_live_witness_state, prior_witness_raw = (
            load_json_file(
                Path(args.prior_protected_live_witness_state),
                "independently retained signed prior live-witness state",
            )
        )
        nonce_consumption_receipt, nonce_receipt_raw = load_json_file(
            Path(args.nonce_consumption_receipt),
            "signed public-attestation nonce consumption receipt",
        )
        nonce_authority_assurance_evidence, nonce_assurance_raw = (
            load_json_file(
                Path(args.nonce_authority_assurance_evidence),
                "signed nonce authority assurance evidence",
            )
        )
        prior_nonce_authority_verifier_state, prior_nonce_state_raw = (
            load_json_file(
                Path(args.prior_nonce_authority_verifier_state),
                "signed prior nonce authority verifier state",
            )
        )
        nonce_authority_state_authorization, nonce_state_auth_raw = (
            load_json_file(
                Path(args.nonce_authority_state_authorization),
                "signed nonce authority current-head authorization",
            )
        )
        nonce_authority_state_commit_receipt, nonce_state_commit_raw = (
            load_json_file(
                Path(args.nonce_authority_state_commit_receipt),
                "signed nonce authority verifier-state commit receipt",
            )
        )
        expected_attestation_pins, expected_pins_raw = load_json_file(
            Path(args.expected_attestation_pins),
            "independently expected public-attestation pins",
        )
        require(
            proof_raw
            == canonical_json_bytes(proof_document) + b"\n"
            and delivery_rebind_raw
            == canonical_json_bytes(delivery_rebind) + b"\n"
            and tls_binding_raw
            == canonical_json_bytes(tls_binding) + b"\n"
            and protected_live_witness_raw
            == canonical_json_bytes(protected_live_witness_state) + b"\n"
            and prior_witness_raw
            == canonical_json_bytes(prior_protected_live_witness_state)
            + b"\n"
            and nonce_receipt_raw
            == canonical_json_bytes(nonce_consumption_receipt) + b"\n"
            and nonce_assurance_raw
            == canonical_json_bytes(
                nonce_authority_assurance_evidence
            )
            + b"\n"
            and prior_nonce_state_raw
            == canonical_json_bytes(
                prior_nonce_authority_verifier_state
            )
            + b"\n"
            and nonce_state_auth_raw
            == canonical_json_bytes(
                nonce_authority_state_authorization
            )
            + b"\n"
            and nonce_state_commit_raw
            == canonical_json_bytes(
                nonce_authority_state_commit_receipt
            )
            + b"\n"
            and expected_pins_raw
            == canonical_json_bytes(expected_attestation_pins) + b"\n",
            "live-mode JSON input is not canonical JSON plus LF",
        )
        response_public_key_raw = read_regular(
            Path(args.response_signing_public_key),
            label="live response signing public key",
        )
        try:
            response_public_key_pem = response_public_key_raw.decode(
                "ascii"
            )
        except UnicodeDecodeError as exc:
            raise VerificationError(
                "live response signing public key is not ASCII PEM"
            ) from exc
        request_body = read_regular(
            Path(args.request_body),
            label="exact public attestation request body",
        )
        caller_nonce = b64url_decode_exact(
            args.caller_nonce,
            "public attestation caller nonce",
            exact_bytes=32,
        )
        witness_verifier_challenge = b64url_decode_exact(
            args.witness_verifier_challenge,
            "public attestation witness verifier challenge",
            exact_bytes=32,
        )
        nonce_authority_verifier_challenge = b64url_decode_exact(
            args.nonce_authority_verifier_challenge,
            "nonce authority verifier challenge",
            exact_bytes=32,
        )
        result = verify_public_v3_response(
            evidence_body=bundle_raw,
            live_session_proof=proof_document,
            live_session_signature=args.live_session_signature,
            response_signing_public_key_pem=response_public_key_pem,
            caller_nonce=caller_nonce,
            request_body=request_body,
            expected_tls_binding=tls_binding,
            delivery_rebind=delivery_rebind,
            trust=trust,
            expected_release_config_sha256=(
                args.expected_release_config_sha256
            ),
            expected_nonce_authority_assurance_sha256=(
                args.expected_nonce_authority_assurance_sha256
            ),
            expected_nonce_authority_assurance_issuer_spki_sha256=(
                args.expected_nonce_authority_assurance_issuer_spki_sha256
            ),
            expected_attestation_pins=expected_attestation_pins,
            protected_witness_state=protected_live_witness_state,
            protected_witness_state_raw=protected_live_witness_raw,
            prior_protected_witness_state=(
                prior_protected_live_witness_state
            ),
            nonce_consumption_receipt=nonce_consumption_receipt,
            nonce_authority_assurance_evidence=(
                nonce_authority_assurance_evidence
            ),
            prior_nonce_authority_verifier_state=(
                prior_nonce_authority_verifier_state
            ),
            nonce_authority_state_authorization=(
                nonce_authority_state_authorization
            ),
            nonce_authority_state_commit_receipt=(
                nonce_authority_state_commit_receipt
            ),
            nonce_authority_verifier_challenge=(
                nonce_authority_verifier_challenge
            ),
            witness_verifier_challenge=witness_verifier_challenge,
            now=now,
        )
        sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")
        return
    require(
        isinstance(args.expectations, str)
        and bool(args.expectations)
        and isinstance(args.protected_client_state, str)
        and bool(args.protected_client_state)
        and isinstance(args.protected_client_state_checkpoint, str)
        and bool(args.protected_client_state_checkpoint)
        and isinstance(args.challenge, str)
        and bool(args.challenge),
        "verify/finalize mode requires expectations, protected state, "
        "protected-state checkpoint, and challenge",
    )
    require(
        all(
            value is None
            for value in (
                args.live_session_proof,
                args.live_session_signature,
                args.response_signing_public_key,
                args.request_body,
                args.tls_binding,
                args.protected_live_witness_state,
                args.prior_protected_live_witness_state,
                args.nonce_consumption_receipt,
                args.nonce_authority_assurance_evidence,
                args.prior_nonce_authority_verifier_state,
                args.nonce_authority_state_authorization,
                args.nonce_authority_state_commit_receipt,
                args.nonce_authority_verifier_challenge,
                args.caller_nonce,
                args.witness_verifier_challenge,
                args.expected_release_config_sha256,
                args.expected_nonce_authority_assurance_sha256,
                args.expected_nonce_authority_assurance_issuer_spki_sha256,
                args.expected_attestation_pins,
            )
        ),
        "live-session inputs are accepted only in live mode",
    )
    expectations_doc, _ = load_json_file(
        Path(args.expectations),
        "independent production expectations",
    )
    state_doc, _ = load_json_file(
        Path(args.protected_client_state),
        "protected prior witness state",
    )
    state_checkpoint_doc, _ = load_json_file(
        Path(args.protected_client_state_checkpoint),
        "protected prior-state checkpoint",
    )
    expectations = load_expectations(expectations_doc)
    require(
        expected_trust_roots_sha256
        == expectations["trustRootBundleSha256"],
        "CLI trust-root digest differs from independent expectations",
    )
    prior_state, _ = verify_protected_client_state(
        state_doc,
        state_checkpoint_doc,
        trust=trust,
        now=now,
    )
    challenge = b64url_decode(args.challenge, "caller challenge", max_bytes=64)
    result = verify_bundle(
        bundle,
        expectations=expectations,
        trust=trust,
        prior_state=prior_state,
        challenge=challenge,
        now=now,
    )
    if args.mode == "finalize":
        require(
            isinstance(args.state_commit_receipt, str)
            and bool(args.state_commit_receipt),
            "finalize mode requires --state-commit-receipt",
        )
        commit_document, _ = load_json_file(
            Path(args.state_commit_receipt),
            "external CAS state-commit receipt",
        )
        result = finalize_state_commit(
            result,
            commit_document,
            trust=trust,
            now=now,
        )
        require(
            isinstance(args.current_head_authorization, str)
            and bool(args.current_head_authorization)
            and isinstance(args.current_head_verifier_nonce, str)
            and bool(args.current_head_verifier_nonce),
            "finalize mode requires --current-head-authorization and "
            "--current-head-verifier-nonce after CAS verification",
        )
        authorization_document, _ = load_json_file(
            Path(args.current_head_authorization),
            "external current-head authorization",
        )
        verifier_nonce = b64url_decode(
            args.current_head_verifier_nonce,
            "current-head verifier nonce",
            max_bytes=64,
        )
        result = authorize_current_head(
            result,
            authorization_document,
            verifier_nonce=verifier_nonce,
            trust=trust,
            now=now,
        )
        require(
            isinstance(args.current_head_redemption_receipt, str)
            and bool(args.current_head_redemption_receipt)
            and isinstance(
                args.current_head_redemption_verifier_nonce,
                str,
            )
            and bool(args.current_head_redemption_verifier_nonce),
            "finalize mode requires --current-head-redemption-receipt and "
            "--current-head-redemption-verifier-nonce after authorization",
        )
        redemption_document, _ = load_json_file(
            Path(args.current_head_redemption_receipt),
            "atomic current-head redemption receipt",
        )
        redemption_verifier_nonce = b64url_decode(
            args.current_head_redemption_verifier_nonce,
            "current-head redemption verifier nonce",
            max_bytes=64,
        )
        result = finalize_current_head_redemption(
            result,
            redemption_document,
            verifier_nonce=redemption_verifier_nonce,
            trust=trust,
            now=now,
        )
        final_inputs = {
            "public Nitro role registry":
            args.public_nitro_role_registry,
            "expected public Nitro role registry digest":
            args.expected_public_nitro_role_registry_sha256,
            "public Nitro result signer provider":
            args.public_nitro_result_signer_provider,
            "public Nitro result signing key ID":
            args.public_nitro_result_signing_key_id,
            "public Nitro result signing SPKI digest":
            args.public_nitro_result_signing_key_spki_sha256,
            "public Nitro result signing public key":
            args.public_nitro_result_signing_public_key,
            "public Nitro result signer server TLS SPKI":
            args.public_nitro_result_signer_server_tls_spki_sha256,
            "public Nitro state-store server TLS SPKI":
            args.public_nitro_state_store_server_tls_spki_sha256,
            "witness-store identity": args.witness_store_identity_sha256,
            "witness-store assurance":
            args.witness_store_assurance_sha256,
        }
        for label, value in final_inputs.items():
            require(
                isinstance(value, str) and bool(value),
                f"{args.mode} mode requires {label}",
            )
        role_registry, role_registry_raw = load_json_file(
            Path(args.public_nitro_role_registry),
            "independently pinned public Nitro role registry",
        )
        require(
            role_registry_raw
            == canonical_json_bytes(role_registry) + b"\n",
            "public Nitro role registry is not canonical JSON plus LF",
        )
        signing_public_key_raw = read_regular(
            Path(args.public_nitro_result_signing_public_key),
            label="public Nitro result signing public key",
        )
        try:
            signing_public_key_pem = signing_public_key_raw.decode(
                "ascii"
            )
        except UnicodeDecodeError as exc:
            raise VerificationError(
                "public Nitro result signing public key is not ASCII PEM"
            ) from exc
        signing_public_key, calculated_signing_key_id = (
            load_ed25519_key(
                signing_public_key_pem,
                "public Nitro result signing public key",
            )
        )
        require(
            calculated_signing_key_id
            == require_sha256(
                args.public_nitro_result_signing_key_id,
                "public Nitro result signing key ID",
            )
            == require_sha256(
                args.public_nitro_result_signing_key_spki_sha256,
                "public Nitro result signing SPKI digest",
            ),
            "public Nitro result signing public key differs from caller pins",
        )
        roles = validate_public_nitro_role_registry(
            role_registry,
            expected_sha256=(
                args.expected_public_nitro_role_registry_sha256
            ),
            result_signer_key_id=calculated_signing_key_id,
            result_signer_server_tls_spki_sha256=(
                args
                .public_nitro_result_signer_server_tls_spki_sha256
            ),
            state_store_server_tls_spki_sha256=(
                args
                .public_nitro_state_store_server_tls_spki_sha256
            ),
            tls_release_key_id=result["tlsSpkiSha256"],
            release_ca_key_id=result["releaseIdentity"][
                "configuration"
            ]["caSpkiSha256"],
            response_key_id=result["releaseIdentity"][
                "configuration"
            ]["responseKeySpkiSha256"],
            trust=trust,
        )
        final_result = project_public_nitro_final_result(
            result,
            roles=roles,
            witness_store_identity_sha256=(
                args.witness_store_identity_sha256
            ),
            witness_store_assurance_sha256=(
                args.witness_store_assurance_sha256
            ),
            verified_at_unix=now,
        )
        signing_request = build_public_nitro_result_signing_request(
            final_result,
            provider=args.public_nitro_result_signer_provider,
            signing_key_id=calculated_signing_key_id,
            signing_key_spki_sha256=calculated_signing_key_id,
            signer_server_tls_spki_sha256=(
                args
                .public_nitro_result_signer_server_tls_spki_sha256
            ),
        )
        require(
            args.public_nitro_result_signing_request is None
            and args.public_nitro_result_signing_response is None,
            "signing request/response files are accepted only in finalize-signed mode",
        )
        sys.stdout.buffer.write(
            canonical_json_bytes(signing_request) + b"\n"
        )
        return
    else:
        require(
            args.state_commit_receipt is None
            and args.current_head_authorization is None
            and args.current_head_verifier_nonce is None,
            "state-commit and current-head inputs are accepted only in finalize mode",
        )
        require(
            args.current_head_redemption_receipt is None
            and args.current_head_redemption_verifier_nonce is None,
            "current-head redemption inputs are accepted only in finalize mode",
        )
        require(
            all(
                value is None
                for value in (
                    args.public_nitro_role_registry,
                    args.expected_public_nitro_role_registry_sha256,
                    args.public_nitro_result_signer_provider,
                    args.public_nitro_result_signing_key_id,
                    args.public_nitro_result_signing_key_spki_sha256,
                    args.public_nitro_result_signing_public_key,
                    args.public_nitro_result_signing_request,
                    args.public_nitro_result_signing_response,
                    args.witness_store_identity_sha256,
                    args.witness_store_assurance_sha256,
                )
            ),
            "public Nitro final-result signer inputs are accepted only in finalize modes",
        )
    sys.stdout.buffer.write(canonical_json_bytes(result) + b"\n")


def _public_nitro_recovery_sha256(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _build_public_nitro_result_terminal_request(
    signing_request: Mapping[str, Any],
    *,
    api_version: str,
    operation: str,
    digest_field: str,
) -> dict[str, Any]:
    request = validate_public_nitro_result_signing_request(signing_request)
    for field in (
        "operationIdSha256",
        "recoveryKeySha256",
        "requestSha256",
        "transportPins",
    ):
        if field not in request:
            raise VerificationError(
                f"public Nitro signing request is missing {field}"
            )
    core = {
        "apiVersion": api_version,
        "operation": operation,
        "operationIdSha256": request["operationIdSha256"],
        "recoveryKeySha256": request["recoveryKeySha256"],
        "requestSha256": request["requestSha256"],
        "signingRequest": request,
        "transportPins": request["transportPins"],
    }
    return {
        **core,
        digest_field: _public_nitro_recovery_sha256(core),
    }


def build_public_nitro_result_recovery_request(
    signing_request: Mapping[str, Any],
) -> dict[str, Any]:
    return _build_public_nitro_result_terminal_request(
        signing_request,
        api_version=PUBLIC_NITRO_RESULT_RECOVERY_REQUEST_VERSION,
        operation="recover-public-nitro-live-verification-result",
        digest_field="recoveryRequestSha256",
    )


def build_public_nitro_result_status_request(
    signing_request: Mapping[str, Any],
) -> dict[str, Any]:
    return _build_public_nitro_result_terminal_request(
        signing_request,
        api_version=PUBLIC_NITRO_RESULT_STATUS_REQUEST_VERSION,
        operation="status-public-nitro-live-verification-result",
        digest_field="statusRequestSha256",
    )


def _validate_public_nitro_result_terminal_request(
    value: Any,
    *,
    api_version: str,
    operation: str,
    digest_field: str,
    label: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise VerificationError(
            f"public Nitro signer {label} request must be an object"
        )
    request = dict(value)
    expected_keys = {
        "apiVersion",
        "operation",
        "operationIdSha256",
        "recoveryKeySha256",
        "requestSha256",
        "signingRequest",
        "transportPins",
        digest_field,
    }
    if set(request) != expected_keys:
        raise VerificationError(
            f"public Nitro signer {label} request fields are not exact"
        )
    if request["apiVersion"] != api_version:
        raise VerificationError(
            f"public Nitro signer {label} request version is unsupported"
        )
    if request["operation"] != operation:
        raise VerificationError(
            f"public Nitro signer {label} operation is invalid"
        )
    signing_request = request["signingRequest"]
    if not isinstance(signing_request, Mapping):
        raise VerificationError(
            f"public Nitro signer {label} signingRequest must be an object"
        )
    signing_request = validate_public_nitro_result_signing_request(
        signing_request
    )
    for field in (
        "operationIdSha256",
        "recoveryKeySha256",
        "requestSha256",
        "transportPins",
    ):
        if signing_request.get(field) != request[field]:
            raise VerificationError(
                f"public Nitro signer {label} identity does not match "
                f"signingRequest.{field}"
            )
    core = {
        key: request[key]
        for key in expected_keys
        if key != digest_field
    }
    if request[digest_field] != _public_nitro_recovery_sha256(core):
        raise VerificationError(
            f"public Nitro signer {label} request digest is invalid"
        )
    return request


def validate_public_nitro_result_recovery_request(
    value: Any,
) -> dict[str, Any]:
    return _validate_public_nitro_result_terminal_request(
        value,
        api_version=PUBLIC_NITRO_RESULT_RECOVERY_REQUEST_VERSION,
        operation="recover-public-nitro-live-verification-result",
        digest_field="recoveryRequestSha256",
        label="recovery",
    )


def validate_public_nitro_result_status_request(
    value: Any,
) -> dict[str, Any]:
    return _validate_public_nitro_result_terminal_request(
        value,
        api_version=PUBLIC_NITRO_RESULT_STATUS_REQUEST_VERSION,
        operation="status-public-nitro-live-verification-result",
        digest_field="statusRequestSha256",
        label="status",
    )


def validate_public_nitro_result_recovered_response(
    recovery_request: Any,
    response: Any,
    *,
    signing_key: Ed25519PublicKey,
) -> dict[str, Any]:
    recovery = validate_public_nitro_result_recovery_request(recovery_request)
    return verify_public_nitro_result_signing_response(
        recovery["signingRequest"],
        response,
        signing_key=signing_key,
    )


def validate_public_nitro_result_status_response(
    status_request: Any,
    response: Any,
    *,
    signing_key: Ed25519PublicKey,
) -> dict[str, Any]:
    status = validate_public_nitro_result_status_request(status_request)
    return verify_public_nitro_result_signing_response(
        status["signingRequest"],
        response,
        signing_key=signing_key,
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, VerificationError) as exc:
        sys.stderr.buffer.write(
            canonical_json_bytes(
                {
                    "apiVersion": RESULT_VERSION,
                    "error": str(exc),
                }
            )
            + b"\n"
        )
        raise SystemExit(1)
