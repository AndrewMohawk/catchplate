#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import errno
import fcntl
import hashlib
import hmac
import importlib
import io
import json
import os
import platform
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import tarfile
import time
import types
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import verify_nitro_tee


def load_readiness_dependencies() -> None:
    """Load the legacy Docker/readiness implementation only after mode dispatch."""
    global build_production_images
    global merge_production_images_env
    global production_release_input_preflight
    global run_production_readiness
    global verify_production_policy_identity
    global PolicySnapshot
    global compile_policy_bundle

    import build_production_images as build_images_module
    import merge_production_images_env as merge_images_module
    import production_release_input_preflight as release_input_module
    import run_production_readiness as readiness_module
    import verify_production_policy_identity as policy_identity_module
    from serverware.policy_bundle import (
        PolicySnapshot as PolicySnapshotType,
        compile_policy_bundle as compile_bundle,
    )

    build_production_images = build_images_module
    merge_production_images_env = merge_images_module
    production_release_input_preflight = release_input_module
    run_production_readiness = readiness_module
    verify_production_policy_identity = policy_identity_module
    PolicySnapshot = PolicySnapshotType
    compile_policy_bundle = compile_bundle


_MEASURED_PREFLIGHT_MODULE: types.ModuleType | None = None
_MEASURED_PREFLIGHT_MODULE_SHA256: str | None = None


def load_production_host_preflight_module(
    production_env: dict[str, str],
    *,
    final: bool,
    after_open: Any | None = None,
) -> types.ModuleType:
    global _MEASURED_PREFLIGHT_MODULE, _MEASURED_PREFLIGHT_MODULE_SHA256
    if not final:
        return importlib.import_module("production_host_preflight")
    setting = run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV
    expected_digest = production_env.get(setting)
    if not isinstance(expected_digest, str) or run_production_readiness.SHA256_RE.fullmatch(
        expected_digest
    ) is None:
        raise ValueError(f"{setting} must be sha256:<64 lowercase hex>")
    if (
        _MEASURED_PREFLIGHT_MODULE is not None
        and _MEASURED_PREFLIGHT_MODULE_SHA256 == expected_digest
    ):
        return _MEASURED_PREFLIGHT_MODULE
    path = (Path(__file__).resolve().parent / "production_host_preflight.py").resolve()
    measured = run_production_readiness.open_measured_script(path, expected_digest, setting)
    try:
        if after_open is not None:
            after_open(measured)
        os.lseek(measured.fd, 0, os.SEEK_SET)
        data = run_production_readiness.read_fd_bytes(
            measured.fd,
            measured.metadata,
            "measured production host preflight module",
            max_bytes=run_production_readiness.MAX_EXECUTABLE_BYTES,
        )
        module_name = "_serverware_measured_production_host_preflight"
        module = types.ModuleType(module_name)
        module.__file__ = str(path)
        module.__package__ = None
        sys.modules[module_name] = module
        try:
            exec(compile(data, str(path), "exec"), module.__dict__, module.__dict__)
        except Exception:
            sys.modules.pop(module_name, None)
            raise
    finally:
        measured.close()
    _MEASURED_PREFLIGHT_MODULE = module
    _MEASURED_PREFLIGHT_MODULE_SHA256 = expected_digest
    return module


REQUIRED_READINESS_CHECKS = {
    "no-dev-fixtures",
    "control-plane-auth",
    "nitro",
    "attested-credential-delivery",
    "cosign-sigstore",
    "external-transparency",
    "apparmor",
    "shared-stores",
    "agent-egress",
    "production-images-no-shell",
}
REQUIRED_MATERIALS = {"broker-kek", "decision-gate-ca"}
REQUIRED_STORES = {"metadata", "grant", "audit"}
TEST_ONLY_BYPASS_ENV = "SERVERWARE_TEST_ONLY_ALLOW_PREFLIGHT_BYPASS"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA384_RE = re.compile(r"^sha384:[0-9a-f]{96}$")
IMAGE_REF_RE = re.compile(r"^(?P<repo>[^@,\s]+)@(?P<digest>sha256:[0-9a-f]{64})$")
BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
PROXY_PROOF_MAX_AGE_LIMIT_SECONDS = 900
PROXY_PROOF_FUTURE_SKEW_SECONDS = 30
PROXY_PROOF_CONTRACT_ENV_KEY = "SERVERWARE_PROXY_PROOF_CONTRACT"
PROXY_PROOF_CONTRACTS = {"buffered-v3", "observation-v1", "streaming-v1"}
PROXY_STREAM_BODY_ENV_KEY = "SERVERWARE_PROXY_STREAM_BODY_FILE"
PROXY_STREAM_MAX_BYTES_ENV_KEY = "SERVERWARE_PROXY_PROOF_MAX_STREAM_BYTES"
PROXY_STREAM_OPERATION_CONTEXT_DIGEST_ENV_KEY = (
    "SERVERWARE_PROXY_EXPECTED_OPERATION_CONTEXT_DIGEST"
)
PROXY_OBSERVATION_BODY_ENV_KEY = "SERVERWARE_PROXY_OBSERVATION_BODY_FILE"
PROXY_OBSERVATION_MAX_BYTES_ENV_KEY = (
    "SERVERWARE_PROXY_PROOF_MAX_OBSERVATION_BODY_BYTES"
)
MAX_PROXY_STREAM_BODY_BYTES = 64 * 1024 * 1024
MAX_PROXY_OBSERVATION_BODY_BYTES = 16 * 1024 * 1024
MAX_VENDOR_QUOTE_BYTES = 96 * 1024
RESPONSE_OBSERVATION_NONCE_EXPIRY_BYTES = 4
RESPONSE_OBSERVATION_NONCE_MAX_LIFETIME_SECONDS = 330
STREAMING_TLS_EXPORTER_LABEL = "EXPORTER-Serverware-Proxy-Stream-v1"
CONTROL_PLANE_AUTHORIZATION_RECEIPT_API_VERSION = "serverware.controlPlaneAuthorizationReceipt/v1"
CONTROL_PLANE_RESPONSE_SIGNATURE_API_VERSION = "serverware.responseSignature/v3"
CONTROL_PLANE_DISPATCH_PATH = "/api/data-plane/release-authorizations/dispatch"
RELEASE_AUTHORIZATION_BINDING_V2 = "serverware.releaseAuthorizationBinding/v2"
RELEASE_AUTHORIZATION_DISPATCH_V1 = "serverware.releaseAuthorizationDispatch/v1"
RELEASE_AUTHORIZATION_DISPATCH_V2 = "serverware.releaseAuthorizationDispatch/v2"
RELEASE_AUTHORIZATION_RESPONSE_V1 = "serverware.releaseAuthorization/v1"
RELEASE_AUTHORIZATION_RESPONSE_V2 = "serverware.releaseAuthorization/v2"
HARDWARE_PROOF_API_VERSION = "serverware.hardwareAssurance/v1"
HARDWARE_PROOF_MAX_AGE_SECONDS = 900
HARDWARE_PROOF_FUTURE_SKEW_SECONDS = 30
EIF_BUILD_MANIFEST_API_VERSION = "serverware.eifBuildManifest/v1"
FINAL_CHALLENGE_LEDGER_API_VERSION = "serverware.finalChallengeLedger/v1"
FINAL_CHALLENGE_LEDGER_MAX_ENTRIES = 4096
FINAL_CHALLENGE_RECEIPT_API_VERSION = "serverware.finalChallengeReceipt/v1"
FINAL_CHALLENGE_RECEIPT_MAX_AGE_SECONDS = 900
FINAL_COMPLETION_IDENTITY_API_VERSION = "serverware.finalCompletionIdentity/v3"
PRODUCTION_RELEASE_IDENTITY_API_VERSION = "serverware.productionReleaseIdentity/v2"
PRODUCTION_CONTINUITY_SUMMARY_API_VERSION = "serverware.productionContinuitySummary/v1"
SOURCE_INPUT_MANIFEST_API_VERSION = "serverware.sourceInputManifest/v2"
GIT_SOURCE_INVENTORY_API_VERSION = "serverware.gitSourceInventory/v1"
UNTRACKED_SOURCE_APPROVAL_API_VERSION = "serverware.untrackedSourceApproval/v1"
CANDIDATE_MANIFEST_V6_API_VERSION = "serverware.consolidatedCandidateArtifacts/v6"
BUILD_WATCHDOG_RECEIPT_API_VERSION = "serverware.ociBuildWatchdogReceipt/v3"
PROMOTION_RECEIPT_API_VERSION = "serverware.verificationPromotionReceipt/v3"
DEPENDENCY_BUNDLE_API_VERSION = "serverware.ociDependencyBundle/v3"
RAW_BUILDER_STATEMENT_API_VERSION = "serverware.rawBuilderStatement/v1"
RAW_BUILDER_TRANSCRIPT_API_VERSION = "serverware.rawBuilderTranscript/v1"
MANIFEST_V6_EIF_BUILD_API_VERSION = "serverware.manifestV6EifBuildStatement/v1"
KEY_CUSTODY_EVIDENCE_API_VERSION = "serverware.enclaveKeyCustodyEvidence/v1"
MONOTONIC_WITNESS_API_VERSION = "serverware.monotonicReleaseWitness/v1"
MONOTONIC_WITNESS_STATE_API_VERSION = "serverware.monotonicReleaseWitnessState/v1"
COMPLETION_AUTHENTICATION_API_VERSION = "serverware.completionProofAuthentication/v1"
COMPLETION_CHECKPOINT_API_VERSION = "serverware.completionProofCheckpoint/v1"
COMPLETION_PROOF_API_VERSION = "serverware.completionProof/v6"
CANONICAL_JSON_PROFILE = (
    "serverware.canonicalJson/integer-string-bool-null-array-object-nfc-v1"
)
PROTECTED_CLIENT_STATE_API_VERSION = "serverware.protectedNitroClientState/v1"
PROTECTED_CLIENT_STATE_CHECKPOINT_API_VERSION = (
    "serverware.protectedNitroClientStateCheckpoint/v1"
)
PROTECTED_CLIENT_STATE_SIGNATURE_DOMAIN = (
    b"serverware.protectedNitroClientState/v1\x00Ed25519\x00"
)
PROTECTED_CLIENT_STATE_CHECKPOINT_SIGNATURE_DOMAIN = (
    b"serverware.protectedNitroClientStateCheckpoint/v1\x00Ed25519\x00"
)
PROTECTED_CLIENT_STATE_PROVENANCE_BOUNDARY = (
    "client-or-out-of-band-pinned-protected-state/v1"
)
FINAL_V6_STATE_COMMIT_API_VERSION = "serverware.publicNitroStateCommit/v1"
FINAL_V6_STATE_COMMIT_SIGNATURE_DOMAIN = (
    b"serverware.publicNitroStateCommit/v1\x00Ed25519\x00"
)
FINAL_V6_RESULT_API_VERSION = "serverware.releaseCompletionVerification/v1"
PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_API_VERSION = (
    "serverware.publicNitroLiveVerificationResultEnvelope/v1"
)
PUBLIC_NITRO_LIVE_RESULT_SIGNATURE_DOMAIN = (
    verify_nitro_tee.PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_DOMAIN
)
FINAL_RESULT_AUTHENTICITY_API_VERSION = (
    "serverware.releaseCompletionResultSignature/v1"
)
FINAL_RESULT_SIGNATURE_DOMAIN = (
    b"serverware.releaseCompletionResultSignature/v1\x00Ed25519\x00"
)
FINAL_RESULT_SIGNING_REQUEST_API_VERSION = (
    "serverware.releaseCompletionResultSigningRequest/v1"
)
FINAL_RESULT_SIGNING_REQUEST_KIND = "ReleaseCompletionResultSigningRequest"
FINAL_RESULT_SIGNING_RESPONSE_API_VERSION = (
    "serverware.releaseCompletionResultSigningResponse/v1"
)
FINAL_RESULT_SIGNING_RESPONSE_KIND = "ReleaseCompletionResultSigningResponse"
FINAL_RESULT_SIGNING_OPERATION = "sign-release-completion-result"
FINAL_RESULT_SIGNING_RETRY_SEMANTICS = (
    "same-idempotency-key-requires-byte-identical-request-and-response"
)
FINAL_RESULT_SIGNING_LOST_RESPONSE_RECOVERY = (
    "resubmit-byte-identical-request-and-recover-identical-signed-response"
)
FINAL_RESULT_SIGNING_CONFLICT_SEMANTICS = (
    "same-idempotency-key-with-different-request-fails-closed"
)
FINAL_V1_IDENTIFIER_RE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_.:@+-]{0,255}\Z",
    re.ASCII,
)
FINAL_V1_DIGEST_MAP_KEY_RE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z",
    re.ASCII,
)
FINAL_V1_NON_EMPTY_STRING_RE = re.compile(
    r"[^\r\n\u2028\u2029]{1,4096}\Z",
)
FINAL_ROLE_REGISTRY_API_VERSION = "serverware.finalRoleRegistry/v1"
PUBLIC_NITRO_ROLE_REGISTRY_API_VERSION = (
    "serverware.publicNitroRoleRegistry/v1"
)
HOST_READINESS_CONTEXT_API_VERSION = "serverware.hostReadinessContext/v1"
CANONICAL_JSON_SIGNED_MAX = (1 << 63) - 1
MILLISECONDS_TO_NANOSECONDS = 1_000_000
EXACT_MILLISECONDS_RE = re.compile(
    r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?\Z",
    re.ASCII,
)
BENCHMARK_MILLISECOND_FIELDS = frozenset(
    {"p50_ms", "p95_ms", "p99_ms", "min_ms", "max_ms", "mean_ms"}
)
PREFLIGHT_BENCHMARK_MILLISECOND_FIELDS = (
    BENCHMARK_MILLISECOND_FIELDS | {"target_p99_ms"}
)
PUBLIC_NITRO_CANONICAL_INTEGER_MAX = (
    verify_nitro_tee.PUBLIC_NITRO_CANONICAL_INTEGER_MAX
)
HOST_READINESS_V6_ENVELOPE_FIELDS = frozenset(
    {
        "proof_core_sha256",
        "independently_authenticated",
        "aggregate_authentication",
        "proof_path",
        "integrity_metadata",
    }
)
_HOST_READINESS_V6_SCHEMA_VALIDATOR: Any | None = None
FINAL_PUBLIC_RESULT_ROLE_NAMES = (
    verify_nitro_tee.PUBLIC_NITRO_RESULT_ROLE_NAMES
)
FINAL_REQUIRED_ROLE_NAMES = FINAL_PUBLIC_RESULT_ROLE_NAMES | {
    "releaseCompletionResult"
}
FINAL_V6_IDENTITY_API_VERSION = "serverware.productionReleaseCompletionBridge/v1"
FINAL_V6_ARTIFACT_BINDINGS_API_VERSION = (
    "serverware.manifestV6CompletionArtifactBindings/v1"
)
FINAL_V6_HOST_BOOTSTRAP_BOUNDARY_API_VERSION = (
    "serverware.hostBootstrapBoundary/v1"
)
FINAL_V6_HOST_BOOTSTRAP_BOUNDARY_FIELDS = frozenset(
    {
        "apiVersion",
        "launchManifestApiVersion",
        "launchAuthorizationRequestApiVersion",
        "launchAuthorizationApiVersion",
        "bootstrapReceiptApiVersion",
        "nonceRollbackAssuranceBindingApiVersion",
        "authorizationScope",
        "freshnessAuthority",
        "evidenceProvidedToFinalVerifier",
        "hostReadinessContextSha256",
        "hostReadinessCompletionProofFileSha256",
        "launchAuthorityKeyId",
        "authoritativeForFinalCompletion",
        "requiredForFinalCompletion",
        "relationship",
        "finalAuthority",
        "completionIdentitySha256",
        "bindingMechanism",
        "boundarySha256",
    }
)
FINAL_V6_PRODUCTION_IDENTITY_FIELDS = frozenset(
    {
        "apiVersion",
        "canonicalProfile",
        "pipeline",
        "legacyDockerNsmAccepted",
        "completionIdentity",
        "completionIdentitySha256",
        "releaseArtifactBindings",
        "publicNitroEvidenceBundleFileSha256",
        "publicNitroExpectationsFileSha256",
        "publicVerifierResultSha256",
        "productionIdentitySha256",
        "candidateManifestFileSha256",
        "candidateManifestPayloadSha256",
        "sourceInputManifestFileSha256",
        "sourceClosureSha256",
        "buildWatchdogReceiptFileSha256",
        "promotionReceiptFileSha256",
        "promotedManifestFileSha256",
        "promotedManifestPayloadSha256",
        "promotedManifestMeasuredFileSha256",
        "candidateToEif",
        "runtimeStateFileSha256",
        "runtimeKeyCustodyFileSha256",
        "enclaveInstanceId",
        "enclaveBootId",
        "runtimeKeyGenerations",
        "releaseGeneration",
        "rollbackEpoch",
        "policyHash",
        "policySequence",
        "caSpkiSha256",
        "eifSha384",
        "pcrs",
        "rawNitroAttestationDocumentSha256",
        "tlsExporterSha256",
        "tlsSpkiSha256",
        "tlsPeerSpkiSha256",
        "tlsStackMeasurementSha256",
        "attestationRequestSha256",
        "requestSha256",
        "responseBytesSha256",
        "releaseKeyCustodyEvidenceSha256",
        "kmsAuditProofSha256s",
        "completionProofFileSha256",
        "completionAuthenticationKeyId",
        "completionCheckpointKeyId",
        "hostBootstrapBoundarySha256",
        "witnessCheckpointSha256",
        "witnessChallengeConsumptionSha256",
        "witnessLeafIndex",
        "challengeSha256",
        "candidateExecutionContract",
        "watchdogAndBuilderGrammar",
        "promotionAcceptance",
        "publicHandoff",
        "protectedPriorClientState",
        "stateCommit",
        "trustRootPin",
        "identitySha256",
    }
)
FINAL_V6_EXTERNAL_PIN_PROVENANCE_BOUNDARY = (
    "The verifier proves equality to supplied pins. It cannot prove that an "
    "on-host argument was independently sourced; the client or another "
    "out-of-band trust channel must pin the bundle digest and protected-state "
    "key IDs."
)
FINAL_V6_EXTERNAL_PROVISIONING_BOUNDARY = (
    "Actual AWS Nitro EIF construction and PCR policy, AWS KMS "
    "CiphertextForRecipient releases, enclave-owned TLS exporter support, "
    "independent builders/promoter, off-host monotonic witness storage, "
    "CAS/current-head reservation and atomic authorization redemption, and a "
    "stateful action gate that re-checks the live final head and consumes the "
    "redemption receipt identity while performing the action must still be "
    "provisioned. This persisted completion is never an action capability."
)
FINAL_V6_COMPLETION_CORE_FIELDS = frozenset(
    {
        "builderA",
        "builderB",
        "continuity",
        "custody",
        "eif",
        "hardware",
        "promotion",
        "release",
        "response",
        "runtime",
        "source",
        "trust",
        "witness",
    }
)
PROTECTED_CLIENT_STATE_LEAF_API_VERSION = (
    "serverware.protectedNitroClientStateLeaf/v1"
)
FINAL_V6_MAX_VALIDITY_SECONDS = 24 * 60 * 60
MANIFEST_V6_PIPELINE = "manifest-v6-promoted-oci-nitro-eif"
LEGACY_DOCKER_NSM_PIPELINES = {
    "legacy-docker-dev-nsm-readiness",
    "serverware.productionReadinessLaunch/v2",
    "serverware.legacyDockerNsmProductionReadinessLaunch/v1",
}
FINAL_V6_TLS_SCOPE_API_VERSION = "serverware.enclaveTlsScope/v2"
FINAL_V6_RUNTIME_CUSTODY_API_VERSION = "serverware.enclaveKeyCustody/v3"
FINAL_V6_RESPONSE_STATEMENT_API_VERSION = "serverware.attestationResponse/v2"
FINAL_V6_HTTP_RESPONSE_API_VERSION = "serverware.attestationHttpResponse/v1"
FINAL_V6_PYTHON_ENTRYPOINT_SOURCE = "scripts/oci_lane_entrypoint.py"
FINAL_V6_PYTHON_ENTRYPOINT_IMAGE = (
    "/opt/serverware/src/scripts/oci_lane_entrypoint.py"
)
FINAL_V6_NPM_ENTRYPOINT_SOURCE = "scripts/npm_publish_companion.js"
FINAL_V6_NPM_ENTRYPOINT_IMAGE = (
    "/opt/serverware/src/scripts/npm_publish_companion.js"
)
FINAL_V6_BASE_ENVIRONMENT = {
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
FINAL_V6_PORTAL_DYNAMIC_ENVIRONMENT = [
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
FINAL_V6_SOURCE_CONTRACTS = {
    "approval-review": {
        "exact": ["scripts/test_approval_review.py"],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "browser-python-compatibility": {"exact": [], "prefixes": []},
    "chromium-compatibility": {"exact": [], "prefixes": []},
    "clean-room": {
        "exact": [
            "scripts/test_agent_trust_clean_room.py",
            "scripts/verify_offline_artifact_manifest.py",
        ],
        "prefixes": ["serverware_agent_trust/"],
    },
    "credential-constraints": {
        "exact": ["scripts/test_credential_constraints.py"],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "credential-constraints-proxy": {
        "exact": ["scripts/test_credential_constraints.py"],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "host-python-compatibility": {"exact": [], "prefixes": []},
    "internal-service-auth": {
        "exact": ["scripts/test_internal_service_auth.py"],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "jit-transaction-sqlite-full": {
        "exact": ["scripts/test_jit_transaction_state.py"],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "onboarding-evidence": {
        "exact": [
            "scripts/test_onboarding_evidence.py",
            "scripts/verify_onboarding_evidence.py",
        ],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "portal-browser-oauth": {
        "exact": [
            "scripts/oauth_provider_simulator.py",
            "scripts/test_portal_browser_oauth.py",
        ],
        "prefixes": [
            "data-plane/decision-gate-rs/",
            "serverware/",
            "serverware_agent_trust/",
        ],
    },
    "proxy-python-compatibility": {"exact": [], "prefixes": []},
    "rust-decision-gate-tests": {
        "exact": [],
        "prefixes": ["data-plane/decision-gate-rs/"],
    },
    "webauthn-attestation": {
        "exact": ["scripts/test_webauthn_attestation.py"],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
}
FINAL_V6_DEPENDENCY_CAPABILITIES = {
    "browser-runtime": ["chromium", "python"],
    "clean-room-runtime": [
        "packaging-25.0",
        "python",
        "sealed-wheelhouse",
    ],
    "npm-11.8-runtime": ["node", "npm-11.8"],
    "python-runtime": ["python"],
    "rust-runtime": ["rust-test-binary"],
}
FINAL_V6_PYTHON_CAPABILITY_PROBES = [
    "dns-nss-local-bounded",
    "multiprocessing-spawn-bounded",
    "openssl-provider-load",
    "sqlite-memory-and-file",
]
GIT_SOURCE_INVENTORY_SIGNATURE_DOMAIN = (
    b"serverware.gitSourceInventory/v1\x00Ed25519\x00"
)
UNTRACKED_SOURCE_APPROVAL_SIGNATURE_DOMAIN = (
    b"serverware.untrackedSourceApproval/v1\x00Ed25519\x00"
)
BUILD_WATCHDOG_SIGNATURE_DOMAIN = (
    b"serverware.ociBuildWatchdogReceipt/v3\x00Ed25519\x00"
)
PROMOTION_RECEIPT_SIGNATURE_DOMAIN = (
    b"serverware.verificationPromotionReceipt/v3\x00Ed25519\x00"
)
RAW_BUILDER_STATEMENT_SIGNATURE_DOMAIN = (
    b"serverware.rawBuilderStatement/v1\x00Ed25519\x00"
)
MANIFEST_V6_EIF_BUILD_SIGNATURE_DOMAIN = (
    b"serverware.manifestV6EifBuildStatement/v1\x00Ed25519\x00"
)
KEY_CUSTODY_SIGNATURE_DOMAIN = (
    b"serverware.enclaveKeyCustodyEvidence/v1\x00Ed25519\x00"
)
MONOTONIC_WITNESS_SIGNATURE_DOMAIN = (
    b"serverware.monotonicReleaseWitness/v1\x00Ed25519\x00"
)
COMPLETION_AUTHENTICATION_SIGNATURE_DOMAIN = (
    b"serverware.completionProofAuthentication/v1\x00Ed25519\x00"
)
COMPLETION_CHECKPOINT_SIGNATURE_DOMAIN = (
    b"serverware.completionProofCheckpoint/v1\x00Ed25519\x00"
)
PRODUCTION_LANE_ORDER = (
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
PRODUCTION_IMAGE_ROLE_ORDER = tuple(
    f"lane-{lane}" for lane in PRODUCTION_LANE_ORDER
) + ("npm-publish-companion",)
DEPENDENCY_ROLE_ORDER = (
    "browser-runtime",
    "clean-room-runtime",
    "npm-11.8-runtime",
    "python-runtime",
    "rust-runtime",
)
KEY_CUSTODY_ROLE_ORDER = (
    "broker-kek",
    "credentials",
    "ca",
    "tls",
    "response",
    "release",
)
CONTINUITY_MAX_VALIDITY_SECONDS = 900
PRODUCTION_IMAGES_BUILD_API_VERSION = "serverware.productionImagesBuild/v2"
PRODUCTION_IMAGES_PUBLISHED_API_VERSION = "serverware.productionImagesPublished/v2"
REPRODUCIBLE_BUILD_MANIFEST_API_VERSION = "serverware.reproducibleBuildManifest/v3"
REPRODUCIBLE_BUILD_VERIFICATION_API_VERSION = (
    "serverware.reproducibleBuildVerification/v3"
)
RELEASE_PROVENANCE_RECORD_TYPE = "release.provenance.v2"
LAUNCH_AUTHORITY_BINDING_FIELDS = (
    "launch_authority_key_id",
    "launch_authority_root_sha256",
)
SECURITY_ROLE_MAP_API_VERSION = "serverware.securityRoleMap/v1"
SECURITY_ROLE_NAMES = (
    "release_provenance_signer",
    "image_signature_signer",
    "rekor_transparency_log",
    "external_checkpoint_log",
    "control_plane_response_signer",
    "policy_identity_signer",
    "policy_activation_signer",
    "reproducible_build_report_signer",
    "reproducible_builder_left",
    "reproducible_builder_right",
    "production_host_preflight_signer",
    "proxy_proof_collector",
    "proxy_response_statement_signer",
    "proxy_vendor_tee_verifier",
    "hardware_assurance_verifier",
    "final_challenge_authority",
    "source_git_inventory_authority",
    "source_untracked_approval_authority",
    "build_watchdog_signer",
    "promotion_receipt_signer",
    "manifest_v6_eif_builder",
    "key_custody_verifier",
    "monotonic_release_witness",
    "completion_proof_authenticator",
    "completion_proof_checkpoint",
)
LAUNCH_GLOBAL_ROLE_NAMES = frozenset(
    {
        "launchAuthority",
        "launchAuthorityWitness",
        "launchAuthorityWitnessStoreAssurance",
        "launchAuthorityWitnessTls",
        "nonceAuthorityAssuranceEvidence",
        "nonceAuthorityVerifierState",
        "nonceAuthorityVerifierStateStoreAttestation",
        "policyActivation",
        "policyIdentity",
        "reproducibleBuild",
    }
)
LAUNCH_GLOBAL_ROLES_OUTSIDE_CLAIM = (
    "actionGate",
    "publicAttestationNonceStore",
    "publicAttestationProducer",
    "publicAttestationWitnessStore",
    "finalVerifier",
    "nonceAuthorityVerifierStateStoreAssurance",
    "release",
    "response",
    "verifierStateTlsClient",
    "verifierStateTlsServer",
)
FINAL_MODE_ENV_KEY = "SERVERWARE_COMPLETION_VERIFICATION_MODE"
FINAL_HARDWARE_ASSURANCE_ENV_KEY = "SERVERWARE_HARDWARE_ASSURANCE"
FINAL_HARDWARE_TRUST_ROOT_ENV_KEY = "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY"
FINAL_HARDWARE_TRUST_ROOT_ID_ENV_KEY = "SERVERWARE_HARDWARE_ASSURANCE_TRUSTED_PUBLIC_KEY_ID"
FINAL_HARDWARE_CHALLENGE_NONCE_ENV_KEY = "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE"
FINAL_HARDWARE_CHALLENGE_DIGEST_ENV_KEY = "SERVERWARE_HARDWARE_ASSURANCE_EXPECTED_CHALLENGE_NONCE_SHA256"
FINAL_CHALLENGE_RECEIPT_ENV_KEY = "SERVERWARE_FINAL_CHALLENGE_RECEIPT"
FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ENV_KEY = "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY"
FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ID_ENV_KEY = "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PUBLIC_KEY_ID"
FINAL_CHALLENGE_AUTHORITY_PROVIDER_ENV_KEY = "SERVERWARE_FINAL_CHALLENGE_AUTHORITY_PROVIDER"
RELEASE_PROVENANCE_TRUST_ROOT_ENV_KEY = "SERVERWARE_RELEASE_PROVENANCE_TRUSTED_PUBLIC_KEY"
SIGSTORE_TRUST_ROOT_ENV_KEY = "SERVERWARE_SIGSTORE_TRUSTED_PUBLIC_KEY"
REKOR_TRUST_ROOT_ENV_KEY = "SERVERWARE_REKOR_TRUSTED_PUBLIC_KEY"
EXTERNAL_CHECKPOINT_TRUST_ROOT_ENV_KEY = "SERVERWARE_EXTERNAL_CHECKPOINT_TRUSTED_PUBLIC_KEY"
EXTERNAL_CHECKPOINT_PROVIDER_ENV_KEY = "SERVERWARE_EXTERNAL_CHECKPOINT_PROVIDER"
CONTROL_PLANE_RESPONSE_SIGNING_KEY_ENV_KEY = (
    "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY"
)
CONTROL_PLANE_RESPONSE_SIGNING_KEY_ID_ENV_KEY = (
    "SERVERWARE_CONTROL_PLANE_RESPONSE_SIGNING_PUBLIC_KEY_ID"
)
PROXY_PRINCIPAL_ENV_KEY = "SERVERWARE_PROXY_PROOF_PRINCIPAL_ID"
RELEASE_IDENTITY_FIELDS = {
    "source_tree_digest",
    "provenance_digest",
    "runtime_manifest_digest",
    "data_plane_binary_digest",
    "production_image_digests",
    "production_image_refs",
    "production_images_build_sha256",
    "production_images_published_sha256",
    "image_signature_bundle_digest",
}
CURRENT_HOST_IDENTITY_SCHEME = "serverware.currentCompletionHostIdentity/v1"
CURRENT_HOST_IDENTITY_MAX_OBSERVATION_AGE_SECONDS = 60
CURRENT_HOST_MACHINE_ID_PATH = Path("/etc/machine-id")
CURRENT_HOST_PRODUCT_UUID_PATH = Path("/sys/devices/virtual/dmi/id/product_uuid")
CURRENT_HOST_BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
MACHINE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
FINAL_HARDWARE_EVIDENCE = (
    "independently signed verifier statement",
    "fresh signed current-host identity commitment",
    "EIF image measurement and build-manifest evidence",
    "PCR0/PCR1/PCR2 measurements",
    "enclave CID and parent-CID evidence",
    "authenticated vsock handshake evidence",
    "KMS Recipient enclave key-custody evidence",
    "evidence that parent processes never held plaintext key material",
)
SECRET_FIELD_NAMES = {
    "plaintext",
    "secret",
    "password",
    "private_key",
    "private_key_pem",
    "raw_material",
    "material_value",
    "unwrapped_key",
    "decrypted_key",
}
FINAL_EVIDENCE_MAX_BYTES = 4 * 1024 * 1024
FINAL_TRUST_ROOT_MAX_BYTES = 64 * 1024
POLICY_BUNDLE_MAX_BYTES = 8 * 1024 * 1024
COMPLETION_INPUT_MAX_BYTES = 64 * 1024 * 1024
ENV_INPUT_MAX_BYTES = 8 * 1024 * 1024
COMPOSE_INPUT_MAX_BYTES = 16 * 1024 * 1024
PROXY_EXPECTED_DIGEST_ENV_KEYS = {
    "proxy_client_request_digest": "SERVERWARE_PROXY_EXPECTED_CLIENT_REQUEST_DIGEST",
    "proxy_request_digest": "SERVERWARE_PROXY_EXPECTED_REQUEST_DIGEST",
    "proxy_operation_digest": "SERVERWARE_PROXY_EXPECTED_OPERATION_DIGEST",
}
PROXY_PROOF_MAX_AGE_ENV_KEY = "SERVERWARE_PROXY_PROOF_MAX_AGE_SECONDS"
COMPLETION_P99_LIMIT_ENV_KEY = "SERVERWARE_COMPLETION_P99_LIMIT_MS"
DOCKER_EXECUTABLE_ENV_KEY = "SERVERWARE_DOCKER_EXECUTABLE"
DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY = (
    "SERVERWARE_DOCKER_COMPOSE_PLUGIN_EXECUTABLE"
)
DOCKER_COMPOSE_PLUGIN_SHA256_ENV_KEY = (
    "SERVERWARE_DOCKER_COMPOSE_PLUGIN_SHA256"
)
DOCKER_UNIX_SOCKET_ENV_KEY = "SERVERWARE_DOCKER_UNIX_SOCKET"
DOCKER_DAEMON_ID_ENV_KEY = "SERVERWARE_DOCKER_DAEMON_ID"
PREFLIGHT_MAX_AGE_ENV_KEY = (
    "SERVERWARE_PRODUCTION_HOST_PREFLIGHT_MAX_AGE_SECONDS"
)
PREFLIGHT_SIGNING_PUBLIC_KEY_ENV_KEY = (
    "SERVERWARE_PRODUCTION_HOST_PREFLIGHT_SIGNING_PUBLIC_KEY"
)
PREFLIGHT_SIGNING_KEY_ID_ENV_KEY = (
    "SERVERWARE_PRODUCTION_HOST_PREFLIGHT_SIGNING_KEY_ID"
)


@dataclass(frozen=True)
class FileSnapshot:
    path: Path
    data: bytes
    sha256: str
    metadata: os.stat_result


class InputSnapshots:
    def __init__(self) -> None:
        self.by_key: dict[str, FileSnapshot] = {}
        self._by_path: dict[str, FileSnapshot] = {}
        self._path_by_inode: dict[tuple[int, int], str] = {}

    def capture(
        self,
        key: str,
        path: Path,
        label: str,
        *,
        max_bytes: int,
        allow_empty: bool = False,
    ) -> FileSnapshot:
        absolute = os.path.abspath(os.fspath(path))
        snapshot = self._by_path.get(absolute)
        if snapshot is None:
            snapshot = snapshot_regular_file(
                path,
                label,
                max_bytes=max_bytes,
                allow_empty=allow_empty,
            )
            inode = (snapshot.metadata.st_dev, snapshot.metadata.st_ino)
            existing_path = self._path_by_inode.get(inode)
            require(
                existing_path is None or existing_path == absolute,
                f"{label} aliases another verification artifact inode: {path}",
            )
            self._by_path[absolute] = snapshot
            self._path_by_inode[inode] = absolute
        else:
            require(len(snapshot.data) <= max_bytes, f"{label} exceeds the {max_bytes}-byte size limit")
            require(allow_empty or snapshot.data, f"{label} must not be empty")
        self.by_key[key] = snapshot
        return snapshot

    def capture_many(
        self,
        paths: dict[str, Path],
        limits: dict[str, tuple[str, int]],
    ) -> dict[str, FileSnapshot]:
        grouped: dict[str, list[tuple[str, Path, str, int]]] = {}
        for key, path in paths.items():
            label, max_bytes = limits[key]
            grouped.setdefault(os.path.abspath(os.fspath(path)), []).append(
                (key, path, label, max_bytes)
            )
        for entries in grouped.values():
            strictest = min(entry[3] for entry in entries)
            body_artifact_keys = {"proxy_stream_body", "proxy_observation_body"}
            snapshot = self.capture(
                entries[0][0],
                entries[0][1],
                entries[0][2],
                max_bytes=strictest,
                allow_empty=all(entry[0] in body_artifact_keys for entry in entries),
            )
            for key, _path, label, max_bytes in entries:
                require(len(snapshot.data) <= max_bytes, f"{label} exceeds the {max_bytes}-byte size limit")
                self.by_key[key] = snapshot
        return self.by_key


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


def validate_canonical_json_profile(
    value: Any,
    *,
    label: str,
    depth: int = 0,
    field_name: str | None = None,
) -> None:
    require(depth <= 64, f"{label} exceeds the canonical JSON nesting limit")
    if field_name is not None and external_counter_field(field_name, value):
        require(
            type(value) is int and value >= 0,
            f"{label} {field_name} must be an unsigned integer",
        )
    if isinstance(value, dict):
        require(len(value) <= 100_000, f"{label} has too many object fields")
        for key, child in value.items():
            require(isinstance(key, str), f"{label} contains a non-string object key")
            validate_canonical_json_string(key, f"{label} object key")
            validate_canonical_json_profile(
                child,
                label=label,
                depth=depth + 1,
                field_name=key,
            )
        return
    if isinstance(value, list):
        require(len(value) <= 100_000, f"{label} has too many array items")
        for child in value:
            validate_canonical_json_profile(
                child,
                label=label,
                depth=depth + 1,
            )
        return
    if isinstance(value, str):
        validate_canonical_json_string(value, label)
        return
    if value is None or isinstance(value, bool):
        return
    if type(value) is int:
        require(
            -(1 << 63) <= value <= CANONICAL_JSON_SIGNED_MAX,
            f"{label} integer is outside the canonical signed 64-bit profile",
        )
        return
    raise ValueError(
        f"{label} contains a value outside {CANONICAL_JSON_PROFILE}"
    )


def validate_canonical_json_string(value: str, label: str) -> None:
    require("\x00" not in value, f"{label} contains NUL")
    require(
        all(not 0xD800 <= ord(character) <= 0xDFFF for character in value),
        f"{label} contains a Unicode surrogate",
    )
    require(
        unicodedata.normalize("NFC", value) == value,
        f"{label} is not Unicode NFC",
    )


def canonical_json(value: Any) -> str:
    validate_canonical_json_profile(value, label="canonical JSON value")
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def canonical_legacy_preflight_signature_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def sha256_prefixed_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_prefixed_json(value: Any) -> str:
    return sha256_prefixed_bytes(canonical_json(value).encode("utf-8"))


def hash_to_bytes(value: str) -> bytes:
    require(SHA256_RE.fullmatch(value) is not None, "Merkle hash must be a sha256-prefixed digest")
    return bytes.fromhex(value.split(":", 1)[1])


def node_hash(left: str, right: str) -> str:
    return sha256_prefixed_bytes(b"\x01" + hash_to_bytes(left) + hash_to_bytes(right))


def transparency_leaf_payload(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "anchor_id": item.get("anchor_id"),
        "sequence": require_bounded_uint(
            item.get("sequence"),
            "transparency leaf sequence",
            minimum=1,
        ),
        "received_at": item.get("received_at"),
        "record": item.get("record"),
        "record_digest": item.get("record_digest"),
    }


def transparency_leaf_hash(item: dict[str, Any]) -> str:
    return sha256_prefixed_bytes(b"\x00" + canonical_json(transparency_leaf_payload(item)).encode("utf-8"))


def verify_merkle_inclusion(leaf: str, proof: list[Any], root: str) -> bool:
    cursor = leaf
    for step in proof:
        if not isinstance(step, dict):
            return False
        side = step.get("side")
        sibling = step.get("hash")
        if not isinstance(sibling, str) or SHA256_RE.fullmatch(sibling) is None:
            return False
        if side == "left":
            cursor = node_hash(sibling, cursor)
        elif side == "right":
            cursor = node_hash(cursor, sibling)
        else:
            return False
    return cursor == root


def decode_canonical_base64url(value: Any, label: str) -> bytes:
    require(
        isinstance(value, str) and bool(value) and BASE64URL_RE.fullmatch(value) is not None,
        f"{label} is not canonical unpadded base64url",
    )
    require(len(value) % 4 != 1, f"{label} is not canonical unpadded base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except Exception as exc:
        raise ValueError(f"{label} is not canonical unpadded base64url") from exc
    require(
        base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") == value,
        f"{label} is not canonical unpadded base64url",
    )
    return decoded


def b64d(value: str) -> bytes:
    return decode_canonical_base64url(value, "base64url value")


def decode_ed25519_signature(value: Any, label: str) -> bytes:
    require(isinstance(value, str) and bool(value), f"{label} is missing")
    encoded = value.split(":", 1)[1] if value.startswith("ed25519:") else value
    decoded = decode_canonical_base64url(encoded, label)
    require(len(decoded) == 64, f"{label} must decode to exactly 64 bytes")
    return decoded


def decode_signature(value: Any, label: str) -> bytes:
    require(isinstance(value, str) and value, f"{label} is missing")
    encoded = value.split(":", 1)[1] if value.startswith("ed25519:") else value
    try:
        return base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
    except Exception as exc:
        raise ValueError(f"{label} is invalid base64") from exc


def decode_sha256_value(value: Any, label: str) -> bytes:
    require(isinstance(value, str) and value, f"{label} is missing")
    candidate = value.split(":", 1)[1] if value.startswith("sha256:") else value
    if re.fullmatch(r"[0-9a-fA-F]{64}", candidate):
        return bytes.fromhex(candidate)
    try:
        decoded = base64.b64decode(candidate + "=" * (-len(candidate) % 4), altchars=b"-_", validate=True)
    except Exception as exc:
        raise ValueError(f"{label} is not a SHA-256 value") from exc
    require(len(decoded) == hashlib.sha256().digest_size, f"{label} is not 32 bytes")
    return decoded


def normalized_sha256_value(value: Any, label: str) -> str:
    return "sha256:" + decode_sha256_value(value, label).hex()


def verify_public_key_signature(public_key_pem: str, signature: str, payload: bytes, label: str) -> None:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        if isinstance(public_key, Ed25519PublicKey):
            signature_bytes = decode_ed25519_signature(signature, f"{label} signature")
            public_key.verify(signature_bytes, payload)
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            signature_bytes = decode_signature(signature, f"{label} signature")
            if isinstance(public_key.curve, ec.SECP256R1):
                digest_algorithm = hashes.SHA256()
            elif isinstance(public_key.curve, ec.SECP384R1):
                digest_algorithm = hashes.SHA384()
            elif isinstance(public_key.curve, ec.SECP521R1):
                digest_algorithm = hashes.SHA512()
            else:
                raise ValueError(f"{label} uses an unsupported elliptic curve")
            public_key.verify(signature_bytes, payload, ec.ECDSA(digest_algorithm))
        elif isinstance(public_key, rsa.RSAPublicKey):
            signature_bytes = decode_signature(signature, f"{label} signature")
            public_key.verify(signature_bytes, payload, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise ValueError(f"{label} uses an unsupported public key type")
    except InvalidSignature as exc:
        raise ValueError(f"{label} signature verification failed") from exc
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"{label} signature verification failed") from exc


def release_public_key_id(public_key_pem: str) -> str:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        der = public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception as exc:
        raise ValueError("release signing public key is invalid") from exc
    return sha256_prefixed_bytes(der)


def verify_ed25519(public_key_pem: str, signature: str, payload: bytes, label: str) -> None:
    if not signature.startswith("ed25519:"):
        raise ValueError(f"{label} signature is not ed25519")
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
        require(isinstance(public_key, Ed25519PublicKey), f"{label} public key is not Ed25519")
        public_key.verify(
            decode_ed25519_signature(signature, f"{label} signature"),
            payload,
        )
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"{label} signature verification failed") from exc


def decode_base64(value: Any, label: str) -> bytes:
    require(isinstance(value, str) and value, f"{label} is missing")
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
    except Exception as exc:
        raise ValueError(f"{label} is invalid base64") from exc


def verify_external_checkpoint_receipt(
    checkpoint: dict[str, Any],
    *,
    expected_provider: str,
    expected_log_id: str,
    trusted_public_key_pem: str,
    expected_fields: dict[str, Any],
    label: str,
) -> dict[str, Any]:
    require(checkpoint.get("ok") is True, f"{label} external transparency checkpoint did not pass")
    provider = checkpoint.get("provider")
    require(isinstance(provider, str) and provider, f"{label} external transparency checkpoint did not bind provider")
    log_id = require_sha256(checkpoint.get("log_id"), f"{label} external transparency log id")
    receipt = checkpoint.get("receipt") if isinstance(checkpoint.get("receipt"), dict) else {}
    require(receipt.get("kind") == "ed25519-signed-checkpoint", f"{label} external transparency receipt is not ed25519-signed")
    payload = receipt.get("payload") if isinstance(receipt.get("payload"), dict) else {}
    require(payload, f"{label} external transparency receipt is missing payload")
    public_key_pem = receipt.get("public_key_pem")
    signature = receipt.get("signature")
    require(isinstance(public_key_pem, str) and public_key_pem, f"{label} external transparency receipt is missing public key")
    require(isinstance(signature, str) and signature, f"{label} external transparency receipt is missing signature")
    trusted_log_id = release_public_key_id(trusted_public_key_pem)
    require(trusted_log_id == expected_log_id, f"{label} trusted external transparency key id mismatch")
    require(
        release_public_key_id(public_key_pem) == trusted_log_id,
        f"{label} external transparency receipt public key is not the independently trusted log key",
    )
    require(provider == expected_provider, f"{label} external transparency provider is not the trusted provider")
    require(log_id == expected_log_id, f"{label} external transparency log is not the trusted log")
    require(payload.get("provider") == provider, f"{label} external transparency receipt provider mismatch")
    require(payload.get("log_id") == log_id, f"{label} external transparency receipt log mismatch")
    for field, expected in expected_fields.items():
        require(payload.get(field) == expected, f"{label} external transparency receipt {field} mismatch")
    external_sequence = require_bounded_uint(
        checkpoint.get("external_sequence"),
        f"{label} external checkpoint sequence",
        minimum=1,
    )
    verify_ed25519(
        trusted_public_key_pem,
        signature,
        canonical_json(payload).encode("utf-8"),
        f"{label} external transparency receipt",
    )
    return {
        "provider": provider,
        "log_id": log_id,
        "external_sequence": external_sequence,
        "checkpoint_sha256": sha256_prefixed_json(checkpoint),
        "receipt_payload_sha256": sha256_prefixed_json(payload),
    }


def verify_signed_tree_head(sth: dict[str, Any], *, root: str, tree_size: int, label: str) -> None:
    require(sth.get("version") == "serverware.transparencyLog/v1", f"{label} signed tree head version mismatch")
    require(sth.get("tree_head_hash") == root, f"{label} signed tree head root mismatch")
    require(
        require_bounded_uint(
            sth.get("tree_size"),
            f"{label} signed tree head size",
            minimum=1,
        )
        == tree_size,
        f"{label} signed tree head size mismatch",
    )
    public_key_pem = sth.get("public_key_pem")
    signature = sth.get("signature")
    require(isinstance(public_key_pem, str) and public_key_pem, f"{label} signed tree head is missing public key")
    require(isinstance(signature, str) and signature, f"{label} signed tree head is missing signature")
    require(sth.get("log_id") == release_public_key_id(public_key_pem), f"{label} signed tree head log id mismatch")
    payload = dict(sth)
    payload.pop("signature", None)
    payload.pop("public_key_pem", None)
    verify_ed25519(public_key_pem, signature, canonical_json(payload).encode("utf-8"), f"{label} signed tree head")


def reject_duplicate_json_object_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    for key, value in pairs:
        if key in parsed:
            raise ValueError(f"duplicate JSON object key: {key}")
        parsed[key] = value
    return parsed


def reject_non_integer_json_number(value: str) -> None:
    raise ValueError(
        f"floating-point or non-finite JSON value {value!r} is not accepted"
    )


@dataclass(frozen=True)
class ExactJsonDecimal:
    token: str


def exact_milliseconds_to_nanoseconds(
    value: int | str | ExactJsonDecimal,
    *,
    label: str,
    positive: bool = False,
) -> int:
    require(type(value) is not bool, f"{label} must be an exact decimal millisecond value")
    if type(value) is int:
        require(value >= 0, f"{label} must not be negative")
        nanoseconds = value * MILLISECONDS_TO_NANOSECONDS
    else:
        token = value.token if isinstance(value, ExactJsonDecimal) else value
        require(
            isinstance(token, str) and EXACT_MILLISECONDS_RE.fullmatch(token) is not None,
            f"{label} must be canonical decimal milliseconds with at most six fractional digits",
        )
        whole, separator, fractional = token.partition(".")
        nanoseconds = int(whole) * MILLISECONDS_TO_NANOSECONDS
        if separator:
            nanoseconds += int(fractional.ljust(6, "0"))
    require(
        nanoseconds <= CANONICAL_JSON_SIGNED_MAX,
        f"{label} exceeds the canonical signed 64-bit nanosecond maximum",
    )
    if positive:
        require(nanoseconds > 0, f"{label} must be positive")
    return nanoseconds


def benchmark_milliseconds_to_nanoseconds(
    value: int | ExactJsonDecimal,
    *,
    label: str,
) -> int:
    require(
        type(value) is int or isinstance(value, ExactJsonDecimal),
        f"{label} must be a JSON number expressed as exact decimal milliseconds",
    )
    return exact_milliseconds_to_nanoseconds(value, label=label)


def snapshot_regular_file(
    path: Path,
    label: str,
    *,
    max_bytes: int,
    allow_empty: bool = False,
) -> FileSnapshot:
    require(max_bytes > 0, f"{label} snapshot size limit is invalid")
    require(hasattr(os, "O_NOFOLLOW"), f"{label} cannot be opened safely on this platform")
    flags = (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"{label} must not be a symlink: {path}") from exc
        raise ValueError(f"{label} could not be opened without following symlinks: {path}") from exc
    try:
        opened_metadata = os.fstat(descriptor)
        require(stat.S_ISREG(opened_metadata.st_mode), f"{label} must be a regular file: {path}")
        require(
            opened_metadata.st_nlink == 1,
            f"{label} must not have hardlink aliases: {path}",
        )
        require(opened_metadata.st_size <= max_bytes, f"{label} exceeds the {max_bytes}-byte size limit")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        require(allow_empty or data, f"{label} must not be empty")
        require(len(data) <= max_bytes, f"{label} exceeds the {max_bytes}-byte size limit")
        completed_metadata = os.fstat(descriptor)
        require(
            (
                completed_metadata.st_dev,
                completed_metadata.st_ino,
                completed_metadata.st_size,
                completed_metadata.st_mtime_ns,
                completed_metadata.st_ctime_ns,
                completed_metadata.st_nlink,
            )
            == (
                opened_metadata.st_dev,
                opened_metadata.st_ino,
                opened_metadata.st_size,
                opened_metadata.st_mtime_ns,
                opened_metadata.st_ctime_ns,
                opened_metadata.st_nlink,
            )
            and len(data) == opened_metadata.st_size,
            f"{label} changed while its byte snapshot was being captured",
        )
    finally:
        os.close(descriptor)
    return FileSnapshot(
        path=path,
        data=data,
        sha256=sha256_prefixed_bytes(data),
        metadata=opened_metadata,
    )


def snapshot_text(snapshot: FileSnapshot, label: str, *, encoding: str) -> str:
    try:
        return snapshot.data.decode(encoding)
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not valid {encoding} text: {snapshot.path}") from exc


def snapshot_final_verification_files(
    paths: dict[str, Path],
    *,
    include_hardware_assurance: bool,
    include_final_receipt: bool,
    include_proxy_security: bool = False,
    include_policy: bool = False,
) -> dict[str, FileSnapshot]:
    requested: list[tuple[str, str, int]] = []
    if include_proxy_security:
        requested.extend(
            [
                (
                    "proxy_response_proof",
                    "production proxy response proof",
                    FINAL_EVIDENCE_MAX_BYTES,
                ),
                (
                    "proxy_collector_public_key",
                    "proxy response collector trust root",
                    FINAL_TRUST_ROOT_MAX_BYTES,
                ),
                (
                    "proxy_proof_verifier_public_key",
                    "proxy proof vendor verifier trust root",
                    FINAL_TRUST_ROOT_MAX_BYTES,
                ),
                (
                    "control_plane_response_signing_public_key",
                    "control-plane response signing trust root",
                    FINAL_TRUST_ROOT_MAX_BYTES,
                ),
            ]
        )
    if include_policy:
        requested.extend(
            [
                ("policy_bundle", "signed production policy bundle", POLICY_BUNDLE_MAX_BYTES),
                (
                    "policy_trusted_public_key",
                    "production policy signing trust root",
                    FINAL_TRUST_ROOT_MAX_BYTES,
                ),
            ]
        )
    if include_hardware_assurance:
        requested.extend(
            [
                ("hardware_assurance", "hardware assurance", FINAL_EVIDENCE_MAX_BYTES),
                (
                    "hardware_assurance_trusted_public_key",
                    "hardware assurance trust root",
                    FINAL_TRUST_ROOT_MAX_BYTES,
                ),
            ]
        )
    if include_final_receipt:
        requested.extend(
            [
                ("final_challenge_receipt", "final challenge receipt", FINAL_EVIDENCE_MAX_BYTES),
                (
                    "final_challenge_authority_public_key",
                    "final challenge authority trust root",
                    FINAL_TRUST_ROOT_MAX_BYTES,
                ),
            ]
        )
    grouped: dict[str, list[tuple[str, str, int, Path]]] = {}
    for key, label, max_bytes in requested:
        path = paths[key]
        grouped.setdefault(os.path.abspath(os.fspath(path)), []).append(
            (key, label, max_bytes, path)
        )
    snapshots: dict[str, FileSnapshot] = {}
    for entries in grouped.values():
        strictest_limit = min(entry[2] for entry in entries)
        snapshot = snapshot_regular_file(
            entries[0][3],
            entries[0][1],
            max_bytes=strictest_limit,
        )
        for key, _label, _max_bytes, _path in entries:
            snapshots[key] = snapshot
    return snapshots


def load_json_bytes(data: bytes, path: Path, label: str) -> dict[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} artifact is not valid UTF-8: {path}") from exc
    parsed = json.loads(
        text,
        object_pairs_hook=reject_duplicate_json_object_keys,
        parse_float=reject_non_integer_json_number,
        parse_constant=reject_non_integer_json_number,
    )
    if not isinstance(parsed, dict):
        raise ValueError(f"{label} artifact must be a JSON object: {path}")
    validate_canonical_json_profile(parsed, label=label)
    return parsed


def load_benchmark_json_snapshot(
    snapshot: FileSnapshot,
    label: str,
) -> dict[str, Any]:
    try:
        text = snapshot.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"{label} artifact is not valid UTF-8: {snapshot.path}"
        ) from exc
    parsed = json.loads(
        text,
        object_pairs_hook=reject_duplicate_json_object_keys,
        parse_float=ExactJsonDecimal,
        parse_constant=reject_non_integer_json_number,
    )
    require(
        isinstance(parsed, dict),
        f"{label} artifact must be a JSON object: {snapshot.path}",
    )
    for key, value in parsed.items():
        validate_canonical_json_string(key, f"{label} object key")
        if key in BENCHMARK_MILLISECOND_FIELDS:
            benchmark_milliseconds_to_nanoseconds(
                value,
                label=f"{label} {key}",
            )
        else:
            validate_canonical_json_profile(value, label=f"{label} {key}")
    return parsed


def load_production_host_preflight_json_snapshot(
    snapshot: FileSnapshot,
    label: str,
) -> dict[str, Any]:
    try:
        text = snapshot.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"{label} artifact is not valid UTF-8: {snapshot.path}"
        ) from exc
    parsed = json.loads(
        text,
        object_pairs_hook=reject_duplicate_json_object_keys,
        parse_float=ExactJsonDecimal,
        parse_constant=reject_non_integer_json_number,
    )
    require(
        isinstance(parsed, dict),
        f"{label} artifact must be a JSON object: {snapshot.path}",
    )
    allowed_decimal_paths = {
        ("checks", "release_artifacts", "bench", field)
        for field in PREFLIGHT_BENCHMARK_MILLISECOND_FIELDS
    }

    def validate_value(value: Any, path: tuple[str, ...], depth: int = 0) -> None:
        require(depth <= 64, f"{label} exceeds the canonical JSON nesting limit")
        if path in allowed_decimal_paths:
            benchmark_milliseconds_to_nanoseconds(
                value,
                label=f"{label} {'/'.join(path)}",
            )
            return
        if isinstance(value, dict):
            require(
                len(value) <= 100_000,
                f"{label} has too many object fields",
            )
            for key, child in value.items():
                require(
                    isinstance(key, str),
                    f"{label} contains a non-string object key",
                )
                validate_canonical_json_string(key, f"{label} object key")
                validate_value(child, path + (key,), depth + 1)
            return
        if isinstance(value, list):
            require(len(value) <= 100_000, f"{label} has too many array items")
            for child in value:
                validate_value(child, path + ("[]",), depth + 1)
            return
        validate_canonical_json_profile(value, label=label, depth=depth)

    validate_value(parsed, ())
    benchmark = (
        parsed.get("checks", {})
        .get("release_artifacts", {})
        .get("bench", {})
    )
    if isinstance(benchmark, dict):
        for field in PREFLIGHT_BENCHMARK_MILLISECOND_FIELDS:
            value = benchmark.get(field)
            if isinstance(value, ExactJsonDecimal):
                benchmark[field] = float(value.token)
    return parsed


def load_json_snapshot(snapshot: FileSnapshot, label: str) -> dict[str, Any]:
    return load_json_bytes(snapshot.data, snapshot.path, label)


def load_production_env_snapshot(snapshot: FileSnapshot) -> dict[str, str]:
    text = snapshot_text(snapshot, "production readiness env", encoding="utf-8")
    loaded: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        parsed = run_production_readiness.parse_env_assignment(raw, lineno)
        if parsed is None:
            continue
        key, value = parsed
        require(key not in loaded, f"production readiness env line {lineno} duplicates {key}")
        require(
            run_production_readiness.PLACEHOLDER_RE.search(value) is None,
            f"production readiness env line {lineno} contains a placeholder value",
        )
        require(
            run_production_readiness.EXAMPLE_DOMAIN_RE.search(value) is None,
            f"production readiness env line {lineno} contains an example placeholder domain",
        )
        loaded[key] = value
    require(bool(loaded), "production readiness env is empty")
    return loaded


def load_images_env_snapshot(snapshot: FileSnapshot) -> tuple[str, list[dict[str, str]]]:
    text = snapshot_text(snapshot, "production images env", encoding="utf-8")
    loaded: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), start=1):
        parsed = run_production_readiness.parse_env_assignment(raw, lineno)
        if parsed is None:
            continue
        key, value = parsed
        require(key not in loaded, f"production images env line {lineno} duplicates {key}")
        loaded[key] = value
    require(
        sorted(loaded) == [merge_production_images_env.KEY],
        f"production images env must contain only {merge_production_images_env.KEY}",
    )
    value = loaded[merge_production_images_env.KEY]
    return value, merge_production_images_env.validate_production_images(value)


def materialize_snapshots(
    snapshots: dict[str, FileSnapshot],
    keys: tuple[str, ...],
) -> tuple[tempfile.TemporaryDirectory[str], dict[str, Path]]:
    temporary = tempfile.TemporaryDirectory(prefix="serverware-completion-inputs-")
    directory = Path(temporary.name)
    os.chmod(directory, 0o700)
    paths: dict[str, Path] = {}
    for index, key in enumerate(keys):
        destination = directory / f"{index:02d}-{key}"
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(snapshots[key].data)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)
        paths[key] = destination
    return temporary, paths


def semantic_result_digest(document: dict[str, Any]) -> str:
    payload = dict(document)
    payload.pop("result_path", None)
    payload.pop("result_sha256", None)
    return sha256_prefixed_json(payload)


def kms_ciphertext_blob(
    config: dict[str, Any],
    material: str,
    snapshots: InputSnapshots,
) -> bytes:
    path = config.get("ciphertext_blob_path") or config.get("ciphertextBlobPath")
    if isinstance(path, str) and path:
        snapshot = snapshots.capture(
            f"kms_ciphertext_{material}",
            Path(path),
            f"current KMS material {material} ciphertext blob",
            max_bytes=COMPLETION_INPUT_MAX_BYTES,
        )
        return snapshot.data
    raw = config.get("ciphertext_blob_b64") or config.get("ciphertextBlobB64")
    require(isinstance(raw, str) and raw, f"current KMS material {material} is missing ciphertext blob")
    try:
        return base64.b64decode(raw + "=" * (-len(raw) % 4), validate=True)
    except Exception as exc:
        raise ValueError(f"current KMS material {material} ciphertext blob is invalid base64") from exc


def current_kms_material_bindings(
    snapshot: FileSnapshot,
    snapshots: InputSnapshots,
) -> dict[str, dict[str, str]]:
    parsed = load_json_snapshot(snapshot, "current KMS materials")
    assert_no_secret_fields(parsed)
    require(isinstance(parsed, dict), "current KMS materials file must be a JSON object")
    material_names = set(parsed)
    missing = sorted(REQUIRED_MATERIALS - material_names)
    unexpected = sorted(material_names - REQUIRED_MATERIALS)
    require(not missing, f"current KMS materials file is missing required materials: {missing}")
    require(not unexpected, f"current KMS materials file contains unauthorized materials: {unexpected}")
    bindings: dict[str, dict[str, str]] = {}
    for material in sorted(REQUIRED_MATERIALS):
        config = parsed.get(material)
        require(isinstance(config, dict), f"current KMS materials file is missing {material}")
        key_id = config.get("key_id") or config.get("keyId") or config.get("kms_key_id")
        require(isinstance(key_id, str) and key_id, f"current KMS material {material} is missing key id")
        context = config.get("encryption_context") or config.get("encryptionContext") or {}
        require(isinstance(context, dict), f"current KMS material {material} encryption context must be an object")
        bindings[material] = {
            "key_id_sha256": sha256_prefixed_bytes(key_id.encode("utf-8")),
            "ciphertext_blob_sha256": sha256_prefixed_bytes(
                kms_ciphertext_blob(config, material, snapshots)
            ),
            "encryption_context_sha256": sha256_prefixed_json(context),
        }
    return bindings


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def require_sha256(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value), f"{label} must be a sha256-prefixed digest")
    return str(value)


def require_image_ref(value: Any, label: str) -> tuple[str, str]:
    require(isinstance(value, str), f"{label} must be a digest-pinned image ref")
    match = IMAGE_REF_RE.fullmatch(str(value))
    require(match is not None, f"{label} must be repo@sha256:<64 hex>")
    return str(value), match.group("digest")


def sigstore_tlog_entries(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    verification = bundle.get("verificationMaterial") or bundle.get("verification_material") or {}
    candidates = [
        verification.get("tlogEntries") if isinstance(verification, dict) else None,
        verification.get("transparencyLogEntries") if isinstance(verification, dict) else None,
        verification.get("transparencyLog") if isinstance(verification, dict) else None,
        bundle.get("tlogEntries"),
    ]
    for candidate in candidates:
        if isinstance(candidate, list):
            return [item for item in candidate if isinstance(item, dict)]
        if isinstance(candidate, dict):
            return [candidate]
    return []


def sigstore_log_id(entry: dict[str, Any]) -> Any:
    value = entry.get("log_id") or entry.get("logID") or entry.get("logId")
    if isinstance(value, dict):
        return value.get("keyId") or value.get("key_id")
    return value


def parse_nonnegative_int64(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{label} is invalid")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value):
        parsed = int(value)
    else:
        raise ValueError(f"{label} is invalid")
    require(0 <= parsed <= 2**63 - 1, f"{label} is outside int64 range")
    return parsed


def verify_sigstore_checkpoint(
    *,
    proof: dict[str, Any],
    expected_tree_size: int,
    expected_root_hash: bytes,
    trusted_rekor_public_key_pem: str,
    label: str,
) -> None:
    checkpoint = proof.get("checkpoint") if isinstance(proof.get("checkpoint"), dict) else {}
    envelope = checkpoint.get("envelope")
    require(isinstance(envelope, str) and envelope, f"{label} Sigstore checkpoint envelope is missing")
    try:
        signed_text, signature_block = envelope.split("\n\n", 1)
    except ValueError as exc:
        raise ValueError(f"{label} Sigstore checkpoint envelope is malformed") from exc
    checkpoint_lines = signed_text.splitlines()
    require(len(checkpoint_lines) == 3, f"{label} Sigstore checkpoint body is malformed")
    origin, tree_size_value, root_hash_value = checkpoint_lines
    checkpoint_tree_size = parse_nonnegative_int64(tree_size_value, f"{label} checkpoint tree size")
    checkpoint_root_hash = decode_sha256_value(root_hash_value, f"{label} checkpoint root hash")
    require(checkpoint_tree_size == expected_tree_size, f"{label} checkpoint tree size mismatch")
    require(checkpoint_root_hash == expected_root_hash, f"{label} checkpoint root hash mismatch")
    signature_lines = [line for line in signature_block.splitlines() if line]
    require(len(signature_lines) == 1, f"{label} Sigstore checkpoint signature block is invalid")
    prefix = "\u2014 "
    require(signature_lines[0].startswith(prefix), f"{label} Sigstore checkpoint signature marker is invalid")
    try:
        signer_name, encoded_signature = signature_lines[0][len(prefix) :].rsplit(" ", 1)
    except ValueError as exc:
        raise ValueError(f"{label} Sigstore checkpoint signature line is malformed") from exc
    require(origin.startswith(signer_name + " "), f"{label} Sigstore checkpoint signer name mismatch")
    signature_with_key_hint = decode_signature(encoded_signature, f"{label} checkpoint note signature")
    require(
        len(signature_with_key_hint) > 4,
        f"{label} Sigstore checkpoint note signature is too short",
    )
    verify_public_key_signature(
        trusted_rekor_public_key_pem,
        base64.b64encode(signature_with_key_hint[4:]).decode("ascii"),
        (signed_text + "\n").encode("utf-8"),
        f"{label} Sigstore checkpoint",
    )


def verify_sigstore_merkle_inclusion(
    *,
    leaf_hash: bytes,
    proof: dict[str, Any],
    label: str,
) -> None:
    tree_size_value = proof.get("treeSize") if proof.get("treeSize") is not None else proof.get("tree_size")
    log_index_value = proof.get("logIndex") if proof.get("logIndex") is not None else proof.get("log_index")
    root_hash = proof.get("rootHash") if proof.get("rootHash") is not None else proof.get("root_hash")
    hashes = proof.get("hashes")
    tree_size = parse_nonnegative_int64(tree_size_value, f"{label} Sigstore inclusion tree size")
    log_index = parse_nonnegative_int64(log_index_value, f"{label} Sigstore inclusion log index")
    require(tree_size >= 1, f"{label} Sigstore inclusion tree size is invalid")
    require(
        0 <= log_index < tree_size,
        f"{label} Sigstore inclusion log index is invalid",
    )
    root = decode_sha256_value(root_hash, f"{label} Sigstore inclusion root")
    require(isinstance(hashes, list), f"{label} Sigstore inclusion hashes must be a list")
    cursor = leaf_hash
    index = log_index
    last = tree_size - 1
    for position, sibling_value in enumerate(hashes):
        require(last != 0, f"{label} Sigstore inclusion proof has extra hashes")
        sibling = decode_sha256_value(sibling_value, f"{label} Sigstore inclusion hash {position}")
        if index & 1 or index == last:
            cursor = hashlib.sha256(b"\x01" + sibling + cursor).digest()
            while index and not index & 1:
                index >>= 1
                last >>= 1
        else:
            cursor = hashlib.sha256(b"\x01" + cursor + sibling).digest()
        index >>= 1
        last >>= 1
    require(last == 0 and cursor == root, f"{label} Sigstore Merkle inclusion proof did not verify")


def verify_sigstore_bundle_binding(
    sigstore: dict[str, Any],
    *,
    expected_statement: dict[str, Any],
    expected_statement_digest: str,
    expected_signature: str,
    trusted_signing_public_key_pem: str,
    expected_signing_key_id: str,
    expected_rekor_log_id: str,
    trusted_rekor_public_key_pem: str,
    label: str,
) -> None:
    trusted_signing_key_id = release_public_key_id(trusted_signing_public_key_pem)
    trusted_rekor_log_id = release_public_key_id(trusted_rekor_public_key_pem)
    require(
        trusted_signing_key_id == expected_signing_key_id,
        f"{label} independently trusted Sigstore key id mismatch",
    )
    require(
        trusted_rekor_log_id == expected_rekor_log_id,
        f"{label} independently trusted Rekor key id mismatch",
    )
    require(
        sha256_prefixed_json(expected_statement) == expected_statement_digest,
        f"{label} expected statement digest mismatch",
    )
    signing_public_key = serialization.load_pem_public_key(
        trusted_signing_public_key_pem.encode("ascii")
    )
    require(
        not isinstance(signing_public_key, Ed25519PublicKey),
        f"{label} transparent Ed25519/Ed25519ph signatures are not supported by this verifier",
    )
    statement_bytes = canonical_json(expected_statement).encode("utf-8")
    bundle = sigstore.get("bundle") if isinstance(sigstore.get("bundle"), dict) else {}
    require(bundle, f"{label} Sigstore proof is missing bundle")
    message_signature = bundle.get("messageSignature") if isinstance(bundle.get("messageSignature"), dict) else {}
    if not message_signature:
        message_signature = bundle.get("message_signature") if isinstance(bundle.get("message_signature"), dict) else {}
    require(message_signature, f"{label} Sigstore bundle is missing message signature")
    message_digest = message_signature.get("messageDigest") if isinstance(message_signature.get("messageDigest"), dict) else {}
    if not message_digest:
        message_digest = message_signature.get("message_digest") if isinstance(message_signature.get("message_digest"), dict) else {}
    digest_algorithm = str(message_digest.get("algorithm", "")).lower().replace("-", "_")
    require(digest_algorithm in {"sha256", "sha2_256"}, f"{label} Sigstore bundle digest algorithm mismatch")
    require(
        decode_sha256_value(message_digest.get("digest"), f"{label} Sigstore bundle digest")
        == hash_to_bytes(expected_statement_digest),
        f"{label} Sigstore bundle digest mismatch",
    )
    require(message_signature.get("signature") == expected_signature, f"{label} Sigstore bundle signature mismatch")
    verify_public_key_signature(
        trusted_signing_public_key_pem,
        expected_signature,
        statement_bytes,
        f"{label} Sigstore message",
    )

    verification_material = (
        bundle.get("verificationMaterial")
        if isinstance(bundle.get("verificationMaterial"), dict)
        else bundle.get("verification_material")
        if isinstance(bundle.get("verification_material"), dict)
        else {}
    )
    public_key = verification_material.get("publicKey") if isinstance(verification_material.get("publicKey"), dict) else {}
    if not public_key:
        public_key = verification_material.get("public_key") if isinstance(verification_material.get("public_key"), dict) else {}
    public_key_hint = public_key.get("hint")
    require(
        normalized_sha256_value(public_key_hint, f"{label} Sigstore bundle public-key hint")
        == expected_signing_key_id,
        f"{label} Sigstore bundle public-key hint mismatch",
    )

    transparency = sigstore.get("transparency") if isinstance(sigstore.get("transparency"), dict) else {}
    entries = sigstore_tlog_entries(bundle)
    require(entries, f"{label} Sigstore bundle is missing transparency log entry")
    entry = entries[0]
    entry_log_id = sigstore_log_id(entry)
    normalized_entry_log_id = normalized_sha256_value(entry_log_id, f"{label} Sigstore bundle Rekor log id")
    require(normalized_entry_log_id == expected_rekor_log_id, f"{label} Sigstore bundle Rekor log mismatch")
    require(
        normalized_entry_log_id
        == normalized_sha256_value(transparency.get("log_id"), f"{label} top-level Rekor log id"),
        f"{label} Sigstore bundle/top-level log mismatch",
    )
    require(
        isinstance(transparency.get("entry_uuid"), str) and transparency.get("entry_uuid"),
        f"{label} top-level transparency entry correlation id is missing",
    )
    for top_key, entry_keys in (
        ("integrated_time", ("integrated_time", "integratedTime")),
        ("log_index", ("log_index", "logIndex")),
    ):
        top_value = parse_nonnegative_int64(transparency.get(top_key), f"{label} top-level {top_key}")
        entry_raw = next((entry.get(key) for key in entry_keys if entry.get(key) is not None), None)
        entry_value = parse_nonnegative_int64(entry_raw, f"{label} bundle {top_key}")
        require(entry_value == top_value, f"{label} Sigstore bundle/top-level {top_key} mismatch")
    entry_inclusion = entry.get("inclusion_proof") or entry.get("inclusionProof")
    require(entry_inclusion == transparency.get("inclusion_proof"), f"{label} Sigstore bundle/top-level inclusion proof mismatch")
    require(isinstance(entry_inclusion, dict), f"{label} Sigstore bundle inclusion proof is missing")

    canonicalized_body_value = entry.get("canonicalizedBody") or entry.get("canonicalized_body")
    canonicalized_body = decode_base64(canonicalized_body_value, f"{label} Sigstore canonicalized body")
    try:
        body = json.loads(canonicalized_body, object_pairs_hook=reject_duplicate_json_object_keys)
    except Exception as exc:
        raise ValueError(f"{label} Sigstore canonicalized body is invalid JSON") from exc
    require(isinstance(body, dict), f"{label} Sigstore canonicalized body must be an object")
    spec = body.get("spec") if isinstance(body.get("spec"), dict) else {}
    data = spec.get("data") if isinstance(spec.get("data"), dict) else {}
    body_hash = data.get("hash") if isinstance(data.get("hash"), dict) else {}
    body_signature = spec.get("signature") if isinstance(spec.get("signature"), dict) else {}
    require(str(body_hash.get("algorithm", "")).lower() == "sha256", f"{label} Rekor body digest algorithm mismatch")
    require(
        body_hash.get("value") == expected_statement_digest.split(":", 1)[1],
        f"{label} Rekor body statement digest mismatch",
    )
    require(body_signature.get("content") == expected_signature, f"{label} Rekor body signature mismatch")
    body_public_key = body_signature.get("publicKey") if isinstance(body_signature.get("publicKey"), dict) else {}
    encoded_body_public_key = body_public_key.get("content")
    decoded_body_public_key = decode_base64(encoded_body_public_key, f"{label} Rekor body public key")
    try:
        body_public_key_pem = decoded_body_public_key.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} Rekor body public key is not ASCII PEM") from exc
    require(
        release_public_key_id(body_public_key_pem) == expected_signing_key_id,
        f"{label} Rekor body key is not the independently trusted Sigstore key",
    )

    integrated_time = parse_nonnegative_int64(
        entry.get("integratedTime") if entry.get("integratedTime") is not None else entry.get("integrated_time"),
        f"{label} Rekor integrated time",
    )
    log_index = parse_nonnegative_int64(
        entry.get("logIndex") if entry.get("logIndex") is not None else entry.get("log_index"),
        f"{label} Rekor log index",
    )
    inclusion_promise = entry.get("inclusionPromise") if isinstance(entry.get("inclusionPromise"), dict) else {}
    if not inclusion_promise:
        inclusion_promise = entry.get("inclusion_promise") if isinstance(entry.get("inclusion_promise"), dict) else {}
    signed_entry_timestamp = inclusion_promise.get("signedEntryTimestamp") or inclusion_promise.get(
        "signed_entry_timestamp"
    )
    set_payload = {
        "body": canonicalized_body_value,
        "integratedTime": integrated_time,
        "logID": decode_sha256_value(entry_log_id, f"{label} Rekor log id").hex(),
        "logIndex": log_index,
    }
    require(isinstance(signed_entry_timestamp, str) and signed_entry_timestamp, f"{label} Rekor signed entry timestamp is missing")
    verify_public_key_signature(
        trusted_rekor_public_key_pem,
        signed_entry_timestamp,
        canonical_json(set_payload).encode("utf-8"),
        f"{label} Rekor signed entry timestamp",
    )
    verify_sigstore_merkle_inclusion(
        leaf_hash=hashlib.sha256(b"\x00" + canonicalized_body).digest(),
        proof=entry_inclusion,
        label=label,
    )
    proof_tree_size = parse_nonnegative_int64(
        entry_inclusion.get("treeSize")
        if entry_inclusion.get("treeSize") is not None
        else entry_inclusion.get("tree_size"),
        f"{label} Sigstore checkpoint tree size",
    )
    proof_root_hash = decode_sha256_value(
        entry_inclusion.get("rootHash")
        if entry_inclusion.get("rootHash") is not None
        else entry_inclusion.get("root_hash"),
        f"{label} Sigstore checkpoint root hash",
    )
    verify_sigstore_checkpoint(
        proof=entry_inclusion,
        expected_tree_size=proof_tree_size,
        expected_root_hash=proof_root_hash,
        trusted_rekor_public_key_pem=trusted_rekor_public_key_pem,
        label=label,
    )


def assert_no_secret_fields(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if str(key).lower() in SECRET_FIELD_NAMES:
                raise ValueError(f"completion artifact contains secret-like field {path}.{key}")
            assert_no_secret_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            assert_no_secret_fields(child, f"{path}[{index}]")


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    validate_canonical_json_profile(value, label=label)
    missing = sorted(expected - set(value))
    unexpected = sorted(set(value) - expected)
    require(not missing, f"{label} is missing required fields: {missing}")
    require(not unexpected, f"{label} contains unexpected fields: {unexpected}")


def require_final_v1_identifier(value: Any, label: str) -> str:
    require(
        type(value) is str and FINAL_V1_IDENTIFIER_RE.fullmatch(value) is not None,
        f"{label} must match the closed final-v1 identifier grammar",
    )
    return value


def require_public_nitro_provider(value: Any, label: str) -> str:
    try:
        return verify_nitro_tee.require_public_nitro_provider(
            value,
            label,
        )
    except verify_nitro_tee.VerificationError as exc:
        raise ValueError(str(exc)) from exc


def validate_final_v1_digest_map(
    value: Any,
    label: str,
) -> dict[str, str]:
    require(
        isinstance(value, dict) and 1 <= len(value) <= 64,
        f"{label} must contain between 1 and 64 entries",
    )
    for name, digest_value in value.items():
        require(
            type(name) is str
            and FINAL_V1_DIGEST_MAP_KEY_RE.fullmatch(name) is not None,
            f"{label} key does not match the closed final-v1 digest-map grammar",
        )
        require_sha256(digest_value, f"{label} {name}")
    return value


def require_final_v1_non_empty_string(value: Any, label: str) -> str:
    require(
        type(value) is str
        and FINAL_V1_NON_EMPTY_STRING_RE.fullmatch(value) is not None,
        f"{label} must match the closed final-v1 boundary-string grammar",
    )
    return value


def require_sha384(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA384_RE.fullmatch(value) is not None, f"{label} must be sha384-prefixed")
    return value


def require_launch_authority_binding(value: Any, label: str) -> dict[str, str]:
    require(isinstance(value, dict), f"{label} must be an object")
    return {
        field: require_sha256(value.get(field), f"{label} {field}")
        for field in LAUNCH_AUTHORITY_BINDING_FIELDS
    }


def require_bounded_uint(
    value: Any,
    label: str,
    *,
    minimum: int = 0,
    maximum: int = 9_007_199_254_740_991,
) -> int:
    require(
        type(value) is int and minimum <= value <= maximum,
        f"{label} must be an integer between {minimum} and {maximum}",
    )
    return value


def load_canonical_json_artifact(
    snapshot: FileSnapshot,
    label: str,
    *,
    api_version: str | None = None,
) -> dict[str, Any]:
    document = load_json_snapshot(snapshot, label)
    require(
        snapshot.data == canonical_json(document).encode("utf-8") + b"\n",
        f"{label} is not canonical versioned JSON with one trailing newline",
    )
    if api_version is not None:
        require(
            document.get("apiVersion") == api_version,
            f"{label} apiVersion mismatch",
        )
    return document


def load_ed25519_trust_root(
    snapshot: FileSnapshot,
    label: str,
) -> tuple[Ed25519PublicKey, dict[str, str]]:
    try:
        if snapshot.data.startswith(b"-----BEGIN PUBLIC KEY-----"):
            public_key = serialization.load_pem_public_key(snapshot.data)
        else:
            public_key = serialization.load_der_public_key(snapshot.data)
    except Exception as exc:
        raise ValueError(f"{label} is not a valid public key") from exc
    require(isinstance(public_key, Ed25519PublicKey), f"{label} is not Ed25519")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return public_key, {
        "file_sha256": snapshot.sha256,
        "spki_sha256": sha256_prefixed_bytes(der),
        "raw_key_sha256": sha256_prefixed_bytes(raw),
    }


def verify_domain_ed25519_envelope(
    document: dict[str, Any],
    *,
    public_key_snapshot: FileSnapshot,
    api_version: str,
    domain: bytes,
    label: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    require_exact_keys(
        document,
        {"apiVersion", "payload", "payloadSha256", "signature"},
        label,
    )
    require(document.get("apiVersion") == api_version, f"{label} apiVersion mismatch")
    payload = document.get("payload")
    require(isinstance(payload, dict), f"{label} payload must be an object")
    payload_sha256 = require_sha256(
        document.get("payloadSha256"),
        f"{label} payload digest",
    )
    require(
        payload_sha256 == sha256_prefixed_json(payload),
        f"{label} payload digest mismatch",
    )
    public_key, identity = load_ed25519_trust_root(
        public_key_snapshot,
        f"{label} trust root",
    )
    signature = document.get("signature")
    require(isinstance(signature, dict), f"{label} signature must be an object")
    require_exact_keys(
        signature,
        {
            "algorithm",
            "domain",
            "keyFileSha256",
            "rawKeySha256",
            "value",
        },
        f"{label} signature",
    )
    require(signature.get("algorithm") == "Ed25519", f"{label} signature algorithm mismatch")
    require(
        signature.get("domain") == domain[:-1].decode("ascii"),
        f"{label} signature domain mismatch",
    )
    require(
        signature.get("keyFileSha256") == identity["file_sha256"],
        f"{label} signature key-file digest mismatch",
    )
    require(
        signature.get("rawKeySha256") == identity["raw_key_sha256"],
        f"{label} signature raw-key digest mismatch",
    )
    signature_value = signature.get("value")
    require(
        isinstance(signature_value, str)
        and re.fullmatch(r"[A-Za-z0-9+/]{86}==", signature_value) is not None,
        f"{label} signature is not canonical padded base64",
    )
    try:
        signature_bytes = base64.b64decode(signature_value, validate=True)
    except Exception as exc:
        raise ValueError(f"{label} signature is invalid base64") from exc
    require(len(signature_bytes) == 64, f"{label} signature is not 64 bytes")
    signed = domain + canonical_json(
        {"payload": payload, "payloadSha256": payload_sha256}
    ).encode("utf-8")
    try:
        public_key.verify(signature_bytes, signed)
    except InvalidSignature as exc:
        raise ValueError(f"{label} signature verification failed") from exc
    return payload, {
        **identity,
        "payload_sha256": payload_sha256,
        "signed_message_sha256": sha256_prefixed_bytes(signed),
    }


def require_digest_list(
    value: Any,
    label: str,
    *,
    minimum: int = 1,
    maximum: int = 4096,
) -> list[str]:
    require(
        isinstance(value, list) and minimum <= len(value) <= maximum,
        f"{label} must contain between {minimum} and {maximum} digests",
    )
    normalized = [require_sha256(item, f"{label} item") for item in value]
    require(
        normalized == list(dict.fromkeys(normalized)),
        f"{label} contains duplicate digests",
    )
    return normalized


def verify_source_input_continuity(
    source_document: dict[str, Any],
    *,
    source_snapshot: FileSnapshot,
    git_inventory_public_key: FileSnapshot,
    untracked_approval_public_key: FileSnapshot,
) -> dict[str, Any]:
    require_exact_keys(
        source_document,
        {
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
            "symlinkCount",
            "trackedInventorySha256",
            "trackedPaths",
            "untrackedApproval",
            "untrackedApprovalPayloadSha256",
        },
        "source-input manifest",
    )
    require(
        source_document.get("apiVersion") == SOURCE_INPUT_MANIFEST_API_VERSION,
        "source-input manifest apiVersion mismatch",
    )
    require(
        source_document.get("selectionModel")
        == "signed-complete-git-index-worktree-status-plus-approved-untracked/v2",
        "source-input manifest selection model mismatch",
    )
    payload_without_digest = dict(source_document)
    supplied_payload_sha256 = require_sha256(
        payload_without_digest.pop("payloadSha256", None),
        "source-input manifest payload digest",
    )
    require(
        supplied_payload_sha256 == sha256_prefixed_json(payload_without_digest),
        "source-input manifest payload digest mismatch",
    )

    git_envelope = source_document.get("gitInventory")
    approval_envelope = source_document.get("untrackedApproval")
    require(isinstance(git_envelope, dict), "source Git inventory envelope is missing")
    require(isinstance(approval_envelope, dict), "untracked source approval envelope is missing")
    git_payload, git_key = verify_domain_ed25519_envelope(
        git_envelope,
        public_key_snapshot=git_inventory_public_key,
        api_version=GIT_SOURCE_INVENTORY_API_VERSION,
        domain=GIT_SOURCE_INVENTORY_SIGNATURE_DOMAIN,
        label="source Git inventory",
    )
    approval_payload, approval_key = verify_domain_ed25519_envelope(
        approval_envelope,
        public_key_snapshot=untracked_approval_public_key,
        api_version=UNTRACKED_SOURCE_APPROVAL_API_VERSION,
        domain=UNTRACKED_SOURCE_APPROVAL_SIGNATURE_DOMAIN,
        label="untracked source approval",
    )
    require(
        git_key["raw_key_sha256"] != approval_key["raw_key_sha256"],
        "source Git inventory and untracked approval authorities must be independent",
    )
    require(
        source_document.get("gitInventoryPayloadSha256")
        == git_key["payload_sha256"],
        "source-input manifest Git inventory payload binding mismatch",
    )
    require(
        source_document.get("untrackedApprovalPayloadSha256")
        == approval_key["payload_sha256"],
        "source-input manifest untracked approval payload binding mismatch",
    )

    require_exact_keys(
        git_payload,
        {
            "headTree",
            "indexEntries",
            "indexEntriesSha256",
            "indexFileSha256",
            "objectFormat",
            "repositoryIdSha256",
            "status",
            "worktreeEntries",
            "worktreeEntriesSha256",
        },
        "source Git inventory payload",
    )
    object_format = git_payload.get("objectFormat")
    object_hex_length = 40 if object_format == "sha1" else 64 if object_format == "sha256" else 0
    require(
        object_hex_length > 0
        and re.fullmatch(
            rf"{object_format}:[0-9a-f]{{{object_hex_length}}}",
            str(git_payload.get("headTree") or ""),
        )
        is not None,
        "source Git inventory tree identity is invalid",
    )
    require_sha256(git_payload.get("indexFileSha256"), "source Git index file")
    require_sha256(git_payload.get("repositoryIdSha256"), "source repository identity")
    index_entries = git_payload.get("indexEntries")
    worktree_entries = git_payload.get("worktreeEntries")
    require(
        isinstance(index_entries, list)
        and isinstance(worktree_entries, list)
        and bool(index_entries)
        and len(index_entries) <= 100_000
        and len(worktree_entries) == len(index_entries),
        "source Git inventory is empty, oversized, or incomplete",
    )
    require(
        git_payload.get("indexEntriesSha256") == sha256_prefixed_json(index_entries)
        and git_payload.get("worktreeEntriesSha256")
        == sha256_prefixed_json(worktree_entries),
        "source Git inventory list digests mismatch",
    )
    indexed_paths: list[str] = []
    worktree_paths: list[str] = []
    for index, entry in enumerate(index_entries):
        require(
            isinstance(entry, dict)
            and set(entry) == {"gitMode", "objectId", "path", "stage"},
            f"source Git index entry {index} is invalid",
        )
        path = entry.get("path")
        require(
            isinstance(path, str)
            and bool(path)
            and path == path.strip()
            and not path.startswith("/")
            and "\x00" not in path
            and all(part not in {"", ".", ".."} for part in path.split("/")),
            f"source Git index entry {index} path is invalid",
        )
        require(entry.get("stage") == 0, f"source Git index entry {index} is not stage zero")
        require(
            entry.get("gitMode") in {"100644", "100755", "120000"},
            f"source Git index entry {index} mode is unsupported",
        )
        require(
            re.fullmatch(
                rf"{object_format}:[0-9a-f]{{{object_hex_length}}}",
                str(entry.get("objectId") or ""),
            )
            is not None,
            f"source Git index entry {index} object identity is invalid",
        )
        indexed_paths.append(path)
    require(
        indexed_paths == sorted(set(indexed_paths)),
        "source Git index paths are not unique and sorted",
    )
    for index, entry in enumerate(worktree_entries):
        require(isinstance(entry, dict), f"source worktree entry {index} is invalid")
        path = entry.get("path")
        require(path == indexed_paths[index], f"source worktree entry {index} path mismatch")
        require(
            entry.get("classification") in {"source", "build-input"}
            and entry.get("gitMode") == index_entries[index]["gitMode"]
            and entry.get("indexObjectId") == index_entries[index]["objectId"]
            and entry.get("type") in {"file", "symlink"},
            f"source worktree entry {index} provenance is invalid",
        )
        if entry.get("type") == "file":
            require_sha256(entry.get("sha256"), f"source worktree file {path}")
            require_bounded_uint(entry.get("size"), f"source worktree file {path} size")
        else:
            require(
                isinstance(entry.get("target"), str)
                and bool(entry["target"])
                and "\x00" not in entry["target"],
                f"source worktree symlink {path} target is invalid",
            )
        worktree_paths.append(path)
    require(worktree_paths == indexed_paths, "source worktree does not match the complete Git index")

    status = git_payload.get("status")
    require(isinstance(status, dict), "source Git status evidence is missing")
    require_exact_keys(
        status,
        {
            "ignoredPaths",
            "ignoredPathsSha256",
            "policy",
            "trackedChanges",
            "trackedChangesSha256",
            "untrackedPaths",
            "untrackedPathsSha256",
        },
        "source Git status evidence",
    )
    ignored = status.get("ignoredPaths")
    untracked_status = status.get("untrackedPaths")
    tracked_changes = status.get("trackedChanges")
    require(
        isinstance(ignored, list)
        and isinstance(untracked_status, list)
        and isinstance(tracked_changes, list)
        and ignored == sorted(set(ignored))
        and untracked_status == sorted(set(untracked_status)),
        "source Git status path lists are invalid",
    )
    require(
        status.get("ignoredPathsSha256") == sha256_prefixed_json(ignored)
        and status.get("untrackedPathsSha256") == sha256_prefixed_json(untracked_status)
        and status.get("trackedChangesSha256") == sha256_prefixed_json(tracked_changes),
        "source Git status list digests mismatch",
    )

    tracked_paths = source_document.get("trackedPaths")
    approved_paths = source_document.get("requiredUntrackedPaths")
    require(
        tracked_paths == indexed_paths
        and isinstance(approved_paths, list)
        and approved_paths == sorted(set(approved_paths))
        and set(approved_paths).issubset(set(untracked_status))
        and not set(approved_paths).intersection(ignored),
        "source-input tracked or approved-untracked inventory mismatch",
    )
    require(
        source_document.get("trackedInventorySha256")
        == sha256_prefixed_json(tracked_paths)
        and source_document.get("requiredUntrackedInventorySha256")
        == sha256_prefixed_json(approved_paths),
        "source-input path inventory digests mismatch",
    )
    selected_paths = sorted([*tracked_paths, *approved_paths])
    require(
        source_document.get("pathListSha256") == sha256_prefixed_json(selected_paths),
        "source-input selected path digest mismatch",
    )
    require_exact_keys(
        approval_payload,
        {
            "challengeSha256",
            "decision",
            "entries",
            "gitInventoryPayloadSha256",
            "pathListSha256",
        },
        "untracked source approval payload",
    )
    require(
        approval_payload.get("decision")
        == "approve-exact-required-untracked-for-source-freeze"
        and approval_payload.get("gitInventoryPayloadSha256")
        == git_key["payload_sha256"]
        and approval_payload.get("pathListSha256") == sha256_prefixed_json(approved_paths),
        "untracked source approval decision or Git binding mismatch",
    )
    require_sha256(
        approval_payload.get("challengeSha256"),
        "untracked source approval challenge",
    )
    approval_entries = approval_payload.get("entries")
    require(isinstance(approval_entries, list), "untracked source approval entries are missing")
    require(
        [entry.get("path") for entry in approval_entries if isinstance(entry, dict)]
        == approved_paths,
        "untracked source approval entries do not match the approved paths",
    )
    entries = source_document.get("entries")
    require(
        isinstance(entries, list)
        and len(entries) == len(selected_paths)
        and len(entries) <= 100_000
        and [entry.get("path") for entry in entries if isinstance(entry, dict)]
        == selected_paths,
        "source-input entries do not exactly match selected paths",
    )
    require(
        source_document.get("entryCount") == len(entries),
        "source-input entry count mismatch",
    )
    file_count = 0
    symlink_count = 0
    aggregate_bytes = 0
    approved_entry_map = {
        entry["path"]: entry for entry in approval_entries if isinstance(entry, dict)
    }
    worktree_entry_map = {
        entry["path"]: entry for entry in worktree_entries if isinstance(entry, dict)
    }
    for entry in entries:
        require(isinstance(entry, dict), "source-input entry is not an object")
        path = entry["path"]
        expected_provenance = "tracked" if path in worktree_entry_map else "required-untracked"
        require(
            entry.get("provenance") == expected_provenance
            and entry.get("classification") in {"source", "build-input"},
            f"source-input entry {path} provenance is invalid",
        )
        if entry.get("type") == "file":
            require_sha256(entry.get("sha256"), f"source-input file {path}")
            aggregate_bytes += require_bounded_uint(
                entry.get("size"),
                f"source-input file {path} size",
            )
            file_count += 1
        elif entry.get("type") == "symlink":
            require(
                isinstance(entry.get("target"), str)
                and bool(entry["target"])
                and "\x00" not in entry["target"],
                f"source-input symlink {path} target is invalid",
            )
            symlink_count += 1
        else:
            raise ValueError(f"source-input entry {path} has unsupported type")
        if expected_provenance == "tracked":
            signed = {
                key: value
                for key, value in worktree_entry_map[path].items()
                if key not in {"gitMode", "indexObjectId"}
            }
            signed["provenance"] = "tracked"
            require(entry == signed, f"source-input tracked entry {path} differs from signed inventory")
        else:
            require(
                entry == approved_entry_map.get(path),
                f"source-input untracked entry {path} differs from signed approval",
            )
    require(
        source_document.get("fileCount") == file_count
        and source_document.get("symlinkCount") == symlink_count
        and source_document.get("aggregateBytes") == aggregate_bytes,
        "source-input aggregate counts mismatch",
    )
    return {
        "file_sha256": source_snapshot.sha256,
        "payload_sha256": supplied_payload_sha256,
        "path_list_sha256": source_document["pathListSha256"],
        "tracked_inventory_sha256": source_document["trackedInventorySha256"],
        "required_untracked_inventory_sha256": source_document[
            "requiredUntrackedInventorySha256"
        ],
        "git_inventory_payload_sha256": git_key["payload_sha256"],
        "untracked_approval_payload_sha256": approval_key["payload_sha256"],
        "git_inventory_key_id": git_key["spki_sha256"],
        "untracked_approval_key_id": approval_key["spki_sha256"],
        "entry_count": len(entries),
        "aggregate_bytes": aggregate_bytes,
    }


def validate_dependency_bundle_continuity(
    document: dict[str, Any],
    *,
    snapshot: FileSnapshot,
) -> dict[str, Any]:
    require_exact_keys(
        document,
        {"apiVersion", "bundles", "manifestSha256"},
        "dependency closure manifest",
    )
    require(
        document.get("apiVersion") == DEPENDENCY_BUNDLE_API_VERSION,
        "dependency closure manifest apiVersion mismatch",
    )
    payload = dict(document)
    manifest_sha256 = require_sha256(
        payload.pop("manifestSha256", None),
        "dependency closure manifest payload",
    )
    require(
        manifest_sha256 == sha256_prefixed_json(payload),
        "dependency closure manifest digest mismatch",
    )
    bundles = document.get("bundles")
    require(
        isinstance(bundles, dict)
        and tuple(bundles) == DEPENDENCY_ROLE_ORDER,
        "dependency closure role inventory is not exact and ordered",
    )
    role_closures: dict[str, str] = {}
    for role in DEPENDENCY_ROLE_ORDER:
        bundle = bundles[role]
        require(isinstance(bundle, dict), f"{role} dependency closure is invalid")
        require_exact_keys(
            bundle,
            {
                "baseImageDigest",
                "capabilities",
                "closureSha256",
                "fileManifestSha256",
                "files",
                "packages",
            },
            f"{role} dependency closure",
        )
        require_sha256(bundle.get("baseImageDigest"), f"{role} base image")
        file_manifest_sha256 = require_sha256(
            bundle.get("fileManifestSha256"),
            f"{role} dependency file manifest",
        )
        files = bundle.get("files")
        packages = bundle.get("packages")
        capabilities = bundle.get("capabilities")
        require(
            isinstance(files, list)
            and isinstance(packages, list)
            and isinstance(capabilities, list)
            and files
            == sorted(files, key=lambda item: str(item.get("path", "")) if isinstance(item, dict) else ""),
            f"{role} dependency files are not a bounded ordered inventory",
        )
        require(
            file_manifest_sha256 == sha256_prefixed_json(files),
            f"{role} dependency file manifest digest mismatch",
        )
        seen_paths: set[str] = set()
        for item in files:
            require(
                isinstance(item, dict)
                and isinstance(item.get("path"), str)
                and item["path"].startswith("/")
                and item["path"] not in seen_paths
                and item.get("type") in {"file", "symlink"},
                f"{role} dependency file inventory is invalid",
            )
            seen_paths.add(item["path"])
            if item["type"] == "file":
                require_sha256(item.get("sha256"), f"{role} dependency file {item['path']}")
                require_bounded_uint(item.get("size"), f"{role} dependency file {item['path']} size")
            else:
                require(
                    isinstance(item.get("target"), str)
                    and bool(item["target"])
                    and "\x00" not in item["target"],
                    f"{role} dependency symlink target is invalid",
                )
        package_paths: set[str] = set()
        for package in packages:
            require(
                isinstance(package, dict)
                and set(package) == {"files", "name", "purl", "version"}
                and all(
                    isinstance(package.get(field), str) and bool(package[field])
                    for field in ("name", "purl", "version")
                )
                and isinstance(package.get("files"), list)
                and package["files"] == sorted(set(package["files"]))
                and set(package["files"]).issubset(seen_paths)
                and not set(package["files"]).intersection(package_paths),
                f"{role} dependency package inventory is invalid",
            )
            package_paths.update(package["files"])
        require(
            package_paths == seen_paths,
            f"{role} dependency packages do not own every file exactly once",
        )
        closure_payload = {
            "baseImageDigest": bundle["baseImageDigest"],
            "capabilities": capabilities,
            "files": files,
            "packages": packages,
        }
        closure_sha256 = require_sha256(
            bundle.get("closureSha256"),
            f"{role} dependency closure digest",
        )
        require(
            closure_sha256 == sha256_prefixed_json(closure_payload),
            f"{role} dependency closure digest mismatch",
        )
        role_closures[role] = closure_sha256
    return {
        "file_sha256": snapshot.sha256,
        "manifest_sha256": manifest_sha256,
        "role_closures": role_closures,
        "role_closures_sha256": sha256_prefixed_json(role_closures),
    }


def candidate_image_identity(value: Any, role: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{role} candidate image is invalid")
    require_exact_keys(
        value,
        {
            "archive",
            "build",
            "configDigest",
            "fileManifest",
            "indexDigest",
            "layerDigests",
            "manifestDigest",
            "platform",
            "role",
            "rootfsDiffIds",
            "rootfsDigest",
            "sbom",
        },
        f"{role} candidate image",
    )
    require(
        value.get("role") == role
        and value.get("platform") == {"architecture": "amd64", "os": "linux"},
        f"{role} candidate image role or platform mismatch",
    )
    archive = value.get("archive")
    file_manifest = value.get("fileManifest")
    sbom = value.get("sbom")
    require(
        isinstance(archive, dict)
        and isinstance(file_manifest, dict)
        and isinstance(sbom, dict),
        f"{role} candidate image artifacts are invalid",
    )
    archive_sha256 = require_sha256(archive.get("sha256"), f"{role} OCI archive")
    archive_size = require_bounded_uint(
        archive.get("size"),
        f"{role} OCI archive size",
        minimum=1,
    )
    identity = {
        "archiveSha256": archive_sha256,
        "archiveSize": archive_size,
        "configDigest": require_sha256(value.get("configDigest"), f"{role} config"),
        "fileManifestSha256": require_sha256(
            file_manifest.get("sha256"),
            f"{role} file manifest",
        ),
        "indexDigest": require_sha256(value.get("indexDigest"), f"{role} OCI index"),
        "layerDigests": require_digest_list(value.get("layerDigests"), f"{role} layers"),
        "manifestDigest": require_sha256(
            value.get("manifestDigest"),
            f"{role} OCI manifest",
        ),
        "rootfsDiffIds": require_digest_list(
            value.get("rootfsDiffIds"),
            f"{role} rootfs diff IDs",
        ),
        "rootfsDigest": require_sha256(
            value.get("rootfsDigest"),
            f"{role} rootfs",
        ),
        "sbomSha256": require_sha256(sbom.get("sha256"), f"{role} SBOM"),
    }
    return identity


def validate_imported_image(value: Any, role: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{role} imported image is invalid")
    require_exact_keys(
        value,
        {
            "configDigest",
            "containerdImageId",
            "fileManifestSha256",
            "independentInspectionSha256",
            "manifestDigest",
            "platform",
            "role",
            "rootfsDiffIds",
            "rootfsDigest",
            "sbomSha256",
        },
        f"{role} imported image",
    )
    require(
        value.get("role") == role
        and value.get("platform") == {"architecture": "amd64", "os": "linux"},
        f"{role} imported image role or platform mismatch",
    )
    normalized = {
        "role": role,
        "platform": value["platform"],
        "configDigest": require_sha256(value.get("configDigest"), f"{role} imported config"),
        "containerdImageId": require_sha256(
            value.get("containerdImageId"),
            f"{role} containerd image ID",
        ),
        "fileManifestSha256": require_sha256(
            value.get("fileManifestSha256"),
            f"{role} imported file manifest",
        ),
        "independentInspectionSha256": require_sha256(
            value.get("independentInspectionSha256"),
            f"{role} independent inspection",
        ),
        "manifestDigest": require_sha256(
            value.get("manifestDigest"),
            f"{role} imported manifest",
        ),
        "rootfsDiffIds": require_digest_list(
            value.get("rootfsDiffIds"),
            f"{role} imported rootfs diff IDs",
        ),
        "rootfsDigest": require_sha256(
            value.get("rootfsDigest"),
            f"{role} imported rootfs",
        ),
        "sbomSha256": require_sha256(
            value.get("sbomSha256"),
            f"{role} imported SBOM",
        ),
    }
    require(
        normalized["containerdImageId"] == normalized["manifestDigest"],
        f"{role} containerd image ID is not the OCI manifest digest",
    )
    return normalized


def validate_candidate_to_imported_mapping(
    value: Any,
    *,
    role: str,
    expected_candidate: dict[str, Any],
    expected_imported: dict[str, Any],
) -> dict[str, Any]:
    require(isinstance(value, dict), f"{role} promotion mapping is invalid")
    require_exact_keys(
        value,
        {"candidate", "imported", "mappingSha256", "role"},
        f"{role} promotion mapping",
    )
    require(value.get("role") == role, f"{role} promotion mapping role mismatch")
    require(value.get("candidate") == expected_candidate, f"{role} candidate mapping mismatch")
    require(value.get("imported") == expected_imported, f"{role} imported mapping mismatch")
    for candidate_key, imported_key in (
        ("configDigest", "configDigest"),
        ("fileManifestSha256", "fileManifestSha256"),
        ("manifestDigest", "manifestDigest"),
        ("rootfsDiffIds", "rootfsDiffIds"),
        ("rootfsDigest", "rootfsDigest"),
        ("sbomSha256", "sbomSha256"),
    ):
        require(
            expected_candidate[candidate_key] == expected_imported[imported_key],
            f"{role} candidate/imported {candidate_key} mismatch",
        )
    mapping_payload = {
        "candidate": expected_candidate,
        "imported": expected_imported,
        "role": role,
    }
    mapping_sha256 = require_sha256(
        value.get("mappingSha256"),
        f"{role} promotion mapping",
    )
    require(
        mapping_sha256 == sha256_prefixed_json(mapping_payload),
        f"{role} promotion mapping digest mismatch",
    )
    return {
        "role": role,
        "candidate": expected_candidate,
        "imported": expected_imported,
        "mappingSha256": mapping_sha256,
    }


def verify_build_watchdog_continuity(
    document: dict[str, Any],
    *,
    snapshot: FileSnapshot,
    public_key_snapshot: FileSnapshot,
    candidate_document: dict[str, Any],
) -> dict[str, Any]:
    payload, key = verify_domain_ed25519_envelope(
        document,
        public_key_snapshot=public_key_snapshot,
        api_version=BUILD_WATCHDOG_RECEIPT_API_VERSION,
        domain=BUILD_WATCHDOG_SIGNATURE_DOMAIN,
        label="build-watchdog receipt",
    )
    build_continuity = candidate_document.get("buildContinuity")
    require(isinstance(build_continuity, dict), "Candidate Manifest v6 build continuity is missing")
    candidate_watchdog = build_continuity.get("buildWatchdogReceipt")
    require(isinstance(candidate_watchdog, dict), "Candidate Manifest v6 watchdog binding is missing")
    require(
        candidate_watchdog.get("document") == document
        and candidate_watchdog.get("receiptFileSha256") == snapshot.sha256,
        "Candidate Manifest v6 does not bind the exact build-watchdog receipt",
    )
    require_exact_keys(
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
        "build-watchdog receipt payload",
    )
    candidate_request = payload.get("candidateRequest")
    require(isinstance(candidate_request, dict), "build-watchdog candidate request is missing")
    require(
        candidate_request.get("imageRoles") == list(PRODUCTION_IMAGE_ROLE_ORDER)
        and candidate_request.get("network") == "none"
        and candidate_request.get("platform") == {"architecture": "amd64", "os": "linux"},
        "build-watchdog candidate request is not the closed no-network image inventory",
    )
    require(
        payload.get("candidateRequestSha256") == sha256_prefixed_json(candidate_request),
        "build-watchdog candidate request digest mismatch",
    )
    request = payload.get("request")
    require(isinstance(request, dict), "build-watchdog request is missing")
    require(
        request.get("candidateRequestSha256") == payload["candidateRequestSha256"]
        and request.get("operation") == "build-all-oci-v3"
        and payload.get("requestSha256") == sha256_prefixed_json(request),
        "build-watchdog request binding mismatch",
    )
    events = payload.get("events")
    require(
        isinstance(events, list) and 6 <= len(events) <= 100_000,
        "build-watchdog event transcript is incomplete or oversized",
    )
    previous = sha256_prefixed_bytes(b"")
    resources: dict[tuple[str, str], dict[str, Any]] = {}
    cleanup_actions: dict[tuple[str, str], set[str]] = {}
    absence_ordinals: list[int] = []
    for sequence, event in enumerate(events, start=1):
        require(
            isinstance(event, dict),
            "build-watchdog event chain is malformed",
        )
        event_sequence = require_bounded_uint(
            event.get("sequence"),
            "build-watchdog event sequence",
            minimum=1,
        )
        require(
            set(event) == {"event", "eventSha256", "previousEventSha256", "sequence"}
            and event_sequence == sequence
            and event.get("previousEventSha256") == previous
            and isinstance(event.get("event"), dict),
            "build-watchdog event chain is malformed",
        )
        event_payload = {
            "event": event["event"],
            "previousEventSha256": previous,
            "sequence": sequence,
        }
        measured = sha256_prefixed_json(event_payload)
        require(event.get("eventSha256") == measured, "build-watchdog event digest mismatch")
        previous = measured
        body = event["event"]
        event_type = body.get("type")
        if event_type == "resource-created":
            resource = body.get("resource")
            require(isinstance(resource, dict), "build-watchdog resource event is invalid")
            kind = resource.get("kind")
            resource_id = resource.get("id")
            role = resource.get("role")
            require(
                kind in {"builder", "container", "content", "image", "snapshot", "task"}
                and isinstance(resource_id, str)
                and bool(resource_id)
                and role in PRODUCTION_IMAGE_ROLE_ORDER,
                "build-watchdog created an unknown, network, or unbound resource",
            )
            key_pair = (kind, resource_id)
            require(key_pair not in resources, "build-watchdog resource identity is duplicated")
            resources[key_pair] = resource
        elif event_type == "cleanup-action":
            resource = body.get("resource")
            require(
                isinstance(resource, dict)
                and set(resource) == {"id", "kind"}
                and body.get("action") in {"inspect", "kill", "remove"},
                "build-watchdog cleanup event is invalid",
            )
            key_pair = (resource["kind"], resource["id"])
            require(key_pair in resources, "build-watchdog cleanup references an unknown resource")
            actions = cleanup_actions.setdefault(key_pair, set())
            require(body["action"] not in actions, "build-watchdog cleanup action is duplicated")
            actions.add(body["action"])
        elif event_type == "daemon-inventory-absence":
            ordinal = body.get("ordinal")
            require(
                type(ordinal) is int
                and ordinal == len(absence_ordinals) + 1
                and body.get("presentResources") == []
                and body.get("labelledAlternates") == [],
                "build-watchdog absence inventory is invalid",
            )
            absence_ordinals.append(ordinal)
        else:
            require(
                event_type in {"lease-begin", "cleanup-started", "lease-finished"},
                "build-watchdog event type is unsupported",
            )
    require(
        payload.get("eventHeadSha256") == previous
        and absence_ordinals == [1, 2, 3]
        and events[0]["event"].get("type") == "lease-begin"
        and events[-1]["event"].get("type") == "lease-finished",
        "build-watchdog transcript boundaries or cleanup observations are invalid",
    )
    image_roles = sorted(
        resource["role"]
        for resource in resources.values()
        if resource.get("kind") == "image"
    )
    require(
        image_roles == sorted(PRODUCTION_IMAGE_ROLE_ORDER),
        "build-watchdog did not create exactly one image resource per production role",
    )
    for key_pair, resource in resources.items():
        expected_actions = {"inspect", "remove"}
        if resource["kind"] in {"builder", "container", "task"}:
            expected_actions.add("kill")
        require(
            cleanup_actions.get(key_pair) == expected_actions,
            "build-watchdog omitted exact cleanup for a created resource",
        )
    return {
        "file_sha256": snapshot.sha256,
        "payload_sha256": key["payload_sha256"],
        "signing_key_id": key["spki_sha256"],
        "event_head_sha256": previous,
        "resource_inventory_sha256": sha256_prefixed_json(
            [resources[key_pair] for key_pair in sorted(resources)]
        ),
    }


def validate_candidate_manifest_v6(
    document: dict[str, Any],
    *,
    snapshot: FileSnapshot,
    source_document: dict[str, Any],
    source_summary: dict[str, Any],
    dependency_document: dict[str, Any],
) -> dict[str, Any]:
    require_exact_keys(
        document,
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
    require(
        document.get("apiVersion") == CANDIDATE_MANIFEST_V6_API_VERSION,
        "Candidate Manifest v6 apiVersion mismatch",
    )
    payload = dict(document)
    payload_sha256 = require_sha256(
        payload.pop("candidateManifestPayloadSha256", None),
        "Candidate Manifest v6 payload",
    )
    require(
        payload_sha256 == sha256_prefixed_json(payload),
        "Candidate Manifest v6 payload digest mismatch",
    )
    require(
        document.get("laneOrder") == list(PRODUCTION_LANE_ORDER)
        and isinstance(document.get("lanes"), dict)
        and tuple(document["lanes"]) == PRODUCTION_LANE_ORDER
        and isinstance(document.get("images"), dict)
        and tuple(document["images"]) == PRODUCTION_IMAGE_ROLE_ORDER,
        "Candidate Manifest v6 role inventory is not the exact ordered 14 lanes plus npm companion",
    )
    source = document.get("sourceSnapshot")
    require(isinstance(source, dict), "Candidate Manifest v6 source snapshot is missing")
    for field in (
        "sourceClosureSha256",
        "sourceManifestFileSha256",
        "sourceManifestPayloadSha256",
        "sourceSelectionManifestFileSha256",
        "sourceSelectionManifestPayloadSha256",
        "sourceGitInventoryPayloadSha256",
        "sourceUntrackedApprovalPayloadSha256",
    ):
        require_sha256(source.get(field), f"Candidate Manifest v6 {field}")
    source_manifest = source.get("sourceManifest")
    require(isinstance(source_manifest, dict), "Candidate Manifest v6 embedded source manifest is missing")
    require_exact_keys(
        source_manifest,
        {
            "aggregateBytes",
            "apiVersion",
            "closureSha256",
            "entries",
            "entryCount",
            "fileCount",
            "root",
            "rootBindingSha256",
            "rootIdentity",
            "selection",
            "selectionManifestFileSha256",
            "selectionManifestPayloadSha256",
            "sourceRoot",
            "sourceRootBindingSha256",
            "sourceRootIdentity",
            "symlinkCount",
        },
        "Candidate Manifest v6 embedded source manifest",
    )
    expected_source_entries = [
        {
            key: value
            for key, value in entry.items()
            if key not in {"classification", "provenance"}
        }
        for entry in source_document["entries"]
    ]
    expected_source_directories: set[str] = set()
    for entry in source_document["entries"]:
        path = PurePosixPath(entry["path"])
        for end in range(1, len(path.parts)):
            expected_source_directories.add(
                PurePosixPath(*path.parts[:end]).as_posix()
            )
    expected_snapshot_entries = [
        {"mode": 0o500, "path": path, "type": "directory"}
        for path in expected_source_directories
    ] + expected_source_entries
    expected_snapshot_entries.sort(
        key=lambda item: (
            len(PurePosixPath(item["path"]).parts),
            item["path"],
            item["type"],
        )
    )
    closure_payload = {
        "aggregateBytes": source_manifest.get("aggregateBytes"),
        "entries": source_manifest.get("entries"),
        "entryCount": source_manifest.get("entryCount"),
        "fileCount": source_manifest.get("fileCount"),
        "symlinkCount": source_manifest.get("symlinkCount"),
    }
    require(
        source_manifest.get("apiVersion") == "serverware.sourceSnapshot/v6"
        and source_manifest.get("selection") == source_document
        and source_manifest.get("entries") == expected_snapshot_entries
        and source_manifest.get("aggregateBytes")
        == source_document.get("aggregateBytes")
        and source_manifest.get("entryCount") == len(expected_snapshot_entries)
        and source_manifest.get("fileCount") == source_document.get("fileCount")
        and source_manifest.get("symlinkCount")
        == source_document.get("symlinkCount")
        and source_manifest.get("selectionManifestFileSha256")
        == source_summary["file_sha256"]
        and source_manifest.get("selectionManifestPayloadSha256")
        == source_summary["payload_sha256"]
        and source_manifest.get("closureSha256")
        == sha256_prefixed_json(closure_payload)
        and source.get("sourceClosureSha256")
        == source_manifest.get("closureSha256")
        and source.get("sourceManifestPayloadSha256")
        == sha256_prefixed_json(source_manifest)
        and source.get("sourceManifestFileSha256")
        == sha256_prefixed_bytes(
            canonical_json(source_manifest).encode("utf-8") + b"\n"
        ),
        "Candidate Manifest v6 embedded source closure or source-input binding mismatch",
    )
    require(
        source.get("sourceSelectionManifestFileSha256") == source_summary["file_sha256"]
        and source.get("sourceSelectionManifestPayloadSha256")
        == source_summary["payload_sha256"]
        and source.get("sourcePathListSha256") == source_summary["path_list_sha256"]
        and source.get("sourceGitInventoryPayloadSha256")
        == source_summary["git_inventory_payload_sha256"]
        and source.get("sourceUntrackedApprovalPayloadSha256")
        == source_summary["untracked_approval_payload_sha256"],
        "Candidate Manifest v6 source selection differs from directly verified source evidence",
    )
    build_continuity = document.get("buildContinuity")
    require(isinstance(build_continuity, dict), "Candidate Manifest v6 build continuity is missing")
    require(
        build_continuity.get("dependencyBundle") == dependency_document,
        "Candidate Manifest v6 dependency closure differs from the supplied closure manifest",
    )
    build_plan = build_continuity.get("buildPlan")
    require(
        isinstance(build_plan, dict)
        and build_plan.get("dependencyBundle") == dependency_document
        and build_plan.get("imageOrder") == list(PRODUCTION_IMAGE_ROLE_ORDER)
        and build_plan.get("sourceSnapshot") == source,
        "Candidate Manifest v6 build plan continuity mismatch",
    )
    candidate_images = {
        role: candidate_image_identity(document["images"][role], role)
        for role in PRODUCTION_IMAGE_ROLE_ORDER
    }
    promotion_contract = document.get("promotionContract")
    require(isinstance(promotion_contract, dict), "Candidate Manifest v6 promotion contract is missing")
    require_sha256(
        promotion_contract.get("contractSha256"),
        "Candidate Manifest v6 promotion contract",
    )
    require(
        promotion_contract.get("finalManifestVersion")
        == "serverware.consolidatedTestArtifacts/v6",
        "Candidate Manifest v6 does not target the Manifest v6 promoted artifact",
    )
    return {
        "file_sha256": snapshot.sha256,
        "payload_sha256": payload_sha256,
        "source_closure_sha256": source["sourceClosureSha256"],
        "source_manifest_file_sha256": source["sourceManifestFileSha256"],
        "source_manifest_payload_sha256": source["sourceManifestPayloadSha256"],
        "source_selection_file_sha256": source_summary["file_sha256"],
        "source_selection_payload_sha256": source_summary["payload_sha256"],
        "promotion_contract_sha256": promotion_contract["contractSha256"],
        "candidate_images": candidate_images,
        "candidate_images_sha256": sha256_prefixed_json(candidate_images),
    }


def verify_promotion_continuity(
    document: dict[str, Any],
    *,
    snapshot: FileSnapshot,
    public_key_snapshot: FileSnapshot,
    candidate_summary: dict[str, Any],
) -> dict[str, Any]:
    payload, key = verify_domain_ed25519_envelope(
        document,
        public_key_snapshot=public_key_snapshot,
        api_version=PROMOTION_RECEIPT_API_VERSION,
        domain=PROMOTION_RECEIPT_SIGNATURE_DOMAIN,
        label="promotion receipt",
    )
    require(
        payload.get("candidateManifestFileSha256")
        == candidate_summary["file_sha256"]
        and payload.get("candidateManifestPayloadSha256")
        == candidate_summary["payload_sha256"]
        and payload.get("candidatePromotionContractSha256")
        == candidate_summary["promotion_contract_sha256"],
        "promotion receipt does not bind the exact Candidate Manifest v6",
    )
    images = payload.get("images")
    mappings = payload.get("imageMappings")
    require(
        isinstance(images, dict)
        and tuple(images) == PRODUCTION_IMAGE_ROLE_ORDER
        and isinstance(mappings, dict)
        and tuple(mappings) == PRODUCTION_IMAGE_ROLE_ORDER,
        "promotion receipt image inventory is not exactly 14 lanes plus npm companion",
    )
    verified_mappings: dict[str, Any] = {}
    imported_images: dict[str, Any] = {}
    for role in PRODUCTION_IMAGE_ROLE_ORDER:
        imported = validate_imported_image(images[role], role)
        mapping = validate_candidate_to_imported_mapping(
            mappings[role],
            role=role,
            expected_candidate=candidate_summary["candidate_images"][role],
            expected_imported=imported,
        )
        imported_images[role] = imported
        verified_mappings[role] = mapping
    return {
        "file_sha256": snapshot.sha256,
        "payload_sha256": key["payload_sha256"],
        "signing_key_id": key["spki_sha256"],
        "final_manifest_sha256": require_sha256(
            payload.get("finalManifestSha256"),
            "promotion receipt final Manifest v6",
        ),
        "promotion_acceptance_sha256": require_sha256(
            payload.get("promotionAcceptanceSha256"),
            "promotion acceptance",
        ),
        "imported_images": imported_images,
        "image_mappings": verified_mappings,
        "image_mappings_sha256": sha256_prefixed_json(verified_mappings),
    }


def verify_raw_builder_transcript(
    document: dict[str, Any],
    *,
    snapshot: FileSnapshot,
    label: str,
    candidate_summary: dict[str, Any],
    source_summary: dict[str, Any],
    dependency_summary: dict[str, Any],
) -> dict[str, Any]:
    require_exact_keys(
        document,
        {
            "apiVersion",
            "builderId",
            "candidate",
            "completedAtUnix",
            "dependencies",
            "eventHeadSha256",
            "events",
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
        label,
    )
    require(
        document.get("apiVersion") == RAW_BUILDER_TRANSCRIPT_API_VERSION
        and document.get("kind") == "HermeticBuilderTranscript"
        and document.get("pipeline") == MANIFEST_V6_PIPELINE,
        f"{label} version, kind, or pipeline mismatch",
    )
    builder_id = document.get("builderId")
    invocation_id = document.get("invocationId")
    require(
        isinstance(builder_id, str)
        and 1 <= len(builder_id) <= 128
        and isinstance(invocation_id, str)
        and 1 <= len(invocation_id) <= 128,
        f"{label} builder or invocation identity is invalid",
    )
    started = require_bounded_uint(document.get("startedAtUnix"), f"{label} start time")
    completed = require_bounded_uint(document.get("completedAtUnix"), f"{label} completion time")
    require(started <= completed, f"{label} completion predates its start")
    require(
        document.get("network") == {"mode": "none", "observedEndpoints": []},
        f"{label} did not directly record a no-network build",
    )
    sandbox = document.get("sandbox")
    require(isinstance(sandbox, dict), f"{label} sandbox evidence is missing")
    require_exact_keys(
        sandbox,
        {
            "environmentSha256",
            "filesystemInputSha256",
            "kind",
            "profileSha256",
            "toolchainSha256",
        },
        f"{label} sandbox evidence",
    )
    require(
        sandbox.get("kind") == "independently-measured-hermetic-builder",
        f"{label} sandbox kind is not independently measured",
    )
    for field in (
        "environmentSha256",
        "filesystemInputSha256",
        "profileSha256",
        "toolchainSha256",
    ):
        require_sha256(sandbox.get(field), f"{label} sandbox {field}")
    expected_source = {
        "sourceClosureSha256": candidate_summary["source_closure_sha256"],
        "sourceInputManifestFileSha256": source_summary["file_sha256"],
        "sourceInputManifestPayloadSha256": source_summary["payload_sha256"],
        "gitInventoryPayloadSha256": source_summary["git_inventory_payload_sha256"],
        "untrackedApprovalPayloadSha256": source_summary[
            "untracked_approval_payload_sha256"
        ],
    }
    expected_candidate = {
        "candidateManifestFileSha256": candidate_summary["file_sha256"],
        "candidateManifestPayloadSha256": candidate_summary["payload_sha256"],
        "candidateImagesSha256": candidate_summary["candidate_images_sha256"],
        "promotionContractSha256": candidate_summary["promotion_contract_sha256"],
    }
    expected_dependencies = {
        "dependencyManifestFileSha256": dependency_summary["file_sha256"],
        "dependencyManifestPayloadSha256": dependency_summary["manifest_sha256"],
        "roleClosuresSha256": dependency_summary["role_closures_sha256"],
    }
    require(document.get("source") == expected_source, f"{label} source binding mismatch")
    require(document.get("candidate") == expected_candidate, f"{label} candidate binding mismatch")
    require(
        document.get("dependencies") == expected_dependencies,
        f"{label} dependency binding mismatch",
    )
    outputs = document.get("imageOutputs")
    require(
        isinstance(outputs, dict)
        and tuple(outputs) == PRODUCTION_IMAGE_ROLE_ORDER
        and outputs == candidate_summary["candidate_images"],
        f"{label} image outputs differ from Candidate Manifest v6",
    )
    events = document.get("events")
    require(
        isinstance(events, list) and 3 <= len(events) <= 100_000,
        f"{label} event transcript is incomplete or oversized",
    )
    previous = sha256_prefixed_bytes(b"")
    for sequence, event in enumerate(events, start=1):
        require(
            isinstance(event, dict),
            f"{label} event chain is malformed",
        )
        event_sequence = require_bounded_uint(
            event.get("sequence"),
            f"{label} event sequence",
            minimum=1,
        )
        require(
            set(event) == {"event", "eventSha256", "previousEventSha256", "sequence"}
            and event_sequence == sequence
            and event.get("previousEventSha256") == previous
            and isinstance(event.get("event"), dict),
            f"{label} event chain is invalid",
        )
        event_payload = {
            "event": event["event"],
            "previousEventSha256": previous,
            "sequence": sequence,
        }
        measured = sha256_prefixed_json(event_payload)
        require(event.get("eventSha256") == measured, f"{label} event digest mismatch")
        previous = measured
    require(
        events[0]["event"].get("type") == "build-started"
        and events[-1]["event"].get("type") == "build-completed"
        and document.get("eventHeadSha256") == previous,
        f"{label} event boundaries or head mismatch",
    )
    transcript_payload = dict(document)
    transcript_sha256 = require_sha256(
        transcript_payload.pop("transcriptSha256", None),
        f"{label} transcript payload",
    )
    require(
        transcript_sha256 == sha256_prefixed_json(transcript_payload),
        f"{label} transcript digest mismatch",
    )
    return {
        "file_sha256": snapshot.sha256,
        "payload_sha256": transcript_sha256,
        "builder_id": builder_id,
        "invocation_id": invocation_id,
        "started_at_unix": started,
        "completed_at_unix": completed,
        "event_head_sha256": previous,
        "sandbox_sha256": sha256_prefixed_json(sandbox),
    }


def verify_raw_builder_statement(
    document: dict[str, Any],
    *,
    snapshot: FileSnapshot,
    public_key_snapshot: FileSnapshot,
    transcript_summary: dict[str, Any],
    candidate_summary: dict[str, Any],
    source_summary: dict[str, Any],
    dependency_summary: dict[str, Any],
    label: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    payload, key = verify_domain_ed25519_envelope(
        document,
        public_key_snapshot=public_key_snapshot,
        api_version=RAW_BUILDER_STATEMENT_API_VERSION,
        domain=RAW_BUILDER_STATEMENT_SIGNATURE_DOMAIN,
        label=label,
    )
    require_exact_keys(
        payload,
        {
            "builderId",
            "candidateManifestFileSha256",
            "candidateManifestPayloadSha256",
            "dependencyManifestFileSha256",
            "dependencyManifestPayloadSha256",
            "environmentSha256",
            "expiresAtUnix",
            "imageOutputsSha256",
            "invocationId",
            "issuedAtUnix",
            "operatorId",
            "pipeline",
            "sourceClosureSha256",
            "sourceInputManifestFileSha256",
            "sourceInputManifestPayloadSha256",
            "toolchainSha256",
            "transcriptFileSha256",
            "transcriptPayloadSha256",
        },
        f"{label} payload",
    )
    require(payload.get("pipeline") == MANIFEST_V6_PIPELINE, f"{label} pipeline mismatch")
    issued = require_bounded_uint(payload.get("issuedAtUnix"), f"{label} issue time")
    expires = require_bounded_uint(payload.get("expiresAtUnix"), f"{label} expiry")
    now = int(time.time()) if now_unix is None else now_unix
    require(
        issued <= now + HARDWARE_PROOF_FUTURE_SKEW_SECONDS
        and expires > now
        and issued < expires
        and expires - issued <= CONTINUITY_MAX_VALIDITY_SECONDS,
        f"{label} validity window is stale, future, expired, or too broad",
    )
    require(
        payload.get("builderId") == transcript_summary["builder_id"]
        and payload.get("invocationId") == transcript_summary["invocation_id"]
        and payload.get("transcriptFileSha256") == transcript_summary["file_sha256"]
        and payload.get("transcriptPayloadSha256") == transcript_summary["payload_sha256"],
        f"{label} does not bind its raw transcript",
    )
    require(
        payload.get("candidateManifestFileSha256") == candidate_summary["file_sha256"]
        and payload.get("candidateManifestPayloadSha256")
        == candidate_summary["payload_sha256"]
        and payload.get("imageOutputsSha256")
        == candidate_summary["candidate_images_sha256"],
        f"{label} Candidate Manifest v6 binding mismatch",
    )
    require(
        payload.get("sourceClosureSha256") == candidate_summary["source_closure_sha256"]
        and payload.get("sourceInputManifestFileSha256")
        == source_summary["file_sha256"]
        and payload.get("sourceInputManifestPayloadSha256")
        == source_summary["payload_sha256"],
        f"{label} source closure binding mismatch",
    )
    require(
        payload.get("dependencyManifestFileSha256")
        == dependency_summary["file_sha256"]
        and payload.get("dependencyManifestPayloadSha256")
        == dependency_summary["manifest_sha256"],
        f"{label} dependency closure binding mismatch",
    )
    for field in ("environmentSha256", "toolchainSha256"):
        require_sha256(payload.get(field), f"{label} {field}")
    operator_id = payload.get("operatorId")
    require(
        isinstance(operator_id, str) and 1 <= len(operator_id) <= 128,
        f"{label} operator identity is invalid",
    )
    return {
        "file_sha256": snapshot.sha256,
        "payload_sha256": key["payload_sha256"],
        "signing_key_id": key["spki_sha256"],
        "builder_id": transcript_summary["builder_id"],
        "operator_id": operator_id,
        "invocation_id": transcript_summary["invocation_id"],
        "transcript_file_sha256": transcript_summary["file_sha256"],
        "transcript_payload_sha256": transcript_summary["payload_sha256"],
        "issued_at_unix": issued,
        "expires_at_unix": expires,
    }


def verify_independent_raw_builders(
    *,
    left_statement: dict[str, Any],
    left_statement_snapshot: FileSnapshot,
    left_transcript: dict[str, Any],
    left_transcript_snapshot: FileSnapshot,
    left_public_key: FileSnapshot,
    right_statement: dict[str, Any],
    right_statement_snapshot: FileSnapshot,
    right_transcript: dict[str, Any],
    right_transcript_snapshot: FileSnapshot,
    right_public_key: FileSnapshot,
    candidate_summary: dict[str, Any],
    source_summary: dict[str, Any],
    dependency_summary: dict[str, Any],
) -> dict[str, Any]:
    transcript_left = verify_raw_builder_transcript(
        left_transcript,
        snapshot=left_transcript_snapshot,
        label="left raw builder transcript",
        candidate_summary=candidate_summary,
        source_summary=source_summary,
        dependency_summary=dependency_summary,
    )
    transcript_right = verify_raw_builder_transcript(
        right_transcript,
        snapshot=right_transcript_snapshot,
        label="right raw builder transcript",
        candidate_summary=candidate_summary,
        source_summary=source_summary,
        dependency_summary=dependency_summary,
    )
    builder_left = verify_raw_builder_statement(
        left_statement,
        snapshot=left_statement_snapshot,
        public_key_snapshot=left_public_key,
        transcript_summary=transcript_left,
        candidate_summary=candidate_summary,
        source_summary=source_summary,
        dependency_summary=dependency_summary,
        label="left raw builder statement",
    )
    builder_right = verify_raw_builder_statement(
        right_statement,
        snapshot=right_statement_snapshot,
        public_key_snapshot=right_public_key,
        transcript_summary=transcript_right,
        candidate_summary=candidate_summary,
        source_summary=source_summary,
        dependency_summary=dependency_summary,
        label="right raw builder statement",
    )
    require(
        builder_left["signing_key_id"] != builder_right["signing_key_id"]
        and builder_left["builder_id"] != builder_right["builder_id"]
        and builder_left["operator_id"] != builder_right["operator_id"]
        and builder_left["invocation_id"] != builder_right["invocation_id"],
        "raw builders must use distinct keys, builders, operators, and invocations",
    )
    builders = {"left": builder_left, "right": builder_right}
    return {**builders, "builders_sha256": sha256_prefixed_json(builders)}


def verify_manifest_v6_eif_build(
    document: dict[str, Any],
    *,
    snapshot: FileSnapshot,
    public_key_snapshot: FileSnapshot,
    candidate_summary: dict[str, Any],
    source_summary: dict[str, Any],
    watchdog_summary: dict[str, Any],
    promotion_summary: dict[str, Any],
    builders_summary: dict[str, Any],
    dependency_summary: dict[str, Any],
) -> dict[str, Any]:
    payload, key = verify_domain_ed25519_envelope(
        document,
        public_key_snapshot=public_key_snapshot,
        api_version=MANIFEST_V6_EIF_BUILD_API_VERSION,
        domain=MANIFEST_V6_EIF_BUILD_SIGNATURE_DOMAIN,
        label="Manifest v6 EIF build statement",
    )
    require_exact_keys(
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
        "Manifest v6 EIF build payload",
    )
    pipeline = payload.get("pipeline")
    require(
        pipeline == MANIFEST_V6_PIPELINE
        and pipeline not in LEGACY_DOCKER_NSM_PIPELINES
        and payload.get("legacyDockerNsmAccepted") is False,
        "EIF build statement is legacy Docker /dev/nsm evidence or accepts cross-pipeline evidence",
    )
    require(
        payload.get("candidateManifestFileSha256") == candidate_summary["file_sha256"]
        and payload.get("candidateManifestPayloadSha256")
        == candidate_summary["payload_sha256"]
        and payload.get("sourceClosureSha256") == candidate_summary["source_closure_sha256"]
        and payload.get("sourceInputManifestFileSha256") == source_summary["file_sha256"]
        and payload.get("sourceInputManifestPayloadSha256")
        == source_summary["payload_sha256"],
        "EIF build statement source or candidate continuity mismatch",
    )
    require(
        payload.get("watchdogReceiptFileSha256") == watchdog_summary["file_sha256"]
        and payload.get("watchdogReceiptPayloadSha256")
        == watchdog_summary["payload_sha256"]
        and payload.get("promotionReceiptFileSha256")
        == promotion_summary["file_sha256"]
        and payload.get("promotionReceiptPayloadSha256")
        == promotion_summary["payload_sha256"],
        "EIF build statement watchdog or promotion continuity mismatch",
    )
    require(
        payload.get("builderStatementsSha256") == builders_summary["builders_sha256"]
        and payload.get("dependencyClosureSha256")
        == dependency_summary["role_closures_sha256"]
        and payload.get("importedImageMappingsSha256")
        == promotion_summary["image_mappings_sha256"],
        "EIF build statement builder, dependency, or imported-image mapping mismatch",
    )
    pcrs = payload.get("pcrs")
    require(isinstance(pcrs, dict), "EIF build statement PCRs are missing")
    require_exact_keys(pcrs, {"PCR0", "PCR1", "PCR2"}, "EIF build statement PCRs")
    normalized_pcrs = {
        name: require_sha384(pcrs.get(name), f"EIF build statement {name}")
        for name in ("PCR0", "PCR1", "PCR2")
    }
    release_generation = require_bounded_uint(
        payload.get("releaseGeneration"),
        "EIF build release generation",
        minimum=1,
    )
    rollback_epoch = require_bounded_uint(
        payload.get("rollbackEpoch"),
        "EIF build rollback epoch",
    )
    return {
        "file_sha256": snapshot.sha256,
        "payload_sha256": key["payload_sha256"],
        "signing_key_id": key["spki_sha256"],
        "eif_file_sha384": require_sha384(
            payload.get("eifFileSha384"),
            "EIF file digest",
        ),
        "pcrs": normalized_pcrs,
        "release_generation": release_generation,
        "rollback_epoch": rollback_epoch,
    }


def production_release_core_identity(
    *,
    candidate_summary: dict[str, Any],
    source_summary: dict[str, Any],
    watchdog_summary: dict[str, Any],
    promotion_summary: dict[str, Any],
    builders_summary: dict[str, Any],
    dependency_summary: dict[str, Any],
    eif_summary: dict[str, Any],
) -> dict[str, Any]:
    return {
        "apiVersion": PRODUCTION_RELEASE_IDENTITY_API_VERSION,
        "pipeline": MANIFEST_V6_PIPELINE,
        "releaseGeneration": eif_summary["release_generation"],
        "rollbackEpoch": eif_summary["rollback_epoch"],
        "candidate": {
            "fileSha256": candidate_summary["file_sha256"],
            "payloadSha256": candidate_summary["payload_sha256"],
            "imagesSha256": candidate_summary["candidate_images_sha256"],
            "promotionContractSha256": candidate_summary[
                "promotion_contract_sha256"
            ],
        },
        "source": {
            "closureSha256": candidate_summary["source_closure_sha256"],
            "sourceManifestFileSha256": candidate_summary[
                "source_manifest_file_sha256"
            ],
            "sourceManifestPayloadSha256": candidate_summary[
                "source_manifest_payload_sha256"
            ],
            "sourceInputManifestFileSha256": source_summary["file_sha256"],
            "sourceInputManifestPayloadSha256": source_summary["payload_sha256"],
            "trackedInventorySha256": source_summary["tracked_inventory_sha256"],
            "requiredUntrackedInventorySha256": source_summary[
                "required_untracked_inventory_sha256"
            ],
            "gitInventoryPayloadSha256": source_summary[
                "git_inventory_payload_sha256"
            ],
            "gitInventoryKeyId": source_summary["git_inventory_key_id"],
            "untrackedApprovalPayloadSha256": source_summary[
                "untracked_approval_payload_sha256"
            ],
            "untrackedApprovalKeyId": source_summary[
                "untracked_approval_key_id"
            ],
        },
        "buildWatchdog": {
            "fileSha256": watchdog_summary["file_sha256"],
            "payloadSha256": watchdog_summary["payload_sha256"],
            "signingKeyId": watchdog_summary["signing_key_id"],
            "eventHeadSha256": watchdog_summary["event_head_sha256"],
            "resourceInventorySha256": watchdog_summary[
                "resource_inventory_sha256"
            ],
        },
        "promotion": {
            "fileSha256": promotion_summary["file_sha256"],
            "payloadSha256": promotion_summary["payload_sha256"],
            "signingKeyId": promotion_summary["signing_key_id"],
            "finalManifestSha256": promotion_summary["final_manifest_sha256"],
            "acceptanceSha256": promotion_summary["promotion_acceptance_sha256"],
            "imageMappingsSha256": promotion_summary["image_mappings_sha256"],
            "importedImages": promotion_summary["imported_images"],
        },
        "builders": {
            "leftStatementSha256": builders_summary["left"]["file_sha256"],
            "leftStatementPayloadSha256": builders_summary["left"][
                "payload_sha256"
            ],
            "leftTranscriptSha256": builders_summary["left"][
                "transcript_file_sha256"
            ],
            "leftTranscriptPayloadSha256": builders_summary["left"][
                "transcript_payload_sha256"
            ],
            "leftKeyId": builders_summary["left"]["signing_key_id"],
            "rightStatementSha256": builders_summary["right"]["file_sha256"],
            "rightStatementPayloadSha256": builders_summary["right"][
                "payload_sha256"
            ],
            "rightTranscriptSha256": builders_summary["right"][
                "transcript_file_sha256"
            ],
            "rightTranscriptPayloadSha256": builders_summary["right"][
                "transcript_payload_sha256"
            ],
            "rightKeyId": builders_summary["right"]["signing_key_id"],
            "buildersSha256": builders_summary["builders_sha256"],
        },
        "dependencies": {
            "fileSha256": dependency_summary["file_sha256"],
            "manifestSha256": dependency_summary["manifest_sha256"],
            "roleClosures": dependency_summary["role_closures"],
            "roleClosuresSha256": dependency_summary["role_closures_sha256"],
        },
        "eif": {
            "buildStatementFileSha256": eif_summary["file_sha256"],
            "buildStatementPayloadSha256": eif_summary["payload_sha256"],
            "buildStatementKeyId": eif_summary["signing_key_id"],
            "eifFileSha384": eif_summary["eif_file_sha384"],
            "pcrs": eif_summary["pcrs"],
        },
    }


def verify_key_custody_continuity(
    document: dict[str, Any],
    *,
    snapshot: FileSnapshot,
    public_key_snapshot: FileSnapshot,
    release_core_identity_sha256: str,
    eif_summary: dict[str, Any],
    expected_policy_hash: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    payload, key = verify_domain_ed25519_envelope(
        document,
        public_key_snapshot=public_key_snapshot,
        api_version=KEY_CUSTODY_EVIDENCE_API_VERSION,
        domain=KEY_CUSTODY_SIGNATURE_DOMAIN,
        label="enclave key-custody evidence",
    )
    require_exact_keys(
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
        "enclave key-custody payload",
    )
    require(payload.get("pipeline") == MANIFEST_V6_PIPELINE, "key-custody pipeline mismatch")
    require_bounded_uint(
        payload.get("releaseGeneration"),
        "key-custody release generation",
        minimum=1,
    )
    require_bounded_uint(
        payload.get("rollbackEpoch"),
        "key-custody rollback epoch",
    )
    require(
        payload.get("releaseCoreIdentitySha256") == release_core_identity_sha256,
        "key-custody evidence does not bind the production release core identity",
    )
    require(
        payload.get("eifFileSha384") == eif_summary["eif_file_sha384"]
        and payload.get("pcrs") == eif_summary["pcrs"]
        and payload.get("releaseGeneration") == eif_summary["release_generation"]
        and payload.get("rollbackEpoch") == eif_summary["rollback_epoch"],
        "key-custody evidence EIF, PCR, generation, or epoch mismatch",
    )
    policy_hash = require_sha256(payload.get("policyHash"), "key-custody policy hash")
    require(policy_hash == expected_policy_hash, "key-custody policy hash mismatch")
    issued = require_bounded_uint(payload.get("issuedAtUnix"), "key-custody issue time")
    expires = require_bounded_uint(payload.get("expiresAtUnix"), "key-custody expiry")
    now = int(time.time()) if now_unix is None else now_unix
    require(
        issued <= now + HARDWARE_PROOF_FUTURE_SKEW_SECONDS
        and expires > now
        and issued < expires
        and expires - issued <= CONTINUITY_MAX_VALIDITY_SECONDS,
        "key-custody evidence validity is stale, future, expired, or too broad",
    )
    for field in ("enclaveBootId", "enclaveInstanceId"):
        value = payload.get(field)
        require(
            isinstance(value, str) and 1 <= len(value) <= 128,
            f"key-custody {field} is invalid",
        )
    keys = payload.get("keys")
    require(
        isinstance(keys, list)
        and [entry.get("role") for entry in keys if isinstance(entry, dict)]
        == list(KEY_CUSTODY_ROLE_ORDER),
        "key-custody role inventory is not exact and ordered",
    )
    normalized_keys: dict[str, Any] = {}
    recipient_ids: set[str] = set()
    identity_ids: set[str] = set()
    for entry in keys:
        role = entry["role"]
        require_exact_keys(
            entry,
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
            f"{role} key-custody entry",
        )
        require(
            entry.get("plaintextExported") is False
            and entry.get("recipientAlgorithm")
            == "RSAES_OAEP_SHA_256_CiphertextForRecipient",
            f"{role} key custody permits plaintext export or wrong recipient algorithm",
        )
        identity_spki = require_sha256(
            entry.get("identitySpkiSha256"),
            f"{role} key identity SPKI",
        )
        recipient_spki = require_sha256(
            entry.get("recipientPublicKeySpkiSha256"),
            f"{role} recipient SPKI",
        )
        require(
            identity_spki not in identity_ids and recipient_spki not in recipient_ids,
            f"{role} key identity or recipient key is reused across custody roles",
        )
        identity_ids.add(identity_spki)
        recipient_ids.add(recipient_spki)
        generation = require_bounded_uint(
            entry.get("recipientKeyGeneration"),
            f"{role} recipient key generation",
            minimum=1,
        )
        for field in (
            "enclaveGenerationEvidenceSha256",
            "kmsAttestationDocumentSha256",
            "kmsCiphertextForRecipientSha256",
            "kmsEncryptionContextSha256",
            "kmsKeyArnSha256",
        ):
            require_sha256(entry.get(field), f"{role} {field}")
        encryption_context = entry.get("kmsEncryptionContext")
        require(isinstance(encryption_context, dict), f"{role} KMS encryption context is missing")
        require_bounded_uint(
            encryption_context.get("releaseGeneration"),
            f"{role} KMS context release generation",
            minimum=1,
        )
        require_bounded_uint(
            encryption_context.get("rollbackEpoch"),
            f"{role} KMS context rollback epoch",
        )
        expected_conditions = {
            "eifFileSha384": eif_summary["eif_file_sha384"],
            "pcrs": eif_summary["pcrs"],
            "policyHash": policy_hash,
            "recipientPublicKeySpkiSha256": recipient_spki,
            "releaseGeneration": eif_summary["release_generation"],
            "rollbackEpoch": eif_summary["rollback_epoch"],
        }
        require(
            encryption_context == {"keyRole": role, **expected_conditions}
            and entry.get("kmsEncryptionContextSha256")
            == sha256_prefixed_json(encryption_context),
            f"{role} KMS encryption context does not bind the exact release conditions",
        )
        conditions = entry.get("releaseConditions")
        require(
            isinstance(conditions, dict),
            f"{role} KMS release conditions are missing",
        )
        require_bounded_uint(
            conditions.get("releaseGeneration"),
            f"{role} KMS condition release generation",
            minimum=1,
        )
        require_bounded_uint(
            conditions.get("rollbackEpoch"),
            f"{role} KMS condition rollback epoch",
        )
        require(
            conditions == expected_conditions,
            f"{role} KMS release conditions do not bind PCR, policy, epoch, release, and recipient",
        )
        normalized_keys[role] = {
            "identitySpkiSha256": identity_spki,
            "recipientPublicKeySpkiSha256": recipient_spki,
            "recipientKeyGeneration": generation,
            "kmsCiphertextForRecipientSha256": entry[
                "kmsCiphertextForRecipientSha256"
            ],
            "kmsAttestationDocumentSha256": entry[
                "kmsAttestationDocumentSha256"
            ],
            "enclaveGenerationEvidenceSha256": entry[
                "enclaveGenerationEvidenceSha256"
            ],
            "kmsKeyArnSha256": entry["kmsKeyArnSha256"],
            "kmsEncryptionContextSha256": entry["kmsEncryptionContextSha256"],
        }
    return {
        "file_sha256": snapshot.sha256,
        "payload_sha256": key["payload_sha256"],
        "signing_key_id": key["spki_sha256"],
        "release_core_identity_sha256": release_core_identity_sha256,
        "policy_hash": policy_hash,
        "enclave_instance_id": payload["enclaveInstanceId"],
        "enclave_boot_id": payload["enclaveBootId"],
        "keys": normalized_keys,
        "keys_sha256": sha256_prefixed_json(normalized_keys),
        "issued_at_unix": issued,
        "expires_at_unix": expires,
        "identity_and_custody_distinguished": True,
        "kms_ciphertext_for_recipient_bound": True,
    }


def verify_merkle_consistency(
    *,
    old_size: int,
    new_size: int,
    old_root: str,
    new_root: str,
    proof: Any,
    label: str,
) -> None:
    require(
        1 <= old_size <= new_size,
        f"{label} tree sizes are invalid",
    )
    old_root = require_sha256(old_root, f"{label} old root")
    new_root = require_sha256(new_root, f"{label} new root")
    require(isinstance(proof, list) and len(proof) <= 256, f"{label} proof is invalid")
    proof_hashes = [require_sha256(item, f"{label} proof hash") for item in proof]
    if old_size == new_size:
        require(not proof_hashes and old_root == new_root, f"{label} equal-size proof mismatch")
        return
    first = old_size - 1
    second = new_size - 1
    while first & 1:
        first >>= 1
        second >>= 1
    index = 0
    if first == 0:
        old_cursor = old_root
        new_cursor = old_root
    else:
        require(bool(proof_hashes), f"{label} proof is empty")
        old_cursor = proof_hashes[0]
        new_cursor = proof_hashes[0]
        index = 1
    while index < len(proof_hashes):
        require(second != 0, f"{label} proof has trailing hashes")
        sibling = proof_hashes[index]
        if (first & 1) or first == second:
            old_cursor = node_hash(sibling, old_cursor)
            new_cursor = node_hash(sibling, new_cursor)
            while first != 0 and (first & 1) == 0:
                first >>= 1
                second >>= 1
        else:
            new_cursor = node_hash(new_cursor, sibling)
        first >>= 1
        second >>= 1
        index += 1
    require(
        second == 0
        and hmac.compare_digest(old_cursor, old_root)
        and hmac.compare_digest(new_cursor, new_root),
        f"{label} does not prove append-only consistency",
    )


def validate_prior_witness_state(
    document: dict[str, Any],
    *,
    snapshot: FileSnapshot,
) -> dict[str, Any]:
    require_exact_keys(
        document,
        {
            "apiVersion",
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
        "prior monotonic witness client state",
    )
    require(
        document.get("apiVersion") == MONOTONIC_WITNESS_STATE_API_VERSION,
        "prior monotonic witness state apiVersion mismatch",
    )
    payload = dict(document)
    state_sha256 = require_sha256(
        payload.pop("stateSha256", None),
        "prior witness state",
    )
    require(
        state_sha256 == sha256_prefixed_json(payload),
        "prior witness state digest mismatch",
    )
    return {
        "file_sha256": snapshot.sha256,
        "state_sha256": state_sha256,
        "provider": document.get("provider"),
        "log_id": require_sha256(document.get("logId"), "prior witness log ID"),
        "witness_key_id": require_sha256(
            document.get("witnessKeyId"),
            "prior witness key ID",
        ),
        "checkpoint_sha256": require_sha256(
            document.get("checkpointSha256"),
            "prior witness checkpoint",
        ),
        "release_generation": require_bounded_uint(
            document.get("releaseGeneration"),
            "prior witness release generation",
            minimum=1,
        ),
        "rollback_epoch": require_bounded_uint(
            document.get("rollbackEpoch"),
            "prior witness rollback epoch",
        ),
        "sequence": require_bounded_uint(
            document.get("sequence"),
            "prior witness sequence",
            minimum=1,
        ),
        "tree_size": require_bounded_uint(
            document.get("treeSize"),
            "prior witness tree size",
            minimum=1,
        ),
        "root_hash": require_sha256(
            document.get("rootHash"),
            "prior witness root hash",
        ),
    }


def verify_monotonic_witness(
    document: dict[str, Any],
    *,
    snapshot: FileSnapshot,
    public_key_snapshot: FileSnapshot,
    prior_state: dict[str, Any],
    production_release_identity_sha256: str,
    release_generation: int,
    rollback_epoch: int,
    expected_challenge_nonce_sha256: str,
    now_unix: int | None = None,
) -> dict[str, Any]:
    payload, key = verify_domain_ed25519_envelope(
        document,
        public_key_snapshot=public_key_snapshot,
        api_version=MONOTONIC_WITNESS_API_VERSION,
        domain=MONOTONIC_WITNESS_SIGNATURE_DOMAIN,
        label="off-host monotonic witness",
    )
    require_exact_keys(
        payload,
        {
            "challengeConsumption",
            "consistencyProof",
            "expiresAtUnix",
            "inclusion",
            "issuedAtUnix",
            "logId",
            "priorStateSha256",
            "provider",
            "releaseGeneration",
            "releaseIdentitySha256",
            "revocation",
            "rollbackEpoch",
            "rootHash",
            "sequence",
            "treeSize",
        },
        "off-host monotonic witness payload",
    )
    require(
        payload.get("priorStateSha256") == prior_state["state_sha256"],
        "off-host witness does not bind the verifier-retained prior state",
    )
    require(
        payload.get("provider") == prior_state["provider"]
        and payload.get("logId") == prior_state["log_id"]
        and key["spki_sha256"] == prior_state["witness_key_id"],
        "off-host witness provider, log, or independently pinned key changed",
    )
    require(
        payload.get("releaseIdentitySha256")
        == production_release_identity_sha256,
        "off-host witness release identity mismatch",
    )
    current_generation = require_bounded_uint(
        payload.get("releaseGeneration"),
        "off-host witness release generation",
        minimum=1,
    )
    current_epoch = require_bounded_uint(
        payload.get("rollbackEpoch"),
        "off-host witness rollback epoch",
    )
    current_sequence = require_bounded_uint(
        payload.get("sequence"),
        "off-host witness sequence",
        minimum=1,
    )
    current_tree_size = require_bounded_uint(
        payload.get("treeSize"),
        "off-host witness tree size",
        minimum=1,
    )
    current_root = require_sha256(payload.get("rootHash"), "off-host witness root")
    require(
        current_generation == release_generation
        and current_epoch == rollback_epoch,
        "off-host witness generation or rollback epoch differs from the production identity",
    )
    require(
        current_sequence > prior_state["sequence"]
        and current_tree_size > prior_state["tree_size"]
        and (
            current_epoch > prior_state["rollback_epoch"]
            or (
                current_epoch == prior_state["rollback_epoch"]
                and current_generation > prior_state["release_generation"]
            )
        ),
        "off-host witness did not advance high-water state",
    )
    verify_merkle_consistency(
        old_size=prior_state["tree_size"],
        new_size=current_tree_size,
        old_root=prior_state["root_hash"],
        new_root=current_root,
        proof=payload.get("consistencyProof"),
        label="off-host witness consistency",
    )
    inclusion = payload.get("inclusion")
    require(isinstance(inclusion, dict), "off-host witness inclusion proof is missing")
    require_exact_keys(
        inclusion,
        {"leafSha256", "proof", "rootHash", "treeSize"},
        "off-host witness inclusion",
    )
    expected_leaf = sha256_prefixed_bytes(
        b"\x00"
        + canonical_json(
            {
                "releaseGeneration": release_generation,
                "releaseIdentitySha256": production_release_identity_sha256,
                "rollbackEpoch": rollback_epoch,
            }
        ).encode("utf-8")
    )
    inclusion_tree_size = require_bounded_uint(
        inclusion.get("treeSize"),
        "off-host witness inclusion tree size",
        minimum=1,
    )
    require(
        inclusion.get("leafSha256") == expected_leaf
        and inclusion.get("rootHash") == current_root
        and inclusion_tree_size == current_tree_size
        and isinstance(inclusion.get("proof"), list)
        and verify_merkle_inclusion(expected_leaf, inclusion["proof"], current_root),
        "off-host witness release inclusion proof is invalid",
    )
    issued = require_bounded_uint(payload.get("issuedAtUnix"), "off-host witness issue time")
    expires = require_bounded_uint(payload.get("expiresAtUnix"), "off-host witness expiry")
    now = int(time.time()) if now_unix is None else now_unix
    require(
        issued <= now + HARDWARE_PROOF_FUTURE_SKEW_SECONDS
        and expires > now
        and issued < expires
        and expires - issued <= CONTINUITY_MAX_VALIDITY_SECONDS,
        "off-host witness is stale, future, expired, or too broadly valid",
    )
    revocation = payload.get("revocation")
    require(isinstance(revocation, dict), "off-host witness revocation evidence is missing")
    require_exact_keys(
        revocation,
        {
            "asOfUnix",
            "releaseIdentitySha256",
            "revocationListSha256",
            "revokedIdentities",
            "status",
        },
        "off-host witness revocation evidence",
    )
    revoked = revocation.get("revokedIdentities")
    require(
        isinstance(revoked, list)
        and revoked == sorted(set(revoked))
        and all(SHA256_RE.fullmatch(str(item)) is not None for item in revoked)
        and revocation.get("revocationListSha256") == sha256_prefixed_json(revoked)
        and revocation.get("releaseIdentitySha256")
        == production_release_identity_sha256
        and revocation.get("status") == "active"
        and production_release_identity_sha256 not in revoked
        and revocation.get("asOfUnix") == issued,
        "off-host witness current revocation state is invalid or revoked",
    )
    consumption = payload.get("challengeConsumption")
    require(isinstance(consumption, dict), "off-host witness challenge consumption is missing")
    require_exact_keys(
        consumption,
        {
            "challengeNonceSha256",
            "consumedAtUnix",
            "consumptionId",
            "expiresAtUnix",
            "oneUse",
            "status",
        },
        "off-host witness challenge consumption",
    )
    consumption_id = consumption.get("consumptionId")
    require(
        consumption.get("challengeNonceSha256")
        == expected_challenge_nonce_sha256
        and consumption.get("status") == "consumed"
        and consumption.get("oneUse") is True
        and isinstance(consumption_id, str)
        and 1 <= len(consumption_id) <= 128
        and consumption.get("consumedAtUnix") == issued
        and consumption.get("expiresAtUnix") == expires,
        "off-host witness did not atomically consume the expected one-use challenge",
    )
    next_state_payload = {
        "apiVersion": MONOTONIC_WITNESS_STATE_API_VERSION,
        "checkpointSha256": snapshot.sha256,
        "logId": prior_state["log_id"],
        "provider": prior_state["provider"],
        "releaseGeneration": current_generation,
        "rollbackEpoch": current_epoch,
        "rootHash": current_root,
        "sequence": current_sequence,
        "treeSize": current_tree_size,
        "witnessKeyId": key["spki_sha256"],
    }
    return {
        "file_sha256": snapshot.sha256,
        "payload_sha256": key["payload_sha256"],
        "signing_key_id": key["spki_sha256"],
        "release_identity_sha256": production_release_identity_sha256,
        "release_generation": current_generation,
        "rollback_epoch": current_epoch,
        "sequence": current_sequence,
        "tree_size": current_tree_size,
        "root_hash": current_root,
        "consumption_id": consumption_id,
        "revocation_checked": True,
        "prior_state_required": True,
        "stateless_verification_rejected": True,
        "next_state": {
            **next_state_payload,
            "stateSha256": sha256_prefixed_json(next_state_payload),
        },
    }


def verify_production_continuity(
    *,
    snapshots: dict[str, FileSnapshot],
    expected_policy_hash: str,
    expected_challenge_nonce_sha256: str,
) -> dict[str, Any]:
    source_document = load_canonical_json_artifact(
        snapshots["source_input_manifest"],
        "source-input manifest",
        api_version=SOURCE_INPUT_MANIFEST_API_VERSION,
    )
    source_summary = verify_source_input_continuity(
        source_document,
        source_snapshot=snapshots["source_input_manifest"],
        git_inventory_public_key=snapshots[
            "source_git_inventory_public_key"
        ],
        untracked_approval_public_key=snapshots[
            "source_untracked_approval_public_key"
        ],
    )
    dependency_document = load_canonical_json_artifact(
        snapshots["dependency_closure"],
        "dependency closure manifest",
        api_version=DEPENDENCY_BUNDLE_API_VERSION,
    )
    dependency_summary = validate_dependency_bundle_continuity(
        dependency_document,
        snapshot=snapshots["dependency_closure"],
    )
    candidate_document = load_canonical_json_artifact(
        snapshots["candidate_manifest_v6"],
        "Candidate Manifest v6",
        api_version=CANDIDATE_MANIFEST_V6_API_VERSION,
    )
    candidate_summary = validate_candidate_manifest_v6(
        candidate_document,
        snapshot=snapshots["candidate_manifest_v6"],
        source_document=source_document,
        source_summary=source_summary,
        dependency_document=dependency_document,
    )
    watchdog_document = load_canonical_json_artifact(
        snapshots["build_watchdog_receipt"],
        "build-watchdog receipt",
        api_version=BUILD_WATCHDOG_RECEIPT_API_VERSION,
    )
    watchdog_summary = verify_build_watchdog_continuity(
        watchdog_document,
        snapshot=snapshots["build_watchdog_receipt"],
        public_key_snapshot=snapshots["build_watchdog_public_key"],
        candidate_document=candidate_document,
    )
    promotion_document = load_canonical_json_artifact(
        snapshots["promotion_receipt"],
        "promotion receipt",
        api_version=PROMOTION_RECEIPT_API_VERSION,
    )
    promotion_summary = verify_promotion_continuity(
        promotion_document,
        snapshot=snapshots["promotion_receipt"],
        public_key_snapshot=snapshots["promotion_public_key"],
        candidate_summary=candidate_summary,
    )
    builders_summary = verify_independent_raw_builders(
        left_statement=load_canonical_json_artifact(
            snapshots["builder_left_statement"],
            "left raw builder statement",
            api_version=RAW_BUILDER_STATEMENT_API_VERSION,
        ),
        left_statement_snapshot=snapshots["builder_left_statement"],
        left_transcript=load_canonical_json_artifact(
            snapshots["builder_left_transcript"],
            "left raw builder transcript",
            api_version=RAW_BUILDER_TRANSCRIPT_API_VERSION,
        ),
        left_transcript_snapshot=snapshots["builder_left_transcript"],
        left_public_key=snapshots["builder_left_public_key"],
        right_statement=load_canonical_json_artifact(
            snapshots["builder_right_statement"],
            "right raw builder statement",
            api_version=RAW_BUILDER_STATEMENT_API_VERSION,
        ),
        right_statement_snapshot=snapshots["builder_right_statement"],
        right_transcript=load_canonical_json_artifact(
            snapshots["builder_right_transcript"],
            "right raw builder transcript",
            api_version=RAW_BUILDER_TRANSCRIPT_API_VERSION,
        ),
        right_transcript_snapshot=snapshots["builder_right_transcript"],
        right_public_key=snapshots["builder_right_public_key"],
        candidate_summary=candidate_summary,
        source_summary=source_summary,
        dependency_summary=dependency_summary,
    )
    eif_summary = verify_manifest_v6_eif_build(
        load_canonical_json_artifact(
            snapshots["manifest_v6_eif_build"],
            "Manifest v6 EIF build statement",
            api_version=MANIFEST_V6_EIF_BUILD_API_VERSION,
        ),
        snapshot=snapshots["manifest_v6_eif_build"],
        public_key_snapshot=snapshots["manifest_v6_eif_builder_public_key"],
        candidate_summary=candidate_summary,
        source_summary=source_summary,
        watchdog_summary=watchdog_summary,
        promotion_summary=promotion_summary,
        builders_summary=builders_summary,
        dependency_summary=dependency_summary,
    )
    release_core = production_release_core_identity(
        candidate_summary=candidate_summary,
        source_summary=source_summary,
        watchdog_summary=watchdog_summary,
        promotion_summary=promotion_summary,
        builders_summary=builders_summary,
        dependency_summary=dependency_summary,
        eif_summary=eif_summary,
    )
    release_core_sha256 = sha256_prefixed_json(release_core)
    custody_summary = verify_key_custody_continuity(
        load_canonical_json_artifact(
            snapshots["key_custody_evidence"],
            "enclave key-custody evidence",
            api_version=KEY_CUSTODY_EVIDENCE_API_VERSION,
        ),
        snapshot=snapshots["key_custody_evidence"],
        public_key_snapshot=snapshots["key_custody_public_key"],
        release_core_identity_sha256=release_core_sha256,
        eif_summary=eif_summary,
        expected_policy_hash=expected_policy_hash,
    )
    production_identity_payload = {
        **release_core,
        "releaseCoreIdentitySha256": release_core_sha256,
        "keyCustody": {
            "evidenceFileSha256": custody_summary["file_sha256"],
            "evidencePayloadSha256": custody_summary["payload_sha256"],
            "verifierKeyId": custody_summary["signing_key_id"],
            "keysSha256": custody_summary["keys_sha256"],
            "keys": custody_summary["keys"],
            "identityAndCustodyDistinguished": True,
            "kmsCiphertextForRecipientBound": True,
        },
    }
    production_identity = {
        **production_identity_payload,
        "productionReleaseIdentitySha256": sha256_prefixed_json(
            production_identity_payload
        ),
    }
    prior_state = validate_prior_witness_state(
        load_canonical_json_artifact(
            snapshots["prior_witness_state"],
            "prior monotonic witness client state",
            api_version=MONOTONIC_WITNESS_STATE_API_VERSION,
        ),
        snapshot=snapshots["prior_witness_state"],
    )
    witness_summary = verify_monotonic_witness(
        load_canonical_json_artifact(
            snapshots["monotonic_witness"],
            "off-host monotonic witness",
            api_version=MONOTONIC_WITNESS_API_VERSION,
        ),
        snapshot=snapshots["monotonic_witness"],
        public_key_snapshot=snapshots["monotonic_witness_public_key"],
        prior_state=prior_state,
        production_release_identity_sha256=production_identity[
            "productionReleaseIdentitySha256"
        ],
        release_generation=eif_summary["release_generation"],
        rollback_epoch=eif_summary["rollback_epoch"],
        expected_challenge_nonce_sha256=expected_challenge_nonce_sha256,
    )
    summary_payload = {
        "apiVersion": PRODUCTION_CONTINUITY_SUMMARY_API_VERSION,
        "pipeline": MANIFEST_V6_PIPELINE,
        "productionReleaseIdentity": production_identity,
        "source": source_summary,
        "candidate": {
            key: value
            for key, value in candidate_summary.items()
            if key != "candidate_images"
        },
        "buildWatchdog": watchdog_summary,
        "promotion": {
            key: value
            for key, value in promotion_summary.items()
            if key not in {"image_mappings", "imported_images"}
        },
        "builders": builders_summary,
        "dependencies": dependency_summary,
        "eif": eif_summary,
        "keyCustody": custody_summary,
        "monotonicWitness": witness_summary,
        "legacyDockerNsmAccepted": False,
    }
    return {
        **summary_payload,
        "continuitySha256": sha256_prefixed_json(summary_payload),
    }


def verify_completion_proof_authentication(
    *,
    authentication_document: dict[str, Any],
    authentication_snapshot: FileSnapshot,
    authentication_public_key: FileSnapshot,
    checkpoint_document: dict[str, Any],
    checkpoint_snapshot: FileSnapshot,
    checkpoint_public_key: FileSnapshot,
    expected_completion_identity_sha256: str,
    expected_proof_core_sha256: str,
    continuity: dict[str, Any],
    now_unix: int | None = None,
) -> dict[str, Any]:
    statement, authentication_key = verify_domain_ed25519_envelope(
        authentication_document,
        public_key_snapshot=authentication_public_key,
        api_version=COMPLETION_AUTHENTICATION_API_VERSION,
        domain=COMPLETION_AUTHENTICATION_SIGNATURE_DOMAIN,
        label="completion proof authentication",
    )
    require_exact_keys(
        statement,
        {
            "completionIdentity",
            "completionIdentitySha256",
            "expiresAtUnix",
            "issuedAtUnix",
            "keyCustodyEvidenceSha256",
            "productionReleaseIdentitySha256",
            "proofApiVersion",
            "proofCoreSha256",
            "witnessEvidenceSha256",
        },
        "completion proof authentication payload",
    )
    require(
        statement.get("proofApiVersion") == COMPLETION_PROOF_API_VERSION
        and statement.get("completionIdentitySha256")
        == expected_completion_identity_sha256
        and statement.get("proofCoreSha256") == expected_proof_core_sha256
        and statement.get("productionReleaseIdentitySha256")
        == continuity["productionReleaseIdentity"][
            "productionReleaseIdentitySha256"
        ]
        and statement.get("keyCustodyEvidenceSha256")
        == continuity["keyCustody"]["file_sha256"]
        and statement.get("witnessEvidenceSha256")
        == continuity["monotonicWitness"]["file_sha256"],
        "completion authentication does not bind the exact aggregate proof and production continuity",
    )
    issued = require_bounded_uint(
        statement.get("issuedAtUnix"),
        "completion authentication issue time",
    )
    expires = require_bounded_uint(
        statement.get("expiresAtUnix"),
        "completion authentication expiry",
    )
    now = int(time.time()) if now_unix is None else now_unix
    require(
        issued <= now + HARDWARE_PROOF_FUTURE_SKEW_SECONDS
        and expires > now
        and issued < expires
        and expires - issued <= CONTINUITY_MAX_VALIDITY_SECONDS,
        "completion authentication is stale, future, expired, or too broadly valid",
    )
    checkpoint, checkpoint_key = verify_domain_ed25519_envelope(
        checkpoint_document,
        public_key_snapshot=checkpoint_public_key,
        api_version=COMPLETION_CHECKPOINT_API_VERSION,
        domain=COMPLETION_CHECKPOINT_SIGNATURE_DOMAIN,
        label="completion proof checkpoint",
    )
    require(
        checkpoint_key["spki_sha256"] != authentication_key["spki_sha256"],
        "completion proof signer and checkpoint log must use independent keys",
    )
    require_exact_keys(
        checkpoint,
        {
            "expiresAtUnix",
            "inclusionProof",
            "issuedAtUnix",
            "leafSha256",
            "logId",
            "provider",
            "rootHash",
            "statementPayloadSha256",
            "treeSize",
        },
        "completion proof checkpoint payload",
    )
    checkpoint_issued = require_bounded_uint(
        checkpoint.get("issuedAtUnix"),
        "completion checkpoint issue time",
    )
    checkpoint_expires = require_bounded_uint(
        checkpoint.get("expiresAtUnix"),
        "completion checkpoint expiry",
    )
    require(
        checkpoint_issued >= issued
        and checkpoint_issued <= now + HARDWARE_PROOF_FUTURE_SKEW_SECONDS
        and checkpoint_expires > now
        and checkpoint_expires > checkpoint_issued
        and checkpoint_expires - checkpoint_issued <= CONTINUITY_MAX_VALIDITY_SECONDS,
        "completion checkpoint is stale, future, expired, or too broadly valid",
    )
    require(
        checkpoint.get("statementPayloadSha256")
        == authentication_key["payload_sha256"]
        and checkpoint.get("logId") == checkpoint_key["spki_sha256"],
        "completion checkpoint does not bind the signed completion statement or pinned log",
    )
    require(
        isinstance(checkpoint.get("provider"), str)
        and 1 <= len(checkpoint["provider"]) <= 256,
        "completion checkpoint provider identity is invalid",
    )
    expected_leaf = sha256_prefixed_bytes(
        b"\x00"
        + canonical_json(
            {
                "completionAuthenticationPayloadSha256": authentication_key[
                    "payload_sha256"
                ],
                "proofCoreSha256": expected_proof_core_sha256,
            }
        ).encode("utf-8")
    )
    tree_size = require_bounded_uint(
        checkpoint.get("treeSize"),
        "completion checkpoint tree size",
        minimum=1,
    )
    root_hash = require_sha256(checkpoint.get("rootHash"), "completion checkpoint root")
    inclusion_proof = checkpoint.get("inclusionProof")
    require(
        checkpoint.get("leafSha256") == expected_leaf
        and isinstance(inclusion_proof, list)
        and verify_merkle_inclusion(expected_leaf, inclusion_proof, root_hash),
        "completion authentication is not included in the independently signed checkpoint",
    )
    return {
        "independently_authenticated": True,
        "authentication_file_sha256": authentication_snapshot.sha256,
        "authentication_payload_sha256": authentication_key["payload_sha256"],
        "authentication_key_id": authentication_key["spki_sha256"],
        "checkpoint_file_sha256": checkpoint_snapshot.sha256,
        "checkpoint_payload_sha256": checkpoint_key["payload_sha256"],
        "checkpoint_key_id": checkpoint_key["spki_sha256"],
        "checkpoint_provider": checkpoint.get("provider"),
        "checkpoint_tree_size": tree_size,
        "checkpoint_root_hash": root_hash,
        "proof_core_sha256": expected_proof_core_sha256,
        "completion_identity_sha256": expected_completion_identity_sha256,
        "issued_at_unix": issued,
        "expires_at_unix": min(expires, checkpoint_expires),
    }


def validate_release_identity(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require_exact_keys(value, RELEASE_IDENTITY_FIELDS, label)
    normalized = {
        "source_tree_digest": require_sha256(value.get("source_tree_digest"), f"{label} source tree digest"),
        "provenance_digest": require_sha256(value.get("provenance_digest"), f"{label} provenance digest"),
        "runtime_manifest_digest": require_sha256(
            value.get("runtime_manifest_digest"),
            f"{label} runtime manifest digest",
        ),
        "data_plane_binary_digest": require_sha256(
            value.get("data_plane_binary_digest"),
            f"{label} data-plane binary digest",
        ),
        "production_images_build_sha256": require_sha256(
            value.get("production_images_build_sha256"),
            f"{label} production image build artifact digest",
        ),
        "production_images_published_sha256": require_sha256(
            value.get("production_images_published_sha256"),
            f"{label} published image artifact digest",
        ),
        "image_signature_bundle_digest": require_sha256(
            value.get("image_signature_bundle_digest"),
            f"{label} image signature bundle digest",
        ),
    }
    image_digests = value.get("production_image_digests")
    image_refs = value.get("production_image_refs")
    require(isinstance(image_digests, list) and image_digests, f"{label} production image digests are missing")
    require(isinstance(image_refs, list) and image_refs, f"{label} production image refs are missing")
    normalized["production_image_digests"] = sorted(
        require_sha256(item, f"{label} production image digest") for item in image_digests
    )
    normalized["production_image_refs"] = sorted(
        require_image_ref(item, f"{label} production image ref")[0] for item in image_refs
    )
    require(
        len(set(normalized["production_image_digests"])) == len(normalized["production_image_digests"]),
        f"{label} contains duplicate production image digests",
    )
    require(
        len(set(normalized["production_image_refs"])) == len(normalized["production_image_refs"]),
        f"{label} contains duplicate production image refs",
    )
    return normalized


def current_host_identity_from_values(*, machine_id: str, product_uuid: str, boot_id: str) -> dict[str, str]:
    normalized_machine_id = machine_id.strip().lower()
    normalized_product_uuid = product_uuid.strip().lower()
    normalized_boot_id = boot_id.strip().lower()
    require(
        MACHINE_ID_RE.fullmatch(normalized_machine_id) is not None and set(normalized_machine_id) != {"0"},
        "current completion host machine id is invalid",
    )
    require(
        UUID_RE.fullmatch(normalized_product_uuid) is not None and set(normalized_product_uuid.replace("-", "")) != {"0"},
        "current completion host product UUID is invalid",
    )
    require(
        UUID_RE.fullmatch(normalized_boot_id) is not None and set(normalized_boot_id.replace("-", "")) != {"0"},
        "current completion host boot id is invalid",
    )

    def component_digest(label: str, value: str) -> str:
        return sha256_prefixed_bytes(
            f"{CURRENT_HOST_IDENTITY_SCHEME}:{label}\0{value}".encode("ascii")
        )

    identity = {
        "scheme": CURRENT_HOST_IDENTITY_SCHEME,
        "machine_id_sha256": component_digest("machine-id", normalized_machine_id),
        "product_uuid_sha256": component_digest("product-uuid", normalized_product_uuid),
        "boot_id_sha256": component_digest("boot-id", normalized_boot_id),
    }
    return {**identity, "identity_sha256": sha256_prefixed_json(identity)}


def read_current_host_identity() -> dict[str, str]:
    values: dict[str, str] = {}
    for key, path in (
        ("machine_id", CURRENT_HOST_MACHINE_ID_PATH),
        ("product_uuid", CURRENT_HOST_PRODUCT_UUID_PATH),
        ("boot_id", CURRENT_HOST_BOOT_ID_PATH),
    ):
        try:
            values[key] = path.read_text(encoding="ascii").strip()
        except OSError as exc:
            raise ValueError(f"current completion host identity source is unavailable: {path}") from exc
    return current_host_identity_from_values(**values)


def current_host_identity_claim(identity: dict[str, str], *, observed_at_unix: int) -> dict[str, Any]:
    require_exact_keys(
        identity,
        {"scheme", "machine_id_sha256", "product_uuid_sha256", "boot_id_sha256", "identity_sha256"},
        "current completion host identity",
    )
    payload: dict[str, Any] = {**identity, "observed_at_unix": observed_at_unix}
    return {**payload, "commitment_sha256": sha256_prefixed_json(payload)}


def verify_hardware_assurance(
    document: dict[str, Any],
    *,
    trusted_public_key_pem: str,
    expected_trusted_public_key_id: str | None,
    hardware_assurance_document_sha256: str,
    nitro_summary: dict[str, Any],
    nitro_evidence_sha256: str,
    production_host_preflight_sha256: str,
    current_host: dict[str, Any],
    expected_release_identity: dict[str, Any],
    expected_challenge_nonce: str | None = None,
    expected_challenge_nonce_sha256: str | None = None,
    now_unix: int | None = None,
) -> dict[str, Any]:
    assert_no_secret_fields(document)
    verified_expected_release_identity = validate_release_identity(
        expected_release_identity,
        "independently verified release identity",
    )
    require_exact_keys(
        document,
        {"apiVersion", "kind", "statement", "signing_key_id", "signature"},
        "hardware assurance document",
    )
    require(document.get("apiVersion") == HARDWARE_PROOF_API_VERSION, "hardware assurance apiVersion mismatch")
    require(document.get("kind") == "ServerwareHardwareAssurance", "hardware assurance kind mismatch")
    statement = document.get("statement") if isinstance(document.get("statement"), dict) else {}
    require(statement, "hardware assurance document is missing its signed statement")
    require_exact_keys(
        statement,
        {
            "verifier",
            "issued_at_unix",
            "expires_at_unix",
            "challenge_nonce",
            "current_host_identity",
            "attestation_document_sha256",
            "eif",
            "pcrs",
            "enclave",
            "key_custody",
            "no_parent_key",
            "release_bindings",
            "artifact_bindings",
        },
        "hardware assurance statement",
    )

    signing_key_id = require_sha256(document.get("signing_key_id"), "hardware assurance signing key id")
    trusted_key_id = release_public_key_id(trusted_public_key_pem)
    if expected_trusted_public_key_id is not None:
        expected_key_id = require_sha256(
            expected_trusted_public_key_id,
            "expected hardware assurance verifier public key id",
        )
        require(
            hmac.compare_digest(trusted_key_id, expected_key_id),
            "hardware assurance verifier key bytes do not match the independently configured SPKI identity",
        )
    require(signing_key_id == trusted_key_id, "hardware assurance signer does not match the separately trusted verifier key")
    signature = document.get("signature")
    require(isinstance(signature, str) and signature, "hardware assurance document is missing its signature")
    signed_statement_bytes = canonical_json(statement).encode("utf-8")
    verify_ed25519(
        trusted_public_key_pem,
        signature,
        signed_statement_bytes,
        "hardware assurance",
    )

    verifier = statement.get("verifier") if isinstance(statement.get("verifier"), dict) else {}
    require_exact_keys(verifier, {"name", "organization", "independent"}, "hardware assurance verifier identity")
    require(isinstance(verifier.get("name"), str) and bool(verifier.get("name")), "hardware assurance verifier name is missing")
    require(
        isinstance(verifier.get("organization"), str) and bool(verifier.get("organization")),
        "hardware assurance verifier organization is missing",
    )
    require(verifier.get("independent") is True, "hardware assurance was not issued by an independent verifier")

    issued_at = statement.get("issued_at_unix")
    expires_at = statement.get("expires_at_unix")
    require(isinstance(issued_at, int) and not isinstance(issued_at, bool), "hardware assurance issued_at_unix is invalid")
    require(isinstance(expires_at, int) and not isinstance(expires_at, bool), "hardware assurance expires_at_unix is invalid")
    now = int(time.time()) if now_unix is None else now_unix
    require(issued_at <= now + HARDWARE_PROOF_FUTURE_SKEW_SECONDS, "hardware assurance was issued in the future")
    require(now - issued_at <= HARDWARE_PROOF_MAX_AGE_SECONDS, "hardware assurance is stale")
    require(expires_at >= now, "hardware assurance has expired")
    require(expires_at > issued_at, "hardware assurance expiry does not follow issuance")
    require(
        expires_at - issued_at <= HARDWARE_PROOF_MAX_AGE_SECONDS,
        "hardware assurance validity window exceeds the allowed maximum",
    )

    host_identity = (
        statement.get("current_host_identity")
        if isinstance(statement.get("current_host_identity"), dict)
        else {}
    )
    require_exact_keys(
        host_identity,
        {
            "scheme",
            "machine_id_sha256",
            "product_uuid_sha256",
            "boot_id_sha256",
            "identity_sha256",
            "observed_at_unix",
            "commitment_sha256",
        },
        "hardware assurance current-host identity",
    )
    require(
        host_identity.get("scheme") == CURRENT_HOST_IDENTITY_SCHEME,
        "hardware assurance current-host identity scheme mismatch",
    )
    identity_payload = {
        "scheme": host_identity["scheme"],
        "machine_id_sha256": require_sha256(
            host_identity.get("machine_id_sha256"),
            "hardware assurance current-host machine id digest",
        ),
        "product_uuid_sha256": require_sha256(
            host_identity.get("product_uuid_sha256"),
            "hardware assurance current-host product UUID digest",
        ),
        "boot_id_sha256": require_sha256(
            host_identity.get("boot_id_sha256"),
            "hardware assurance current-host boot id digest",
        ),
    }
    identity_sha256 = require_sha256(
        host_identity.get("identity_sha256"),
        "hardware assurance current-host identity digest",
    )
    require(
        identity_sha256 == sha256_prefixed_json(identity_payload),
        "hardware assurance current-host identity digest mismatch",
    )
    observed_at = host_identity.get("observed_at_unix")
    require(
        isinstance(observed_at, int) and not isinstance(observed_at, bool),
        "hardware assurance current-host identity observation time is invalid",
    )
    require(
        observed_at <= issued_at,
        "hardware assurance current-host identity observation follows assurance issuance",
    )
    require(
        issued_at - observed_at <= CURRENT_HOST_IDENTITY_MAX_OBSERVATION_AGE_SECONDS,
        "hardware assurance current-host identity observation is stale relative to assurance issuance",
    )
    host_identity_commitment = require_sha256(
        host_identity.get("commitment_sha256"),
        "hardware assurance current-host identity commitment",
    )
    require(
        host_identity_commitment
        == sha256_prefixed_json({**identity_payload, "identity_sha256": identity_sha256, "observed_at_unix": observed_at}),
        "hardware assurance current-host identity commitment mismatch",
    )
    current_host_identity_bound = False
    if current_host.get("skipped") is not True:
        require(
            current_host.get("identity_recomputed") is True,
            "current completion host identity was not recomputed",
        )
        recomputed_identity = current_host.get("identity") if isinstance(current_host.get("identity"), dict) else {}
        require(
            recomputed_identity == {**identity_payload, "identity_sha256": identity_sha256},
            "hardware assurance current-host identity does not match current completion host",
        )
        current_host_identity_bound = True

    challenge_nonce = statement.get("challenge_nonce")
    require(
        isinstance(challenge_nonce, str) and BASE64URL_RE.fullmatch(challenge_nonce) is not None,
        "hardware assurance challenge nonce is invalid",
    )
    try:
        challenge_nonce_bytes = b64d(challenge_nonce)
    except Exception as exc:
        raise ValueError("hardware assurance challenge nonce is invalid") from exc
    require(len(challenge_nonce_bytes) >= 32, "hardware assurance challenge nonce is too short")
    supplied_expected_challenges = sum(
        value is not None
        for value in (expected_challenge_nonce, expected_challenge_nonce_sha256)
    )
    require(
        supplied_expected_challenges == 1,
        "hardware assurance verification requires exactly one caller-expected challenge nonce or nonce SHA-256",
    )
    challenge_nonce_sha256 = sha256_prefixed_bytes(challenge_nonce_bytes)
    if expected_challenge_nonce is not None:
        require(
            isinstance(expected_challenge_nonce, str)
            and BASE64URL_RE.fullmatch(expected_challenge_nonce) is not None,
            "expected hardware assurance challenge nonce is invalid",
        )
        try:
            expected_challenge_nonce_bytes = b64d(expected_challenge_nonce)
        except Exception as exc:
            raise ValueError("expected hardware assurance challenge nonce is invalid") from exc
        require(
            len(expected_challenge_nonce_bytes) >= 32,
            "expected hardware assurance challenge nonce is too short",
        )
        challenge_matches = hmac.compare_digest(
            challenge_nonce_bytes,
            expected_challenge_nonce_bytes,
        )
    else:
        expected_digest = require_sha256(
            expected_challenge_nonce_sha256,
            "expected hardware assurance challenge nonce digest",
        )
        challenge_matches = hmac.compare_digest(challenge_nonce_sha256, expected_digest)
    require(
        challenge_matches,
        "hardware assurance challenge nonce does not match the caller-expected challenge",
    )

    attestation_document_sha256 = require_sha256(
        statement.get("attestation_document_sha256"),
        "hardware assurance attestation document digest",
    )
    require(
        attestation_document_sha256 == nitro_summary["raw_attestation_document_sha256"],
        "hardware assurance does not bind the verified Nitro attestation document",
    )

    eif = statement.get("eif") if isinstance(statement.get("eif"), dict) else {}
    require_exact_keys(
        eif,
        {"image_sha384", "build_manifest", "build_manifest_sha256", "signature_verified", "evidence_sha256"},
        "hardware assurance EIF evidence",
    )
    eif_image_sha384 = require_sha384(eif.get("image_sha384"), "hardware assurance EIF image digest")
    build_manifest_sha256 = require_sha256(
        eif.get("build_manifest_sha256"),
        "hardware assurance EIF build manifest digest",
    )
    require_sha256(eif.get("evidence_sha256"), "hardware assurance EIF evidence digest")
    require(eif.get("signature_verified") is True, "hardware assurance did not verify the EIF signature")

    pcrs = statement.get("pcrs") if isinstance(statement.get("pcrs"), dict) else {}
    require_exact_keys(pcrs, {"PCR0", "PCR1", "PCR2"}, "hardware assurance PCR measurements")
    verified_pcrs = {name: require_sha384(pcrs.get(name), f"hardware assurance {name}") for name in ("PCR0", "PCR1", "PCR2")}
    require(verified_pcrs["PCR0"] == eif_image_sha384, "hardware assurance EIF image digest does not match PCR0")
    build_manifest = eif.get("build_manifest") if isinstance(eif.get("build_manifest"), dict) else {}
    require_exact_keys(
        build_manifest,
        {"apiVersion", "release_identity", "release_identity_sha256", "eif_image_sha384", "pcrs"},
        "hardware assurance EIF build manifest",
    )
    require(
        build_manifest.get("apiVersion") == EIF_BUILD_MANIFEST_API_VERSION,
        "hardware assurance EIF build manifest apiVersion mismatch",
    )
    manifest_release_identity = validate_release_identity(
        build_manifest.get("release_identity"),
        "hardware assurance EIF build manifest release identity",
    )
    require(
        manifest_release_identity == verified_expected_release_identity,
        "hardware assurance EIF build manifest does not match the independently verified source/build/release identity",
    )
    require(
        build_manifest.get("release_identity_sha256") == sha256_prefixed_json(verified_expected_release_identity),
        "hardware assurance EIF build manifest release identity digest mismatch",
    )
    require(
        build_manifest.get("eif_image_sha384") == eif_image_sha384,
        "hardware assurance EIF build manifest image measurement mismatch",
    )
    require(
        build_manifest.get("pcrs") == verified_pcrs,
        "hardware assurance EIF build manifest PCR measurements mismatch",
    )
    require(
        sha256_prefixed_json(build_manifest) == build_manifest_sha256,
        "hardware assurance EIF build manifest digest mismatch",
    )

    enclave = statement.get("enclave") if isinstance(statement.get("enclave"), dict) else {}
    require_exact_keys(
        enclave,
        {
            "cid",
            "parent_cid",
            "vsock_port",
            "cid_evidence_sha256",
            "vsock_evidence_sha256",
            "vsock_handshake_verified",
        },
        "hardware assurance enclave connectivity evidence",
    )
    cid = enclave.get("cid")
    parent_cid = enclave.get("parent_cid")
    vsock_port = enclave.get("vsock_port")
    require(isinstance(cid, int) and not isinstance(cid, bool) and 4 <= cid <= 0xFFFFFFFF, "hardware assurance enclave CID is invalid")
    require(parent_cid == 3, "hardware assurance parent CID is not the Nitro parent CID")
    require(
        isinstance(vsock_port, int) and not isinstance(vsock_port, bool) and 1 <= vsock_port <= 0xFFFFFFFF,
        "hardware assurance vsock port is invalid",
    )
    require_sha256(enclave.get("cid_evidence_sha256"), "hardware assurance CID evidence digest")
    require_sha256(enclave.get("vsock_evidence_sha256"), "hardware assurance vsock evidence digest")
    require(enclave.get("vsock_handshake_verified") is True, "hardware assurance did not verify a vsock handshake")

    key_custody = statement.get("key_custody") if isinstance(statement.get("key_custody"), dict) else {}
    require_exact_keys(
        key_custody,
        {
            "recipient_key_generated_in_enclave",
            "kms_recipient_bound",
            "plaintext_key_exported",
            "parent_process_key_access",
            "kms_recipient_bindings_sha256",
            "evidence_sha256",
        },
        "hardware assurance key-custody evidence",
    )
    require(
        key_custody.get("recipient_key_generated_in_enclave") is True,
        "hardware assurance did not prove enclave-local recipient-key generation",
    )
    require(key_custody.get("kms_recipient_bound") is True, "hardware assurance did not bind AWS KMS Recipient release")
    require(key_custody.get("plaintext_key_exported") is False, "hardware assurance permits plaintext key export")
    require(key_custody.get("parent_process_key_access") is False, "hardware assurance permits parent-process key access")
    kms_recipient_bindings_sha256 = require_sha256(
        key_custody.get("kms_recipient_bindings_sha256"),
        "hardware assurance KMS Recipient bindings digest",
    )
    require(
        kms_recipient_bindings_sha256 == sha256_prefixed_json(nitro_summary["material_release_receipts"]),
        "hardware assurance KMS Recipient bindings do not match Nitro release evidence",
    )
    require_sha256(key_custody.get("evidence_sha256"), "hardware assurance key-custody evidence digest")

    no_parent_key = statement.get("no_parent_key") if isinstance(statement.get("no_parent_key"), dict) else {}
    require_exact_keys(
        no_parent_key,
        {"verified", "parent_key_material_absent", "evidence_sha256"},
        "hardware assurance no-parent-key evidence",
    )
    require(no_parent_key.get("verified") is True, "hardware assurance no-parent-key evidence is not verified")
    require(
        no_parent_key.get("parent_key_material_absent") is True,
        "hardware assurance found key material in a parent process",
    )
    require_sha256(no_parent_key.get("evidence_sha256"), "hardware assurance no-parent-key evidence digest")

    release_bindings = statement.get("release_bindings") if isinstance(statement.get("release_bindings"), dict) else {}
    require(
        release_bindings == nitro_summary["attested_runtime"],
        "hardware assurance release bindings do not exactly match the Nitro-attested runtime",
    )
    require(
        release_bindings.get("source_tree_digest") == verified_expected_release_identity["source_tree_digest"]
        and release_bindings.get("provenance_digest") == verified_expected_release_identity["provenance_digest"]
        and release_bindings.get("runtime_manifest_digest")
        == verified_expected_release_identity["runtime_manifest_digest"]
        and release_bindings.get("data_plane_binary_digest")
        == verified_expected_release_identity["data_plane_binary_digest"],
        "hardware assurance Nitro release bindings do not match the independently verified release identity",
    )
    artifact_bindings = statement.get("artifact_bindings") if isinstance(statement.get("artifact_bindings"), dict) else {}
    require_exact_keys(
        artifact_bindings,
        {"nitro_evidence_sha256", "production_host_preflight_sha256"},
        "hardware assurance artifact bindings",
    )
    require(
        artifact_bindings.get("nitro_evidence_sha256") == nitro_evidence_sha256,
        "hardware assurance does not bind the current Nitro evidence artifact",
    )
    require(
        artifact_bindings.get("production_host_preflight_sha256") == production_host_preflight_sha256,
        "hardware assurance does not bind the current production host preflight artifact",
    )

    independent_evidence_digests = {
        eif["evidence_sha256"],
        enclave["cid_evidence_sha256"],
        enclave["vsock_evidence_sha256"],
        key_custody["evidence_sha256"],
        no_parent_key["evidence_sha256"],
    }
    require(
        len(independent_evidence_digests) == 5,
        "hardware assurance reused one evidence artifact for distinct assurance claims",
    )
    return {
        "verified": True,
        "trusted_verifier_key_id": trusted_key_id,
        "hardware_assurance_document_sha256": require_sha256(
            hardware_assurance_document_sha256,
            "hardware assurance document digest",
        ),
        "hardware_assurance_signed_statement_sha256": sha256_prefixed_bytes(
            signed_statement_bytes
        ),
        "verifier": verifier,
        "issued_at_unix": issued_at,
        "expires_at_unix": expires_at,
        "challenge_nonce_sha256": challenge_nonce_sha256,
        "expected_challenge_bound": True,
        "current_host_identity": host_identity,
        "current_host_identity_bound": current_host_identity_bound,
        "attestation_document_sha256": attestation_document_sha256,
        "eif": eif,
        "pcrs": verified_pcrs,
        "release_identity": verified_expected_release_identity,
        "release_identity_sha256": sha256_prefixed_json(verified_expected_release_identity),
        "release_measurements_bound": True,
        "enclave": enclave,
        "key_custody": key_custody,
        "no_parent_key": no_parent_key,
        "release_bindings": release_bindings,
        "artifact_bindings": artifact_bindings,
        "independent_evidence_bound": True,
    }


def completion_assurance(
    hardware_assurance: dict[str, Any] | None,
    current_host: dict[str, Any],
) -> dict[str, Any]:
    current_identity = current_host.get("identity") if isinstance(current_host.get("identity"), dict) else {}
    host_bound = (
        current_host.get("skipped") is False
        and current_host.get("preflight_bound") is True
        and current_host.get("identity_recomputed") is True
        and bool(current_identity)
    )
    if hardware_assurance is None:
        return {
            "level": "pre-enclave-readiness",
            "final_completion": False,
            "hardware_proof": False,
            "hardware_evidence_verified": False,
            "reason": "ordinary Docker, development, or /dev/nsm readiness does not prove enclave execution or key custody",
            "required_final_evidence": list(FINAL_HARDWARE_EVIDENCE),
        }
    require(hardware_assurance.get("verified") is True, "hardware assurance summary is not verified")
    require(
        hardware_assurance.get("expected_challenge_bound") is True,
        "hardware assurance summary is not bound to an externally supplied expected challenge",
    )
    require(
        hardware_assurance.get("release_measurements_bound") is True,
        "hardware assurance summary is not bound to independently verified release measurements",
    )
    if not host_bound:
        return {
            "level": "pre-enclave-readiness",
            "final_completion": False,
            "hardware_proof": False,
            "hardware_evidence_verified": True,
            "reason": "hardware evidence cannot establish final completion while the current-host binding is bypassed",
            "required_final_evidence": ["current host binding without a test-only bypass"],
        }
    hardware_identity = (
        hardware_assurance.get("current_host_identity")
        if isinstance(hardware_assurance.get("current_host_identity"), dict)
        else {}
    )
    require(
        hardware_assurance.get("current_host_identity_bound") is True
        and hardware_identity.get("identity_sha256") == current_identity.get("identity_sha256")
        and hardware_identity.get("boot_id_sha256") == current_identity.get("boot_id_sha256"),
        "hardware assurance is not bound to the recomputed current-host identity",
    )
    return {
        "level": "pre-enclave-readiness",
        "final_completion": False,
        "hardware_proof": False,
        "hardware_evidence_verified": True,
        "reason": (
            "legacy hardware evidence and current-host binding are readiness context "
            "only; final completion requires the independent final-v1 path"
        ),
        "required_final_evidence": [
            "independent Manifest v6 public Nitro verification and protected state",
            "releaseCompletionVerification/v1 external result signature",
        ],
    }


def release_materials(
    evidence: dict[str, Any],
    label: str,
    *,
    nitro_attestation_sha256: str,
) -> dict[str, dict[str, str]]:
    seen: dict[str, dict[str, str]] = {}
    for item in evidence.get("release_materials") or []:
        if not isinstance(item, dict):
            continue
        material = item.get("material")
        require(isinstance(material, str) and material, f"{label} release material entry is missing material")
        require(material not in seen, f"{label} has duplicate release material: {material}")
        kms_request_digest = require_sha256(
            item.get("kms_request_digest"),
            f"{label} material {material} KMS request digest",
        )
        kms = item.get("kms_release") if isinstance(item.get("kms_release"), dict) else {}
        require(kms.get("ok") is True, f"{label} material {material} does not include an ok KMS release")
        require(
            kms.get("request_digest") == kms_request_digest,
            f"{label} material {material} KMS request digest mismatch",
        )
        recipient_ciphertext_sha256 = require_sha256(
            kms.get("recipient_ciphertext_sha256"),
            f"{label} material {material} recipient ciphertext digest",
        )
        require(
            kms.get("material_handle") == recipient_ciphertext_sha256,
            f"{label} material {material} material handle does not match recipient ciphertext digest",
        )
        attestation_document_sha256 = require_sha256(
            kms.get("attestation_document_sha256"),
            f"{label} material {material} KMS Recipient attestation digest",
        )
        require(
            attestation_document_sha256 == nitro_attestation_sha256,
            f"{label} material {material} KMS release attestation digest does not match Nitro evidence",
        )
        key_provider = kms.get("key_provider") if isinstance(kms.get("key_provider"), dict) else {}
        key_id = key_provider.get("key_id")
        require(isinstance(key_id, str) and key_id, f"{label} material {material} does not bind a KMS/HSM key id")
        audit = kms.get("audit") if isinstance(kms.get("audit"), dict) else {}
        ciphertext_blob_sha256 = kms.get("ciphertext_blob_sha256") or audit.get("ciphertext_blob_sha256")
        encryption_context_sha256 = kms.get("encryption_context_sha256") or audit.get("encryption_context_sha256")
        seen[material] = {
            "material": material,
            "key_id_sha256": sha256_prefixed_bytes(key_id.encode("utf-8")),
            "kms_request_digest": kms_request_digest,
            "recipient_ciphertext_sha256": recipient_ciphertext_sha256,
            "attestation_document_sha256": attestation_document_sha256,
            "ciphertext_blob_sha256": require_sha256(
                ciphertext_blob_sha256,
                f"{label} material {material} input ciphertext digest",
            ),
            "encryption_context_sha256": require_sha256(
                encryption_context_sha256,
                f"{label} material {material} encryption context digest",
            ),
        }
    return seen


def verify_nitro_evidence(evidence: dict[str, Any], label: str) -> dict[str, Any]:
    assert_no_secret_fields(evidence)
    require(evidence.get("apiVersion") == "serverware.nitroKmsEvidence/v1", f"{label} has wrong apiVersion")
    require(evidence.get("ok") is True, f"{label} is not ok")
    require(evidence.get("provider") == "aws-nitro-enclaves", f"{label} does not prove AWS Nitro")
    require(evidence.get("tee_platform") == "aws-nitro", f"{label} does not prove aws-nitro platform")
    nitro = evidence.get("nitro") if isinstance(evidence.get("nitro"), dict) else {}
    require(nitro.get("verified") is True, f"{label} Nitro metadata is not verified")
    require(nitro.get("debug") is False, f"{label} Nitro metadata is debug")
    raw_attestation_document_sha256 = require_sha256(
        nitro.get("raw_attestation_document_sha256"),
        f"{label} raw attestation digest",
    )
    materials = release_materials(
        evidence,
        label,
        nitro_attestation_sha256=raw_attestation_document_sha256,
    )
    require(REQUIRED_MATERIALS.issubset(materials), f"{label} does not prove all required materials")
    redaction = evidence.get("redaction") if isinstance(evidence.get("redaction"), dict) else {}
    require(redaction.get("plaintext_material") == "rejected", f"{label} does not document plaintext material rejection")
    config = evidence.get("config") if isinstance(evidence.get("config"), dict) else {}
    require(config.get("kms_command_required") is True, f"{label} did not require the KMS/HSM release command")
    require(config.get("fixtures_allowed_for_test") is not True, f"{label} was collected with fixtures allowed")
    command_hashes = {
        "attestation_command_sha256": require_sha256(
            config.get("attestation_command_sha256"),
            f"{label} attestation command digest",
        ),
        "kms_release_command_sha256": require_sha256(
            config.get("kms_release_command_sha256"),
            f"{label} KMS release command digest",
        ),
    }
    claims = evidence.get("claims") if isinstance(evidence.get("claims"), dict) else {}
    claim_fields = claims.get("fields") if isinstance(claims.get("fields"), dict) else {}
    attested_runtime = {
        "policy_digest": require_sha256(
            claim_fields.get("policy_bundle_digest"),
            f"{label} attested policy bundle digest",
        ),
        "policy_sequence": claim_fields.get("policy_sequence"),
        "policy_high_water_digest": require_sha256(
            claim_fields.get("policy_high_water_digest"),
            f"{label} attested policy high-water digest",
        ),
        "runtime_manifest_digest": require_sha256(
            claim_fields.get("runtime_manifest_digest"),
            f"{label} attested runtime manifest digest",
        ),
        "data_plane_binary_digest": require_sha256(
            claim_fields.get("data_plane_binary_digest"),
            f"{label} attested data-plane binary digest",
        ),
        "provenance_digest": require_sha256(
            claim_fields.get("provenance_digest"),
            f"{label} attested release provenance digest",
        ),
        "source_tree_digest": require_sha256(
            claim_fields.get("source_tree_digest"),
            f"{label} attested source tree digest",
        ),
        "response_signing_key_id": require_sha256(
            claim_fields.get("response_signing_key_id"),
            f"{label} attested response signing key id",
        ),
    }
    require(claim_fields.get("debug") is False, f"{label} attested runtime claims are debug")
    require(
        isinstance(attested_runtime["policy_sequence"], int)
        and not isinstance(attested_runtime["policy_sequence"], bool)
        and attested_runtime["policy_sequence"] > 0,
        f"{label} attested policy sequence is invalid",
    )
    require(
        isinstance(claim_fields.get("release_channel"), str) and bool(claim_fields.get("release_channel")),
        f"{label} attested runtime claims omit release channel",
    )
    return {
        "provider": evidence.get("provider"),
        "tee_platform": evidence.get("tee_platform"),
        "assurance_level": "pre-enclave-readiness",
        "hardware_proof": False,
        "materials": sorted(REQUIRED_MATERIALS),
        "material_key_ids": {material: materials[material]["key_id_sha256"] for material in sorted(REQUIRED_MATERIALS)},
        "material_bindings": {
            material: {
                "key_id_sha256": materials[material]["key_id_sha256"],
                "ciphertext_blob_sha256": materials[material]["ciphertext_blob_sha256"],
                "encryption_context_sha256": materials[material]["encryption_context_sha256"],
            }
            for material in sorted(REQUIRED_MATERIALS)
        },
        "material_release_receipts": {
            material: {
                "kms_request_digest": materials[material]["kms_request_digest"],
                "recipient_ciphertext_sha256": materials[material]["recipient_ciphertext_sha256"],
                "attestation_document_sha256": materials[material]["attestation_document_sha256"],
            }
            for material in sorted(REQUIRED_MATERIALS)
        },
        "command_hashes": command_hashes,
        "raw_attestation_document_sha256": raw_attestation_document_sha256,
        "attested_runtime": attested_runtime,
    }


def verify_readiness(readiness: dict[str, Any]) -> dict[str, Any]:
    assert_no_secret_fields(readiness)
    require(readiness.get("ok") is True, "production readiness is not ok")
    require(readiness.get("production_readiness") == "pass", "production readiness did not pass")
    require(readiness.get("mode") == "live", "production readiness must be a live-mode result")
    checks = set(readiness.get("checks") or [])
    require(REQUIRED_READINESS_CHECKS.issubset(checks), "production readiness omitted required checks")
    environment = verify_readiness_environment(readiness.get("environment"), "production readiness")
    live = readiness.get("live")
    require(isinstance(live, dict), "production readiness is missing live probe results")

    sigstore = live.get("sigstore") if isinstance(live.get("sigstore"), dict) else {}
    require(sigstore.get("ok") is True, "live Sigstore probe did not pass")
    require_sha256(sigstore.get("key_id"), "live Sigstore key id")
    require_sha256(sigstore.get("transparency_log_id"), "live Sigstore/Rekor log id")

    transparency = live.get("external_transparency") if isinstance(live.get("external_transparency"), dict) else {}
    require(transparency.get("ok") is True, "live external transparency probe did not pass")
    require(bool(transparency.get("provider")), "live external transparency probe did not bind provider")
    require_sha256(transparency.get("log_id"), "live external transparency log id")

    stores = live.get("shared_stores") if isinstance(live.get("shared_stores"), dict) else {}
    require(stores.get("ok") is True, "live shared-store probe did not pass")
    store_results = stores.get("stores") if isinstance(stores.get("stores"), dict) else {}
    require(REQUIRED_STORES.issubset(set(store_results)), "live shared-store probe omitted required stores")
    for label in REQUIRED_STORES:
        result = store_results.get(label) if isinstance(store_results.get(label), dict) else {}
        require(result.get("ok") is True, f"live {label} store probe did not pass")
        require(bool(result.get("tables")), f"live {label} store probe did not list required tables")

    nitro_summary = verify_nitro_evidence(live.get("nitro") if isinstance(live.get("nitro"), dict) else {}, "readiness Nitro evidence")

    images = live.get("production_images_no_shell") if isinstance(live.get("production_images_no_shell"), dict) else {}
    require(images.get("ok") is True, "production image no-shell probe did not pass")
    require(bool(images.get("images")), "production image no-shell probe did not list images")
    production_image_digests: list[str] = []
    for image in images.get("images") or []:
        require(isinstance(image, str) and "@sha256:" in image, f"production image was not digest-pinned: {image}")
        production_image_digests.append("sha256:" + image.rsplit("@sha256:", 1)[1])

    apparmor = live.get("apparmor") if isinstance(live.get("apparmor"), dict) else {}
    require(apparmor.get("ok") is True, "AppArmor live probe did not pass")

    return {
        "checks": sorted(checks),
        "environment": environment,
        "sigstore_key_id": sigstore.get("key_id"),
        "rekor_log_id": sigstore.get("transparency_log_id"),
        "external_transparency_provider": transparency.get("provider"),
        "external_transparency_log_id": transparency.get("log_id"),
        "nitro": nitro_summary,
        "production_images": images.get("images"),
        "production_image_digests": sorted(production_image_digests),
    }


def verify_readiness_environment(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} is missing redacted environment evidence")
    require(value.get("secret_values_redacted") is True, f"{label} environment evidence is not redacted")
    env_keys = value.get("env_keys")
    require(isinstance(env_keys, list), f"{label} environment keys must be a list")
    require("SERVERWARE_PRODUCTION_IMAGES" in env_keys, f"{label} environment did not include production images")
    production_readiness_env_sha256 = require_sha256(
        value.get("production_readiness_env_sha256"),
        f"{label} production readiness env digest",
    )
    production_images_env_sha256 = require_sha256(
        value.get("production_images_env_sha256"),
        f"{label} production images env digest",
    )
    return {
        "env_keys": sorted(str(key) for key in env_keys),
        "production_readiness_env_sha256": production_readiness_env_sha256,
        "production_images_env_sha256": production_images_env_sha256,
        "secret_values_redacted": True,
    }


def verify_production_config_result(config: dict[str, Any], preflight_summary: dict[str, Any]) -> dict[str, Any]:
    assert_no_secret_fields(config)
    require(config.get("ok") is True, "production config gate artifact is not ok")
    require(config.get("production_readiness") == "pass", "production config gate artifact did not pass")
    require(config.get("mode") == "config", "production config gate artifact must be config mode")
    checks = set(config.get("checks") or [])
    require(REQUIRED_READINESS_CHECKS.issubset(checks), "production config gate artifact omitted required checks")
    require(config.get("live") is None, "production config gate artifact must not contain live probe results")
    environment = verify_readiness_environment(config.get("environment"), "production config gate")
    require(
        environment["production_readiness_env_sha256"] == preflight_summary["production_readiness_env_sha256"],
        "production config gate env digest does not match production host preflight",
    )
    require(
        environment["production_images_env_sha256"] == preflight_summary["production_images_env_sha256"],
        "production config gate image env digest does not match production host preflight",
    )
    semantic_sha256 = semantic_result_digest(config)
    require(
        semantic_sha256 == preflight_summary["production_config_semantic_sha256"],
        "production config gate artifact does not match production host preflight config gate",
    )
    return {
        "mode": "config",
        "checks": sorted(checks),
        "environment": environment,
        "semantic_sha256": semantic_sha256,
        "preflight_config_bound": True,
    }


def external_checkpoint_binding(
    transparency: dict[str, Any],
    *,
    anchor_key: str,
    expected_provider: str,
    expected_log_id: str,
    trusted_public_key_pem: str,
    expected_checkpoint_sha256: str,
    label: str,
) -> dict[str, Any]:
    anchor_response = transparency.get(anchor_key) if isinstance(transparency.get(anchor_key), dict) else {}
    anchors = anchor_response.get("anchors") if isinstance(anchor_response.get("anchors"), list) else []
    checkpoints = [
        item.get("external_checkpoint")
        for item in anchors
        if isinstance(item, dict) and isinstance(item.get("external_checkpoint"), dict)
    ]
    require(checkpoints, f"{label} transparency anchor is missing external checkpoint evidence")
    checkpoint = checkpoints[0]
    require(checkpoint.get("ok") is True, f"{label} external transparency checkpoint did not pass")
    provider = checkpoint.get("provider")
    log_id = require_sha256(checkpoint.get("log_id"), f"{label} external transparency log id")
    require(provider == expected_provider, f"{label} external transparency provider does not match live readiness")
    require(log_id == expected_log_id, f"{label} external transparency log does not match live readiness")
    verified = verify_external_checkpoint_receipt(
        checkpoint,
        expected_provider=expected_provider,
        expected_log_id=expected_log_id,
        trusted_public_key_pem=trusted_public_key_pem,
        expected_fields={},
        label=label,
    )
    require(
        verified["checkpoint_sha256"] == expected_checkpoint_sha256,
        f"{label} used a different external checkpoint than the receipt binding its release record",
    )
    return verified


def transparency_record_binding(
    transparency: dict[str, Any],
    *,
    anchor_key: str,
    inclusion_key: str,
    expected_type: str,
    expected_fields: dict[str, Any],
    expected_external_provider: str,
    expected_external_log_id: str,
    trusted_external_public_key_pem: str,
    label: str,
) -> dict[str, Any]:
    record = transparency.get("record") if isinstance(transparency.get("record"), dict) else {}
    require(record, f"{label} transparency record is missing")
    require(record.get("type") == expected_type, f"{label} transparency record type mismatch")
    for key, expected in expected_fields.items():
        require(record.get(key) == expected, f"{label} transparency record {key} mismatch")
    record_digest = sha256_prefixed_json(record)

    inclusion = transparency.get(inclusion_key) if isinstance(transparency.get(inclusion_key), dict) else {}
    require(inclusion.get("verified") is True, f"{label} transparency inclusion proof was not verified")
    require(inclusion.get("record_digest") == record_digest, f"{label} transparency inclusion record digest mismatch")
    item = inclusion.get("item") if isinstance(inclusion.get("item"), dict) else {}
    require(item.get("record") == record, f"{label} transparency inclusion returned the wrong record")
    require(item.get("record_digest") == record_digest, f"{label} transparency inclusion item digest mismatch")
    expected_leaf_hash = transparency_leaf_hash(item)
    require(item.get("leaf_hash") == expected_leaf_hash, f"{label} transparency inclusion leaf payload mismatch")
    require(inclusion.get("leaf_hash") == expected_leaf_hash, f"{label} transparency inclusion leaf hash mismatch")
    tree_size = require_bounded_uint(
        inclusion.get("tree_size"),
        f"{label} transparency tree size",
        minimum=1,
    )
    tree_head_hash = require_sha256(inclusion.get("tree_head_hash"), f"{label} transparency tree head")
    proof = inclusion.get("proof")
    require(isinstance(proof, list), f"{label} transparency inclusion proof must be a list")
    require(verify_merkle_inclusion(expected_leaf_hash, proof, tree_head_hash), f"{label} transparency Merkle inclusion proof did not verify")
    signed_tree_head = inclusion.get("signed_tree_head") if isinstance(inclusion.get("signed_tree_head"), dict) else {}
    verify_signed_tree_head(signed_tree_head, root=tree_head_hash, tree_size=tree_size, label=label)

    anchor_response = transparency.get(anchor_key) if isinstance(transparency.get(anchor_key), dict) else {}
    anchors = anchor_response.get("anchors") if isinstance(anchor_response.get("anchors"), list) else []
    matching_anchor = next(
        (item for item in anchors if isinstance(item, dict) and item.get("record_digest") == record_digest),
        None,
    )
    require(matching_anchor is not None, f"{label} transparency anchor response did not bind record digest")
    require(matching_anchor.get("leaf_hash") == expected_leaf_hash, f"{label} transparency anchor leaf hash mismatch")
    require(matching_anchor.get("tree_head_hash") == tree_head_hash, f"{label} transparency anchor tree head mismatch")
    require(
        require_bounded_uint(
            matching_anchor.get("tree_size"),
            f"{label} transparency anchor tree size",
            minimum=1,
        )
        == tree_size,
        f"{label} transparency anchor tree size mismatch",
    )
    anchor_sth = matching_anchor.get("signed_tree_head") if isinstance(matching_anchor.get("signed_tree_head"), dict) else {}
    require(anchor_sth == signed_tree_head, f"{label} transparency anchor signed tree head mismatch")
    checkpoint = matching_anchor.get("external_checkpoint") if isinstance(matching_anchor.get("external_checkpoint"), dict) else {}
    item_checkpoint = item.get("external_checkpoint") if isinstance(item.get("external_checkpoint"), dict) else {}
    require(item_checkpoint, f"{label} transparency inclusion item is missing its external checkpoint")
    require(
        item_checkpoint == checkpoint,
        f"{label} transparency inclusion and anchor response used different external checkpoints",
    )
    verified_checkpoint = verify_external_checkpoint_receipt(
        checkpoint,
        expected_provider=expected_external_provider,
        expected_log_id=expected_external_log_id,
        trusted_public_key_pem=trusted_external_public_key_pem,
        expected_fields={
            "record_digest": record_digest,
            "leaf_hash": expected_leaf_hash,
            "tree_head_hash": tree_head_hash,
            "tree_size": tree_size,
        },
        label=label,
    )
    return {
        "record_digest": record_digest,
        "leaf_hash": expected_leaf_hash,
        "tree_head_hash": tree_head_hash,
        "external_checkpoint": verified_checkpoint,
    }


def verified_reproducible_builder_identities(
    value: Any,
    label: str,
) -> list[dict[str, str]]:
    require(
        isinstance(value, list) and len(value) == 2,
        f"{label} must contain exactly two builders",
    )
    builders: list[dict[str, str]] = []
    for index, item in enumerate(value):
        require_exact_keys(item, {"builder_id", "key_id"}, f"{label}[{index}]")
        builder_id = item.get("builder_id")
        require(
            isinstance(builder_id, str) and bool(builder_id),
            f"{label}[{index}] builder_id is invalid",
        )
        builders.append(
            {
                "builder_id": builder_id,
                "key_id": require_sha256(
                    item.get("key_id"),
                    f"{label}[{index}] key_id",
                ),
            }
        )
    require(
        len({item["builder_id"] for item in builders}) == 2,
        f"{label} builder identities must be independent",
    )
    require(
        len({item["key_id"] for item in builders}) == 2,
        f"{label} builder signing keys must be independent",
    )
    return builders


def verify_release_provenance(
    summary: dict[str, Any],
    document: dict[str, Any],
    expected_external_provider: str,
    expected_external_log_id: str,
    trusted_release_public_key_pem: str,
    trusted_external_public_key_pem: str,
) -> dict[str, Any]:
    require(summary.get("ok") is True and summary.get("release_provenance") == "pass", "release provenance summary did not pass")
    require(summary.get("anchored") is True, "release provenance was not anchored")
    require(summary.get("inclusion_verified") is True, "release provenance inclusion proof was not verified")
    provenance = document.get("provenance")
    require(isinstance(provenance, dict), "release provenance document is missing provenance")
    require(
        provenance.get("version") == 2,
        "production release provenance payload must use version 2",
    )
    require(
        provenance.get("source") == "serverware-digest-pinned-production-release",
        "release provenance was not generated in digest-pinned production mode",
    )
    launch_authority = require_launch_authority_binding(
        provenance.get("launch_authority"),
        "release provenance launch authority",
    )
    require(
        require_launch_authority_binding(
            (provenance.get("images") or {}).get("serverware-decision-gate"),
            "release provenance decision-gate image",
        )
        == launch_authority,
        "release provenance decision-gate launch-authority binding mismatch",
    )
    reproducible_build = provenance.get("reproducible_build")
    require(
        isinstance(reproducible_build, dict)
        and reproducible_build.get("apiVersion")
        == REPRODUCIBLE_BUILD_VERIFICATION_API_VERSION
        and reproducible_build.get("kind") == "ReproducibleBuildVerification",
        "release provenance reproducible-build binding uses an unsupported contract",
    )
    reproducible_build_verification_sha256 = require_sha256(
        reproducible_build.get("verification_sha256"),
        "release provenance reproducible-build verification digest",
    )
    require(
        summary.get("reproducible_build_verification_sha256")
        == reproducible_build_verification_sha256,
        "release provenance summary reproducible-build digest mismatch",
    )
    require(
        require_launch_authority_binding(
            reproducible_build,
            "release provenance reproducible-build evidence",
        )
        == launch_authority,
        "release provenance reproducible-build launch-authority binding mismatch",
    )
    reproducible_builders = verified_reproducible_builder_identities(
        reproducible_build.get("builders"),
        "release provenance reproducible-build builders",
    )
    require(
        all(summary.get(field) == launch_authority[field] for field in LAUNCH_AUTHORITY_BINDING_FIELDS),
        "release provenance summary launch-authority binding mismatch",
    )
    digest = require_sha256(document.get("provenance_digest"), "release provenance digest")
    require(summary.get("provenance_digest") == digest, "release provenance summary digest mismatch")
    require(sha256_prefixed_json(provenance) == digest, "release provenance payload digest mismatch")
    signature = document.get("signature")
    public_key_pem = document.get("release_signing_public_key_pem")
    require(isinstance(signature, str) and signature, "release provenance document is missing signature")
    require(isinstance(public_key_pem, str) and public_key_pem, "release provenance document is missing signing public key")
    release_signing_key_id = require_sha256(document.get("release_signing_key_id"), "release signing key id")
    require(summary.get("release_signing_key_id") == release_signing_key_id, "release provenance summary signing key mismatch")
    trusted_release_signing_key_id = release_public_key_id(trusted_release_public_key_pem)
    require(
        release_signing_key_id == trusted_release_signing_key_id,
        "release provenance signer does not match the independently trusted release key",
    )
    require(
        release_public_key_id(public_key_pem) == trusted_release_signing_key_id,
        "release provenance embedded signing key is not the independently trusted release key",
    )
    verify_ed25519(
        trusted_release_public_key_pem,
        signature,
        canonical_json(provenance).encode("utf-8"),
        "release provenance",
    )
    transparency = document.get("transparency") if isinstance(document.get("transparency"), dict) else {}
    inclusion_proof = transparency.get("inclusion_proof") if isinstance(transparency.get("inclusion_proof"), dict) else {}
    anchor_response = transparency.get("anchor_response") if isinstance(transparency.get("anchor_response"), dict) else {}
    require(
        transparency.get("inclusion_verified") is True or bool(inclusion_proof) or anchor_response.get("accepted"),
        "release provenance document is missing verified transparency inclusion evidence",
    )
    release_record = transparency_record_binding(
        transparency,
        anchor_key="anchor_response",
        inclusion_key="inclusion_proof",
        expected_type=RELEASE_PROVENANCE_RECORD_TYPE,
        expected_fields={
            "provenance_digest": digest,
            "signature": signature,
            "release_signing_key_id": release_signing_key_id,
            "production_launcher_binary_digest": require_sha256(
                ((provenance.get("images") or {}).get("serverware-decision-gate") or {}).get(
                    "launcher_binary_digest"
                ),
                "release provenance production launcher binary digest",
            ),
            **launch_authority,
            "reproducible_build_verification_sha256": (
                reproducible_build_verification_sha256
            ),
        },
        expected_external_provider=expected_external_provider,
        expected_external_log_id=expected_external_log_id,
        trusted_external_public_key_pem=trusted_external_public_key_pem,
        label="release provenance",
    )
    external_transparency = external_checkpoint_binding(
        transparency,
        anchor_key="anchor_response",
        expected_provider=expected_external_provider,
        expected_log_id=expected_external_log_id,
        trusted_public_key_pem=trusted_external_public_key_pem,
        expected_checkpoint_sha256=release_record["external_checkpoint"]["checkpoint_sha256"],
        label="release provenance",
    )
    source_tree = provenance.get("source_tree") if isinstance(provenance.get("source_tree"), dict) else {}
    provenance_images = provenance.get("images")
    require(
        isinstance(provenance_images, dict)
        and set(provenance_images)
        == {"serverware-control", "serverware-decision-gate"},
        "release provenance must bind exactly both production image identities",
    )
    image_config_ids: dict[str, str] = {}
    for service in ("serverware-control", "serverware-decision-gate"):
        image = provenance_images.get(service)
        require(isinstance(image, dict), f"release provenance {service} image is invalid")
        require_sha256(
            image.get("image_id"),
            f"release provenance {service} registry manifest digest",
        )
        local_config_id = require_sha256(
            image.get("local_build_image_id"),
            f"release provenance {service} local config id",
        )
        remote_config_id = require_sha256(
            image.get("remote_image_id"),
            f"release provenance {service} remote config id",
        )
        approved_config_id = require_sha256(
            image.get("config_id"),
            f"release provenance {service} approved config id",
        )
        require(
            hmac.compare_digest(local_config_id, remote_config_id)
            and hmac.compare_digest(local_config_id, approved_config_id),
            f"release provenance {service} local, remote, and approved config IDs differ",
        )
        image_config_ids[service] = approved_config_id
    compose_config_sha256 = require_sha256(
        provenance.get("compose_config_sha256"),
        "release provenance compose config digest",
    )
    compose = provenance.get("compose") if isinstance(provenance.get("compose"), dict) else {}
    require(
        compose.get("sha256") == compose_config_sha256,
        "release provenance Compose summary digest does not match its rendered config digest",
    )
    require(
        Path(str(compose.get("file") or "")).name == "docker-compose.production.yml",
        "release provenance did not bind docker-compose.production.yml",
    )
    sbom = provenance.get("sbom") if isinstance(provenance.get("sbom"), dict) else {}
    cyclonedx = sbom.get("cyclonedx") if isinstance(sbom.get("cyclonedx"), dict) else {}
    sbom_components = cyclonedx.get("components")
    require(isinstance(sbom_components, int) and sbom_components > 0, "release provenance CycloneDX SBOM component count is invalid")
    production_launcher_binary_digest = require_sha256(
        ((provenance.get("images") or {}).get("serverware-decision-gate") or {}).get(
            "launcher_binary_digest"
        ),
        "release provenance production launcher binary digest",
    )
    require(
        summary.get("production_launcher_binary_digest")
        == production_launcher_binary_digest,
        "release provenance summary production launcher digest mismatch",
    )
    return {
        "provenance_digest": digest,
        "release_signing_key_id": release_signing_key_id,
        "transparency_mode": summary.get("transparency_mode"),
        "external_transparency": external_transparency,
        "transparency_record_digest": release_record["record_digest"],
        "source_tree_digest": require_sha256(source_tree.get("digest"), "release provenance source tree digest"),
        "compose_config_sha256": compose_config_sha256,
        "sbom_cyclonedx_sha256": require_sha256(cyclonedx.get("sha256"), "release provenance CycloneDX SBOM digest"),
        "sbom_cyclonedx_components": sbom_components,
        "production_launcher_binary_digest": production_launcher_binary_digest,
        "launch_authority": launch_authority,
        "image_config_ids": image_config_ids,
        "reproducible_build_builders": reproducible_builders,
        "reproducible_build_verification_sha256": (
            reproducible_build_verification_sha256
        ),
    }


def verify_production_image_build(build: dict[str, Any], source_tree_digest: str) -> dict[str, Any]:
    assert_no_secret_fields(build)
    require(
        build.get("apiVersion") == PRODUCTION_IMAGES_BUILD_API_VERSION
        and build.get("kind") == "ProductionImagesBuild",
        f"production image build artifact must use {PRODUCTION_IMAGES_BUILD_API_VERSION}",
    )
    require(build.get("ok") is True, "production image build artifact is not ok")
    no_shell = build.get("no_shell") if isinstance(build.get("no_shell"), dict) else {}
    require(no_shell.get("ok") is True, "production image build artifact did not pass no-shell verification")
    metadata = build.get("metadata") if isinstance(build.get("metadata"), dict) else {}
    launch_authority = require_launch_authority_binding(
        metadata,
        "production image build metadata",
    )
    build_source_tree_digest = require_sha256(metadata.get("source_tree_digest"), "production image build source tree digest")
    require(
        build_source_tree_digest == source_tree_digest,
        "production image build source tree digest does not match release provenance",
    )
    images = build.get("images")
    require(isinstance(images, list) and images, "production image build artifact has no images")
    normalized = []
    seen_services: set[str] = set()
    for image in images:
        require(isinstance(image, dict), "production image build entry must be an object")
        service = image.get("service")
        require(isinstance(service, str) and service, "production image build entry is missing service")
        require(service not in seen_services, f"duplicate production image build service: {service}")
        seen_services.add(service)
        binary_digest = None
        launcher_binary_digest = None
        if service == "serverware-decision-gate":
            binary_digest = require_sha256(
                image.get("binary_digest"),
                "serverware-decision-gate production image binary digest",
            )
            launcher_binary_digest = require_sha256(
                image.get("launcher_binary_digest"),
                "serverware production launcher binary digest",
            )
            require(
                require_launch_authority_binding(
                    image,
                    "serverware-decision-gate production image",
                )
                == launch_authority,
                "production image launch-authority binding does not match build metadata",
            )
        normalized.append(
            {
                "service": service,
                "image_id": require_sha256(
                    image.get("image_id"),
                    f"{service} image config id",
                ),
                "dockerfile": image.get("dockerfile"),
                "tag": image.get("tag"),
                **({"binary_digest": binary_digest} if binary_digest else {}),
                **(
                    {"launcher_binary_digest": launcher_binary_digest}
                    if launcher_binary_digest
                    else {}
                ),
            }
        )
    require(
        "serverware-decision-gate" in seen_services,
        "production image build artifact is missing the decision gate",
    )
    return {
        "source_tree_digest": build_source_tree_digest,
        "images": normalized,
        "no_shell": "pass",
        "launch_authority": launch_authority,
    }


def verify_published_images(
    published: dict[str, Any],
    build_summary: dict[str, Any],
    readiness_image_refs: list[str],
) -> dict[str, Any]:
    assert_no_secret_fields(published)
    require(
        published.get("apiVersion") == PRODUCTION_IMAGES_PUBLISHED_API_VERSION
        and published.get("kind") == "ProductionImagesPublished",
        f"published production images artifact must use {PRODUCTION_IMAGES_PUBLISHED_API_VERSION}",
    )
    require(published.get("ok") is True, "production images published artifact is not ok")
    build_by_service = {item["service"]: item for item in build_summary["images"]}
    remote_no_shell = published.get("remote_no_shell")
    require(
        isinstance(remote_no_shell, dict) and remote_no_shell.get("ok") is True,
        "published production images did not pass remote no-shell verification",
    )
    expected_refs = sorted(readiness_image_refs)
    images = published.get("images")
    require(isinstance(images, list) and images, "production images published artifact has no images")
    published_refs: list[str] = []
    published_digests: list[str] = []
    published_services: list[str] = []
    config_ids: dict[str, str] = {}
    for image in images:
        require(isinstance(image, dict), "published image entry must be an object")
        service = image.get("service")
        require(isinstance(service, str) and service, "published image entry is missing service")
        local_image_id = require_sha256(image.get("local_image_id"), f"{service} published local image id")
        require(service in build_by_service, f"published image service is not in current build artifact: {service}")
        require(
            local_image_id == build_by_service[service]["image_id"],
            "published production images do not match current no-shell build",
        )
        remote_image_id = require_sha256(
            image.get("remote_image_id"),
            f"{service} published remote config id",
        )
        config_id = require_sha256(
            image.get("config_id"),
            f"{service} published approved config id",
        )
        require(
            hmac.compare_digest(local_image_id, remote_image_id)
            and hmac.compare_digest(local_image_id, config_id),
            f"published {service} local, remote, and approved config IDs must be identical",
        )
        config_ids[service] = config_id
        if service == "serverware-decision-gate":
            require(
                require_sha256(image.get("binary_digest"), "published decision-gate binary digest")
                == build_by_service[service]["binary_digest"],
                "published decision-gate executable does not match the measured build executable",
            )
            require(
                require_sha256(
                    image.get("launcher_binary_digest"),
                    "published production launcher binary digest",
                )
                == build_by_service[service]["launcher_binary_digest"],
                "published production launcher does not match the measured build launcher",
            )
            require(
                require_launch_authority_binding(
                    image,
                    "published decision-gate image",
                )
                == build_summary["launch_authority"],
                "published decision-gate launch-authority binding does not match the measured build",
            )
        repo_digest, digest = require_image_ref(image.get("repo_digest"), f"{service} published repo digest")
        published_refs.append(repo_digest)
        published_digests.append(digest)
        published_services.append(service)
    require(
        sorted(published_services) == sorted(build_by_service),
        "published production image services do not match current build artifact",
    )
    require(sorted(published_refs) == expected_refs, "published production image refs do not match live readiness images")
    env_value = published.get("env") if isinstance(published.get("env"), dict) else {}
    if env_value.get("SERVERWARE_PRODUCTION_IMAGES"):
        require(
            sorted(item.strip() for item in str(env_value["SERVERWARE_PRODUCTION_IMAGES"]).split(",") if item.strip())
            == expected_refs,
            "published artifact env value does not match live readiness images",
        )
    return {
        "services": sorted(published_services),
        "repo_digests": sorted(published_refs),
        "image_digests": sorted(published_digests),
        "source_build_file": published.get("source_build_file"),
        "launch_authority": build_summary["launch_authority"],
        "config_ids": config_ids,
    }


def normalized_image_signature_payload(document: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(document))
    copied.pop("image_signature_bundle_digest", None)
    copied.pop("bundle_signature", None)
    metadata = copied.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("signature", None)
        metadata.pop("transparency", None)
        metadata.pop("bundleSigstore", None)
    return copied


def verify_image_signatures(
    summary: dict[str, Any],
    document: dict[str, Any],
    provenance: dict[str, Any],
    expected_image_digests: list[str],
    expected_image_refs: list[str],
    expected_sigstore_key_id: str,
    expected_rekor_log_id: str,
    expected_external_provider: str,
    expected_external_log_id: str,
    trusted_sigstore_public_key_pem: str,
    trusted_rekor_public_key_pem: str,
    trusted_external_public_key_pem: str,
) -> dict[str, Any]:
    provenance_digest = str(provenance["provenance_digest"])
    require(summary.get("ok") is True and summary.get("image_signatures") == "pass", "image signatures summary did not pass")
    require(summary.get("image_signature_provider") == "sigstore-command", "image signatures did not use sigstore-command")
    require(summary.get("inclusion_verified") is True, "image signature bundle inclusion proof was not verified")
    require(summary.get("provenance_digest") == provenance_digest, "image signatures summary provenance digest mismatch")
    release_signing_key_id = require_sha256(provenance.get("release_signing_key_id"), "release signing key id")
    require(summary.get("release_signing_key_id") == release_signing_key_id, "image signatures summary release signing key mismatch")
    image_signing_key_id = require_sha256(summary.get("image_signing_key_id"), "image signing key id")
    require(image_signing_key_id == expected_sigstore_key_id, "image signing key does not match live Sigstore key")
    require(
        release_public_key_id(trusted_sigstore_public_key_pem) == image_signing_key_id,
        "image signing key does not match the independently trusted Sigstore key",
    )
    require(
        release_public_key_id(trusted_rekor_public_key_pem) == expected_rekor_log_id,
        "live Rekor log does not match the independently trusted Rekor key",
    )
    digest = require_sha256(document.get("image_signature_bundle_digest"), "image signature bundle digest")
    require(summary.get("image_signature_bundle_digest") == digest, "image signature summary digest mismatch")
    normalized_payload = normalized_image_signature_payload(document)
    require(sha256_prefixed_json(normalized_payload) == digest, "image signature bundle payload digest mismatch")
    require(document.get("apiVersion") == "serverware.imageSignatures/v1", "image signature bundle has wrong apiVersion")
    images = document.get("images")
    require(isinstance(images, list) and images, "image signature bundle has no images")
    require(summary.get("images") == len(images), "image signature summary image count mismatch")
    signed_image_digests: list[str] = []
    signed_image_map: dict[str, str] = {}
    signed_repo_digests: list[str] = []
    transparency_log_ids: list[str] = []
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    require(metadata.get("provenanceDigest") == provenance_digest, "image signature metadata provenance digest mismatch")
    require(metadata.get("releaseSigningKeyId") == release_signing_key_id, "image signature metadata release signing key mismatch")
    require(metadata.get("sourceTreeDigest") == provenance["source_tree_digest"], "image signature metadata source tree digest mismatch")
    require(metadata.get("composeConfigSha256") == provenance["compose_config_sha256"], "image signature metadata compose config digest mismatch")
    require(metadata.get("sbomCyclonedxSha256") == provenance["sbom_cyclonedx_sha256"], "image signature metadata SBOM digest mismatch")
    require(metadata.get("sigstoreTransparencyRequired") is True, "image signature metadata does not require transparency")
    bundle_sigstore = document.get("bundle_signature") if isinstance(document.get("bundle_signature"), dict) else {}
    metadata_bundle_sigstore = metadata.get("bundleSigstore") if isinstance(metadata.get("bundleSigstore"), dict) else {}
    require(bundle_sigstore, "image signature bundle is missing Sigstore signature")
    require(metadata_bundle_sigstore == bundle_sigstore, "image signature metadata bundle Sigstore proof mismatch")
    require(bundle_sigstore.get("ok") is True, "image signature bundle Sigstore proof did not pass")
    require(bool(bundle_sigstore.get("signature")), "image signature bundle Sigstore proof is missing signature")
    require(metadata.get("signature") == bundle_sigstore.get("signature"), "image signature metadata signature mismatch")
    require(bundle_sigstore.get("statement_digest") == digest, "image signature bundle Sigstore statement digest mismatch")
    bundle_key_provider = bundle_sigstore.get("key_provider") if isinstance(bundle_sigstore.get("key_provider"), dict) else {}
    require(bundle_key_provider.get("key_id") == image_signing_key_id, "image signature bundle Sigstore signing key mismatch")
    bundle_sigstore_transparency = bundle_sigstore.get("transparency") if isinstance(bundle_sigstore.get("transparency"), dict) else {}
    bundle_rekor_log_id = require_sha256(bundle_sigstore_transparency.get("log_id"), "image signature bundle transparency log id")
    require(bundle_rekor_log_id == expected_rekor_log_id, "image signature bundle transparency log does not match live Rekor log")
    require(bool(bundle_sigstore_transparency.get("inclusion_proof")), "image signature bundle has no transparency inclusion proof")
    verify_sigstore_bundle_binding(
        bundle_sigstore,
        expected_statement=normalized_payload,
        expected_statement_digest=digest,
        expected_signature=str(bundle_sigstore.get("signature")),
        trusted_signing_public_key_pem=trusted_sigstore_public_key_pem,
        expected_signing_key_id=image_signing_key_id,
        expected_rekor_log_id=expected_rekor_log_id,
        trusted_rekor_public_key_pem=trusted_rekor_public_key_pem,
        label="image signature bundle",
    )
    transparency_log_ids.append(bundle_rekor_log_id)
    metadata_transparency = metadata.get("transparency") if isinstance(metadata.get("transparency"), dict) else {}
    for image in images:
        require(isinstance(image, dict), "image signature entry must be an object")
        service = image.get("service")
        require(isinstance(service, str) and service, "image signature entry is missing service")
        image_id = require_sha256(image.get("image_id"), f"image {image.get('service')} digest")
        signed_image_digests.append(image_id)
        signed_image_map[service] = image_id
        sigstore = image.get("sigstore") if isinstance(image.get("sigstore"), dict) else {}
        require(sigstore.get("ok") is True, f"image {image.get('service')} Sigstore proof did not pass")
        require(bool(sigstore.get("signature")), f"image {image.get('service')} Sigstore proof is missing signature")
        require(image.get("signature") == sigstore.get("signature"), f"image {image.get('service')} Sigstore signature mismatch")
        transparency = sigstore.get("transparency") if isinstance(sigstore.get("transparency"), dict) else {}
        log_id = require_sha256(transparency.get("log_id"), f"image {image.get('service')} transparency log id")
        require(log_id == expected_rekor_log_id, f"image {image.get('service')} transparency log does not match live Rekor log")
        transparency_log_ids.append(log_id)
        require(bool(transparency.get("inclusion_proof")), f"image {image.get('service')} has no transparency inclusion proof")
        statement = image.get("statement") if isinstance(image.get("statement"), dict) else {}
        statement_digest = sha256_prefixed_json(statement)
        require(image.get("statement_digest") == statement_digest, f"image {image.get('service')} statement digest mismatch")
        require(sigstore.get("statement_digest") == statement_digest, f"image {image.get('service')} Sigstore statement digest mismatch")
        verify_sigstore_bundle_binding(
            sigstore,
            expected_statement=statement,
            expected_statement_digest=statement_digest,
            expected_signature=str(sigstore.get("signature")),
            trusted_signing_public_key_pem=trusted_sigstore_public_key_pem,
            expected_signing_key_id=image_signing_key_id,
            expected_rekor_log_id=expected_rekor_log_id,
            trusted_rekor_public_key_pem=trusted_rekor_public_key_pem,
            label=f"image {image.get('service')}",
        )
        key_provider = sigstore.get("key_provider") if isinstance(sigstore.get("key_provider"), dict) else {}
        require(key_provider.get("key_id") == image_signing_key_id, f"image {image.get('service')} Sigstore signing key mismatch")
        subject = statement.get("subject") if isinstance(statement.get("subject"), list) else []
        require(any((item.get("digest") or {}).get("sha256") == image_id.split(":", 1)[1] for item in subject if isinstance(item, dict)), f"image {image.get('service')} statement subject digest mismatch")
        predicate = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
        require(predicate.get("provenance_digest") == provenance_digest, f"image {image.get('service')} statement provenance mismatch")
        require(predicate.get("release_signing_key_id") == release_signing_key_id, f"image {image.get('service')} statement release signing key mismatch")
        require(predicate.get("image_id") == image_id, f"image {image.get('service')} statement image digest mismatch")
        require(predicate.get("source_tree_digest") == provenance["source_tree_digest"], f"image {image.get('service')} statement source tree digest mismatch")
        require(predicate.get("compose_config_sha256") == provenance["compose_config_sha256"], f"image {image.get('service')} statement compose config digest mismatch")
        require(predicate.get("sbom_cyclonedx_sha256") == provenance["sbom_cyclonedx_sha256"], f"image {image.get('service')} statement SBOM digest mismatch")
        require(predicate.get("sbom_cyclonedx_components") == provenance["sbom_cyclonedx_components"], f"image {image.get('service')} statement SBOM component count mismatch")
        for repo_digest in predicate.get("repo_digests") or []:
            ref, _digest = require_image_ref(repo_digest, f"image {image.get('service')} statement repo digest")
            signed_repo_digests.append(ref)
    image_record = transparency_record_binding(
        metadata_transparency,
        anchor_key="anchorResponse",
        inclusion_key="inclusionProof",
        expected_type="release.image_signatures.v1",
        expected_fields={
            "provenance_digest": provenance_digest,
            "image_signature_bundle_digest": digest,
            "image_signing_key_id": image_signing_key_id,
            "image_signature_provider": "sigstore-command",
            "release_signing_key_id": release_signing_key_id,
            "signature": metadata.get("signature"),
            "images": signed_image_map,
        },
        expected_external_provider=expected_external_provider,
        expected_external_log_id=expected_external_log_id,
        trusted_external_public_key_pem=trusted_external_public_key_pem,
        label="image signature bundle",
    )
    external_transparency = external_checkpoint_binding(
        metadata_transparency,
        anchor_key="anchorResponse",
        expected_provider=expected_external_provider,
        expected_log_id=expected_external_log_id,
        trusted_public_key_pem=trusted_external_public_key_pem,
        expected_checkpoint_sha256=image_record["external_checkpoint"]["checkpoint_sha256"],
        label="image signature bundle",
    )
    require(
        sorted(signed_image_digests) == sorted(expected_image_digests),
        "image signature bundle does not cover exactly the digest-pinned production images from readiness",
    )
    require(
        sorted(signed_repo_digests) == sorted(expected_image_refs),
        "image signature bundle does not cover exactly the published production image refs from readiness",
    )
    return {
        "image_signature_bundle_digest": digest,
        "image_signing_key_id": image_signing_key_id,
        "transparency_log_ids": sorted(set(transparency_log_ids)),
        "external_transparency": external_transparency,
        "transparency_record_digest": image_record["record_digest"],
        "images": len(images),
        "signed_image_digests": sorted(signed_image_digests),
        "signed_repo_digests": sorted(signed_repo_digests),
    }


def verify_benchmark(
    bench: dict[str, Any],
    p99_limit_ns: int,
    expected_binary_digest: str,
) -> dict[str, Any]:
    require(bench.get("candidate") == "rust-decision-gate", "benchmark did not run against rust-decision-gate")
    binary_digest = require_sha256(bench.get("data_plane_binary_digest"), "benchmark data-plane binary digest")
    require(
        binary_digest == expected_binary_digest,
        "benchmark data-plane binary digest does not match production key-release measurement",
    )
    policy_hash = require_sha256(bench.get("policy_hash"), "benchmark policy hash")
    runtime_manifest_digest = require_sha256(bench.get("runtime_manifest_digest"), "benchmark runtime manifest digest")
    nonce_before = bench.get("attestation_nonce_before")
    nonce_after = bench.get("attestation_nonce_after")
    require(isinstance(nonce_before, str) and bool(nonce_before), "benchmark is missing its initial attestation nonce")
    require(isinstance(nonce_after, str) and bool(nonce_after), "benchmark is missing its final attestation nonce")
    require(nonce_before != nonce_after, "benchmark attestation nonces must be distinct")
    requests = bench.get("requests")
    require(
        type(requests) is int
        and 100 <= requests <= CANONICAL_JSON_SIGNED_MAX,
        "benchmark request count must be an integer between 100 and the signed 64-bit maximum",
    )
    p50_ns = benchmark_milliseconds_to_nanoseconds(
        bench.get("p50_ms"),
        label="benchmark p50_ms",
    )
    p95_ns = benchmark_milliseconds_to_nanoseconds(
        bench.get("p95_ms"),
        label="benchmark p95_ms",
    )
    p99_ns = benchmark_milliseconds_to_nanoseconds(
        bench.get("p99_ms"),
        label="benchmark p99_ms",
    )
    require(
        type(p99_limit_ns) is int and 0 < p99_limit_ns <= CANONICAL_JSON_SIGNED_MAX,
        "benchmark p99 nanosecond limit must be a positive signed 64-bit integer",
    )
    require(
        p99_ns <= p99_limit_ns,
        f"benchmark p99 {p99_ns} ns exceeds {p99_limit_ns} ns",
    )
    return {
        "candidate": bench.get("candidate"),
        "requests": requests,
        "latency_unit": "nanoseconds",
        "p50_ns": p50_ns,
        "p95_ns": p95_ns,
        "p99_ns": p99_ns,
        "limit_ns": p99_limit_ns,
        "data_plane_binary_digest": binary_digest,
        "policy_hash": policy_hash,
        "runtime_manifest_digest": runtime_manifest_digest,
        "attestation_nonce_bound": True,
    }


def verify_nitro_binding(
    readiness_summary: dict[str, Any],
    nitro_summary: dict[str, Any],
    preflight_summary: dict[str, Any],
) -> dict[str, Any]:
    readiness_nitro = readiness_summary["nitro"]
    require(
        readiness_nitro["raw_attestation_document_sha256"] == nitro_summary["raw_attestation_document_sha256"],
        "standalone Nitro/KMS evidence does not match live readiness attestation",
    )
    require(
        readiness_nitro["materials"] == nitro_summary["materials"],
        "standalone Nitro/KMS evidence materials do not match live readiness",
    )
    require(
        readiness_nitro["material_key_ids"] == nitro_summary["material_key_ids"],
        "standalone Nitro/KMS evidence KMS key IDs do not match live readiness",
    )
    require(
        readiness_nitro["material_bindings"] == nitro_summary["material_bindings"],
        "standalone Nitro/KMS evidence KMS material bindings do not match live readiness",
    )
    require(
        readiness_nitro["material_release_receipts"] == nitro_summary["material_release_receipts"],
        "standalone Nitro/KMS evidence KMS release receipts do not match live readiness",
    )
    require(
        readiness_nitro["command_hashes"] == nitro_summary["command_hashes"],
        "standalone Nitro/KMS evidence command hashes do not match live readiness",
    )
    require(
        readiness_nitro["attested_runtime"] == nitro_summary["attested_runtime"],
        "standalone Nitro/KMS evidence runtime claims do not match live readiness",
    )
    require(
        nitro_summary["material_key_ids"] == preflight_summary["kms_material_key_ids"],
        "standalone Nitro/KMS evidence KMS key IDs do not match production host preflight KMS materials",
    )
    require(
        nitro_summary["material_bindings"] == preflight_summary["kms_material_bindings"],
        "standalone Nitro/KMS evidence KMS material bindings do not match production host preflight KMS materials",
    )
    return {
        "raw_attestation_document_sha256": nitro_summary["raw_attestation_document_sha256"],
        "materials": nitro_summary["materials"],
        "material_key_ids": nitro_summary["material_key_ids"],
        "material_bindings": nitro_summary["material_bindings"],
        "material_release_receipts": nitro_summary["material_release_receipts"],
        "command_hashes": nitro_summary["command_hashes"],
        "attested_runtime": nitro_summary["attested_runtime"],
        "readiness_bound": True,
        "commands_bound": True,
        "preflight_kms_materials_bound": True,
    }


def nested(value: dict[str, Any], *keys: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def require_preflight_file_digest(
    preflight: dict[str, Any],
    snapshots: dict[str, FileSnapshot],
    artifact: str,
    *keys: str,
) -> None:
    expected = nested(preflight, "checks", "release_artifacts", *keys)
    require(
        expected == snapshots[artifact].sha256,
        f"production host preflight {artifact} digest does not match current artifact",
    )


def verify_preflight_authenticity(
    preflight: dict[str, Any],
    *,
    trusted_public_key: FileSnapshot,
    expected_key_id: str,
    max_age_seconds: int,
) -> dict[str, Any]:
    require(1 <= max_age_seconds <= 900, "production host preflight max age is invalid")
    authenticity = preflight.get("authenticity")
    require(isinstance(authenticity, dict), "final production host preflight is unsigned")
    require_exact_keys(
        authenticity,
        {"apiVersion", "algorithm", "key_id", "payload_sha256", "signed_at_unix", "signature"},
        "production host preflight authenticity",
    )
    require(
        authenticity.get("apiVersion") == "serverware.productionHostPreflightSignature/v1"
        and authenticity.get("algorithm") == "ed25519",
        "production host preflight authenticity scheme is invalid",
    )
    key_id = require_sha256(authenticity.get("key_id"), "production host preflight signing key ID")
    require(
        hmac.compare_digest(key_id, require_sha256(expected_key_id, "expected preflight signing key ID")),
        "production host preflight signing key ID does not match the selected trust root",
    )
    public_key_pem = snapshot_text(
        trusted_public_key,
        "production host preflight signing public key",
        encoding="ascii",
    )
    require(
        hmac.compare_digest(release_public_key_id(public_key_pem), key_id),
        "production host preflight signing public key bytes do not match the expected key ID",
    )
    payload_document = dict(preflight)
    payload_document.pop("authenticity", None)
    payload = canonical_legacy_preflight_signature_json(
        payload_document
    ).encode("utf-8")
    require(
        hmac.compare_digest(
            require_sha256(authenticity.get("payload_sha256"), "production host preflight payload digest"),
            sha256_prefixed_bytes(payload),
        ),
        "production host preflight signed payload digest mismatch",
    )
    verify_ed25519(
        public_key_pem,
        str(authenticity.get("signature")),
        payload,
        "production host preflight",
    )
    now = int(time.time())
    generated_at = preflight.get("generated_at_unix")
    signed_at = authenticity.get("signed_at_unix")
    require(isinstance(generated_at, int) and generated_at > 0, "production host preflight generated_at_unix is invalid")
    require(isinstance(signed_at, int) and signed_at > 0, "production host preflight signed_at_unix is invalid")
    for timestamp, label in ((generated_at, "generated"), (signed_at, "signed")):
        require(timestamp <= now + PROXY_PROOF_FUTURE_SKEW_SECONDS, f"production host preflight was {label} in the future")
        require(now - timestamp <= max_age_seconds, f"production host preflight {label} timestamp is stale")
    require(abs(signed_at - generated_at) <= 5, "production host preflight signing time is not bound to generation")
    return {
        "verified": True,
        "key_id": key_id,
        "payload_sha256": authenticity["payload_sha256"],
        "generated_at_unix": generated_at,
        "signed_at_unix": signed_at,
        "max_age_seconds": max_age_seconds,
    }


def verify_production_host_preflight(
    preflight: dict[str, Any],
    paths: dict[str, Path],
    snapshots: InputSnapshots,
    readiness_summary: dict[str, Any],
    *,
    verification_mode: str = "readiness",
    preflight_signing_public_key: FileSnapshot | None = None,
    preflight_signing_key_id: str | None = None,
    preflight_max_age_seconds: int | None = None,
    expected_bootstrap_receipt: dict[str, Any] | None = None,
    expected_nonce_rollback_assurance: dict[str, Any] | None = None,
) -> dict[str, Any]:
    launcher_enforced = expected_bootstrap_receipt is not None
    strict_execution = verification_mode == "final" or launcher_enforced
    production_env_snapshot = load_production_env_snapshot(
        snapshots.by_key["production_readiness_env"]
    )
    preflight_module = load_production_host_preflight_module(
        production_env_snapshot,
        final=strict_execution,
    )
    assert_no_secret_fields(preflight)
    require(preflight.get("apiVersion") == "serverware.productionHostPreflight/v1", "production host preflight has wrong apiVersion")
    require(preflight.get("ok") is True, "production host preflight is not ok")
    require(not preflight.get("failures"), "production host preflight includes failures")
    require(
        preflight.get("verification_mode") == "readiness"
        and preflight.get("readiness_only") is True
        and preflight.get("final_nitro_execution_proven") is False
        and preflight.get("ok_for_action") is False,
        "production host preflight crossed its readiness-only authority boundary",
    )
    preflight_authority_boundary = (
        preflight_module.validate_readiness_authority_boundary(
            preflight.get("authority_boundary")
        )
    )
    launcher_authorization_fresh = False
    if launcher_enforced:
        launch_identity = (
            run_production_readiness.bootstrap_launch_authorization_identity(
                expected_bootstrap_receipt
            )
        )
        launcher_authorization_fresh = (
            int(time.time()) < launch_identity["expires_at_unix_seconds"]
        )
    require(
        preflight_authority_boundary.get("launcherEvidenceVerified")
        is launcher_enforced
        and preflight_authority_boundary.get(
            "currentFreshnessVerifiedUsingTrustedHostWallClock"
        )
        is launcher_authorization_fresh,
        "production host preflight launcher evidence classification does not match the selected readiness path",
    )
    preflight_authenticity: dict[str, Any] | None = None
    if strict_execution:
        require(preflight_signing_public_key is not None, "final completion is missing the preflight signing trust root snapshot")
        require(isinstance(preflight_signing_key_id, str), "final completion is missing the preflight signing key ID")
        require(isinstance(preflight_max_age_seconds, int), "final completion is missing the preflight freshness policy")
        preflight_authenticity = verify_preflight_authenticity(
            preflight,
            trusted_public_key=preflight_signing_public_key,
            expected_key_id=preflight_signing_key_id,
            max_age_seconds=preflight_max_age_seconds,
        )
    checks = preflight.get("checks") if isinstance(preflight.get("checks"), dict) else {}
    host = checks.get("host") if isinstance(checks.get("host"), dict) else {}
    require(host.get("ok") is True, "production host preflight host check did not pass")
    require(host.get("skipped") is not True, "production host preflight skipped host checks")
    require(host.get("linux") is True, "production host preflight did not prove Linux")
    require(host.get("nitro_nsm_device") is True, "production host preflight did not prove /dev/nsm")
    require(host.get("apparmor_sysfs") is True, "production host preflight did not prove AppArmor sysfs")

    runtime_trust = checks.get("runtime_trust_materials") if isinstance(checks.get("runtime_trust_materials"), dict) else {}
    require(runtime_trust.get("ok") is True, "production host preflight runtime trust material check did not pass")
    require(runtime_trust.get("skipped") is not True, "production host preflight skipped runtime trust material checks")
    require(
        sorted(runtime_trust.get("tls_files") or []) == ["ca.pem", "serverware.crt", "serverware.key"],
        "production host preflight did not validate every control-plane TLS file",
    )
    require(
        sorted(runtime_trust.get("helper_files") or [])
        == [
            "control-plane-attestation-verify",
            "lease-recipient-attest",
            "lease-recipient-verify",
            "nsm-attest",
            "nsm-unseal",
            "response-proof-attest",
        ],
        "production host preflight did not validate every attestation helper",
    )
    require(
        sorted(runtime_trust.get("anchor_tls_files") or []) == ["audit-anchor.crt", "audit-anchor.key"],
        "production host preflight did not validate every audit-anchor TLS file",
    )
    require(
        len(runtime_trust.get("proof_files") or []) == 4,
        "production host preflight did not validate every response-proof trust file",
    )
    require(
        runtime_trust.get("proof_collector_files") == ["serverware-proof-client"],
        "production host preflight did not validate the response-proof collector executable",
    )
    require(
        runtime_trust.get("proof_collector_private_key_mode") == "0o600",
        "production host preflight did not enforce response-proof collector private-key mode 0600",
    )
    require_sha256(runtime_trust.get("proof_collector_key_id"), "production host preflight collector key id")
    require_sha256(runtime_trust.get("proof_verifier_key_id"), "production host preflight verifier key id")
    executable_digest_entries = runtime_trust.get("executable_digests")
    require(
        isinstance(executable_digest_entries, list),
        "production host preflight did not report pinned executable digests",
    )
    executable_digests: dict[str, str] = {}
    for item in executable_digest_entries:
        require(
            isinstance(item, dict)
            and set(item) == {"setting", "executable", "host_path", "sha256", "verified"},
            "production host preflight executable digest entry is invalid",
        )
        setting = item.get("setting")
        require(
            isinstance(setting, str)
            and setting in preflight_module.PINNED_EXECUTABLE_COMMAND_SETTINGS,
            "production host preflight executable digest setting is invalid",
        )
        require(
            setting not in executable_digests,
            f"production host preflight has duplicate executable digest setting: {setting}",
        )
        require(
            isinstance(item.get("executable"), str)
            and Path(str(item["executable"])).is_absolute()
            and (
                setting
                in {
                    preflight_module.PRODUCTION_PYTHON_EXECUTABLE_SETTING,
                    preflight_module.PRODUCTION_DOCKER_EXECUTABLE_SETTING,
                }
                or Path(str(item["executable"])).parent == Path("/opt/serverware/bin")
            ),
            f"production host preflight executable path is invalid for {setting}",
        )
        require(
            isinstance(item.get("host_path"), str) and bool(item["host_path"]),
            f"production host preflight host executable path is invalid for {setting}",
        )
        require(
            item.get("verified") is True,
            f"production host preflight did not verify the executable digest for {setting}",
        )
        executable_digests[setting] = require_sha256(
            item.get("sha256"),
            f"production host preflight executable digest for {setting}",
        )
    require(
        set(executable_digests)
        == preflight_module.PINNED_EXECUTABLE_COMMAND_SETTINGS,
        "production host preflight did not validate every pinned helper and collector executable",
    )
    script_digests: dict[str, str] = {}
    docker_toolchain = runtime_trust.get("docker_toolchain")
    material_digests = runtime_trust.get("material_digests")
    if strict_execution:
        script_entries = runtime_trust.get("python_script_digests")
        require(isinstance(script_entries, list), "production host preflight did not report pinned Python scripts")
        for item in script_entries:
            require(
                isinstance(item, dict)
                and set(item) == {"setting", "path", "sha256", "verified"}
                and item.get("verified") is True,
                "production host preflight Python script digest entry is invalid",
            )
            setting = str(item["setting"])
            require(
                setting in set(run_production_readiness.PINNED_PYTHON_SCRIPTS.values())
                and setting not in script_digests,
                "production host preflight Python script digest setting is invalid or duplicated",
            )
            script_digests[setting] = require_sha256(
                item.get("sha256"),
                f"production host preflight Python script digest for {setting}",
            )
        require(
            set(script_digests) == set(run_production_readiness.PINNED_PYTHON_SCRIPTS.values()),
            "production host preflight did not validate every pinned Python script",
        )
        require(
            isinstance(docker_toolchain, dict)
            and docker_toolchain.get("ok") is True
            and nested(docker_toolchain, "compose_plugin", "verified") is True
            and nested(docker_toolchain, "daemon", "daemon_id_verified") is True,
            "production host preflight did not authenticate the Docker toolchain and daemon",
        )
        required_runtime_materials = {
            "control_plane_certificate",
            "control_plane_private_key",
            "control_plane_ca_bundle",
            "anchor_certificate",
            "anchor_private_key",
            "proof_ca_bundle",
            "proof_collector_private_key",
            "proof_collector_public_key",
            "proof_verifier_public_key",
            "preflight_signing_public_key",
        }
        require(
            isinstance(material_digests, dict)
            and set(material_digests) == required_runtime_materials,
            "production host preflight runtime trust digest set is incomplete",
        )
        for label, report in material_digests.items():
            require(
                isinstance(report, dict)
                and set(report)
                == {"path", "sha256", "bytes", "mode", "owner_uid", "nofollow", "secure_ancestors"}
                and report.get("nofollow") is True
                and report.get("secure_ancestors") is True,
                f"production host preflight runtime trust digest report is invalid: {label}",
            )
            require_sha256(report.get("sha256"), f"production host preflight runtime trust digest {label}")

    production_env = checks.get("production_env") if isinstance(checks.get("production_env"), dict) else {}
    require(production_env.get("ok") is True, "production host preflight production env check did not pass")
    preflight_executing_script: dict[str, Any] | None = None
    preflight_bootstrap_receipt: dict[str, Any] | None = None
    preflight_nonce_rollback_assurance = (
        checks.get("nonce_rollback_assurance")
        if isinstance(checks.get("nonce_rollback_assurance"), dict)
        else {}
    )
    if strict_execution:
        launcher_trust = (
            production_env.get("launcher_trust")
            if isinstance(production_env.get("launcher_trust"), dict)
            else {}
        )
        candidate_receipt = launcher_trust.get("bootstrap_receipt")
        require(
            isinstance(expected_bootstrap_receipt, dict)
            and isinstance(candidate_receipt, dict)
            and candidate_receipt == expected_bootstrap_receipt,
            "production host preflight is not bound to the current sealed launcher receipt",
        )
        preflight_bootstrap_receipt = candidate_receipt
        require(
            isinstance(expected_nonce_rollback_assurance, dict)
            and expected_nonce_rollback_assurance.get("verified") is True
            and preflight_nonce_rollback_assurance
            == expected_nonce_rollback_assurance
            and launcher_trust.get("nonce_rollback_assurance")
            == expected_nonce_rollback_assurance,
            "production host preflight is not bound to the current retained nonce rollback assurance snapshot",
        )
        candidate = production_env.get("executing_script")
        require(
            isinstance(candidate, dict)
            and set(candidate)
            == {
                "path",
                "sha256",
                "device",
                "inode",
                "measured_from",
                "matches_pinned_path_inode",
            }
            and candidate.get("matches_pinned_path_inode") is True
            and candidate.get("sha256")
            == script_digests[
                run_production_readiness.PRODUCTION_HOST_PREFLIGHT_SCRIPT_SHA256_ENV
            ],
            "production host preflight did not bind its descriptor-executed script identity",
        )
        preflight_executing_script = candidate
    else:
        require(
            preflight_nonce_rollback_assurance
            == {
                "apiVersion": run_production_readiness.NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION,
                "enforcement": "not-native-launcher-enforced",
                "verified": False,
            },
            "manual production host preflight must not claim launcher-enforced nonce rollback assurance",
        )
    production_env_file = production_env.get("file") if isinstance(production_env.get("file"), dict) else {}
    require(
        production_env_file.get("sha256") == snapshots.by_key["production_readiness_env"].sha256,
        "production host preflight production env digest does not match current production readiness env",
    )
    config_gate = production_env.get("config_gate") if isinstance(production_env.get("config_gate"), dict) else {}
    require(config_gate.get("skipped") is not True, "production host preflight skipped the config gate")
    require(config_gate.get("ok") is True, "production host preflight config gate did not pass")
    preflight_config_file = config_gate.get("file") if isinstance(config_gate.get("file"), dict) else {}
    preflight_config_path = Path(str(config_gate.get("out") or preflight_config_file.get("path") or ""))
    preflight_config_snapshot = snapshots.capture(
        "production_host_preflight_config",
        preflight_config_path,
        "production host preflight config gate",
        max_bytes=COMPLETION_INPUT_MAX_BYTES,
    )
    require(
        preflight_config_file.get("sha256") == preflight_config_snapshot.sha256,
        "production host preflight config gate digest does not match current preflight config artifact",
    )
    require(
        config_gate.get("result_sha256") == preflight_config_file.get("sha256"),
        "production host preflight config gate result digest mismatch",
    )
    preflight_config = load_json_snapshot(
        preflight_config_snapshot,
        "production host preflight config gate",
    )
    preflight_config_semantic_sha256 = semantic_result_digest(preflight_config)
    require(
        config_gate.get("semantic_sha256") == preflight_config_semantic_sha256,
        "production host preflight config gate semantic digest mismatch",
    )

    images_env = checks.get("production_images_env") if isinstance(checks.get("production_images_env"), dict) else {}
    require(images_env.get("ok") is True and images_env.get("status") == "valid", "production host preflight image env check did not pass")
    images_env_file = images_env.get("file") if isinstance(images_env.get("file"), dict) else {}
    require(
        images_env_file.get("sha256") == snapshots.by_key["production_images_env"].sha256,
        "production host preflight production images env digest does not match current production images env",
    )
    require(
        sorted(images_env.get("image_digests") or []) == sorted(readiness_summary["production_image_digests"]),
        "production host preflight image env digests do not match readiness",
    )
    env_refs = sorted(item.get("ref") for item in images_env.get("images") or [] if isinstance(item, dict))
    require(env_refs == sorted(readiness_summary["production_images"]), "production host preflight image env refs do not match readiness")

    env_merge = checks.get("production_images_env_merge") if isinstance(checks.get("production_images_env_merge"), dict) else {}
    require(env_merge.get("ok") is True, "production host preflight image env merge check did not pass")
    production_compose = checks.get("production_compose") if isinstance(checks.get("production_compose"), dict) else {}
    require(production_compose.get("ok") is True, "production host preflight Compose check did not pass")
    require(production_compose.get("skipped") is not True, "production host preflight skipped the Compose check")
    production_compose_sha256 = require_sha256(
        production_compose.get("sha256"),
        "production host preflight Compose digest",
    )
    compose_renderer: dict[str, Any] | None = None
    production_runtime_model: dict[str, Any] | None = None
    if strict_execution:
        compose_renderer = {
            "path": production_compose.get("compose_plugin_executable"),
            "sha256": require_sha256(
                production_compose.get("compose_plugin_sha256"),
                "production host preflight Compose renderer digest",
            ),
        }
        require(
            compose_renderer["path"] == nested(docker_toolchain, "compose_plugin", "path")
            and compose_renderer["sha256"]
            == nested(docker_toolchain, "compose_plugin", "sha256"),
            "production host preflight Compose renderer differs from the measured Docker toolchain",
        )
        require(
            production_compose.get("docker_unix_socket")
            == nested(docker_toolchain, "daemon", "socket", "path")
            and production_compose.get("docker_daemon_id")
            == nested(docker_toolchain, "daemon", "daemon_id"),
            "production host preflight Compose renderer used a different Docker endpoint",
        )
        require(
            production_compose.get("docker_daemon_before")
            == production_compose.get("docker_daemon_after")
            == docker_toolchain.get("daemon"),
            "production host preflight Docker endpoint changed during Compose rendering",
        )
        require(
            production_compose.get("compose_project_name")
            == production_env_snapshot.get(
                run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV
            )
            == docker_toolchain.get("compose_project_name"),
            "production host preflight Compose project name differs from the hashed production env",
        )
        candidate_runtime_model = production_compose.get("runtime_model")
        require(
            isinstance(candidate_runtime_model, dict)
            and set(candidate_runtime_model)
            == {"services", "networks", "volumes", "sha256"}
            and isinstance(candidate_runtime_model.get("services"), dict)
            and isinstance(candidate_runtime_model.get("networks"), dict)
            and isinstance(candidate_runtime_model.get("volumes"), dict)
            and set(candidate_runtime_model["services"])
            == set(run_production_readiness.FINAL_SERVICE_USERS),
            "production host preflight normalized runtime model is incomplete",
        )
        runtime_model_digest = sha256_prefixed_bytes(
            canonical_json(
                {
                    key: candidate_runtime_model[key]
                    for key in ("services", "networks", "volumes")
                }
            ).encode("utf-8")
        )
        require(
            candidate_runtime_model.get("sha256")
            == production_compose.get("runtime_model_sha256")
            == runtime_model_digest,
            "production host preflight normalized runtime model digest is invalid",
        )
        production_runtime_model = candidate_runtime_model

    artifacts = checks.get("release_artifacts") if isinstance(checks.get("release_artifacts"), dict) else {}
    require(artifacts.get("ok") is True, "production host preflight release artifact check did not pass")
    require_preflight_file_digest(preflight, snapshots.by_key, "production_images_build", "production_images", "file", "sha256")
    require_preflight_file_digest(preflight, snapshots.by_key, "production_images_published", "production_images_published", "file", "sha256")
    require_preflight_file_digest(preflight, snapshots.by_key, "release_provenance_summary", "release_provenance", "file", "sha256")
    require_preflight_file_digest(preflight, snapshots.by_key, "release_provenance", "release_provenance_document", "sha256")
    require_preflight_file_digest(preflight, snapshots.by_key, "image_signatures_summary", "image_signatures_summary", "file", "sha256")
    require_preflight_file_digest(preflight, snapshots.by_key, "image_signatures", "image_signatures", "file", "sha256")
    require_preflight_file_digest(preflight, snapshots.by_key, "bench", "bench", "file", "sha256")
    release_security = checks.get("release_security_evidence") if isinstance(checks.get("release_security_evidence"), dict) else {}
    require(release_security.get("ok") is True, "production host preflight release security evidence did not pass")
    policy_trust_roots: dict[str, Any] = {}
    if strict_execution:
        candidate_trust_roots = release_security.get("trust_roots")
        require(
            isinstance(candidate_trust_roots, dict)
            and set(candidate_trust_roots)
            == {"policy_identity", "policy_activation", "reproducible_build"},
            "production host preflight policy trust-root binding set is incomplete",
        )
        role_bindings = {
            "policy_identity": (
                "policy_trusted_public_key",
                run_production_readiness.POLICY_TRUST_ROOT_ENV,
                run_production_readiness.POLICY_TRUST_ROOT_ID_ENV,
            ),
            "policy_activation": (
                "policy_activation_trusted_public_key",
                run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ENV,
                run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV,
            ),
            "reproducible_build": (
                "reproducible_build_trusted_public_key",
                run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ENV,
                run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV,
            ),
        }
        for role, (snapshot_key, path_setting, id_setting) in role_bindings.items():
            report = candidate_trust_roots.get(role)
            require(
                isinstance(report, dict)
                and report.get("verified") is True
                and report.get("path") == production_env_snapshot.get(path_setting)
                and report.get("sha256") == snapshots.by_key[snapshot_key].sha256,
                f"production host preflight {role} trust-root snapshot binding is invalid",
            )
            current_id = release_public_key_id(
                snapshot_text(snapshots.by_key[snapshot_key], f"{role} trust root", encoding="ascii")
            )
            require(
                hmac.compare_digest(
                    current_id,
                    require_sha256(
                        production_env_snapshot.get(id_setting),
                        f"production env {role} SPKI pin",
                    ),
                )
                and report.get("spki_sha256") == current_id,
                f"production host preflight {role} SPKI binding mismatch",
            )
            policy_trust_roots[role] = {
                "path": report["path"],
                "sha256": report["sha256"],
                "spki_sha256": current_id,
            }
        require(
            len({item["spki_sha256"] for item in policy_trust_roots.values()}) == 3,
            "policy identity, activation, and reproducible-build trust roots are not distinct",
        )
    policy_identity = release_security.get("policy_identity") if isinstance(release_security.get("policy_identity"), dict) else {}
    require(
        policy_identity.get("reportSha256") == snapshots.by_key["policy_identity_verification"].sha256,
        "production host preflight policy identity report digest does not match current artifact",
    )
    require(
        policy_identity.get("policyBundleSha256") == snapshots.by_key["policy_bundle"].sha256,
        "production host preflight policy bundle digest does not match current artifact",
    )
    require(
        policy_identity.get("trustedPublicKeySha256") == snapshots.by_key["policy_trusted_public_key"].sha256,
        "production host preflight policy trust root digest does not match current artifact",
    )
    activation_evidence = release_security.get("policy_activation") if isinstance(release_security.get("policy_activation"), dict) else {}
    require(
        activation_evidence.get("reportSha256") == snapshots.by_key["policy_activation_verification"].sha256,
        "production host preflight activation report digest does not match current artifact",
    )
    require(
        activation_evidence.get("signatureSha256") == snapshots.by_key["policy_activation_signature"].sha256,
        "production host preflight activation signature digest does not match current artifact",
    )
    require(
        activation_evidence.get("trustedPublicKeySha256")
        == snapshots.by_key["policy_activation_trusted_public_key"].sha256,
        "production host preflight activation trust-root digest does not match current artifact",
    )
    reproducibility_evidence = release_security.get("reproducible_builds") if isinstance(release_security.get("reproducible_builds"), dict) else {}
    require(
        reproducibility_evidence.get("reportSha256") == snapshots.by_key["reproducible_build_verification"].sha256,
        "production host preflight reproducibility report digest does not match current artifact",
    )
    require(
        reproducibility_evidence.get("signatureSha256") == snapshots.by_key["reproducible_build_signature"].sha256,
        "production host preflight reproducibility signature digest does not match current artifact",
    )
    require(
        reproducibility_evidence.get("trustedPublicKeySha256")
        == snapshots.by_key["reproducible_build_trusted_public_key"].sha256,
        "production host preflight reproducibility trust-root digest does not match current artifact",
    )
    artifact_mounts = checks.get("release_artifact_mounts") if isinstance(checks.get("release_artifact_mounts"), dict) else {}
    require(artifact_mounts.get("ok") is True, "production host preflight release artifact mount check did not pass")
    mounted_artifacts = artifact_mounts.get("artifacts") if isinstance(artifact_mounts.get("artifacts"), list) else []
    require(len(mounted_artifacts) == 2, "production host preflight did not validate both release artifact mounts")
    for item in mounted_artifacts:
        require(isinstance(item, dict), "production host preflight release artifact mount entry must be an object")
        require(item.get("matches_approved_artifact") is True, "production release artifact mount did not match approved bytes")
    benchmark = artifacts.get("bench") if isinstance(artifacts.get("bench"), dict) else {}
    benchmark_binary_digest = require_sha256(
        benchmark.get("data_plane_binary_digest"),
        "production host preflight benchmark binary digest",
    )
    signatures = artifacts.get("image_signatures") if isinstance(artifacts.get("image_signatures"), dict) else {}
    require(signatures.get("covers_published_production_images") is True, "production host preflight did not prove published image digest coverage")
    require(signatures.get("covers_published_production_image_refs") is True, "production host preflight did not prove published image ref coverage")

    kms = checks.get("kms_materials") if isinstance(checks.get("kms_materials"), dict) else {}
    require(kms.get("ok") is True, "production host preflight KMS materials check did not pass")
    require(kms.get("secret_values_redacted") is True, "production host preflight KMS materials did not redact secret values")
    kms_file = kms.get("file") if isinstance(kms.get("file"), dict) else {}
    require(
        kms_file.get("sha256") == snapshots.by_key["kms_materials"].sha256,
        "production host preflight KMS materials digest does not match current KMS materials file",
    )
    kms_material_key_ids: dict[str, str] = {}
    kms_material_bindings: dict[str, dict[str, str]] = {}
    for item in kms.get("materials") or []:
        require(isinstance(item, dict), "production host preflight KMS material entry must be an object")
        material = item.get("material")
        require(isinstance(material, str) and material, "production host preflight KMS material entry is missing material")
        require(material not in kms_material_key_ids, f"production host preflight has duplicate KMS material: {material}")
        kms_material_key_ids[material] = require_sha256(
            item.get("key_id_sha256"),
            f"production host preflight {material} KMS key id digest",
        )
        kms_material_bindings[material] = {
            "key_id_sha256": kms_material_key_ids[material],
            "ciphertext_blob_sha256": require_sha256(
                item.get("ciphertext_blob_sha256"),
                f"production host preflight {material} KMS ciphertext digest",
            ),
            "encryption_context_sha256": require_sha256(
                item.get("encryption_context_sha256"),
                f"production host preflight {material} KMS encryption context digest",
            ),
        }
    materials = sorted(kms_material_key_ids)
    require(sorted(REQUIRED_MATERIALS) == materials, "production host preflight did not validate all required KMS materials")
    current_bindings = current_kms_material_bindings(
        snapshots.by_key["kms_materials"],
        snapshots,
    )
    require(
        kms_material_bindings == current_bindings,
        "production host preflight KMS material bindings do not match current KMS materials file",
    )
    return {
        "verification_mode": "readiness",
        "readiness_only": True,
        "final_nitro_execution_proven": False,
        "ok_for_action": False,
        "authority_boundary": preflight_authority_boundary,
        "host": {
            "system": host.get("system"),
            "machine": host.get("machine"),
            "linux": host.get("linux"),
            "nitro_nsm_device": host.get("nitro_nsm_device"),
            "apparmor_sysfs": host.get("apparmor_sysfs"),
        },
        "runtime_trust_materials": {
            "tls_files": sorted(runtime_trust.get("tls_files") or []),
            "anchor_tls_files": sorted(runtime_trust.get("anchor_tls_files") or []),
            "helper_files": sorted(runtime_trust.get("helper_files") or []),
            "proof_files": sorted(runtime_trust.get("proof_files") or []),
            "proof_collector_files": sorted(runtime_trust.get("proof_collector_files") or []),
            "proof_collector_private_key_mode": runtime_trust.get("proof_collector_private_key_mode"),
            "proof_collector_key_id": runtime_trust.get("proof_collector_key_id"),
            "proof_verifier_key_id": runtime_trust.get("proof_verifier_key_id"),
            "executable_digests": executable_digests,
            "python_script_digests": script_digests,
            "docker_toolchain": docker_toolchain,
            "material_digests": material_digests,
            "private_key_mode": runtime_trust.get("private_key_mode"),
            "certificate_not_after": runtime_trust.get("certificate_not_after"),
        },
        "authenticity": preflight_authenticity,
        "bootstrap_receipt": preflight_bootstrap_receipt,
        "nonce_rollback_assurance": preflight_nonce_rollback_assurance,
        "executing_script": preflight_executing_script,
        "production_env_keys": production_env.get("env_keys") or [],
        "production_readiness_env_sha256": production_env_file.get("sha256"),
        "production_images_env_sha256": images_env_file.get("sha256"),
        "production_config_sha256": preflight_config_file.get("sha256"),
        "production_config_semantic_sha256": preflight_config_semantic_sha256,
        "production_compose_sha256": production_compose_sha256,
        "production_compose_renderer": compose_renderer,
        "production_compose_project_name": production_compose.get(
            "compose_project_name"
        ),
        "production_runtime_model": production_runtime_model,
        "release_artifact_mounts": mounted_artifacts,
        "production_image_refs": sorted(readiness_summary["production_images"]),
        "benchmark_binary_digest": benchmark_binary_digest,
        "release_security_evidence": {
            "trust_roots": policy_trust_roots,
            "policy_identity": policy_identity,
            "policy_activation": activation_evidence,
            "reproducible_builds": reproducibility_evidence,
            "benchmarkPolicyBound": release_security.get("benchmarkPolicyBound"),
        },
        "kms_materials": sorted(REQUIRED_MATERIALS),
        "kms_material_key_ids": {material: kms_material_key_ids[material] for material in sorted(REQUIRED_MATERIALS)},
        "kms_material_bindings": {
            material: kms_material_bindings[material]
            for material in sorted(REQUIRED_MATERIALS)
        },
        "kms_materials_file_sha256": kms_file.get("sha256"),
    }


def verify_current_completion_host(preflight_summary: dict[str, Any], *, skip_current_host_check: bool) -> dict[str, Any]:
    current = {
        "system": platform.system(),
        "machine": platform.machine(),
        "linux": platform.system() == "Linux",
        "nitro_nsm_device": Path("/dev/nsm").exists(),
        "apparmor_sysfs": Path("/sys/module/apparmor").exists(),
    }
    if skip_current_host_check:
        require(
            os.environ.get(TEST_ONLY_BYPASS_ENV) == "1",
            f"--skip-current-host-check is test-only; set {TEST_ONLY_BYPASS_ENV}=1 in fixture tests",
        )
        return {**current, "skipped": True, "preflight_bound": False, "identity_recomputed": False}
    for key, message in (
        ("linux", "current completion host must be Linux"),
        ("nitro_nsm_device", "current completion host must expose /dev/nsm"),
        ("apparmor_sysfs", "current completion host must expose AppArmor sysfs"),
    ):
        require(current[key] is True, message)
    for key in ("system", "machine", "linux", "nitro_nsm_device", "apparmor_sysfs"):
        require(
            current[key] == preflight_summary["host"].get(key),
            f"current completion host {key} does not match production host preflight",
        )
    return {
        **current,
        "skipped": False,
        "preflight_bound": True,
        "identity_recomputed": True,
        "identity": read_current_host_identity(),
    }


def verify_current_production_env_binding(
    paths: dict[str, Path],
    snapshots: InputSnapshots,
    readiness_summary: dict[str, Any],
    preflight_summary: dict[str, Any],
    config_summary: dict[str, Any],
    *,
    verification_mode: str = "readiness",
    release_trust_inputs: dict[str, str | None] | None = None,
    final_inputs: dict[str, str | None] | None = None,
    final_file_snapshots: dict[str, FileSnapshot] | None = None,
    proxy_digest_inputs: dict[str, str | None] | None = None,
    launcher_trust_inputs: dict[str, str | None] | None = None,
    proxy_proof_max_age_seconds: int | None = None,
    proxy_proof_contract: str | None = None,
    proxy_stream_body: str | None = None,
    proxy_max_stream_bytes: int | None = None,
    proxy_observation_body: str | None = None,
    proxy_max_observation_body_bytes: int | None = None,
    proxy_operation_context_digest: str | None = None,
    p99_limit_ms: str | None = None,
    docker_executable: str | None = None,
    docker_compose_plugin_executable: str | None = None,
    docker_unix_socket: str | None = None,
    docker_daemon_id: str | None = None,
    preflight_signing_public_key: str | None = None,
    preflight_signing_key_id: str | None = None,
    preflight_max_age_seconds: int | None = None,
    remeasure_runtime_trust: bool = True,
    launcher_enforced: bool = False,
) -> dict[str, Any]:
    strict_execution = verification_mode == "final" or launcher_enforced
    env_snapshot = snapshots.by_key["production_readiness_env"]
    launcher_trust: dict[str, Any] | None = None
    if strict_execution:
        require(launcher_trust_inputs is not None, "final verification is missing launcher trust inputs")
        launcher_trust = run_production_readiness.validate_launcher_trusted_env(
            env_snapshot.path,
            env_snapshot.data,
            env_snapshot.metadata,
            expected_path=launcher_trust_inputs.get(
                run_production_readiness.LAUNCHER_TRUSTED_ENV_PATH_INPUT
            ),
            expected_sha256=launcher_trust_inputs.get(
                run_production_readiness.LAUNCHER_TRUSTED_ENV_SHA256_INPUT
            ),
        )
    try:
        production_env = load_production_env_snapshot(env_snapshot)
    except Exception as exc:
        raise ValueError(f"current production readiness env is invalid: {exc}") from exc
    require(
        not run_production_readiness.LAUNCHER_TRUST_INPUT_NAMES & set(production_env),
        "out-of-band launcher trust inputs must not be defined inside the production readiness env",
    )
    if strict_execution:
        launcher_trust["startup_environment_contract"] = (
            run_production_readiness.validate_final_launcher_contract(production_env)
        )
    preflight_module = load_production_host_preflight_module(
        production_env,
        final=strict_execution,
    )
    raw_max_age = production_env.get(PROXY_PROOF_MAX_AGE_ENV_KEY)
    require(isinstance(raw_max_age, str), f"production readiness env must pin {PROXY_PROOF_MAX_AGE_ENV_KEY}")
    try:
        expected_proxy_proof_max_age_seconds = int(raw_max_age)
    except ValueError as exc:
        raise ValueError(f"{PROXY_PROOF_MAX_AGE_ENV_KEY} must be an integer") from exc
    require(
        1 <= expected_proxy_proof_max_age_seconds <= PROXY_PROOF_MAX_AGE_LIMIT_SECONDS,
        f"{PROXY_PROOF_MAX_AGE_ENV_KEY} must be between 1 and {PROXY_PROOF_MAX_AGE_LIMIT_SECONDS}",
    )
    expected_proxy_proof_contract = production_env.get(PROXY_PROOF_CONTRACT_ENV_KEY)
    require(
        expected_proxy_proof_contract in PROXY_PROOF_CONTRACTS,
        f"production readiness env must pin {PROXY_PROOF_CONTRACT_ENV_KEY} to buffered-v3, observation-v1, or streaming-v1",
    )
    require(
        proxy_proof_contract == expected_proxy_proof_contract,
        f"selected proxy proof contract does not exactly match {PROXY_PROOF_CONTRACT_ENV_KEY}",
    )
    expected_proxy_stream_body: str | None = None
    expected_proxy_max_stream_bytes: int | None = None
    expected_proxy_observation_body: str | None = None
    expected_proxy_max_observation_body_bytes: int | None = None
    if expected_proxy_proof_contract == "streaming-v1":
        expected_proxy_stream_body = production_env.get(PROXY_STREAM_BODY_ENV_KEY)
        require(
            isinstance(expected_proxy_stream_body, str)
            and Path(expected_proxy_stream_body).is_absolute(),
            f"streaming production readiness env must pin absolute {PROXY_STREAM_BODY_ENV_KEY}",
        )
        raw_stream_max_bytes = production_env.get(PROXY_STREAM_MAX_BYTES_ENV_KEY)
        require(
            isinstance(raw_stream_max_bytes, str),
            f"streaming production readiness env must pin {PROXY_STREAM_MAX_BYTES_ENV_KEY}",
        )
        try:
            expected_proxy_max_stream_bytes = int(raw_stream_max_bytes)
        except ValueError as exc:
            raise ValueError(f"{PROXY_STREAM_MAX_BYTES_ENV_KEY} must be an integer") from exc
        require(
            1 <= expected_proxy_max_stream_bytes <= MAX_PROXY_STREAM_BODY_BYTES,
            f"{PROXY_STREAM_MAX_BYTES_ENV_KEY} must be between 1 and {MAX_PROXY_STREAM_BODY_BYTES}",
        )
        require(
            proxy_stream_body == expected_proxy_stream_body,
            f"selected proxy stream body does not exactly match {PROXY_STREAM_BODY_ENV_KEY}",
        )
        require(
            proxy_max_stream_bytes == expected_proxy_max_stream_bytes,
            f"selected proxy stream byte limit does not exactly match {PROXY_STREAM_MAX_BYTES_ENV_KEY}",
        )
        expected_operation_context_digest = require_sha256(
            production_env.get(PROXY_STREAM_OPERATION_CONTEXT_DIGEST_ENV_KEY),
            "production readiness expected streaming operation context digest",
        )
        require(
            proxy_operation_context_digest == expected_operation_context_digest,
            f"selected proxy operation context digest does not exactly match {PROXY_STREAM_OPERATION_CONTEXT_DIGEST_ENV_KEY}",
        )
        require(
            PROXY_OBSERVATION_BODY_ENV_KEY not in production_env
            and PROXY_OBSERVATION_MAX_BYTES_ENV_KEY not in production_env
            and proxy_observation_body is None
            and proxy_max_observation_body_bytes is None,
            "streaming-v1 must not select observation body settings",
        )
    elif expected_proxy_proof_contract == "observation-v1":
        require(
            PROXY_STREAM_BODY_ENV_KEY not in production_env
            and PROXY_STREAM_MAX_BYTES_ENV_KEY not in production_env
            and PROXY_STREAM_OPERATION_CONTEXT_DIGEST_ENV_KEY not in production_env
            and proxy_stream_body is None
            and proxy_max_stream_bytes is None
            and proxy_operation_context_digest is None,
            "observation-v1 production readiness env must not define streaming proof settings",
        )
        expected_proxy_observation_body = production_env.get(
            PROXY_OBSERVATION_BODY_ENV_KEY
        )
        require(
            isinstance(expected_proxy_observation_body, str)
            and Path(expected_proxy_observation_body).is_absolute(),
            f"observation production readiness env must pin absolute {PROXY_OBSERVATION_BODY_ENV_KEY}",
        )
        raw_observation_max_bytes = production_env.get(
            PROXY_OBSERVATION_MAX_BYTES_ENV_KEY
        )
        require(
            isinstance(raw_observation_max_bytes, str),
            f"observation production readiness env must pin {PROXY_OBSERVATION_MAX_BYTES_ENV_KEY}",
        )
        try:
            expected_proxy_max_observation_body_bytes = int(
                raw_observation_max_bytes
            )
        except ValueError as exc:
            raise ValueError(
                f"{PROXY_OBSERVATION_MAX_BYTES_ENV_KEY} must be an integer"
            ) from exc
        require(
            1
            <= expected_proxy_max_observation_body_bytes
            <= MAX_PROXY_OBSERVATION_BODY_BYTES,
            f"{PROXY_OBSERVATION_MAX_BYTES_ENV_KEY} must be between 1 and {MAX_PROXY_OBSERVATION_BODY_BYTES}",
        )
        require(
            proxy_observation_body == expected_proxy_observation_body,
            f"selected proxy observation body does not exactly match {PROXY_OBSERVATION_BODY_ENV_KEY}",
        )
        require(
            proxy_max_observation_body_bytes
            == expected_proxy_max_observation_body_bytes,
            f"selected proxy observation body byte limit does not exactly match {PROXY_OBSERVATION_MAX_BYTES_ENV_KEY}",
        )
        expected_operation_context_digest = None
    else:
        require(
            PROXY_STREAM_BODY_ENV_KEY not in production_env
            and PROXY_STREAM_MAX_BYTES_ENV_KEY not in production_env
            and PROXY_STREAM_OPERATION_CONTEXT_DIGEST_ENV_KEY not in production_env
            and proxy_stream_body is None
            and proxy_max_stream_bytes is None
            and proxy_operation_context_digest is None,
            "buffered-v3 completion must not select streaming proof settings",
        )
        require(
            PROXY_OBSERVATION_BODY_ENV_KEY not in production_env
            and PROXY_OBSERVATION_MAX_BYTES_ENV_KEY not in production_env
            and proxy_observation_body is None
            and proxy_max_observation_body_bytes is None,
            "buffered-v3 completion must not select observation body settings",
        )
        expected_operation_context_digest = None
    raw_p99_limit = production_env.get(COMPLETION_P99_LIMIT_ENV_KEY)
    require(isinstance(raw_p99_limit, str), f"production readiness env must pin {COMPLETION_P99_LIMIT_ENV_KEY}")
    expected_p99_limit_ns = exact_milliseconds_to_nanoseconds(
        raw_p99_limit,
        label=COMPLETION_P99_LIMIT_ENV_KEY,
        positive=True,
    )
    expected_docker_executable = production_env.get(DOCKER_EXECUTABLE_ENV_KEY)
    require(
        isinstance(expected_docker_executable, str)
        and Path(expected_docker_executable).is_absolute(),
        f"production readiness env must pin absolute {DOCKER_EXECUTABLE_ENV_KEY}",
    )
    docker_toolchain_settings = (
        run_production_readiness.validate_docker_toolchain_settings(production_env)
        if strict_execution
        else {
            DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY: production_env.get(
                DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY, "readiness-unbound"
            ),
            DOCKER_COMPOSE_PLUGIN_SHA256_ENV_KEY: production_env.get(
                DOCKER_COMPOSE_PLUGIN_SHA256_ENV_KEY, "sha256:" + "0" * 64
            ),
            DOCKER_UNIX_SOCKET_ENV_KEY: production_env.get(
                DOCKER_UNIX_SOCKET_ENV_KEY, "/var/run/docker.sock"
            ),
            DOCKER_DAEMON_ID_ENV_KEY: production_env.get(
                DOCKER_DAEMON_ID_ENV_KEY, "readiness-unbound"
            ),
            run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV: production_env.get(
                run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV,
                "serverware-production",
            ),
        }
    )
    raw_preflight_max_age = production_env.get(PREFLIGHT_MAX_AGE_ENV_KEY)
    try:
        expected_preflight_max_age = int(raw_preflight_max_age or "300")
    except ValueError as exc:
        raise ValueError(f"{PREFLIGHT_MAX_AGE_ENV_KEY} must be an integer") from exc
    require(1 <= expected_preflight_max_age <= 900, f"{PREFLIGHT_MAX_AGE_ENV_KEY} must be between 1 and 900")
    expected_preflight_public_key = production_env.get(PREFLIGHT_SIGNING_PUBLIC_KEY_ENV_KEY)
    expected_preflight_key_id = (
        require_sha256(
            production_env.get(PREFLIGHT_SIGNING_KEY_ID_ENV_KEY),
            "production host preflight signing key ID",
        )
        if strict_execution
        else production_env.get(PREFLIGHT_SIGNING_KEY_ID_ENV_KEY, "sha256:" + "0" * 64)
    )
    if strict_execution:
        require(
            proxy_proof_max_age_seconds == expected_proxy_proof_max_age_seconds,
            f"selected proxy proof max age does not exactly match {PROXY_PROOF_MAX_AGE_ENV_KEY}",
        )
        require(
            p99_limit_ms is not None
            and exact_milliseconds_to_nanoseconds(
                p99_limit_ms,
                label="selected p99 limit",
                positive=True,
            )
            == expected_p99_limit_ns,
            f"selected p99 limit does not exactly match {COMPLETION_P99_LIMIT_ENV_KEY}",
        )
        require(
            docker_executable == expected_docker_executable,
            f"selected Docker executable does not exactly match {DOCKER_EXECUTABLE_ENV_KEY}",
        )
        for selected, setting in (
            (docker_compose_plugin_executable, DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY),
            (docker_unix_socket, DOCKER_UNIX_SOCKET_ENV_KEY),
            (docker_daemon_id, DOCKER_DAEMON_ID_ENV_KEY),
        ):
            require(
                selected == docker_toolchain_settings[setting],
                f"selected Docker setting does not exactly match {setting}",
            )
        require(
            preflight_signing_public_key == expected_preflight_public_key,
            f"selected preflight signing public key does not exactly match {PREFLIGHT_SIGNING_PUBLIC_KEY_ENV_KEY}",
        )
        require(
            preflight_signing_key_id == expected_preflight_key_id,
            f"selected preflight signing key ID does not exactly match {PREFLIGHT_SIGNING_KEY_ID_ENV_KEY}",
        )
        require(
            preflight_max_age_seconds == expected_preflight_max_age,
            f"selected preflight max age does not exactly match {PREFLIGHT_MAX_AGE_ENV_KEY}",
        )
        measured_compose_plugin = run_production_readiness.open_measured_executable(
            Path(docker_toolchain_settings[DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY]),
            docker_toolchain_settings[DOCKER_COMPOSE_PLUGIN_SHA256_ENV_KEY],
            DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY,
        )
        measured_compose_plugin.close()
    try:
        images_value, images = load_images_env_snapshot(
            snapshots.by_key["production_images_env"]
        )
    except Exception as exc:
        raise ValueError(f"current production images env is invalid: {exc}") from exc

    configured_images = production_env.get(merge_production_images_env.KEY)
    require(
        configured_images == images_value,
        "production readiness env SERVERWARE_PRODUCTION_IMAGES does not match production images env",
    )
    refs = sorted(image["ref"] for image in images)
    digests = sorted(image["digest"] for image in images)
    require(
        refs == sorted(readiness_summary["production_images"]),
        "current production images env refs do not match readiness",
    )
    require(
        digests == sorted(readiness_summary["production_image_digests"]),
        "current production images env digests do not match readiness",
    )
    require(
        refs == sorted(preflight_summary["production_image_refs"]),
        "current production images env refs do not match production host preflight",
    )
    require(
        sorted(production_env) == sorted(preflight_summary["production_env_keys"]),
        "current production readiness env keys do not match production host preflight",
    )
    expected_binary_digest = require_sha256(
        production_env.get("SERVERWARE_EXPECTED_DATA_PLANE_BINARY_DIGEST"),
        "production readiness expected data-plane binary digest",
    )
    require(
        expected_binary_digest == preflight_summary["benchmark_binary_digest"],
        "production readiness expected data-plane binary digest does not match production host preflight benchmark",
    )
    expected_server_instance_id = production_env.get("SERVERWARE_DATA_PLANE_INSTANCE_ID", "")
    require(
        expected_server_instance_id.startswith("spiffe://")
        and len(expected_server_instance_id) > len("spiffe://"),
        "production readiness env does not pin a data-plane SPIFFE instance",
    )
    expected_collector_key_id = require_sha256(
        production_env.get("SERVERWARE_PROXY_PROOF_COLLECTOR_KEY_ID"),
        "production readiness response-proof collector key id",
    )
    expected_verifier_key_id = require_sha256(
        production_env.get("SERVERWARE_PROXY_PROOF_VERIFIER_KEY_ID"),
        "production readiness response-proof verifier key id",
    )
    expected_proxy_principal_id = production_env.get(PROXY_PRINCIPAL_ENV_KEY)
    require(
        isinstance(expected_proxy_principal_id, str)
        and expected_proxy_principal_id == expected_proxy_principal_id.strip()
        and 1 <= len(expected_proxy_principal_id) <= 256
        and all(character.isprintable() for character in expected_proxy_principal_id),
        "production readiness expected proxy principal ID is invalid",
    )
    expected_proxy_digests = {
        env_name: require_sha256(
            production_env.get(env_name),
            f"production readiness expected proxy digest {env_name}",
        )
        for env_name in PROXY_EXPECTED_DIGEST_ENV_KEYS.values()
    }
    if strict_execution:
        require(proxy_digest_inputs is not None, "final verification is missing expected proxy digest inputs")
        for attribute, env_name in PROXY_EXPECTED_DIGEST_ENV_KEYS.items():
            require(
                proxy_digest_inputs.get(attribute) == expected_proxy_digests[env_name],
                f"selected {attribute.replace('_', ' ')} does not exactly match the hashed production readiness env",
            )
    runtime_trust = preflight_summary["runtime_trust_materials"]
    require(
        runtime_trust.get("proof_collector_key_id") == expected_collector_key_id,
        "production readiness response-proof collector key id does not match production host preflight",
    )
    require(
        runtime_trust.get("proof_verifier_key_id") == expected_verifier_key_id,
        "production readiness response-proof verifier key id does not match production host preflight",
    )
    raw_executable_digest_manifest = production_env.get(
        preflight_module.ATTESTATION_EXECUTABLE_DIGEST_MANIFEST_ENV
    )
    try:
        executable_digest_manifest = json.loads(str(raw_executable_digest_manifest))
    except json.JSONDecodeError as exc:
        raise ValueError(
            "production readiness attestation executable digest manifest is invalid JSON"
        ) from exc
    require(
        isinstance(executable_digest_manifest, dict)
        and set(executable_digest_manifest)
        == preflight_module.PINNED_EXECUTABLE_COMMAND_SETTINGS,
        "production readiness attestation executable digest manifest is not closed and complete",
    )
    expected_executable_digests = {
        setting: require_sha256(
            executable_digest_manifest.get(setting),
            f"production readiness executable digest pin for {setting}",
        )
        for setting in sorted(preflight_module.PINNED_EXECUTABLE_COMMAND_SETTINGS)
    }
    require(
        runtime_trust.get("executable_digests") == expected_executable_digests,
        "production host preflight executable digests do not match the hashed production readiness env pins",
    )
    current_executable_reports, current_executable_failures = (
        preflight_module.snapshot_pinned_executables(production_env)
    )
    require(
        not current_executable_failures,
        "current pinned executable remeasurement failed: " + "; ".join(current_executable_failures),
    )
    current_executable_digests = {
        item["setting"]: item["sha256"] for item in current_executable_reports
    }
    require(
        current_executable_digests == expected_executable_digests,
        "current executable bytes do not match the hashed production readiness env pins",
    )
    current_script_digests: dict[str, str] = {}
    if strict_execution:
        expected_script_pins = {
            setting: production_env.get(setting)
            for setting in run_production_readiness.PINNED_PYTHON_SCRIPTS.values()
        }
        expected_script_digests = {
            setting: require_sha256(value, f"production readiness Python script digest pin {setting}")
            for setting, value in expected_script_pins.items()
        }
        require(
            runtime_trust.get("python_script_digests") == expected_script_digests,
            "production host preflight Python script digests do not match the hashed production readiness env pins",
        )
        current_script_reports, current_script_failures = preflight_module.snapshot_pinned_python_scripts(
            production_env
        )
        require(
            not current_script_failures,
            "current pinned Python script remeasurement failed: " + "; ".join(current_script_failures),
        )
        current_script_digests = {item["setting"]: item["sha256"] for item in current_script_reports}
        require(
            current_script_digests == expected_script_digests,
            "current Python script bytes do not match the hashed production readiness env pins",
        )
        if remeasure_runtime_trust:
            current_runtime_trust, current_runtime_failures = (
                preflight_module.runtime_trust_materials_check(
                    production_env,
                    skip_host_check=False,
                )
            )
            require(
                not current_runtime_failures and current_runtime_trust.get("ok") is True,
                "current runtime trust material revalidation failed: "
                + "; ".join(current_runtime_failures),
            )
            require(
                current_runtime_trust.get("material_digests")
                == runtime_trust.get("material_digests"),
                "current TLS/audit/proof material bytes differ from the authenticated production host preflight",
            )
            require(
                current_runtime_trust.get("proof_collector_key_id")
                == runtime_trust.get("proof_collector_key_id")
                and current_runtime_trust.get("proof_verifier_key_id")
                == runtime_trust.get("proof_verifier_key_id"),
                "current proof signing identities differ from the authenticated production host preflight",
            )
            require(
                current_runtime_trust.get("docker_toolchain")
                == runtime_trust.get("docker_toolchain"),
                "current Docker toolchain/daemon binding differs from the authenticated production host preflight",
            )
        require(
            preflight_summary.get("production_compose_renderer")
            == {
                "path": docker_toolchain_settings[
                    DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY
                ],
                "sha256": docker_toolchain_settings[
                    DOCKER_COMPOSE_PLUGIN_SHA256_ENV_KEY
                ],
            },
            "authenticated preflight Compose renderer does not match the hashed production env pin",
        )
        require(
            preflight_summary.get("production_compose_project_name")
            == docker_toolchain_settings[
                run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV
            ],
            "authenticated preflight Compose project name does not match the hashed production env pin",
        )
    production_readiness_env_sha256 = snapshots.by_key["production_readiness_env"].sha256
    production_images_env_sha256 = snapshots.by_key["production_images_env"].sha256
    require(
        production_readiness_env_sha256 == preflight_summary["production_readiness_env_sha256"],
        "current production readiness env digest does not match production host preflight",
    )
    require(
        production_images_env_sha256 == preflight_summary["production_images_env_sha256"],
        "current production images env digest does not match production host preflight",
    )
    for summary_label, summary in (
        ("production readiness", readiness_summary),
        ("production config gate", config_summary),
    ):
        environment = summary["environment"]
        require(
            environment["production_readiness_env_sha256"] == production_readiness_env_sha256,
            f"{summary_label} env digest does not match current production readiness env",
        )
        require(
            environment["production_images_env_sha256"] == production_images_env_sha256,
            f"{summary_label} image env digest does not match current production images env",
        )

    require(release_trust_inputs is not None, "release completion is missing production env trust bindings")
    for env_name, label in (
        (RELEASE_PROVENANCE_TRUST_ROOT_ENV_KEY, "release provenance trust root"),
        (SIGSTORE_TRUST_ROOT_ENV_KEY, "Sigstore trust root"),
        (REKOR_TRUST_ROOT_ENV_KEY, "Rekor trust root"),
        (EXTERNAL_CHECKPOINT_TRUST_ROOT_ENV_KEY, "external checkpoint trust root"),
        (EXTERNAL_CHECKPOINT_PROVIDER_ENV_KEY, "external checkpoint provider"),
        (
            CONTROL_PLANE_RESPONSE_SIGNING_KEY_ENV_KEY,
            "control-plane response signing trust root",
        ),
        (
            CONTROL_PLANE_RESPONSE_SIGNING_KEY_ID_ENV_KEY,
            "control-plane response signing expected SPKI identity",
        ),
        (
            run_production_readiness.POLICY_TRUST_ROOT_ENV,
            "policy identity trust root",
        ),
        (
            run_production_readiness.POLICY_TRUST_ROOT_ID_ENV,
            "policy identity expected SPKI identity",
        ),
        (
            run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ENV,
            "policy activation trust root",
        ),
        (
            run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV,
            "policy activation expected SPKI identity",
        ),
        (
            run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ENV,
            "reproducible-build trust root",
        ),
        (
            run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV,
            "reproducible-build expected SPKI identity",
        ),
    ):
        if (
            not strict_execution
            and env_name
            in {
                run_production_readiness.POLICY_TRUST_ROOT_ENV,
                run_production_readiness.POLICY_TRUST_ROOT_ID_ENV,
                run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ENV,
                run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV,
                run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ENV,
                run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV,
            }
        ):
            continue
        selected = release_trust_inputs.get(env_name)
        require(isinstance(selected, str) and bool(selected), f"release completion is missing the selected {label}")
        require(
            production_env.get(env_name) == selected,
            f"selected {label} does not exactly match the hashed production readiness env",
        )
    try:
        release_provenance_trust_root_id = release_public_key_id(
            snapshot_text(snapshots.by_key["release_provenance_trusted_public_key"], "release provenance trust root", encoding="ascii")
        )
        sigstore_trust_root_id = release_public_key_id(
            snapshot_text(snapshots.by_key["sigstore_trusted_public_key"], "Sigstore trust root", encoding="ascii")
        )
        rekor_trust_root_id = release_public_key_id(
            snapshot_text(snapshots.by_key["rekor_trusted_public_key"], "Rekor trust root", encoding="ascii")
        )
        external_checkpoint_trust_root_id = release_public_key_id(
            snapshot_text(snapshots.by_key["external_checkpoint_trusted_public_key"], "external checkpoint trust root", encoding="ascii")
        )
        policy_trust_root_id = release_public_key_id(
            snapshot_text(
                snapshots.by_key["policy_trusted_public_key"],
                "policy identity trust root",
                encoding="ascii",
            )
        )
        policy_activation_trust_root_id = release_public_key_id(
            snapshot_text(
                snapshots.by_key["policy_activation_trusted_public_key"],
                "policy activation trust root",
                encoding="ascii",
            )
        )
        reproducible_build_trust_root_id = release_public_key_id(
            snapshot_text(
                snapshots.by_key["reproducible_build_trusted_public_key"],
                "reproducible-build trust root",
                encoding="ascii",
            )
        )
    except Exception as exc:
        raise ValueError(f"production readiness env release trust root is unreadable or invalid: {exc}") from exc
    require(
        final_file_snapshots is not None,
        "release completion is missing immutable control-plane response signing snapshots",
    )
    try:
        control_plane_response_signing_public_key_pem = snapshot_text(
            final_file_snapshots[
                "control_plane_response_signing_public_key"
            ],
            "control-plane response signing trust root",
            encoding="ascii",
        )
    except KeyError as exc:
        raise ValueError(
            f"release completion is missing immutable control-plane response signing trust-root snapshot: {exc}"
        ) from exc
    control_plane_response_signing_key_id = ed25519_public_key_id(
        control_plane_response_signing_public_key_pem,
        "control-plane response signing trust root",
    )
    expected_control_plane_response_signing_key_id = require_sha256(
        production_env.get(CONTROL_PLANE_RESPONSE_SIGNING_KEY_ID_ENV_KEY),
        "production readiness expected control-plane response signing SPKI identity",
    )
    require(
        hmac.compare_digest(
            control_plane_response_signing_key_id,
            expected_control_plane_response_signing_key_id,
        ),
        "control-plane response signing trust root does not match the independently configured SPKI identity",
    )
    policy_role_ids = {
        "policy_identity": policy_trust_root_id,
        "policy_activation": policy_activation_trust_root_id,
        "reproducible_build": reproducible_build_trust_root_id,
    }
    policy_role_settings = {
        "policy_identity": run_production_readiness.POLICY_TRUST_ROOT_ID_ENV,
        "policy_activation": run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV,
        "reproducible_build": run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV,
    }
    for role, key_id in policy_role_ids.items():
        if strict_execution:
            require(
                hmac.compare_digest(
                    key_id,
                    require_sha256(
                        production_env.get(policy_role_settings[role]),
                        f"production readiness {role} expected SPKI identity",
                    ),
                ),
                f"{role} trust-root bytes do not match the hashed production env SPKI pin",
            )
            preflight_role = nested(
                preflight_summary,
                "release_security_evidence",
                "trust_roots",
                role,
            )
            require(
                isinstance(preflight_role, dict)
                and preflight_role.get("spki_sha256") == key_id
                and preflight_role.get("sha256")
                == snapshots.by_key[
                    {
                        "policy_identity": "policy_trusted_public_key",
                        "policy_activation": "policy_activation_trusted_public_key",
                        "reproducible_build": "reproducible_build_trusted_public_key",
                    }[role]
                ].sha256,
                f"current {role} trust root differs from the authenticated preflight",
            )
    existing_release_trust_root_ids = {
        release_provenance_trust_root_id,
        sigstore_trust_root_id,
        rekor_trust_root_id,
        external_checkpoint_trust_root_id,
    }
    require(
        control_plane_response_signing_key_id
        not in existing_release_trust_root_ids,
        "control-plane responses must use an independent signing public key",
    )
    if strict_execution:
        require(
            len(set(policy_role_ids.values())) == len(policy_role_ids),
            "policy identity, activation, and reproducible-build roles must use distinct public keys",
        )
    release_trust_binding = {
        "release_trust_roots_env_bound": True,
        "release_provenance_trusted_public_key_id": release_provenance_trust_root_id,
        "sigstore_trusted_public_key_id": sigstore_trust_root_id,
        "rekor_trusted_public_key_id": rekor_trust_root_id,
        "external_checkpoint_trusted_public_key_id": external_checkpoint_trust_root_id,
        "external_checkpoint_provider": production_env[EXTERNAL_CHECKPOINT_PROVIDER_ENV_KEY],
        "control_plane_response_signing_public_key_id": (
            control_plane_response_signing_key_id
        ),
        "policy_trusted_public_key_id": policy_trust_root_id,
        "policy_activation_trusted_public_key_id": policy_activation_trust_root_id,
        "reproducible_build_trusted_public_key_id": (
            reproducible_build_trust_root_id
        ),
    }

    final_trust_binding: dict[str, Any] = {
        "verification_mode": verification_mode,
        "final_trust_roots_env_bound": False,
    }
    if verification_mode == "final":
        require(final_inputs is not None, "final verification mode is missing final input bindings")
        require(
            production_env.get(FINAL_MODE_ENV_KEY) == "final",
            f"production readiness env must set {FINAL_MODE_ENV_KEY}=final for final verification",
        )
        for env_name, label in (
            (FINAL_HARDWARE_ASSURANCE_ENV_KEY, "hardware assurance evidence"),
            (FINAL_HARDWARE_TRUST_ROOT_ENV_KEY, "hardware assurance trust root"),
            (FINAL_HARDWARE_TRUST_ROOT_ID_ENV_KEY, "hardware assurance expected SPKI identity"),
            (FINAL_CHALLENGE_RECEIPT_ENV_KEY, "final challenge receipt"),
            (FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ENV_KEY, "final challenge authority trust root"),
            (
                FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ID_ENV_KEY,
                "final challenge authority expected SPKI identity",
            ),
            (FINAL_CHALLENGE_AUTHORITY_PROVIDER_ENV_KEY, "final challenge authority provider"),
        ):
            selected = final_inputs.get(env_name)
            require(
                isinstance(selected, str) and bool(selected),
                f"final verification is missing the selected {label}",
            )
            require(
                production_env.get(env_name) == selected,
                f"selected {label} does not exactly match the hashed production readiness env",
            )
        env_challenge_nonce = production_env.get(FINAL_HARDWARE_CHALLENGE_NONCE_ENV_KEY)
        env_challenge_digest = production_env.get(FINAL_HARDWARE_CHALLENGE_DIGEST_ENV_KEY)
        require(
            bool(env_challenge_nonce) != bool(env_challenge_digest),
            "hashed production readiness env must pin exactly one hardware assurance expected challenge nonce or digest",
        )
        selected_challenge_nonce = final_inputs.get(FINAL_HARDWARE_CHALLENGE_NONCE_ENV_KEY)
        selected_challenge_digest = final_inputs.get(FINAL_HARDWARE_CHALLENGE_DIGEST_ENV_KEY)
        require(
            bool(selected_challenge_nonce) != bool(selected_challenge_digest),
            "final verification must select exactly one hardware assurance expected challenge nonce or digest",
        )
        require(
            env_challenge_nonce == selected_challenge_nonce
            and env_challenge_digest == selected_challenge_digest,
            "selected hardware assurance expected challenge does not exactly match the hashed production readiness env",
        )
        require(final_file_snapshots is not None, "final verification is missing immutable final-file snapshots")
        try:
            hardware_trust_root_pem = snapshot_text(
                final_file_snapshots["hardware_assurance_trusted_public_key"],
                "hardware assurance trust root",
                encoding="ascii",
            )
            authority_trust_root_pem = snapshot_text(
                final_file_snapshots["final_challenge_authority_public_key"],
                "final challenge authority trust root",
                encoding="ascii",
            )
        except KeyError as exc:
            raise ValueError(f"final verification is missing immutable trust-root snapshot: {exc}") from exc
        hardware_trust_root_id = release_public_key_id(hardware_trust_root_pem)
        authority_trust_root_id = release_public_key_id(authority_trust_root_pem)
        expected_hardware_trust_root_id = require_sha256(
            production_env.get(FINAL_HARDWARE_TRUST_ROOT_ID_ENV_KEY),
            "production readiness expected hardware assurance verifier SPKI identity",
        )
        expected_authority_trust_root_id = require_sha256(
            production_env.get(FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ID_ENV_KEY),
            "production readiness expected final challenge authority SPKI identity",
        )
        require(
            hmac.compare_digest(hardware_trust_root_id, expected_hardware_trust_root_id),
            "hardware assurance verifier key bytes do not match the independently configured SPKI identity",
        )
        require(
            hmac.compare_digest(authority_trust_root_id, expected_authority_trust_root_id),
            "final challenge authority key bytes do not match the independently configured SPKI identity",
        )
        require(
            not hmac.compare_digest(hardware_trust_root_id, authority_trust_root_id),
            "hardware assurance verifier and final challenge authority must use different public keys",
        )
        release_role_ids = {
            release_trust_binding["release_provenance_trusted_public_key_id"],
            release_trust_binding["sigstore_trusted_public_key_id"],
            release_trust_binding["rekor_trusted_public_key_id"],
            release_trust_binding["external_checkpoint_trusted_public_key_id"],
            release_trust_binding[
                "control_plane_response_signing_public_key_id"
            ],
            release_trust_binding["policy_trusted_public_key_id"],
            release_trust_binding["policy_activation_trusted_public_key_id"],
            release_trust_binding["reproducible_build_trusted_public_key_id"],
        }
        require(
            hardware_trust_root_id not in release_role_ids,
            "hardware assurance verifier must not reuse a release trust public key",
        )
        require(
            authority_trust_root_id not in release_role_ids,
            "final challenge authority must not reuse a release trust public key",
        )
        final_trust_binding = {
            "verification_mode": verification_mode,
            "final_trust_roots_env_bound": True,
            "hardware_assurance_trusted_public_key_id": hardware_trust_root_id,
            "final_challenge_authority_public_key_id": authority_trust_root_id,
            "final_challenge_authority_provider": production_env[FINAL_CHALLENGE_AUTHORITY_PROVIDER_ENV_KEY],
            "hardware_assurance_expected_challenge_selector": (
                "nonce" if env_challenge_nonce is not None else "nonce_sha256"
            ),
        }
    return {
        **release_trust_binding,
        **final_trust_binding,
        "production_readiness_env_sha256": production_readiness_env_sha256,
        "production_images_env_sha256": production_images_env_sha256,
        "production_env_keys": sorted(production_env),
        "production_images_key": merge_production_images_env.KEY,
        "production_images_key_bound": True,
        "preflight_env_files_bound": True,
        "production_image_refs": refs,
        "production_image_digests": digests,
        "expected_data_plane_binary_digest": expected_binary_digest,
        "expected_server_instance_id": expected_server_instance_id,
        "expected_proxy_principal_id": expected_proxy_principal_id,
        "expected_proxy_collector_key_id": expected_collector_key_id,
        "expected_proxy_verifier_key_id": expected_verifier_key_id,
        "current_executable_digests": current_executable_digests,
        "current_python_script_digests": current_script_digests,
        "launcher_trust": launcher_trust,
        "proxy_proof_max_age_seconds": expected_proxy_proof_max_age_seconds,
        "proxy_proof_contract": expected_proxy_proof_contract,
        "proxy_stream_body": expected_proxy_stream_body,
        "proxy_max_stream_bytes": expected_proxy_max_stream_bytes,
        "proxy_observation_body": expected_proxy_observation_body,
        "proxy_max_observation_body_bytes": (
            expected_proxy_max_observation_body_bytes
        ),
        "proxy_operation_context_digest": expected_operation_context_digest,
        "p99_limit_ns": expected_p99_limit_ns,
        "docker_executable": expected_docker_executable,
        "docker_compose_plugin_executable": docker_toolchain_settings[
            DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV_KEY
        ],
        "docker_compose_plugin_sha256": docker_toolchain_settings[
            DOCKER_COMPOSE_PLUGIN_SHA256_ENV_KEY
        ],
        "docker_unix_socket": docker_toolchain_settings[DOCKER_UNIX_SOCKET_ENV_KEY],
        "docker_daemon_id": docker_toolchain_settings[DOCKER_DAEMON_ID_ENV_KEY],
        "docker_compose_project_name": docker_toolchain_settings[
            run_production_readiness.DOCKER_COMPOSE_PROJECT_NAME_ENV
        ],
        "production_host_preflight_signing_public_key": expected_preflight_public_key,
        "production_host_preflight_signing_key_id": expected_preflight_key_id,
        "production_host_preflight_max_age_seconds": expected_preflight_max_age,
        **expected_proxy_digests,
    }


def verify_current_interpreter_binding(
    production_env: dict[str, str],
    executable_digests: dict[str, str],
) -> dict[str, Any]:
    setting = run_production_readiness.PRODUCTION_PYTHON_EXECUTABLE_ENV
    configured_path = production_env.get(setting)
    require(
        isinstance(configured_path, str) and Path(configured_path).is_absolute(),
        f"production readiness env must pin absolute {setting}",
    )
    expected_digest = executable_digests.get(setting)
    require(isinstance(expected_digest, str), "production Python digest pin is missing")
    measured = run_production_readiness.open_measured_executable(
        Path(configured_path),
        expected_digest,
        setting,
    )
    try:
        if sys.platform.startswith("linux"):
            descriptor = os.open("/proc/self/exe", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            source = "/proc/self/exe"
            try:
                current_metadata = os.fstat(descriptor)
                current_bytes = run_production_readiness.read_fd_bytes(
                    descriptor,
                    current_metadata,
                    "currently executing Python interpreter",
                    max_bytes=run_production_readiness.MAX_EXECUTABLE_BYTES,
                )
            finally:
                os.close(descriptor)
        else:
            current_path = Path(sys.executable).resolve()
            current_bytes, current_metadata = run_production_readiness.read_regular_file_once(
                current_path,
                "currently executing Python interpreter",
                max_bytes=run_production_readiness.MAX_EXECUTABLE_BYTES,
                executable=True,
            )
            source = str(current_path)
        current_digest = sha256_prefixed_bytes(current_bytes)
        require(
            hmac.compare_digest(current_digest, measured.sha256),
            "currently executing interpreter bytes do not match the production Python pin",
        )
        require(
            (current_metadata.st_dev, current_metadata.st_ino)
            == (measured.metadata.st_dev, measured.metadata.st_ino),
            "currently executing interpreter inode does not match the production Python pin",
        )
        return {
            "path": configured_path,
            "sha256": current_digest,
            "device": current_metadata.st_dev,
            "inode": current_metadata.st_ino,
            "measured_from": source,
            "matches_pinned_path_inode": True,
        }
    finally:
        measured.close()


def verify_current_script_binding(production_env: dict[str, str]) -> dict[str, Any]:
    setting = run_production_readiness.VERIFY_RELEASE_COMPLETION_SCRIPT_SHA256_ENV
    expected_digest = require_sha256(
        production_env.get(setting),
        "release completion verifier script digest pin",
    )
    raw_descriptor = os.environ.get("SERVERWARE_EXECUTING_SCRIPT_FD")
    require(
        isinstance(raw_descriptor, str) and raw_descriptor.isdigit(),
        "final verifier was not launched from a retained measured script descriptor",
    )
    descriptor = int(raw_descriptor)
    metadata = os.fstat(descriptor)
    os.lseek(descriptor, 0, os.SEEK_SET)
    data = run_production_readiness.read_fd_bytes(
        descriptor,
        metadata,
        "currently executing release completion verifier script",
        max_bytes=run_production_readiness.MAX_EXECUTABLE_BYTES,
    )
    digest = sha256_prefixed_bytes(data)
    require(
        hmac.compare_digest(digest, expected_digest),
        "currently executing release completion verifier script does not match the hashed env pin",
    )
    configured = run_production_readiness.open_measured_script(
        (Path(__file__).resolve().parent / "verify_release_completion.py"),
        expected_digest,
        setting,
    )
    try:
        require(
            (metadata.st_dev, metadata.st_ino)
            == (configured.metadata.st_dev, configured.metadata.st_ino),
            "currently executing release completion verifier script inode differs from the pinned path",
        )
    finally:
        configured.close()
    return {
        "path": str((Path(__file__).resolve().parent / "verify_release_completion.py")),
        "sha256": digest,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "measured_from": f"/proc/self/fd/{descriptor}",
        "matches_pinned_path_inode": True,
    }


def hashed_environment_from_docker(
    value: Any,
    label: str,
) -> list[dict[str, str]]:
    require(isinstance(value, list), f"{label} environment must be a list")
    variables: dict[str, str] = {}
    for item in value:
        require(
            isinstance(item, str) and "=" in item,
            f"{label} environment entry is invalid",
        )
        name, rendered = item.split("=", 1)
        require(
            bool(name) and "=" not in name and name not in variables,
            f"{label} environment has an invalid or duplicate name",
        )
        variables[name] = sha256_prefixed_bytes(rendered.encode("utf-8"))
    return [
        {"name": name, "value_sha256": variables[name]}
        for name in sorted(variables)
    ]


def merged_expected_environment(
    image_environment: Any,
    compose_environment: Any,
    label: str,
) -> list[dict[str, str]]:
    merged = {
        item["name"]: item["value_sha256"]
        for item in hashed_environment_from_docker(
            image_environment or [], f"{label} image"
        )
    }
    require(
        isinstance(compose_environment, list),
        f"{label} signed Compose environment must be a list",
    )
    for item in compose_environment:
        require(
            isinstance(item, dict)
            and set(item) == {"name", "value_sha256"},
            f"{label} signed Compose environment entry is invalid",
        )
        merged[str(item["name"])] = require_sha256(
            item.get("value_sha256"),
            f"{label} signed Compose environment value",
        )
    return [
        {"name": name, "value_sha256": merged[name]} for name in sorted(merged)
    ]


def compose_resource_runtime_name(
    logical_name: str,
    resources: dict[str, Any],
    project_name: str,
) -> str:
    resource = resources.get(logical_name)
    require(isinstance(resource, dict), f"signed Compose resource is missing: {logical_name}")
    explicit_name = resource.get("name")
    if isinstance(explicit_name, str) and explicit_name:
        return explicit_name
    if resource.get("external") is True:
        return logical_name
    return f"{project_name}_{logical_name}"


def normalized_security_options(
    values: Any,
    *,
    project_directory: Path,
) -> list[str]:
    require(
        values is None
        or (isinstance(values, list) and all(isinstance(item, str) for item in values)),
        "container security options must be a string list",
    )
    normalized: list[str] = []
    for item in values or []:
        if item.startswith("seccomp="):
            prefix, raw_path = item.split("=", 1)
            path = Path(raw_path)
            if not path.is_absolute() and raw_path not in {"unconfined", "default"}:
                path = (project_directory / path).resolve()
                item = f"{prefix}={path}"
        normalized.append(item)
    return sorted(normalized)


def normalize_expected_ports(value: Any, label: str) -> list[dict[str, str]]:
    require(isinstance(value, list), f"{label} ports must be a list")
    normalized: list[dict[str, str]] = []
    for item in value:
        require(isinstance(item, dict), f"{label} port entry must be an object")
        target = item.get("target")
        published = item.get("published")
        require(
            isinstance(target, int) and 1 <= target <= 65535,
            f"{label} target port is invalid",
        )
        require(published is not None, f"{label} published port is required")
        normalized.append(
            {
                "target": str(target),
                "published": str(published),
                "host_ip": str(item.get("host_ip") or ""),
                "protocol": str(item.get("protocol") or "tcp"),
            }
        )
    return sorted(
        normalized,
        key=lambda item: (
            item["target"],
            item["protocol"],
            item["host_ip"],
            item["published"],
        ),
    )


def normalize_observed_ports(value: Any, label: str) -> list[dict[str, str]]:
    require(isinstance(value, dict), f"{label} port bindings must be an object")
    normalized: list[dict[str, str]] = []
    for container_port, bindings in value.items():
        require(
            isinstance(container_port, str) and "/" in container_port,
            f"{label} container port is invalid",
        )
        target, protocol = container_port.rsplit("/", 1)
        require(isinstance(bindings, list), f"{label} port bindings are invalid")
        for binding in bindings:
            require(isinstance(binding, dict), f"{label} port binding is invalid")
            normalized.append(
                {
                    "target": target,
                    "published": str(binding.get("HostPort") or ""),
                    "host_ip": str(binding.get("HostIp") or ""),
                    "protocol": protocol,
                }
            )
    return sorted(
        normalized,
        key=lambda item: (
            item["target"],
            item["protocol"],
            item["host_ip"],
            item["published"],
        ),
    )


def normalize_expected_ulimits(value: Any, label: str) -> list[dict[str, int | str]]:
    require(isinstance(value, dict), f"{label} ulimits must be an object")
    normalized: list[dict[str, int | str]] = []
    for name, limits in sorted(value.items()):
        require(isinstance(limits, dict), f"{label} ulimit {name} is invalid")
        normalized.append(
            {
                "name": name,
                "soft": int(limits.get("soft", 0)),
                "hard": int(limits.get("hard", 0)),
            }
        )
    return normalized


def normalize_observed_ulimits(value: Any, label: str) -> list[dict[str, int | str]]:
    require(isinstance(value, list), f"{label} ulimits must be a list")
    normalized = []
    for item in value:
        require(isinstance(item, dict), f"{label} ulimit entry is invalid")
        normalized.append(
            {
                "name": str(item.get("Name") or ""),
                "soft": int(item.get("Soft")),
                "hard": int(item.get("Hard")),
            }
        )
    return sorted(normalized, key=lambda item: str(item["name"]))


def normalize_expected_mounts(
    service_model: dict[str, Any],
    runtime_model: dict[str, Any],
    image_config: dict[str, Any],
    project_name: str,
) -> list[dict[str, Any]]:
    expected: list[dict[str, Any]] = []
    destinations: set[str] = set()
    for item in service_model.get("mounts") or []:
        require(isinstance(item, dict), "signed Compose mount entry is invalid")
        mount_type = item.get("type")
        target = item.get("target")
        require(
            mount_type in {"bind", "volume", "tmpfs"}
            and isinstance(target, str)
            and target.startswith("/")
            and target not in destinations,
            "signed Compose mount destination is invalid or duplicated",
        )
        destinations.add(target)
        source = str(item.get("source") or "")
        if mount_type == "volume":
            source = compose_resource_runtime_name(
                source,
                runtime_model.get("volumes") or {},
                project_name,
            )
        bind = item.get("bind") if isinstance(item.get("bind"), dict) else {}
        expected.append(
            {
                "type": mount_type,
                "source": source,
                "target": target,
                "read_only": bool(item.get("read_only", False)),
                "propagation": str(bind.get("propagation") or ("rprivate" if mount_type == "bind" else "")),
            }
        )
    image_volumes = image_config.get("Volumes") or {}
    require(isinstance(image_volumes, dict), "image volume defaults must be an object")
    for target in image_volumes:
        require(isinstance(target, str) and target.startswith("/"), "image volume destination is invalid")
        if target not in destinations:
            expected.append(
                {
                    "type": "volume",
                    "source": "<anonymous>",
                    "target": target,
                    "read_only": False,
                    "propagation": "",
                }
            )
    for item in service_model.get("tmpfs") or []:
        require(isinstance(item, dict), "signed Compose tmpfs entry is invalid")
        target = item.get("target")
        require(
            isinstance(target, str) and target.startswith("/") and target not in destinations,
            "signed Compose tmpfs destination is invalid or duplicated",
        )
        options = item.get("options") or []
        destinations.add(target)
        expected.append(
            {
                "type": "tmpfs",
                "source": "",
                "target": target,
                "read_only": "ro" in options and "rw" not in options,
                "propagation": "",
            }
        )
    return sorted(expected, key=lambda item: item["target"])


def normalize_observed_mounts(value: Any, label: str) -> list[dict[str, Any]]:
    require(isinstance(value, list), f"{label} mounts must be a list")
    normalized: list[dict[str, Any]] = []
    destinations: set[str] = set()
    for item in value:
        require(isinstance(item, dict), f"{label} mount entry is invalid")
        mount_type = item.get("Type")
        target = item.get("Destination")
        require(
            mount_type in {"bind", "volume", "tmpfs"}
            and isinstance(target, str)
            and target not in destinations,
            f"{label} mount type or destination is invalid",
        )
        destinations.add(target)
        source = item.get("Name") if mount_type == "volume" else item.get("Source")
        normalized.append(
            {
                "type": mount_type,
                "source": str(source or ""),
                "target": target,
                "read_only": item.get("RW") is not True,
                "propagation": str(item.get("Propagation") or ""),
            }
        )
    return sorted(normalized, key=lambda item: item["target"])


def mount_projections_match(
    expected: list[dict[str, Any]],
    observed: list[dict[str, Any]],
) -> bool:
    if len(expected) != len(observed):
        return False
    for expected_item, observed_item in zip(expected, observed):
        if expected_item["source"] == "<anonymous>":
            if not observed_item["source"]:
                return False
            expected_item = {**expected_item, "source": observed_item["source"]}
        if expected_item != observed_item:
            return False
    return True


def normalized_tmpfs_mapping(value: Any, label: str) -> list[dict[str, Any]]:
    require(isinstance(value, dict), f"{label} tmpfs must be an object")
    return sorted(
        (
            {
                "target": str(target),
                "options": run_production_readiness.normalize_tmpfs_options(
                    str(options).split(",")
                ),
            }
            for target, options in value.items()
        ),
        key=lambda item: item["target"],
    )


def expected_runtime_projection(
    service: str,
    service_model: dict[str, Any],
    runtime_model: dict[str, Any],
    image_config: dict[str, Any],
    *,
    project_name: str,
    project_directory: Path,
) -> dict[str, Any]:
    image_user = str(image_config.get("User") or "")
    compose_user = str(service_model.get("compose_user") or "")
    effective_user = compose_user or image_user
    require(
        effective_user == service_model.get("required_runtime_user"),
        f"production service {service} effective image/Compose user is not the fixed final user",
    )
    image_entrypoint = run_production_readiness.normalize_command_value(
        image_config.get("Entrypoint"), f"{service} image entrypoint"
    )
    image_command = run_production_readiness.normalize_command_value(
        image_config.get("Cmd"), f"{service} image command"
    )
    entrypoint = service_model.get("entrypoint")
    command = service_model.get("command")
    networks = [
        compose_resource_runtime_name(
            name,
            runtime_model.get("networks") or {},
            project_name,
        )
        for name in service_model.get("networks") or []
    ]
    host = service_model.get("host_config")
    require(isinstance(host, dict), f"production service {service} host config is invalid")
    expected_network_mode = str(host.get("network_mode") or "")
    if not expected_network_mode and networks:
        logical_networks = service_model.get("networks") or []
        primary = "default" if "default" in logical_networks else logical_networks[0]
        expected_network_mode = compose_resource_runtime_name(
            primary,
            runtime_model.get("networks") or {},
            project_name,
        )
    expected_ports = normalize_expected_ports(service_model.get("ports") or [], service)
    exposed_ports = set(str(item) for item in (image_config.get("ExposedPorts") or {}))
    exposed_ports.update(
        f"{item['target']}/{item['protocol']}" for item in expected_ports
    )
    return {
        "user": effective_user,
        "entrypoint": image_entrypoint if entrypoint is None else entrypoint,
        "command": image_command if command is None else command,
        "working_dir": str(service_model.get("working_dir") or image_config.get("WorkingDir") or ""),
        "environment": merged_expected_environment(
            image_config.get("Env") or [],
            service_model.get("environment") or [],
            service,
        ),
        "devices": service_model.get("devices") or [],
        "networks": sorted(networks),
        "mounts": normalize_expected_mounts(
            service_model, runtime_model, image_config, project_name
        ),
        "tmpfs": service_model.get("tmpfs") or [],
        "ports": expected_ports,
        "exposed_ports": sorted(exposed_ports),
        "links": service_model.get("links") or [],
        "host_config": {
            "read_only": bool(host.get("read_only")),
            "privileged": bool(host.get("privileged")),
            "publish_all_ports": False,
            "cap_add": sorted(host.get("cap_add") or []),
            "cap_drop": sorted(host.get("cap_drop") or []),
            "security_opt": normalized_security_options(
                host.get("security_opt"), project_directory=project_directory
            ),
            "pids_limit": int(host.get("pids_limit") or 0),
            "memory": int(host.get("memory") or 0),
            "init": bool(host.get("init")),
            "group_add": sorted(host.get("group_add") or []),
            "volumes_from": sorted(host.get("volumes_from") or []),
            "dns": sorted(host.get("dns") or []),
            "dns_search": sorted(host.get("dns_search") or []),
            "dns_opt": sorted(host.get("dns_opt") or []),
            "extra_hosts": sorted(host.get("extra_hosts") or []),
            "pid": str(host.get("pid") or ""),
            "ipc": str(host.get("ipc") or ""),
            "uts": str(host.get("uts") or ""),
            "network_mode": expected_network_mode,
            "userns_mode": str(host.get("userns_mode") or ""),
            "ulimits": normalize_expected_ulimits(host.get("ulimits") or {}, service),
        },
    }


def observed_runtime_projection(
    service: str,
    container: dict[str, Any],
    *,
    project_directory: Path,
) -> dict[str, Any]:
    config = container.get("Config")
    host = container.get("HostConfig")
    network_settings = container.get("NetworkSettings")
    require(isinstance(config, dict), f"production service {service} Config is invalid")
    require(isinstance(host, dict), f"production service {service} HostConfig is invalid")
    require(
        isinstance(network_settings, dict)
        and isinstance(network_settings.get("Networks"), dict),
        f"production service {service} NetworkSettings is invalid",
    )
    devices = []
    for item in host.get("Devices") or []:
        require(isinstance(item, dict), f"production service {service} device is invalid")
        devices.append(
            {
                "source": str(item.get("PathOnHost") or ""),
                "target": str(item.get("PathInContainer") or ""),
                "permissions": str(item.get("CgroupPermissions") or ""),
            }
        )
    projection = {
        "user": str(config.get("User") or ""),
        "entrypoint": run_production_readiness.normalize_command_value(
            config.get("Entrypoint"), f"{service} runtime entrypoint"
        ),
        "command": run_production_readiness.normalize_command_value(
            config.get("Cmd"), f"{service} runtime command"
        ),
        "working_dir": str(config.get("WorkingDir") or ""),
        "environment": hashed_environment_from_docker(
            config.get("Env") or [], f"{service} runtime"
        ),
        "devices": sorted(
            devices,
            key=lambda item: (item["target"], item["source"], item["permissions"]),
        ),
        "networks": sorted(network_settings["Networks"]),
        "mounts": normalize_observed_mounts(container.get("Mounts") or [], service),
        "tmpfs": normalized_tmpfs_mapping(host.get("Tmpfs") or {}, service),
        "ports": normalize_observed_ports(host.get("PortBindings") or {}, service),
        "exposed_ports": sorted((config.get("ExposedPorts") or {}).keys()),
        "links": sorted(host.get("Links") or []),
        "host_config": {
            "read_only": host.get("ReadonlyRootfs") is True,
            "privileged": host.get("Privileged") is True,
            "publish_all_ports": host.get("PublishAllPorts") is True,
            "cap_add": sorted(host.get("CapAdd") or []),
            "cap_drop": sorted(host.get("CapDrop") or []),
            "security_opt": normalized_security_options(
                host.get("SecurityOpt"), project_directory=project_directory
            ),
            "pids_limit": int(host.get("PidsLimit") or 0),
            "memory": int(host.get("Memory") or 0),
            "init": host.get("Init") is True,
            "group_add": sorted(str(item) for item in (host.get("GroupAdd") or [])),
            "volumes_from": sorted(host.get("VolumesFrom") or []),
            "dns": sorted(host.get("Dns") or []),
            "dns_search": sorted(host.get("DnsSearch") or []),
            "dns_opt": sorted(host.get("DnsOptions") or []),
            "extra_hosts": sorted(host.get("ExtraHosts") or []),
            "pid": str(host.get("PidMode") or ""),
            "ipc": str(host.get("IpcMode") or ""),
            "uts": str(host.get("UTSMode") or ""),
            "network_mode": str(host.get("NetworkMode") or ""),
            "userns_mode": str(host.get("UsernsMode") or ""),
            "ulimits": normalize_observed_ulimits(host.get("Ulimits") or [], service),
        },
    }
    return projection


def verify_runtime_projection(
    service: str,
    expected: dict[str, Any],
    observed: dict[str, Any],
) -> None:
    expected_without_mounts = {key: value for key, value in expected.items() if key != "mounts"}
    observed_without_mounts = {key: value for key, value in observed.items() if key != "mounts"}
    require(
        observed_without_mounts == expected_without_mounts,
        f"production service {service} runtime projection differs from signed Compose and pinned image defaults",
    )
    require(
        mount_projections_match(expected["mounts"], observed["mounts"]),
        f"production service {service} complete mount projection differs from signed Compose and pinned image defaults",
    )


def parse_container_copy_archive(
    archive: bytes,
    *,
    expected_sha256: str,
    expected_bytes: int,
    label: str,
) -> dict[str, Any]:
    require(
        0 < expected_bytes <= COMPLETION_INPUT_MAX_BYTES,
        f"{label} approved artifact length is invalid",
    )
    require(
        0 < len(archive) <= expected_bytes + 1024 * 1024,
        f"{label} Docker copy archive is empty or too large",
    )
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:*") as bundle:
            members = bundle.getmembers()
            require(
                len(members) == 1 and members[0].isreg(),
                f"{label} Docker copy archive must contain exactly one regular file",
            )
            member = members[0]
            require(
                member.size == expected_bytes,
                f"{label} container artifact length differs from the approved snapshot",
            )
            extracted = bundle.extractfile(member)
            require(extracted is not None, f"{label} Docker copy archive member is unreadable")
            data = extracted.read(expected_bytes + 1)
    except (tarfile.TarError, OSError) as exc:
        raise ValueError(f"{label} Docker copy archive is invalid: {exc}") from exc
    require(
        len(data) == expected_bytes,
        f"{label} Docker copy archive member length is invalid",
    )
    digest = sha256_prefixed_bytes(data)
    require(
        hmac.compare_digest(digest, require_sha256(expected_sha256, label)),
        f"{label} container-visible bytes differ from the approved snapshot",
    )
    return {
        "sha256": digest,
        "bytes": len(data),
        "tar_members": 1,
        "regular_file": True,
        "container_namespace_verified": True,
    }


def require_stable_container_generation(
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    require(
        before == after,
        "production Compose service IDs, running StartedAt values, or runtime projections changed during inspection",
    )


def verify_running_image_config_ids(
    observed_image_config_ids: dict[str, str],
    approved_image_config_ids: dict[str, str],
) -> dict[str, str]:
    require(
        set(approved_image_config_ids)
        == {"serverware-control", "serverware-decision-gate"},
        "approved production image config identity set is incomplete",
    )
    expected_config_ids = {
        "serverware": require_sha256(
            approved_image_config_ids["serverware-control"],
            "approved control image config id",
        ),
        "audit-anchor": require_sha256(
            approved_image_config_ids["serverware-control"],
            "approved audit-anchor image config id",
        ),
        "decision-gate-rs": require_sha256(
            approved_image_config_ids["serverware-decision-gate"],
            "approved decision-gate image config id",
        ),
        "custody-runtime": require_sha256(
            approved_image_config_ids["serverware-decision-gate"],
            "approved custody image config id",
        ),
    }
    require(
        set(observed_image_config_ids) == set(expected_config_ids),
        "running production image config identity set is incomplete",
    )
    for service, expected_config_id in expected_config_ids.items():
        observed_config_id = require_sha256(
            observed_image_config_ids[service],
            f"production service {service} image id",
        )
        require(
            hmac.compare_digest(observed_config_id, expected_config_id),
            f"production service {service} running image config ID does not match the approved reproduced config identity",
        )
    return expected_config_ids


def verify_running_production_containers(
    *,
    env_file: Path,
    compose_file: Path,
    production_env: dict[str, str],
    project_directory: Path,
    production_image_refs: list[str],
    approved_image_config_ids: dict[str, str],
    source_tree_digest: str,
    runtime_model: dict[str, Any],
    artifact_expectations: dict[str, dict[str, Any]],
    compose_project_name: str,
    skip_current_host_check: bool,
    docker_executable: str,
    docker_sha256: str,
    compose_plugin_executable: str,
    compose_plugin_sha256: str,
    docker_unix_socket: str,
    docker_daemon_id: str,
    final_mode: bool,
) -> dict[str, Any]:
    if skip_current_host_check:
        return {"skipped": True, "containers": []}
    require(final_mode, "live production container verification requires final mode")
    require(
        runtime_model.get("sha256")
        == sha256_prefixed_bytes(
            canonical_json(
                {
                    key: runtime_model[key]
                    for key in ("services", "networks", "volumes")
                }
            ).encode("utf-8")
        ),
        "signed normalized runtime model digest is invalid",
    )
    services_model = runtime_model.get("services")
    require(
        isinstance(services_model, dict)
        and set(services_model) == set(run_production_readiness.FINAL_SERVICE_USERS),
        "signed normalized runtime model service set is incomplete",
    )
    by_name = {
        ref.split("@", 1)[0].rsplit("/", 1)[-1]: ref
        for ref in production_image_refs
    }
    expected_refs = {
        "serverware": by_name["control"],
        "audit-anchor": by_name["control"],
        "decision-gate-rs": by_name["decision-gate"],
        "custody-runtime": by_name["decision-gate"],
    }

    child_env = run_production_readiness.build_final_child_environment(production_env)
    socket_path = Path(docker_unix_socket)
    docker_env = run_production_readiness.docker_subprocess_environment(
        child_env,
        socket_path,
    )
    docker_endpoint = f"unix://{socket_path}"
    daemon_before = run_production_readiness.verify_docker_daemon_identity(
        docker_executable=Path(docker_executable),
        docker_sha256=docker_sha256,
        socket_path=socket_path,
        expected_daemon_id=docker_daemon_id,
        base_env=child_env,
    )

    def measured_text(command: list[str], *, compose: bool = False) -> str:
        expected_executable = compose_plugin_executable if compose else docker_executable
        require(
            command[0] == expected_executable,
            "Docker command did not use its pinned absolute executable",
        )
        if compose:
            require(
                command[1:5]
                == ["--host", docker_endpoint, "--project-name", compose_project_name],
                "Compose command did not pin the Docker endpoint and project name",
            )
        else:
            require(
                command[1:3] == ["--host", docker_endpoint],
                "Docker command did not pin the Docker endpoint",
            )
        result = run_production_readiness.run_measured_command(
            command,
            setting=(
                run_production_readiness.DOCKER_COMPOSE_PLUGIN_EXECUTABLE_ENV
                if compose
                else run_production_readiness.PRODUCTION_DOCKER_EXECUTABLE_ENV
            ),
            expected_digest=compose_plugin_sha256 if compose else docker_sha256,
            cwd=Path(__file__).resolve().parent.parent,
            env=docker_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            text=True,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or result.stdout.strip()
            raise ValueError(
                f"{' '.join(command)} failed with exit {result.returncode}: {detail}"
            )
        return result.stdout.strip()

    def measured_container_copy(
        container_id: str,
        destination: str,
        expected: dict[str, Any],
    ) -> dict[str, Any]:
        command = [
            docker_executable,
            "--host",
            docker_endpoint,
            "container",
            "cp",
            f"{container_id}:{destination}",
            "-",
        ]
        max_archive = int(expected["bytes"]) + 1024 * 1024
        result = run_production_readiness.run_measured_binary_command_bounded(
            command,
            setting=run_production_readiness.PRODUCTION_DOCKER_EXECUTABLE_ENV,
            expected_digest=docker_sha256,
            max_stdout_bytes=max_archive,
            cwd=Path(__file__).resolve().parent.parent,
            env=docker_env,
        )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(
                f"pinned docker container cp failed with exit {result.returncode}: {detail}"
            )
        return parse_container_copy_archive(
            result.stdout,
            expected_sha256=str(expected["sha256"]),
            expected_bytes=int(expected["bytes"]),
            label=f"{container_id}:{destination}",
        )

    compose_base = [
        compose_plugin_executable,
        "--host",
        docker_endpoint,
        "--project-name",
        compose_project_name,
        "--project-directory",
        str(project_directory),
        "--env-file",
        str(env_file),
        "-f",
        str(compose_file),
    ]

    def snapshot_ids() -> dict[str, str]:
        identifiers: dict[str, str] = {}
        for service in sorted(expected_refs):
            identifier = measured_text(
                [*compose_base, "ps", "-q", service], compose=True
            )
            require(
                re.fullmatch(r"[0-9a-f]{64}", identifier) is not None,
                f"production Compose service {service} did not resolve to one full container ID",
            )
            identifiers[service] = identifier
        require(
            len(set(identifiers.values())) == len(identifiers),
            "production Compose services resolved to duplicate container IDs",
        )
        return identifiers

    def inspect_containers(identifiers: dict[str, str]) -> dict[str, dict[str, Any]]:
        raw = json.loads(
            measured_text(
                [
                    docker_executable,
                    "--host",
                    docker_endpoint,
                    "container",
                    "inspect",
                    *[identifiers[service] for service in sorted(identifiers)],
                ]
            )
        )
        require(
            isinstance(raw, list) and len(raw) == len(identifiers),
            "Docker container inspection did not return the complete service set",
        )
        by_id = {
            str(item.get("Id")): item for item in raw if isinstance(item, dict)
        }
        require(
            set(by_id) == set(identifiers.values()),
            "Docker container inspection IDs differ from the Compose snapshot",
        )
        return {service: by_id[identifier] for service, identifier in identifiers.items()}

    ids_before = snapshot_ids()
    containers_before = inspect_containers(ids_before)
    image_ids: dict[str, str] = {}
    for service, container in containers_before.items():
        require(
            (container.get("State") or {}).get("Status") == "running",
            f"production service {service} is not running",
        )
        require(
            (container.get("Config") or {}).get("Image") == expected_refs[service]
            == services_model[service].get("image"),
            f"production service {service} was not created from the signed digest-pinned image ref",
        )
        image_ids[service] = require_sha256(
            container.get("Image"), f"production service {service} image id"
        )
    expected_config_ids = verify_running_image_config_ids(
        image_ids,
        approved_image_config_ids,
    )
    raw_images = json.loads(
        measured_text(
            [
                docker_executable,
                "--host",
                docker_endpoint,
                "image",
                "inspect",
                *sorted(set(image_ids.values())),
            ]
        )
    )
    require(isinstance(raw_images, list), "Docker image inspection is invalid")
    images = {
        str(item.get("Id")): item for item in raw_images if isinstance(item, dict)
    }
    require(
        set(images) == set(image_ids.values()),
        "Docker image inspection did not return every running image",
    )

    generation_before: dict[str, Any] = {}
    container_summaries: list[dict[str, Any]] = []
    for service in sorted(expected_refs):
        container = containers_before[service]
        image_id = image_ids[service]
        image = images[image_id]
        require(
            expected_refs[service] in (image.get("RepoDigests") or []),
            f"production service {service} local image does not retain the approved registry digest",
        )
        labels = ((image.get("Config") or {}).get("Labels")) or {}
        require(
            labels.get("dev.serverware.source_tree_digest") == source_tree_digest,
            f"production service {service} image source-tree label does not match release provenance",
        )
        expected_projection = expected_runtime_projection(
            service,
            services_model[service],
            runtime_model,
            image.get("Config") or {},
            project_name=compose_project_name,
            project_directory=project_directory,
        )
        observed_projection = observed_runtime_projection(
            service, container, project_directory=project_directory
        )
        verify_runtime_projection(service, expected_projection, observed_projection)
        started_at = (container.get("State") or {}).get("StartedAt")
        require(
            isinstance(started_at, str) and bool(started_at),
            f"production service {service} running StartedAt is missing",
        )
        generation_before[service] = {
            "container_id": ids_before[service],
            "started_at": started_at,
            "image_id": image_id,
            "runtime_projection": observed_projection,
        }
        namespace_artifacts: dict[str, Any] = {}
        if service in {"serverware", "decision-gate-rs"}:
            for destination, expectation in sorted(artifact_expectations.items()):
                namespace_artifacts[destination] = measured_container_copy(
                    ids_before[service], destination, expectation
                )
        container_summaries.append(
            {
                "service": service,
                **generation_before[service],
                "image_ref": expected_refs[service],
                "source_tree_digest": source_tree_digest,
                "container_namespace_artifacts": namespace_artifacts,
            }
        )

    ids_after = snapshot_ids()
    require(
        ids_after == ids_before,
        "production Compose service ID mapping changed during runtime inspection",
    )
    containers_after = inspect_containers(ids_after)
    generation_after: dict[str, Any] = {}
    for service in sorted(expected_refs):
        container = containers_after[service]
        require(
            (container.get("State") or {}).get("Status") == "running",
            f"production service {service} stopped during runtime inspection",
        )
        require(
            require_sha256(
                container.get("Image"), f"production service {service} final image id"
            )
            == image_ids[service],
            f"production service {service} image changed during runtime inspection",
        )
        final_projection = observed_runtime_projection(
            service, container, project_directory=project_directory
        )
        verify_runtime_projection(
            service,
            expected_runtime_projection(
                service,
                services_model[service],
                runtime_model,
                images[image_ids[service]].get("Config") or {},
                project_name=compose_project_name,
                project_directory=project_directory,
            ),
            final_projection,
        )
        generation_after[service] = {
            "container_id": ids_after[service],
            "started_at": (container.get("State") or {}).get("StartedAt"),
            "image_id": image_ids[service],
            "runtime_projection": final_projection,
        }
    require_stable_container_generation(generation_before, generation_after)

    daemon_after = run_production_readiness.verify_docker_daemon_identity(
        docker_executable=Path(docker_executable),
        docker_sha256=docker_sha256,
        socket_path=socket_path,
        expected_daemon_id=docker_daemon_id,
        base_env=child_env,
    )
    run_production_readiness.require_stable_docker_daemon_binding(
        daemon_before,
        daemon_after,
    )
    return {
        "skipped": False,
        "compose_file": str(compose_file),
        "compose_project_name": compose_project_name,
        "runtime_model_sha256": runtime_model["sha256"],
        "docker_executable": docker_executable,
        "docker_sha256": docker_sha256,
        "compose_plugin_executable": compose_plugin_executable,
        "compose_plugin_sha256": compose_plugin_sha256,
        "docker_daemon_before": daemon_before,
        "docker_daemon_after": daemon_after,
        "service_generation_before": generation_before,
        "service_generation_after": generation_after,
        "approved_image_config_ids": {
            service: expected_config_ids[service] for service in sorted(expected_config_ids)
        },
        "containers": container_summaries,
    }


def ed25519_public_key_der(public_key_pem: str, label: str) -> bytes:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    except Exception as exc:
        raise ValueError(f"{label} public key is invalid") from exc
    require(isinstance(public_key, Ed25519PublicKey), f"{label} public key is not Ed25519")
    return public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def ed25519_public_key_id(public_key_pem: str, label: str) -> str:
    return sha256_prefixed_bytes(ed25519_public_key_der(public_key_pem, label))


def require_base64url_bytes(value: Any, label: str, *, minimum_bytes: int) -> bytes:
    require(isinstance(value, str) and bool(value), f"{label} is required")
    require(BASE64URL_RE.fullmatch(value) is not None, f"{label} must be unpadded base64url")
    try:
        decoded = b64d(value)
    except Exception as exc:
        raise ValueError(f"{label} is invalid base64url") from exc
    require(len(decoded) >= minimum_bytes, f"{label} must contain at least {minimum_bytes} bytes")
    require(base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") == value, f"{label} is not canonical base64url")
    return decoded


def require_unix_time(value: Any, label: str) -> int:
    require(isinstance(value, int) and not isinstance(value, bool), f"{label} must be an integer Unix timestamp")
    require(value > 0, f"{label} must be positive")
    return value


def require_production_identifier(value: Any, label: str) -> str:
    require(isinstance(value, str) and bool(value.strip()), f"{label} is required")
    normalized = value.strip().lower()
    require(
        normalized not in {"none", "none-dev", "dev", "development", "fixture", "self-reported"}
        and not normalized.startswith("dev-")
        and "fixture" not in normalized
        and "self-report" not in normalized,
        f"{label} is not a production identifier",
    )
    return value.strip()


def require_exact_object_fields(value: dict[str, Any], expected_fields: set[str], label: str) -> None:
    validate_canonical_json_profile(value, label=label)
    actual_fields = set(value)
    missing = sorted(expected_fields - actual_fields)
    unexpected = sorted(actual_fields - expected_fields)
    require(
        not missing and not unexpected,
        f"{label} fields do not match the contract; missing={missing}, unexpected={unexpected}",
    )


def is_bounded_printable_utf8_identity(value: Any) -> bool:
    if not isinstance(value, str) or value != value.strip():
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return (
        1 <= len(encoded) <= 256
        and all(character.isprintable() for character in value)
    )


def verify_proxy_release_authority(
    value: Any,
    *,
    expected_request_digest: str,
    expected_operation_digest: str,
    latest_observation_at_unix: int,
) -> dict[str, Any]:
    label = "proxy response release authority"
    require(isinstance(value, dict), f"{label} must be an object")
    authority = dict(value)
    require_exact_object_fields(
        authority,
        {
            "authority_mode",
            "grant_id",
            "approval_id",
            "credential_ref",
            "credential_version",
            "request_digest",
            "operation_digest",
            "attempt_id",
            "consumption_identity_digest",
            "authorization_state_at_upstream_dispatch",
            "authorization_state_observed_at_epoch_ms",
            "reservation_expires_at_epoch_ms",
            "dispatch_expires_at_epoch_ms",
        },
        label,
    )
    require(
        authority.get("authority_mode") == "atomic",
        f"{label} did not use atomic release authorization",
    )
    grant_id = authority.get("grant_id")
    approval_id = authority.get("approval_id")
    for field, identifier in (("grant_id", grant_id), ("approval_id", approval_id)):
        require(
            identifier is None
            or (
                isinstance(identifier, str)
                and identifier == identifier.strip()
                and 1 <= len(identifier) <= 256
                and all(character.isprintable() for character in identifier)
            ),
            f"{label} {field} is invalid",
        )
    require(
        (grant_id is None and approval_id is None)
        or (isinstance(grant_id, str) and isinstance(approval_id, str)),
        f"{label} grant and approval identities are inconsistent",
    )
    credential_ref = authority.get("credential_ref")
    credential_version = authority.get("credential_version")
    require(
        credential_ref is None
        or (
            isinstance(credential_ref, str)
            and credential_ref == credential_ref.strip()
            and 1 <= len(credential_ref) <= 256
            and all(character.isprintable() for character in credential_ref)
        ),
        f"{label} credential_ref is invalid",
    )
    require(
        isinstance(credential_version, int)
        and not isinstance(credential_version, bool)
        and 0 <= credential_version <= 2**63 - 1,
        f"{label} credential_version is invalid",
    )
    require(
        (credential_ref is None and credential_version == 0)
        or (isinstance(credential_ref, str) and credential_version > 0),
        f"{label} credential identity and version are inconsistent",
    )
    request_digest = require_sha256(
        authority.get("request_digest"),
        f"{label} request digest",
    )
    operation_digest = require_sha256(
        authority.get("operation_digest"),
        f"{label} operation digest",
    )
    require(
        request_digest == expected_request_digest,
        f"{label} request digest mismatch",
    )
    require(
        operation_digest == expected_operation_digest,
        f"{label} operation digest mismatch",
    )
    require_sha256(authority.get("attempt_id"), f"{label} attempt ID")
    require_sha256(
        authority.get("consumption_identity_digest"),
        f"{label} consumption identity digest",
    )
    require(
        authority.get("authorization_state_at_upstream_dispatch") == "dispatching",
        f"{label} does not prove historical dispatch authorization",
    )
    observed_at_epoch_ms = authority.get("authorization_state_observed_at_epoch_ms")
    require(
        isinstance(observed_at_epoch_ms, int)
        and not isinstance(observed_at_epoch_ms, bool)
        and 0 < observed_at_epoch_ms <= 2**63 - 1,
        f"{label} dispatch observation timestamp is invalid",
    )
    require(
        observed_at_epoch_ms <= latest_observation_at_unix * 1000 + 999,
        f"{label} dispatch observation postdates the enclosing proof event",
    )
    reservation_expires_at_epoch_ms = authority.get("reservation_expires_at_epoch_ms")
    require(
        reservation_expires_at_epoch_ms is None
        or (
            isinstance(reservation_expires_at_epoch_ms, int)
            and not isinstance(reservation_expires_at_epoch_ms, bool)
            and 0 < reservation_expires_at_epoch_ms <= 2**63 - 1
            and observed_at_epoch_ms < reservation_expires_at_epoch_ms
        ),
        f"{label} reservation expiry is invalid",
    )
    dispatch_expires_at_epoch_ms = authority.get("dispatch_expires_at_epoch_ms")
    require(
        isinstance(dispatch_expires_at_epoch_ms, int)
        and not isinstance(dispatch_expires_at_epoch_ms, bool)
        and observed_at_epoch_ms < dispatch_expires_at_epoch_ms <= 2**63 - 1,
        f"{label} dispatch expiry is invalid",
    )
    require(
        "completion_outcome" not in authority,
        f"{label} must not claim response completion before downstream release",
    )
    return authority


def canonical_control_plane_response_headers(
    value: Any,
    *,
    label: str,
) -> bytes:
    require(
        isinstance(value, list) and 1 <= len(value) <= 128,
        f"{label} response headers must contain 1 to 128 fields",
    )
    previous_name: str | None = None
    total_bytes = 0
    repeatable = {"link", "set-cookie", "warning", "www-authenticate"}
    forbidden = {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
    secret_markers = {
        "authorization",
        "cookie",
        "secret",
        "token",
        "password",
        "passwd",
        "api-key",
        "apikey",
        "private-key",
    }
    for index, item in enumerate(value):
        item_label = f"{label} response header {index}"
        require(isinstance(item, dict), f"{item_label} must be an object")
        require_exact_object_fields(
            item,
            {"name", "value_b64"},
            item_label,
        )
        name = item.get("name")
        require(
            isinstance(name, str)
            and len(name) <= 256
            and bool(re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9a-z]+", name))
            and not name.startswith("x-serverware-response-")
            and name not in forbidden
            and not any(marker in name for marker in secret_markers),
            f"{item_label} name is invalid",
        )
        if previous_name is not None:
            require(
                name >= previous_name,
                f"{label} response headers are not canonically ordered",
            )
            require(
                name != previous_name or name in repeatable,
                f"{label} response headers duplicate a singleton field",
            )
        encoded_value = item.get("value_b64")
        require(
            isinstance(encoded_value, str),
            f"{item_label} value is invalid",
        )
        decoded = (
            b""
            if encoded_value == ""
            else decode_canonical_base64url(
                encoded_value,
                f"{item_label} value",
            )
        )
        require(
            not any(
                byte <= 0x08
                or 0x0A <= byte <= 0x1F
                or byte == 0x7F
                for byte in decoded
            ),
            f"{item_label} value contains a forbidden control byte",
        )
        total_bytes += len(name) + len(decoded)
        require(
            total_bytes <= 64 * 1024,
            f"{label} response headers exceed 64 KiB",
        )
        previous_name = name
    return canonical_json(value).encode("ascii")


def verify_control_plane_receipt_authorization_binding(
    value: Any,
    *,
    expected_release_authority: dict[str, Any],
    expected_principal_id: str,
    expected_route_id: str,
    expected_policy_digest: str,
) -> dict[str, Any] | None:
    if value is None:
        return None
    label = "control-plane authorization receipt trusted authorization binding"
    require(isinstance(value, dict), f"{label} must be an object")
    binding = dict(value)
    base_fields = {
        "attempt_id",
        "flow_id",
        "principal_id",
        "route_id",
        "credential_id",
        "credential_version",
        "policy_hash",
        "request_digest",
        "operation_digest",
        "operation_context",
        "require_jit_grant",
        "shared_quotas",
    }
    durable_present = "api_version" in binding or "durable_policy" in binding
    expected_fields = (
        base_fields | {"api_version", "durable_policy"}
        if durable_present
        else base_fields
    )
    require_exact_object_fields(binding, expected_fields, label)
    if durable_present:
        require(
            binding.get("api_version") == RELEASE_AUTHORIZATION_BINDING_V2
            and isinstance(binding.get("durable_policy"), dict),
            f"{label} durable protocol is inconsistent",
        )
    expected_fields_and_values = {
        "attempt_id": expected_release_authority["attempt_id"],
        "flow_id": expected_release_authority["attempt_id"],
        "principal_id": expected_principal_id,
        "route_id": expected_route_id,
        "credential_id": expected_release_authority["credential_ref"] or "",
        "credential_version": expected_release_authority["credential_version"],
        "policy_hash": expected_policy_digest,
        "request_digest": expected_release_authority["request_digest"],
        "operation_digest": expected_release_authority["operation_digest"],
    }
    for field, expected in expected_fields_and_values.items():
        require(
            binding.get(field) == expected,
            f"{label} identity or digest binding mismatch",
        )
    require(
        isinstance(binding.get("operation_context"), dict),
        f"{label} operation context is invalid",
    )
    require(
        isinstance(binding.get("require_jit_grant"), bool)
        and binding["require_jit_grant"]
        == (
            expected_release_authority["grant_id"] is not None
            and expected_release_authority["approval_id"] is not None
        ),
        f"{label} JIT binding is inconsistent",
    )
    require(
        isinstance(binding.get("shared_quotas"), list)
        and len(binding["shared_quotas"]) <= 256,
        f"{label} shared quota binding is invalid",
    )
    require(
        sha256_prefixed_json(binding)
        == expected_release_authority["consumption_identity_digest"],
        f"{label} digest mismatch",
    )
    if not durable_present:
        return None
    durable = binding["durable_policy"]
    require_exact_object_fields(
        durable,
        {"actorId", "claimDigest", "claims"},
        f"{label} durable policy",
    )
    actor_id = durable.get("actorId")
    require(
        is_bounded_printable_utf8_identity(actor_id),
        f"{label} durable actor is invalid",
    )
    claim_digest = require_sha256(
        durable.get("claimDigest"),
        f"{label} durable claim digest",
    )
    claims = durable.get("claims")
    require(
        isinstance(claims, list)
        and 1 <= len(claims) <= 64
        and all(isinstance(claim, dict) for claim in claims),
        f"{label} durable claims are invalid",
    )
    require(
        claim_digest == sha256_prefixed_json(claims),
        f"{label} durable claim digest mismatch",
    )
    return durable


def verify_custody_authorization_envelope(
    envelope: Any,
    *,
    expected_custody_signing_key_id: str,
    expected_binding_digest: str,
    expected_receipt: Any,
) -> dict[str, Any]:
    label = "custody authorization envelope"
    require(isinstance(envelope, dict), f"{label} must be an object")
    require_exact_object_fields(
        envelope,
        {"statement", "statement_sha256", "signature"},
        label,
    )
    statement = envelope.get("statement")
    require(isinstance(statement, dict), f"{label} statement must be an object")
    statement_digest = require_sha256(
        envelope.get("statement_sha256"),
        f"{label} statement digest",
    )
    require(
        statement_digest == sha256_prefixed_json(statement),
        f"{label} statement digest mismatch",
    )
    signature = envelope.get("signature")
    require(isinstance(signature, dict), f"{label} signature must be an object")
    require_exact_object_fields(
        signature,
        {"algorithm", "key_id", "public_key_pem", "signature"},
        f"{label} signature",
    )
    require(
        signature.get("algorithm") == "Ed25519",
        f"{label} signature algorithm mismatch",
    )
    response_public_key_pem = signature.get("public_key_pem")
    require(
        isinstance(response_public_key_pem, str) and response_public_key_pem,
        f"{label} signing public key is missing",
    )
    response_signing_key_id = ed25519_public_key_id(
        response_public_key_pem,
        f"{label} response signer",
    )
    require(
        signature.get("key_id") == response_signing_key_id,
        f"{label} embedded response signer identity mismatch",
    )
    require(
        hmac.compare_digest(
            response_signing_key_id,
            require_sha256(
                expected_custody_signing_key_id,
                f"{label} expected response signer",
            ),
        ),
        f"{label} response signer mismatch",
    )
    verify_ed25519(
        response_public_key_pem,
        str(signature.get("signature") or ""),
        canonical_json(statement).encode("utf-8"),
        f"{label} statement",
    )
    if isinstance(statement.get("release_authority"), dict):
        binding_digest = statement["release_authority"].get(
            "consumption_identity_digest"
        )
        embedded_receipt = statement.get("control_plane_authorization_receipt")
    else:
        authorization = statement.get("authorization")
        require(
            isinstance(authorization, dict),
            f"{label} statement lacks authorization evidence",
        )
        binding_digest = authorization.get("binding_digest")
        embedded_receipt = authorization.get(
            "control_plane_authorization_receipt"
        )
    binding_digest = require_sha256(
        binding_digest,
        f"{label} binding digest",
    )
    require(
        hmac.compare_digest(
            binding_digest,
            require_sha256(
                expected_binding_digest,
                f"{label} expected binding digest",
            ),
        ),
        f"{label} authorization binding mismatch",
    )
    require(
        embedded_receipt == expected_receipt,
        f"{label} receipt mismatch",
    )
    return {
        "binding_digest": binding_digest,
        "statement_digest": statement_digest,
        "response_signing_key_id": response_signing_key_id,
        "receipt_digest": sha256_prefixed_json(expected_receipt),
        "signature_verified": True,
    }


def verify_control_plane_authorization_receipt(
    document: Any,
    *,
    trusted_public_key_pem: str,
    expected_trusted_public_key_id: str,
    expected_release_authority: dict[str, Any],
    expected_principal_id: str,
    expected_route_id: str,
    expected_runtime_manifest_digest: str,
    expected_policy_digest: str,
    expected_provenance_digest: str,
    expected_image_signatures_digest: str,
    expected_source_tree_digest: str,
    expected_authorization_binding: dict[str, Any] | None = None,
    custody_authorization_envelope: Any | None = None,
    expected_custody_signing_key_id: str | None = None,
) -> dict[str, Any]:
    label = "control-plane authorization receipt"
    require(isinstance(document, dict), f"{label} must be an object")
    assert_no_secret_fields(document)
    require_exact_object_fields(
        document,
        {
            "apiVersion",
            "kind",
            "principal_id",
            "route_id",
            "release_authority",
            "request",
            "response",
        },
        label,
    )
    require(
        document.get("apiVersion")
        == CONTROL_PLANE_AUTHORIZATION_RECEIPT_API_VERSION,
        f"{label} apiVersion mismatch",
    )
    require(
        document.get("kind") == "ControlPlaneAuthorizationReceipt",
        f"{label} kind mismatch",
    )
    require(
        document.get("principal_id") == expected_principal_id,
        f"{label} principal ID mismatch",
    )
    require(
        document.get("route_id") == expected_route_id,
        f"{label} route ID mismatch",
    )
    require(
        document.get("release_authority") == expected_release_authority,
        f"{label} release authority mismatch",
    )
    trusted_durable_binding = verify_control_plane_receipt_authorization_binding(
        expected_authorization_binding,
        expected_release_authority=expected_release_authority,
        expected_principal_id=expected_principal_id,
        expected_route_id=expected_route_id,
        expected_policy_digest=expected_policy_digest,
    )
    custody_authorization_binding: dict[str, Any] | None = None
    if expected_authorization_binding is None:
        require(
            custody_authorization_envelope is not None
            and expected_custody_signing_key_id is not None,
            f"{label} requires an authenticated custody authorization binding",
        )
        custody_authorization_binding = verify_custody_authorization_envelope(
            custody_authorization_envelope,
            expected_custody_signing_key_id=expected_custody_signing_key_id,
            expected_binding_digest=expected_release_authority[
                "consumption_identity_digest"
            ],
            expected_receipt=document,
        )
    else:
        require(
            custody_authorization_envelope is None
            and expected_custody_signing_key_id is None,
            f"{label} authorization binding trust source is ambiguous",
        )

    request = document.get("request")
    require(isinstance(request, dict), f"{label} request must be an object")
    require_exact_object_fields(
        request,
        {"method", "path", "query", "nonce", "body_b64", "body_sha256"},
        f"{label} request",
    )
    require(
        request.get("method") == "POST"
        and request.get("path") == CONTROL_PLANE_DISPATCH_PATH
        and request.get("query") == "",
        f"{label} request context mismatch",
    )
    request_nonce = request.get("nonce")
    request_nonce_bytes = require_base64url_bytes(
        request_nonce,
        f"{label} request nonce",
        minimum_bytes=32,
    )
    require(
        len(request_nonce_bytes) == 32,
        f"{label} request nonce must contain exactly 32 bytes",
    )
    request_body_bytes = decode_canonical_base64url(
        request.get("body_b64"),
        f"{label} request body",
    )
    require(
        0 < len(request_body_bytes) <= 4 * 1024,
        f"{label} request body size is invalid",
    )
    request_body_sha256 = require_sha256(
        request.get("body_sha256"),
        f"{label} request body digest",
    )
    require(
        request_body_sha256 == sha256_prefixed_bytes(request_body_bytes),
        f"{label} request body digest mismatch",
    )
    request_body = load_json_bytes(
        request_body_bytes,
        Path("<embedded-control-plane-dispatch-request>"),
        f"{label} request body",
    )
    require(isinstance(request_body, dict), f"{label} request body must be an object")
    require(
        canonical_json(request_body).encode("utf-8") == request_body_bytes,
        f"{label} request body is not canonical JSON",
    )
    request_version = request_body.get("apiVersion")
    request_base = {
        "apiVersion",
        "attemptId",
        "bindingDigest",
    }
    durable_request: dict[str, Any] | None = None
    if request_version == RELEASE_AUTHORIZATION_DISPATCH_V1:
        require_exact_object_fields(
            request_body,
            request_base,
            f"{label} request body",
        )
        require(
            trusted_durable_binding is None,
            f"{label} v1 request cannot carry a durable authorization binding",
        )
    elif request_version == RELEASE_AUTHORIZATION_DISPATCH_V2:
        # Buffered and observation proofs intentionally keep the full durable
        # binding preimage inside custody. Their callers set the explicit marker
        # only after verifying the custody-signed envelope that binds this receipt.
        require(
            trusted_durable_binding is not None
            or custody_authorization_binding is not None,
            f"{label} v2 request requires the full trusted binding or a verified custody envelope",
        )
        require_exact_object_fields(
            request_body,
            request_base | {"durablePolicy"},
            f"{label} request body",
        )
        durable_value = request_body.get("durablePolicy")
        require(
            isinstance(durable_value, dict),
            f"{label} request durable policy must be an object",
        )
        durable_request = dict(durable_value)
        require_exact_object_fields(
            durable_request,
            {
                "actorId",
                "attemptId",
                "claimDigest",
                "reservationId",
                "dispatchDeadlineAtEpochMs",
            },
            f"{label} request durable policy",
        )
        reservation_id = durable_request.get("reservationId")
        require(
            is_bounded_printable_utf8_identity(reservation_id),
            f"{label} request durable reservation ID is invalid",
        )
        require(
            is_bounded_printable_utf8_identity(
                durable_request.get("actorId")
            )
            and SHA256_RE.fullmatch(str(durable_request.get("claimDigest")))
            is not None
            and durable_request.get("attemptId")
            == expected_release_authority["attempt_id"]
            and durable_request.get("dispatchDeadlineAtEpochMs")
            == expected_release_authority["dispatch_expires_at_epoch_ms"],
            f"{label} request durable policy binding mismatch",
        )
        if trusted_durable_binding is not None:
            require(
                durable_request.get("actorId")
                == trusted_durable_binding["actorId"]
                and durable_request.get("claimDigest")
                == trusted_durable_binding["claimDigest"],
                f"{label} request durable policy differs from the trusted binding",
            )
    else:
        raise ValueError(f"{label} request apiVersion is unsupported")
    require(
        request_body.get("attemptId") == expected_release_authority["attempt_id"]
        and request_body.get("bindingDigest")
        == expected_release_authority["consumption_identity_digest"],
        f"{label} dispatch request body mismatch",
    )

    response = document.get("response")
    require(isinstance(response, dict), f"{label} response must be an object")
    require_exact_object_fields(
        response,
        {
            "status",
            "body_b64",
            "body_sha256",
            "response_headers",
            "response_signing_key_id",
            "statement_b64",
            "statement_sha256",
            "signature",
        },
        f"{label} response",
    )
    response_status = response.get("status")
    require(
        isinstance(response_status, int)
        and not isinstance(response_status, bool)
        and response_status == 200,
        f"{label} response status is not an exact successful dispatch status",
    )

    response_body_bytes = decode_canonical_base64url(
        response.get("body_b64"),
        f"{label} response body",
    )
    require(
        0 < len(response_body_bytes) <= 64 * 1024,
        f"{label} response body size is invalid",
    )
    response_body_sha256 = require_sha256(
        response.get("body_sha256"),
        f"{label} response body digest",
    )
    require(
        response_body_sha256 == sha256_prefixed_bytes(response_body_bytes),
        f"{label} response body digest mismatch",
    )
    response_headers_bytes = canonical_control_plane_response_headers(
        response.get("response_headers"),
        label=label,
    )
    response_body = load_json_bytes(
        response_body_bytes,
        Path("<embedded-control-plane-dispatch-response>"),
        f"{label} response body",
    )
    assert_no_secret_fields(response_body)
    response_base = {
        "apiVersion",
        "ok",
        "authorized",
        "state",
        "reason",
        "attemptId",
        "bindingDigest",
        "idempotentReplay",
        "grantId",
        "approvalRequestId",
        "reservationExpiresAtEpochMs",
        "dispatchStartedAtEpochMs",
        "dispatchExpiresAtEpochMs",
        "completionOutcome",
        "retryAfterSeconds",
        "quotas",
        "store",
    }
    expected_response_version = (
        RELEASE_AUTHORIZATION_RESPONSE_V2
        if durable_request is not None
        else RELEASE_AUTHORIZATION_RESPONSE_V1
    )
    require_exact_object_fields(
        response_body,
        response_base | ({"durablePolicy"} if durable_request is not None else set()),
        f"{label} response body",
    )
    exact_dispatch_fields = {
        "apiVersion": expected_response_version,
        "ok": True,
        "authorized": True,
        "state": "dispatching",
        "reason": "dispatching",
        "attemptId": expected_release_authority["attempt_id"],
        "bindingDigest": expected_release_authority["consumption_identity_digest"],
        "grantId": expected_release_authority["grant_id"],
        "approvalRequestId": expected_release_authority["approval_id"],
        "reservationExpiresAtEpochMs": expected_release_authority[
            "reservation_expires_at_epoch_ms"
        ],
        "dispatchStartedAtEpochMs": expected_release_authority[
            "authorization_state_observed_at_epoch_ms"
        ],
        "dispatchExpiresAtEpochMs": expected_release_authority[
            "dispatch_expires_at_epoch_ms"
        ],
        "completionOutcome": None,
        "retryAfterSeconds": 0,
    }
    for field, expected in exact_dispatch_fields.items():
        require(
            response_body.get(field) == expected,
            f"{label} response body {field} does not match release authority",
        )
    require(
        isinstance(response_body.get("idempotentReplay"), bool),
        f"{label} response body idempotentReplay is invalid",
    )
    quotas = response_body.get("quotas")
    require(
        isinstance(quotas, list) and all(isinstance(item, dict) for item in quotas),
        f"{label} response body quotas are invalid",
    )
    for index, quota in enumerate(quotas):
        quota_label = f"{label} response body quota {index}"
        window_kind = quota.get("windowKind")
        common_fields = {
            "counterKey",
            "constraintId",
            "operation",
            "windowStartEpochMs",
            "max",
            "count",
            "remaining",
            "reservationState",
        }
        if window_kind is None:
            # releaseAuthorization/v1 originally emitted fixed windows without
            # an explicit kind or end. Accept only that closed legacy shape;
            # current calendar windows can never be confused with it.
            require(
                expected_response_version == RELEASE_AUTHORIZATION_RESPONSE_V1,
                f"{quota_label} legacy fixed-window shape is forbidden in v2",
            )
            window_kind = "fixed"
            quota_fields = common_fields | {"windowSeconds"}
            legacy_fixed_window = True
        else:
            require(
                window_kind in {"fixed", "utcDay", "utcIsoWeek", "utcMonth"},
                f"{quota_label} window kind is invalid",
            )
            quota_fields = common_fields | {
                "windowKind",
                "windowEndEpochMs",
                "windowSeconds" if window_kind == "fixed" else "calendarWindow",
            }
            legacy_fixed_window = False
        require_exact_object_fields(quota, quota_fields, quota_label)
        require_sha256(quota.get("counterKey"), f"{quota_label} counter key")
        require_streaming_identifier(
            quota.get("constraintId"), f"{quota_label} constraint ID"
        )
        operation = quota.get("operation")
        require(
            operation is None
            or (
                isinstance(operation, str)
                and require_streaming_identifier(
                    operation, f"{quota_label} operation"
                )
                == operation
            ),
            f"{quota_label} operation is invalid",
        )
        window_start = require_uint64(
            quota.get("windowStartEpochMs"), f"{quota_label} window start"
        )
        if window_kind == "fixed":
            window_seconds = require_uint64(
                quota.get("windowSeconds"), f"{quota_label} window seconds"
            )
            require(
                1 <= window_seconds <= 31_536_000,
                f"{quota_label} window seconds are out of range",
            )
            if not legacy_fixed_window:
                window_end = require_uint64(
                    quota.get("windowEndEpochMs"), f"{quota_label} window end"
                )
                require(
                    window_end == window_start + window_seconds * 1000,
                    f"{quota_label} fixed window mismatch",
                )
        else:
            require(
                quota.get("calendarWindow") == window_kind,
                f"{quota_label} calendar kind mismatch",
            )
            window_end = require_uint64(
                quota.get("windowEndEpochMs"), f"{quota_label} window end"
            )
            require(
                (window_start, window_end)
                == streaming_calendar_window_bounds(window_kind, window_start),
                f"{quota_label} calendar boundaries are not exact",
            )
        maximum = require_uint64(quota.get("max"), f"{quota_label} maximum")
        count = require_uint64(quota.get("count"), f"{quota_label} count")
        remaining = require_uint64(
            quota.get("remaining"), f"{quota_label} remaining count"
        )
        require(
            1 <= maximum <= 1_000_000_000
            and count <= maximum
            and remaining == maximum - count
            and quota.get("reservationState") == "reserved",
            f"{quota_label} lifecycle evidence is invalid",
        )
    store = response_body.get("store")
    require(isinstance(store, dict), f"{label} response body store is invalid")
    require_exact_object_fields(store, {"backend", "ha"}, f"{label} response body store")
    store_backend = store.get("backend")
    require(
        isinstance(store_backend, str)
        and store_backend == store_backend.strip()
        and 1 <= len(store_backend.encode("utf-8")) <= 256
        and all(character.isprintable() for character in store_backend)
        and store.get("ha") is True,
        f"{label} response body does not prove an HA authorization store",
    )

    dispatch_started_at_epoch_ms = response_body["dispatchStartedAtEpochMs"]
    dispatch_expires_at_epoch_ms = response_body["dispatchExpiresAtEpochMs"]
    reservation_expires_at_epoch_ms = response_body["reservationExpiresAtEpochMs"]
    for field, value in (
        ("dispatch start", dispatch_started_at_epoch_ms),
        ("dispatch expiry", dispatch_expires_at_epoch_ms),
        ("reservation expiry", reservation_expires_at_epoch_ms),
    ):
        require(
            isinstance(value, int)
            and not isinstance(value, bool)
            and 0 < value <= 2**63 - 1,
            f"{label} {field} is invalid",
        )
    require(dispatch_started_at_epoch_ms < dispatch_expires_at_epoch_ms, f"{label} dispatch window is invalid")
    require(dispatch_started_at_epoch_ms < reservation_expires_at_epoch_ms, f"{label} reservation expired before dispatch")
    if durable_request is None:
        require(
            trusted_durable_binding is None
            and "durablePolicy" not in response_body,
            f"{label} v1 response cannot carry durable policy state",
        )
    else:
        durable_response_value = response_body.get("durablePolicy")
        require(
            isinstance(durable_response_value, dict),
            f"{label} response durable policy must be an object",
        )
        durable_response = dict(durable_response_value)
        require_exact_object_fields(
            durable_response,
            {
                "state",
                "attemptId",
                "claimDigest",
                "reservationId",
                "actorId",
                "reservationDeadlineAtEpochMs",
                "dispatchDeadlineAtEpochMs",
                "responseEvidenceDigest",
                "failureReason",
                "responseBodySha256",
                "uncertainty",
            },
            f"{label} response durable policy",
        )
        require(
            durable_response.get("state") == "dispatched"
            and durable_response.get("attemptId")
            == expected_release_authority["attempt_id"]
            and durable_response.get("attemptId") == durable_request["attemptId"]
            and durable_response.get("actorId") == durable_request["actorId"]
            and durable_response.get("claimDigest")
            == durable_request["claimDigest"]
            and durable_response.get("reservationId")
            == durable_request["reservationId"]
            and durable_response.get("reservationDeadlineAtEpochMs")
            == reservation_expires_at_epoch_ms
            and durable_response.get("dispatchDeadlineAtEpochMs")
            == dispatch_expires_at_epoch_ms
            and durable_response.get("dispatchDeadlineAtEpochMs")
            == durable_request["dispatchDeadlineAtEpochMs"]
            and durable_response.get("responseEvidenceDigest") is None
            and durable_response.get("failureReason") is None
            and durable_response.get("responseBodySha256") is None
            and durable_response.get("uncertainty") is None,
            f"{label} durable policy lifecycle mismatch",
        )
        if trusted_durable_binding is not None:
            require(
                durable_response.get("actorId")
                == trusted_durable_binding["actorId"]
                and durable_response.get("claimDigest")
                == trusted_durable_binding["claimDigest"],
                f"{label} durable response differs from the trusted binding",
            )

    response_statement_bytes = decode_canonical_base64url(
        response.get("statement_b64"),
        f"{label} response statement",
    )
    require(
        0 < len(response_statement_bytes) <= 64 * 1024,
        f"{label} response statement size is invalid",
    )
    response_statement = load_json_bytes(
        response_statement_bytes,
        Path("<embedded-control-plane-response-statement>"),
        f"{label} response statement",
    )
    require(
        canonical_json(response_statement).encode("utf-8") == response_statement_bytes,
        f"{label} response statement is not canonical JSON",
    )
    require_exact_object_fields(
        response_statement,
        {
            "version",
            "issued_at_ms",
            "request",
            "status_code",
            "body_sha256",
            "response_headers_sha256",
            "response_header_count",
            "nonce",
            "response_signing_key_id",
            "context",
        },
        f"{label} response statement",
    )
    require(
        response_statement.get("version") == CONTROL_PLANE_RESPONSE_SIGNATURE_API_VERSION,
        f"{label} response statement version mismatch",
    )
    issued_at_ms = response_statement.get("issued_at_ms")
    require(
        isinstance(issued_at_ms, int)
        and not isinstance(issued_at_ms, bool)
        and 0 < issued_at_ms <= 2**63 - 1,
        f"{label} signed response issue time is invalid",
    )
    require(
        dispatch_started_at_epoch_ms <= issued_at_ms,
        f"{label} signed response predates dispatch start",
    )
    require(
        issued_at_ms < dispatch_expires_at_epoch_ms,
        f"{label} signed response was issued at or after dispatch expiry",
    )
    require(
        issued_at_ms < reservation_expires_at_epoch_ms,
        f"{label} signed response was issued at or after reservation expiry",
    )

    signed_request = response_statement.get("request")
    require(isinstance(signed_request, dict), f"{label} signed request must be an object")
    require_exact_object_fields(
        signed_request,
        {"method", "path", "query_sha256"},
        f"{label} signed request",
    )
    require(
        signed_request
        == {
            "method": request["method"],
            "path": request["path"],
            "query_sha256": sha256_prefixed_bytes(request["query"].encode("utf-8")),
        },
        f"{label} signed request context mismatch",
    )
    require(response_statement.get("status_code") == response_status, f"{label} signed response status mismatch")
    require(response_statement.get("body_sha256") == response_body_sha256, f"{label} signed response body digest mismatch")
    require(
        response_statement.get("response_headers_sha256")
        == sha256_prefixed_bytes(response_headers_bytes),
        f"{label} signed response header digest mismatch",
    )
    require(
        response_statement.get("response_header_count")
        == len(response["response_headers"]),
        f"{label} signed response header count mismatch",
    )
    require(response_statement.get("nonce") == request_nonce, f"{label} signed response nonce mismatch")

    expected_context = {
        "runtime_manifest_digest": require_sha256(
            expected_runtime_manifest_digest,
            f"expected {label} runtime manifest digest",
        ),
        "policy_bundle_digest": require_sha256(expected_policy_digest, f"expected {label} policy digest"),
        "provenance_digest": require_sha256(expected_provenance_digest, f"expected {label} provenance digest"),
        "image_signatures_digest": require_sha256(
            expected_image_signatures_digest,
            f"expected {label} image signatures digest",
        ),
        "source_tree_digest": require_sha256(expected_source_tree_digest, f"expected {label} source tree digest"),
    }
    require(
        response_statement.get("context") == expected_context,
        f"{label} signed response attested context mismatch",
    )

    trusted_key_id = ed25519_public_key_id(
        trusted_public_key_pem,
        f"{label} trust root",
    )
    require(
        hmac.compare_digest(
            trusted_key_id,
            require_sha256(
                expected_trusted_public_key_id,
                f"expected {label} trust-root identity",
            ),
        ),
        f"{label} trust root does not match the independently configured key ID",
    )
    require(
        response.get("response_signing_key_id") == trusted_key_id,
        f"{label} is not signed by the independently trusted control-plane response key",
    )
    require(
        response_statement.get("response_signing_key_id") == trusted_key_id,
        f"{label} signed response statement key ID mismatch",
    )
    response_statement_sha256 = require_sha256(
        response.get("statement_sha256"),
        f"{label} response statement digest",
    )
    require(
        response_statement_sha256 == sha256_prefixed_bytes(response_statement_bytes),
        f"{label} response statement digest mismatch",
    )
    verify_ed25519(
        trusted_public_key_pem,
        str(response.get("signature") or ""),
        response_statement_bytes,
        label,
    )
    return {
        "apiVersion": document["apiVersion"],
        "signing_key_id": trusted_key_id,
        "principal_id": expected_principal_id,
        "route_id": expected_route_id,
        "request_nonce_sha256": sha256_prefixed_bytes(request_nonce_bytes),
        "request_body_sha256": request_body_sha256,
        "response_body_sha256": response_body_sha256,
        "response_statement_sha256": response_statement_sha256,
        "dispatch_started_at_epoch_ms": dispatch_started_at_epoch_ms,
        "dispatch_expires_at_epoch_ms": dispatch_expires_at_epoch_ms,
        "reservation_expires_at_epoch_ms": reservation_expires_at_epoch_ms,
        "issued_at_ms": issued_at_ms,
        "quotas": quotas,
        "dispatch_request_api_version": request_version,
        "dispatch_response_api_version": expected_response_version,
        "durable_policy_verified": durable_request is not None,
        "idempotent_replay": response_body["idempotentReplay"],
        "custody_authorization_envelope_verified": (
            custody_authorization_binding is not None
        ),
        "custody_authorization_statement_sha256": (
            custody_authorization_binding["statement_digest"]
            if custody_authorization_binding is not None
            else None
        ),
        "custody_authorization_signing_key_id": (
            custody_authorization_binding["response_signing_key_id"]
            if custody_authorization_binding is not None
            else None
        ),
        "canonical_signature_verified": True,
        "dispatch_body_exact_match": True,
        "attested_context_exact_match": True,
        "secret_values_included": False,
    }


def verify_and_compile_policy_snapshot(
    bundle_snapshot: FileSnapshot,
    trusted_key_snapshot: FileSnapshot,
    *,
    expected_policy_digest: str,
) -> PolicySnapshot:
    bundle = load_json_snapshot(bundle_snapshot, "signed production policy bundle")
    trusted_public_key_pem = snapshot_text(
        trusted_key_snapshot,
        "production policy signing trust root",
        encoding="ascii",
    )
    trusted_key_id = ed25519_public_key_id(
        trusted_public_key_pem,
        "production policy signing trust root",
    )
    verification = verify_production_policy_identity.verify_production_policy_identity(
        bundle,
        trusted_public_key_pem,
        trusted_public_key_hash=trusted_key_id,
    )
    require(
        verification.get("ok") is True,
        "snapshotted production policy bundle failed pinned Ed25519 verification",
    )
    try:
        compiled = compile_policy_bundle(
            bundle,
            validate_schema=True,
            verify_signature=False,
        )
    except Exception as exc:
        raise ValueError(f"snapshotted production policy bundle could not be compiled: {exc}") from exc
    expected_digest = require_sha256(expected_policy_digest, "expected production policy digest")
    require(compiled.hash == expected_digest, "snapshotted production policy bundle digest mismatch")
    require(
        (verification.get("policy") or {}).get("hash") == compiled.hash,
        "compiled production policy hash differs from signature verification",
    )
    return compiled


def require_proxy_policy_route(
    policy: PolicySnapshot,
    *,
    principal_id: str,
    route_id: str,
) -> Any:
    label = "proxy response independently matched policy route identity"
    require(
        isinstance(principal_id, str)
        and principal_id == principal_id.strip()
        and 1 <= len(principal_id) <= 256
        and all(character.isprintable() for character in principal_id),
        f"{label} principal ID is invalid",
    )
    require(principal_id in policy.principals, f"{label} principal is absent from the signed policy")
    require(
        isinstance(route_id, str)
        and route_id == route_id.strip()
        and 1 <= len(route_id) <= 256,
        f"{label} route ID is invalid",
    )
    routes = [route for route in policy.routes if route.id == route_id]
    require(len(routes) == 1, f"{label} is absent or ambiguous in the signed policy")
    route = routes[0]
    require(
        principal_id in route.principals or "*" in route.principals,
        f"{label} does not authorize the independently pinned principal",
    )
    return route


def match_proxy_policy_route(
    policy: PolicySnapshot,
    *,
    principal_id: str,
    route_id: str,
) -> tuple[str, set[str]]:
    route = require_proxy_policy_route(
        policy,
        principal_id=principal_id,
        route_id=route_id,
    )
    label = "proxy response independently matched policy route identity"
    response_profile = route.adapter_config.get("response")
    require(isinstance(response_profile, dict), f"{label} success response profile is missing")
    raw_allowed_headers = response_profile.get("allowedHeaders", [])
    require(
        isinstance(raw_allowed_headers, list)
        and all(
            isinstance(name, str)
            and name == name.lower()
            and re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) is not None
            for name in raw_allowed_headers
        )
        and len(raw_allowed_headers) == len(set(raw_allowed_headers)),
        f"{label} success allowedHeaders are invalid",
    )
    return route.id, {
        "content-encoding",
        "content-length",
        "content-type",
        *raw_allowed_headers,
    }


def route_shared_quota_constraints(route: Any) -> list[dict[str, Any]]:
    return [
        constraint
        for constraint in route.constraints
        if constraint.get("type") == "rateLimit"
        and constraint.get("store", "local") == "shared"
        and constraint.get("phase", "request") in {"request", "both"}
    ]


def route_requires_atomic_authorization(route: Any) -> bool:
    return bool(
        route.credential_ref
        or (route.jit or {}).get("required") is True
        or route_shared_quota_constraints(route)
    )


def verify_route_authorization_evidence(
    route: Any,
    release_authority: dict[str, Any],
    control_plane_receipt: dict[str, Any],
    *,
    label: str,
) -> None:
    expected_credential_ref = route.credential_ref
    require(
        release_authority["credential_ref"] == expected_credential_ref,
        f"{label} release authority credential does not match the signed route",
    )
    jit_required = (route.jit or {}).get("required") is True
    has_jit_authority = (
        release_authority["grant_id"] is not None
        and release_authority["approval_id"] is not None
    )
    require(
        has_jit_authority == jit_required,
        f"{label} release authority JIT evidence does not match the signed route",
    )

    expected_quotas = route_shared_quota_constraints(route)
    observed_quotas = control_plane_receipt.get("quotas")
    require(
        isinstance(observed_quotas, list),
        f"{label} control-plane receipt quota evidence is missing",
    )
    require(
        len(observed_quotas) == len(expected_quotas),
        f"{label} control-plane receipt quota count does not match the signed route",
    )
    observed_by_id = {
        quota.get("constraintId"): quota
        for quota in observed_quotas
        if isinstance(quota, dict)
    }
    require(
        len(observed_by_id) == len(observed_quotas),
        f"{label} control-plane receipt quota identities are not unique",
    )
    for constraint in expected_quotas:
        constraint_id = str(constraint.get("id") or "unnamed")
        quota = observed_by_id.get(constraint_id)
        require(
            isinstance(quota, dict),
            f"{label} control-plane receipt omits signed route quota {constraint_id}",
        )
        require(
            quota.get("max") == constraint.get("max"),
            f"{label} control-plane receipt quota {constraint_id} maximum mismatch",
        )
        calendar_window = constraint.get("calendarWindow")
        if calendar_window is None:
            require(
                quota.get("windowKind") in {None, "fixed"}
                and quota.get("windowSeconds") == constraint.get("windowSeconds"),
                f"{label} control-plane receipt quota {constraint_id} fixed window mismatch",
            )
        else:
            require(
                quota.get("windowKind") == calendar_window
                and quota.get("calendarWindow") == calendar_window,
                f"{label} control-plane receipt quota {constraint_id} calendar window mismatch",
            )


def verify_proxy_upstream_response(
    value: Any,
    *,
    expected_status: int,
    expected_header_names: set[str],
) -> dict[str, Any]:
    label = "proxy upstream response"
    require(isinstance(value, dict), f"{label} must be an object")
    upstream = dict(value)
    require_exact_object_fields(
        upstream,
        {
            "status",
            "selected_raw_policy_headers_b64",
            "body_digest",
            "canonical_digest",
        },
        label,
    )
    status = upstream.get("status")
    require(
        isinstance(status, int)
        and not isinstance(status, bool)
        and 100 <= status <= 599,
        f"{label} status is invalid",
    )
    require(status == expected_status, f"{label} status mismatch")
    body_digest = require_sha256(upstream.get("body_digest"), f"{label} body digest")
    selected = upstream.get("selected_raw_policy_headers_b64")
    require(isinstance(selected, dict), f"{label} raw policy headers must be an object")
    require(
        set(selected) == expected_header_names,
        f"{label} raw policy header names do not exactly match the signed route success profile",
    )
    for name, values in selected.items():
        require(
            isinstance(name, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) is not None
            and isinstance(values, list)
            and len(values) <= 128,
            f"{label} raw policy header {name!r} is invalid",
        )
        for index, encoded in enumerate(values):
            decoded = decode_canonical_base64url(
                encoded,
                f"{label} raw policy header {name}[{index}]",
            )
            require(
                len(decoded) <= 8 * 1024,
                f"{label} raw policy header {name}[{index}] is too large",
            )
    canonical_digest = require_sha256(
        upstream.get("canonical_digest"),
        f"{label} canonical digest",
    )
    require(
        canonical_digest
        == sha256_prefixed_json(
            {
                "status": status,
                "selected_raw_policy_headers_b64": selected,
                "body_digest": body_digest,
            }
        ),
        f"{label} canonical digest mismatch",
    )
    return upstream


def require_uint64(value: Any, label: str) -> int:
    require(
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 2**64 - 1,
        f"{label} must be an unsigned 64-bit integer",
    )
    return value


def require_streaming_identifier(value: Any, label: str, *, allow_empty: bool = False) -> str:
    require(isinstance(value, str), f"{label} must be a string")
    if allow_empty and value == "":
        return value
    require(
        1 <= len(value) <= 256
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", value) is not None,
        f"{label} is invalid",
    )
    return value


def verify_streaming_authorization_binding(
    value: Any,
    *,
    statement: dict[str, Any],
    release_authority: dict[str, Any],
    expected_operation_context_digest: str,
) -> tuple[dict[str, Any], str]:
    label = "streaming authorization binding validation"
    require(isinstance(value, dict), f"{label} must be an object")
    validation = dict(value)
    require_exact_object_fields(
        validation,
        {"status", "binding_commitment", "binding_digest"},
        label,
    )
    require(validation.get("status") == "validated", f"{label} status is not validated")
    binding_digest = require_sha256(validation.get("binding_digest"), f"{label} digest")
    require(
        binding_digest == release_authority["consumption_identity_digest"],
        f"{label} digest does not match release authority",
    )
    commitment = validation.get("binding_commitment")
    require(isinstance(commitment, dict), f"{label} commitment must be an object")
    commitment = dict(commitment)
    require_exact_object_fields(
        commitment,
        {
            "attempt_id",
            "flow_id",
            "principal_id",
            "route_id",
            "credential_id",
            "credential_version",
            "policy_hash",
            "request_digest",
            "operation_digest",
            "operation_context_digest",
            "require_jit_grant",
            "shared_quotas",
        },
        f"{label} commitment",
    )
    require_sha256(commitment.get("attempt_id"), f"{label} attempt ID")
    require_sha256(commitment.get("flow_id"), f"{label} flow ID")
    require_streaming_identifier(commitment.get("principal_id"), f"{label} principal ID")
    require_streaming_identifier(commitment.get("route_id"), f"{label} route ID")
    credential_id = require_streaming_identifier(
        commitment.get("credential_id"),
        f"{label} credential ID",
        allow_empty=True,
    )
    credential_version = require_uint64(
        commitment.get("credential_version"),
        f"{label} credential version",
    )
    require(
        (credential_id == "" and credential_version == 0)
        or (credential_id != "" and credential_version > 0),
        f"{label} credential identity and version are inconsistent",
    )
    for field in (
        "policy_hash",
        "request_digest",
        "operation_digest",
        "operation_context_digest",
    ):
        require_sha256(commitment.get(field), f"{label} {field.replace('_', ' ')}")
    require(
        isinstance(commitment.get("require_jit_grant"), bool),
        f"{label} JIT requirement is invalid",
    )
    expected_fields = {
        "attempt_id": release_authority["attempt_id"],
        "flow_id": release_authority["attempt_id"],
        "principal_id": statement["principal_id"],
        "route_id": statement["route_id"],
        "credential_id": release_authority["credential_ref"] or "",
        "credential_version": release_authority["credential_version"],
        "policy_hash": statement["policy_digest"],
        "request_digest": statement["request_digest"],
        "operation_digest": statement["operation_digest"],
        "operation_context_digest": require_sha256(
            expected_operation_context_digest,
            f"{label} independently expected operation context digest",
        ),
    }
    for field, expected in expected_fields.items():
        require(
            commitment.get(field) == expected,
            f"{label} {field} claim substitution",
        )
    has_jit_authority = (
        release_authority["grant_id"] is not None
        and release_authority["approval_id"] is not None
    )
    require(
        commitment["require_jit_grant"] == has_jit_authority,
        f"{label} JIT commitment does not match release authority",
    )

    quotas = commitment.get("shared_quotas")
    require(
        isinstance(quotas, list) and len(quotas) <= 256,
        f"{label} shared quotas are invalid",
    )
    previous_counter_key: str | None = None
    for index, quota_value in enumerate(quotas):
        quota_label = f"{label} shared quota {index}"
        require(isinstance(quota_value, dict), f"{quota_label} must be an object")
        quota = quota_value
        window_kind = quota.get("window_kind")
        require(
            window_kind in {"fixed", "utcDay", "utcIsoWeek", "utcMonth"},
            f"{quota_label} window kind is invalid",
        )
        expected_quota_fields = {
            "counter_key",
            "constraint_id",
            "operation",
            "window_kind",
            "max_count",
        }
        if window_kind == "fixed":
            expected_quota_fields.add("window_seconds")
        require_exact_object_fields(quota, expected_quota_fields, quota_label)
        counter_key = require_sha256(quota.get("counter_key"), f"{quota_label} counter key")
        require(
            previous_counter_key is None or previous_counter_key < counter_key,
            f"{label} shared quotas are not uniquely and canonically ordered",
        )
        previous_counter_key = counter_key
        require_streaming_identifier(quota.get("constraint_id"), f"{quota_label} constraint ID")
        operation = quota.get("operation")
        require(
            operation is None
            or (
                isinstance(operation, str)
                and require_streaming_identifier(operation, f"{quota_label} operation") == operation
            ),
            f"{quota_label} operation is invalid",
        )
        if window_kind == "fixed":
            window_seconds = require_uint64(
                quota.get("window_seconds"),
                f"{quota_label} window seconds",
            )
            require(1 <= window_seconds <= 31_536_000, f"{quota_label} window seconds are out of range")
        max_count = require_uint64(quota.get("max_count"), f"{quota_label} maximum count")
        require(1 <= max_count <= 1_000_000_000, f"{quota_label} maximum count is out of range")
    return commitment, binding_digest


def verify_streaming_upstream_response(
    value: Any,
    *,
    expected_status: int,
    expected_header_names: set[str],
) -> dict[str, Any]:
    label = "streaming proxy upstream response"
    require(isinstance(value, dict), f"{label} must be an object")
    upstream = dict(value)
    require_exact_object_fields(
        upstream,
        {
            "status",
            "selected_raw_policy_headers_b64",
            "body_digest",
            "body_bytes",
            "canonical_digest",
        },
        label,
    )
    status = upstream.get("status")
    require(
        isinstance(status, int)
        and not isinstance(status, bool)
        and 200 <= status < 300
        and status == expected_status,
        f"{label} status mismatch",
    )
    selected = upstream.get("selected_raw_policy_headers_b64")
    require(isinstance(selected, dict), f"{label} raw policy headers must be an object")
    require(
        set(selected) == expected_header_names,
        f"{label} raw policy header names do not exactly match the signed route success profile",
    )
    for name, values in selected.items():
        require(
            re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) is not None
            and isinstance(values, list)
            and len(values) <= 128,
            f"{label} raw policy header {name!r} is invalid",
        )
        for index, encoded in enumerate(values):
            decoded = decode_canonical_base64url(
                encoded,
                f"{label} raw policy header {name}[{index}]",
            )
            require(len(decoded) <= 8 * 1024, f"{label} raw policy header {name}[{index}] is too large")
    body_digest = require_sha256(upstream.get("body_digest"), f"{label} body digest")
    body_bytes = require_uint64(upstream.get("body_bytes"), f"{label} body byte count")
    canonical_digest = require_sha256(upstream.get("canonical_digest"), f"{label} canonical digest")
    require(
        canonical_digest
        == sha256_prefixed_json(
            {
                "status": status,
                "selected_raw_policy_headers_b64": selected,
                "body_digest": body_digest,
                "body_bytes": body_bytes,
            }
        ),
        f"{label} canonical digest mismatch",
    )
    return upstream


def verify_streaming_released_response(
    value: Any,
    *,
    streamed_body_snapshot: FileSnapshot,
) -> dict[str, Any]:
    label = "streaming released response"
    require(isinstance(value, dict), f"{label} must be an object")
    released = dict(value)
    require_exact_object_fields(
        released,
        {
            "status",
            "content_type",
            "selected_wire_headers",
            "selected_wire_headers_digest",
            "body_digest",
            "body_bytes",
            "framing",
            "completion",
            "trailer_names",
        },
        label,
    )
    status = released.get("status")
    require(
        isinstance(status, int) and not isinstance(status, bool) and 200 <= status < 300,
        f"{label} status is not successful",
    )
    content_type = released.get("content_type")
    require(
        isinstance(content_type, str)
        and 1 <= len(content_type) <= 1024
        and not any(ord(character) < 32 or ord(character) == 127 for character in content_type),
        f"{label} content type is invalid",
    )
    wire_headers = released.get("selected_wire_headers")
    require(isinstance(wire_headers, dict), f"{label} selected wire headers must be an object")
    expected_wire_headers = {
        "connection": "close",
        "content-type": content_type,
        "trailer": "X-Serverware-Stream-Proof-B64, X-Serverware-Stream-Proof-SHA256",
        "transfer-encoding": "chunked",
    }
    require(wire_headers == expected_wire_headers, f"{label} wire headers do not match the terminal stream contract")
    selected_wire_headers_digest = require_sha256(
        released.get("selected_wire_headers_digest"),
        f"{label} selected wire header digest",
    )
    require(
        selected_wire_headers_digest == sha256_prefixed_json(wire_headers),
        f"{label} selected wire header digest mismatch",
    )
    body_digest = require_sha256(released.get("body_digest"), f"{label} body digest")
    body_bytes = require_uint64(released.get("body_bytes"), f"{label} body byte count")
    require(
        body_digest == streamed_body_snapshot.sha256,
        f"{label} body digest does not match the separately published body",
    )
    require(
        body_bytes == len(streamed_body_snapshot.data),
        f"{label} body byte count does not match the separately published body",
    )
    require(released.get("framing") == "http1.1-chunked-trailers", f"{label} framing mismatch")
    require(released.get("completion") == "normal-eof", f"{label} does not prove normal EOF")
    require(
        released.get("trailer_names")
        == ["X-Serverware-Stream-Proof-B64", "X-Serverware-Stream-Proof-SHA256"],
        f"{label} trailer contract mismatch",
    )
    return released


def streaming_calendar_window_bounds(window_kind: str, start_epoch_ms: int) -> tuple[int, int]:
    require(start_epoch_ms % 1000 == 0, "streaming calendar quota start must be second-aligned")
    start_value = datetime.fromtimestamp(start_epoch_ms / 1000, tz=timezone.utc)
    if window_kind == "utcDay":
        expected_start = start_value.replace(hour=0, minute=0, second=0, microsecond=0)
        expected_end = expected_start + timedelta(days=1)
    elif window_kind == "utcIsoWeek":
        expected_start = (
            start_value - timedelta(days=start_value.weekday())
        ).replace(hour=0, minute=0, second=0, microsecond=0)
        expected_end = expected_start + timedelta(days=7)
    elif window_kind == "utcMonth":
        expected_start = start_value.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        expected_end = (
            expected_start.replace(year=expected_start.year + 1, month=1)
            if expected_start.month == 12
            else expected_start.replace(month=expected_start.month + 1)
        )
    else:
        raise ValueError("streaming calendar quota window kind is invalid")
    return int(expected_start.timestamp() * 1000), int(expected_end.timestamp() * 1000)


def verify_streaming_dispatch_quota_commitments(
    receipt: dict[str, Any],
    commitments: list[dict[str, Any]],
) -> None:
    label = "streaming control-plane dispatch quotas"
    response = receipt.get("response") if isinstance(receipt.get("response"), dict) else {}
    body_bytes = decode_canonical_base64url(response.get("body_b64"), f"{label} response body")
    body = load_json_bytes(body_bytes, Path("<embedded-streaming-dispatch-response>"), f"{label} response body")
    require(canonical_json(body).encode("utf-8") == body_bytes, f"{label} response body is not canonical JSON")
    actual_quotas = body.get("quotas")
    require(
        isinstance(actual_quotas, list) and len(actual_quotas) == len(commitments),
        f"{label} do not match the authorization binding commitment",
    )
    dispatch_started_at = body.get("dispatchStartedAtEpochMs")
    reservation_expires_at = body.get("reservationExpiresAtEpochMs")
    require(
        isinstance(dispatch_started_at, int)
        and not isinstance(dispatch_started_at, bool)
        and isinstance(reservation_expires_at, int)
        and not isinstance(reservation_expires_at, bool),
        f"{label} lifecycle timestamps are invalid",
    )
    previous_counter_key: str | None = None
    for index, (actual, expected) in enumerate(zip(actual_quotas, commitments, strict=True)):
        quota_label = f"{label} item {index}"
        require(isinstance(actual, dict), f"{quota_label} must be an object")
        expected_kind = expected["window_kind"]
        expected_actual_fields = {
            "counterKey",
            "constraintId",
            "operation",
            "windowKind",
            "windowStartEpochMs",
            "windowEndEpochMs",
            "max",
            "count",
            "remaining",
            "reservationState",
        }
        expected_actual_fields.add("windowSeconds" if expected_kind == "fixed" else "calendarWindow")
        require_exact_object_fields(actual, expected_actual_fields, quota_label)
        counter_key = require_sha256(actual.get("counterKey"), f"{quota_label} counter key")
        require(previous_counter_key is None or previous_counter_key < counter_key, f"{label} are not uniquely sorted")
        previous_counter_key = counter_key
        require(
            counter_key == expected["counter_key"]
            and actual.get("constraintId") == expected["constraint_id"]
            and actual.get("operation") == expected["operation"]
            and actual.get("windowKind") == expected_kind
            and actual.get("max") == expected["max_count"],
            f"{quota_label} claim substitution",
        )
        window_start = require_uint64(actual.get("windowStartEpochMs"), f"{quota_label} window start")
        window_end = require_uint64(actual.get("windowEndEpochMs"), f"{quota_label} window end")
        if expected_kind == "fixed":
            require(
                actual.get("windowSeconds") == expected["window_seconds"]
                and window_end == window_start + expected["window_seconds"] * 1000,
                f"{quota_label} fixed window mismatch",
            )
        else:
            require(actual.get("calendarWindow") == expected_kind, f"{quota_label} calendar kind mismatch")
            require(
                (window_start, window_end)
                == streaming_calendar_window_bounds(expected_kind, window_start),
                f"{quota_label} calendar boundaries are not exact",
            )
        count = require_uint64(actual.get("count"), f"{quota_label} count")
        remaining = require_uint64(actual.get("remaining"), f"{quota_label} remaining count")
        require(
            count <= expected["max_count"]
            and remaining == expected["max_count"] - count
            and actual.get("reservationState") == "reserved"
            and window_start <= dispatch_started_at < window_end
            and (expected_kind == "fixed" or reservation_expires_at <= window_end),
            f"{quota_label} lifecycle evidence is invalid",
        )


def verify_streaming_vendor_tee(
    value: Any,
    *,
    trusted_verifier_public_key_pem: str,
    expected_tee_platform: str,
    expected_quote_provider: str,
    statement_digest: str,
    response_signing_key_id: str,
    expected_attested_claims: dict[str, Any],
    max_age_seconds: int,
    now: int,
) -> dict[str, Any]:
    label = "streaming proxy response vendor TEE"
    require(isinstance(value, dict), f"{label} must be an object")
    vendor_tee = dict(value)
    require_exact_object_fields(
        vendor_tee,
        {"platform", "provider", "quote_sha256", "quote", "trusted_verifier"},
        label,
    )
    tee_platform = require_production_identifier(vendor_tee.get("platform"), f"{label} platform")
    quote_provider = require_production_identifier(vendor_tee.get("provider"), f"{label} quote provider")
    require(tee_platform == expected_tee_platform, f"{label} platform does not match release attestation")
    require(quote_provider == expected_quote_provider, f"{label} provider does not match release attestation")
    quote = vendor_tee.get("quote")
    require(isinstance(quote, dict), f"{label} quote must be an object")
    require_exact_object_fields(quote, {"format", "body_b64"}, f"{label} quote")
    require_production_identifier(quote.get("format"), f"{label} quote format")
    quote_body = require_base64url_bytes(
        quote.get("body_b64"),
        f"{label} quote body",
        minimum_bytes=64,
    )
    require(
        len(quote_body) <= MAX_VENDOR_QUOTE_BYTES,
        f"{label} quote body exceeds the schema size limit",
    )
    quote_digest = require_sha256(vendor_tee.get("quote_sha256"), f"{label} quote digest")
    require(quote_digest == sha256_prefixed_json(quote), f"{label} quote digest mismatch")

    trusted_verifier = vendor_tee.get("trusted_verifier")
    require(isinstance(trusted_verifier, dict), f"{label} trusted verifier must be an object")
    require_exact_object_fields(
        trusted_verifier,
        {"apiVersion", "kind", "statement", "signature"},
        f"{label} trusted verifier",
    )
    require(
        trusted_verifier.get("apiVersion") == "serverware.vendorTeeVerification/v1"
        and trusted_verifier.get("kind") == "ServerwareVendorTeeVerification",
        f"{label} trusted verifier type mismatch",
    )
    verifier_statement = trusted_verifier.get("statement")
    require(isinstance(verifier_statement, dict), f"{label} verifier statement must be an object")
    require_exact_object_fields(
        verifier_statement,
        {
            "verifier_key_id",
            "outcome",
            "environment",
            "trust_basis",
            "vendor_quote_verified",
            "certificate_chain_verified",
            "revocation_checked",
            "debug",
            "verified_at_unix",
            "expires_at_unix",
            "tee_platform",
            "quote_provider",
            "vendor_quote_sha256",
            "streaming_response_statement_sha256",
            "response_signing_key_id",
            "attested_claims",
        },
        f"{label} verifier statement",
    )
    trusted_verifier_key_id = ed25519_public_key_id(
        trusted_verifier_public_key_pem,
        f"{label} trust root",
    )
    require(
        verifier_statement.get("verifier_key_id") == trusted_verifier_key_id,
        f"{label} verifier key is not the configured trust root",
    )
    verify_ed25519(
        trusted_verifier_public_key_pem,
        str(trusted_verifier.get("signature") or ""),
        canonical_json(verifier_statement).encode("utf-8"),
        f"{label} trusted verifier",
    )
    exact_verifier_fields = {
        "outcome": "verified",
        "environment": "production",
        "trust_basis": "vendor-root-certificate-chain",
        "vendor_quote_verified": True,
        "certificate_chain_verified": True,
        "revocation_checked": True,
        "debug": False,
        "tee_platform": tee_platform,
        "quote_provider": quote_provider,
        "vendor_quote_sha256": quote_digest,
        "streaming_response_statement_sha256": statement_digest,
        "response_signing_key_id": response_signing_key_id,
    }
    for field, expected in exact_verifier_fields.items():
        require(verifier_statement.get(field) == expected, f"{label} verifier {field} mismatch")
    verified_at = require_unix_time(verifier_statement.get("verified_at_unix"), f"{label} verification time")
    expires_at = require_unix_time(verifier_statement.get("expires_at_unix"), f"{label} verification expiry")
    require(verified_at <= now + PROXY_PROOF_FUTURE_SKEW_SECONDS, f"{label} verification time is in the future")
    require(now - verified_at <= max_age_seconds, f"{label} verifier receipt is stale")
    require(expires_at >= now and expires_at > verified_at, f"{label} verifier receipt is expired")
    require(
        expires_at - verified_at <= PROXY_PROOF_MAX_AGE_LIMIT_SECONDS,
        f"{label} verifier validity window is too long",
    )
    attested_claims = verifier_statement.get("attested_claims")
    require(isinstance(attested_claims, dict), f"{label} attested claims must be an object")
    require(
        attested_claims == expected_attested_claims,
        f"{label} attested claims do not exactly match the signed streaming statement",
    )
    return {
        "platform": tee_platform,
        "provider": quote_provider,
        "quote_sha256": quote_digest,
        "trusted_verifier_key_id": trusted_verifier_key_id,
        "verified_at_unix": verified_at,
        "expires_at_unix": expires_at,
    }


def verify_production_streaming_proxy_response_proof(
    document: dict[str, Any],
    *,
    streamed_body_snapshot: FileSnapshot,
    trusted_verifier_public_key_pem: str,
    trusted_collector_public_key_pem: str,
    trusted_control_plane_response_signing_public_key_pem: str,
    expected_control_plane_response_signing_public_key_id: str,
    policy_snapshot: PolicySnapshot,
    expected_principal_id: str,
    expected_server_instance_id: str,
    expected_client_nonce: str,
    expected_client_request_digest: str,
    expected_request_digest: str,
    expected_operation_digest: str,
    expected_operation_context_digest: str,
    expected_tls_channel_binding: str,
    expected_policy_digest: str,
    expected_runtime_manifest_digest: str,
    expected_binary_digest: str,
    expected_release_digest: str,
    expected_image_signatures_digest: str,
    expected_source_tree_digest: str,
    expected_response_signing_key_id: str,
    expected_tee_platform: str,
    expected_quote_provider: str,
    max_age_seconds: int,
) -> dict[str, Any]:
    label = "streaming proxy response proof"
    assert_no_secret_fields(document)
    require(1 <= max_age_seconds <= PROXY_PROOF_MAX_AGE_LIMIT_SECONDS, f"{label} max age is invalid")
    require(
        document.get("apiVersion") == "serverware.streamingProxyResponseProof/v1"
        and document.get("kind") == "ServerwareStreamingProxyResponseProof",
        f"{label} has the wrong type",
    )
    require_exact_object_fields(
        document,
        {
            "apiVersion",
            "kind",
            "external_capture",
            "collector_signature",
            "streaming_response_statement",
            "server_signature",
            "vendor_tee",
        },
        label,
    )
    require(
        isinstance(expected_server_instance_id, str)
        and expected_server_instance_id.startswith("spiffe://")
        and len(expected_server_instance_id) > len("spiffe://"),
        f"{label} expected server identity must be a SPIFFE ID",
    )
    expected_nonce_bytes = require_base64url_bytes(expected_client_nonce, f"{label} expected nonce", minimum_bytes=32)
    require(len(expected_nonce_bytes) == 32, f"{label} expected nonce must contain exactly 32 bytes")
    expected_tls_bytes = require_base64url_bytes(
        expected_tls_channel_binding,
        f"{label} expected TLS exporter",
        minimum_bytes=32,
    )
    require(len(expected_tls_bytes) == 32, f"{label} expected TLS exporter must contain exactly 32 bytes")
    expected_client_request_digest = require_sha256(expected_client_request_digest, f"{label} expected client request digest")
    expected_request_digest = require_sha256(expected_request_digest, f"{label} expected request digest")
    expected_operation_digest = require_sha256(expected_operation_digest, f"{label} expected operation digest")
    expected_bindings = {
        "policy_digest": require_sha256(expected_policy_digest, f"{label} expected policy digest"),
        "runtime_manifest_digest": require_sha256(expected_runtime_manifest_digest, f"{label} expected runtime digest"),
        "data_plane_binary_digest": require_sha256(expected_binary_digest, f"{label} expected binary digest"),
        "release_digest": require_sha256(expected_release_digest, f"{label} expected release digest"),
    }

    external_capture = document.get("external_capture")
    require(isinstance(external_capture, dict), f"{label} external capture must be an object")
    require_exact_object_fields(
        external_capture,
        {
            "apiVersion",
            "environment",
            "collection_mode",
            "classification",
            "captured_at_unix",
            "client_nonce",
            "client_request_digest",
            "principal_id",
            "route_id",
            "request_digest",
            "operation_digest",
            "release_authority",
            "authorization_binding_commitment",
            "control_plane_authorization_receipt",
            "control_plane_authorization_receipt_sha256",
            "upstream_response",
            "released_response",
            "tls_channel_binding",
            "tls_peer",
            "streaming_response_statement_sha256",
            "runtime_proof_sha256",
        },
        f"{label} external capture",
    )
    require(
        external_capture.get("apiVersion") == "serverware.streamingProxyResponseCapture/v1"
        and external_capture.get("environment") == "production"
        and external_capture.get("collection_mode") == "strict-incremental-stream-capture"
        and external_capture.get("classification")
        == "runtime-verified-complete-stream",
        f"{label} external capture is not strict production stream evidence",
    )
    captured_at = require_unix_time(external_capture.get("captured_at_unix"), f"{label} capture time")
    now = int(time.time())
    require(captured_at <= now + PROXY_PROOF_FUTURE_SKEW_SECONDS, f"{label} capture time is in the future")
    require(now - captured_at <= max_age_seconds, f"{label} external capture is stale")
    nonce = external_capture.get("client_nonce")
    nonce_bytes = require_base64url_bytes(nonce, f"{label} capture nonce", minimum_bytes=32)
    require(nonce == expected_client_nonce and nonce_bytes == expected_nonce_bytes, f"{label} capture nonce mismatch")
    require(external_capture.get("principal_id") == expected_principal_id, f"{label} principal mismatch")
    matched_route_id, expected_raw_header_names = match_proxy_policy_route(
        policy_snapshot,
        principal_id=expected_principal_id,
        route_id=external_capture.get("route_id"),
    )
    matched_route = require_proxy_policy_route(
        policy_snapshot,
        principal_id=expected_principal_id,
        route_id=matched_route_id,
    )
    client_request_digest = require_sha256(external_capture.get("client_request_digest"), f"{label} client request digest")
    request_digest = require_sha256(external_capture.get("request_digest"), f"{label} request digest")
    operation_digest = require_sha256(external_capture.get("operation_digest"), f"{label} operation digest")
    require(client_request_digest == expected_client_request_digest, f"{label} client request digest mismatch")
    require(request_digest == expected_request_digest, f"{label} request digest mismatch")
    require(operation_digest == expected_operation_digest, f"{label} operation digest mismatch")
    release_authority = verify_proxy_release_authority(
        external_capture.get("release_authority"),
        expected_request_digest=request_digest,
        expected_operation_digest=operation_digest,
        latest_observation_at_unix=captured_at,
    )
    released_response = verify_streaming_released_response(
        external_capture.get("released_response"),
        streamed_body_snapshot=streamed_body_snapshot,
    )
    upstream_response = verify_streaming_upstream_response(
        external_capture.get("upstream_response"),
        expected_status=released_response["status"],
        expected_header_names=expected_raw_header_names,
    )

    tls_channel_binding = external_capture.get("tls_channel_binding")
    require(isinstance(tls_channel_binding, dict), f"{label} TLS channel binding must be an object")
    require_exact_object_fields(
        tls_channel_binding,
        {"type", "exporter_label", "value"},
        f"{label} TLS channel binding",
    )
    require(
        tls_channel_binding
        == {
            "type": "tls-exporter",
            "exporter_label": STREAMING_TLS_EXPORTER_LABEL,
            "value": expected_tls_channel_binding,
        },
        f"{label} TLS exporter binding mismatch",
    )
    tls_peer = external_capture.get("tls_peer")
    require(isinstance(tls_peer, dict), f"{label} TLS peer must be an object")
    require_exact_object_fields(tls_peer, {"spiffe_id", "leaf_certificate_sha256"}, f"{label} TLS peer")
    require(tls_peer.get("spiffe_id") == expected_server_instance_id, f"{label} TLS peer SPIFFE ID mismatch")
    tls_peer_leaf_digest = require_sha256(tls_peer.get("leaf_certificate_sha256"), f"{label} TLS peer certificate digest")

    collector_signature = document.get("collector_signature")
    require(isinstance(collector_signature, dict), f"{label} collector signature must be an object")
    require_exact_object_fields(
        collector_signature,
        {"algorithm", "key_id", "public_key_pem", "signature"},
        f"{label} collector signature",
    )
    require(collector_signature.get("algorithm") == "Ed25519", f"{label} collector algorithm mismatch")
    collector_public_key_pem = collector_signature.get("public_key_pem")
    require(isinstance(collector_public_key_pem, str) and collector_public_key_pem, f"{label} collector public key is missing")
    collector_public_key_der = ed25519_public_key_der(collector_public_key_pem, f"{label} collector")
    trusted_collector_der = ed25519_public_key_der(trusted_collector_public_key_pem, f"{label} trusted collector")
    require(collector_public_key_der == trusted_collector_der, f"{label} collector key is not the configured trust root")
    collector_signing_key_id = sha256_prefixed_bytes(collector_public_key_der)
    require(collector_signature.get("key_id") == collector_signing_key_id, f"{label} collector key ID mismatch")
    verify_ed25519(
        collector_public_key_pem,
        str(collector_signature.get("signature") or ""),
        canonical_json(external_capture).encode("utf-8"),
        f"{label} collector",
    )

    statement = document.get("streaming_response_statement")
    require(isinstance(statement, dict), f"{label} statement must be an object")
    require_exact_object_fields(
        statement,
        {
            "apiVersion",
            "issued_at_unix",
            "client_nonce",
            "client_request_digest",
            "principal_id",
            "route_id",
            "request_digest",
            "operation_digest",
            "release_authority",
            "authorization_binding_validation",
            "control_plane_authorization_receipt",
            "control_plane_authorization_receipt_sha256",
            "upstream_response",
            "released_response",
            "policy_digest",
            "runtime_manifest_digest",
            "data_plane_binary_digest",
            "release_digest",
            "server_instance",
            "tls_channel_binding",
        },
        f"{label} statement",
    )
    require(statement.get("apiVersion") == "serverware.streamingResponseStatement/v1", f"{label} statement version mismatch")
    issued_at = require_unix_time(statement.get("issued_at_unix"), f"{label} statement issue time")
    require(issued_at <= now + PROXY_PROOF_FUTURE_SKEW_SECONDS, f"{label} statement issue time is in the future")
    require(now - issued_at <= max_age_seconds, f"{label} statement is stale")
    require(issued_at <= captured_at + PROXY_PROOF_FUTURE_SKEW_SECONDS, f"{label} statement postdates capture")
    statement_digest = require_sha256(
        external_capture.get("streaming_response_statement_sha256"),
        f"{label} statement digest",
    )
    require(statement_digest == sha256_prefixed_json(statement), f"{label} statement digest mismatch")
    server_signature = document.get("server_signature")
    require(isinstance(server_signature, dict), f"{label} server signature must be an object")
    require_exact_object_fields(
        server_signature,
        {"algorithm", "key_id", "public_key_pem", "signature"},
        f"{label} server signature",
    )
    require(server_signature.get("algorithm") == "Ed25519", f"{label} server signature algorithm mismatch")
    response_public_key_pem = server_signature.get("public_key_pem")
    require(isinstance(response_public_key_pem, str) and response_public_key_pem, f"{label} response public key is missing")
    response_signing_key_id = ed25519_public_key_id(response_public_key_pem, f"{label} response signer")
    require(server_signature.get("key_id") == response_signing_key_id, f"{label} response key ID mismatch")
    require(
        response_signing_key_id == require_sha256(expected_response_signing_key_id, f"{label} expected response key ID"),
        f"{label} response signer does not match the fresh attested runtime",
    )
    verify_ed25519(
        response_public_key_pem,
        str(server_signature.get("signature") or ""),
        canonical_json(statement).encode("utf-8"),
        f"{label} statement",
    )

    require(statement.get("client_nonce") == nonce, f"{label} statement nonce mismatch")
    require(statement.get("client_request_digest") == client_request_digest, f"{label} statement client request mismatch")
    require(statement.get("principal_id") == expected_principal_id, f"{label} statement principal mismatch")
    require(statement.get("route_id") == matched_route_id, f"{label} statement route mismatch")
    require(statement.get("request_digest") == request_digest, f"{label} statement request mismatch")
    require(statement.get("operation_digest") == operation_digest, f"{label} statement operation mismatch")
    statement_authority = verify_proxy_release_authority(
        statement.get("release_authority"),
        expected_request_digest=request_digest,
        expected_operation_digest=operation_digest,
        latest_observation_at_unix=issued_at,
    )
    require(statement_authority == release_authority, f"{label} release authority mismatch")
    authorization_binding, authorization_binding_digest = verify_streaming_authorization_binding(
        statement.get("authorization_binding_validation"),
        statement=statement,
        release_authority=statement_authority,
        expected_operation_context_digest=expected_operation_context_digest,
    )
    require(
        external_capture.get("authorization_binding_commitment") == authorization_binding,
        f"{label} external authorization binding commitment mismatch",
    )
    embedded_receipt = statement.get("control_plane_authorization_receipt")
    receipt_digest = require_sha256(
        statement.get("control_plane_authorization_receipt_sha256"),
        f"{label} control-plane receipt digest",
    )
    require(receipt_digest == sha256_prefixed_json(embedded_receipt), f"{label} control-plane receipt digest mismatch")
    require(
        external_capture.get("control_plane_authorization_receipt") == embedded_receipt
        and external_capture.get("control_plane_authorization_receipt_sha256") == receipt_digest,
        f"{label} external control-plane receipt mismatch",
    )
    require(statement.get("upstream_response") == upstream_response, f"{label} upstream response mismatch")
    require(statement.get("released_response") == released_response, f"{label} released response mismatch")
    require(statement.get("tls_channel_binding") == tls_channel_binding, f"{label} TLS channel binding mismatch")
    bindings = {
        field: require_sha256(statement.get(field), f"{label} statement {field.replace('_', ' ')}")
        for field in expected_bindings
    }
    for field, expected in expected_bindings.items():
        require(bindings[field] == expected, f"{label} {field.replace('_', ' ')} mismatch")
    server_instance = statement.get("server_instance")
    require(isinstance(server_instance, dict), f"{label} server instance must be an object")
    require_exact_object_fields(server_instance, {"id", "identity_digest"}, f"{label} server instance")
    require(server_instance.get("id") == expected_server_instance_id, f"{label} server instance mismatch")
    server_instance_identity_digest = require_sha256(server_instance.get("identity_digest"), f"{label} server identity digest")
    require(
        server_instance_identity_digest == sha256_prefixed_bytes(expected_server_instance_id.encode("utf-8")),
        f"{label} server identity digest mismatch",
    )

    runtime_proof = {
        "apiVersion": "serverware.streamingResponseRuntimeProof/v1",
        "kind": "ServerwareStreamingResponseRuntimeProof",
        "streaming_response_statement": statement,
        "streaming_response_statement_sha256": statement_digest,
        "server_signature": server_signature,
        "vendor_tee": document.get("vendor_tee"),
    }
    runtime_proof_digest = require_sha256(external_capture.get("runtime_proof_sha256"), f"{label} runtime proof digest")
    require(runtime_proof_digest == sha256_prefixed_json(runtime_proof), f"{label} runtime proof digest mismatch")
    expected_attested_claims = {
        "streaming_response_statement_api_version": statement["apiVersion"],
        "streaming_response_statement_sha256": statement_digest,
        "issued_at_unix": issued_at,
        "client_nonce_sha256": sha256_prefixed_bytes(nonce_bytes),
        "client_request_digest": client_request_digest,
        "principal_id": expected_principal_id,
        "route_id": matched_route_id,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "release_authority": release_authority,
        "authorization_binding_digest": authorization_binding_digest,
        "control_plane_authorization_receipt_sha256": receipt_digest,
        "upstream_status": upstream_response["status"],
        "upstream_selected_raw_policy_headers_digest": sha256_prefixed_json(
            upstream_response["selected_raw_policy_headers_b64"]
        ),
        "upstream_body_digest": upstream_response["body_digest"],
        "upstream_body_bytes": upstream_response["body_bytes"],
        "upstream_canonical_digest": upstream_response["canonical_digest"],
        "released_response_status": released_response["status"],
        "released_response_content_type": released_response["content_type"],
        "selected_response_wire_headers_digest": released_response["selected_wire_headers_digest"],
        "released_response_body_digest": released_response["body_digest"],
        "released_response_body_bytes": released_response["body_bytes"],
        "response_framing": released_response["framing"],
        "response_completion": released_response["completion"],
        "response_trailer_names": released_response["trailer_names"],
        **bindings,
        "server_instance_id": expected_server_instance_id,
        "server_instance_identity_digest": server_instance_identity_digest,
        "tls_channel_binding_type": tls_channel_binding["type"],
        "tls_exporter_label": tls_channel_binding["exporter_label"],
        "tls_channel_binding_sha256": sha256_prefixed_json(tls_channel_binding),
        "response_signing_key_id": response_signing_key_id,
    }
    vendor_summary = verify_streaming_vendor_tee(
        document.get("vendor_tee"),
        trusted_verifier_public_key_pem=trusted_verifier_public_key_pem,
        expected_tee_platform=expected_tee_platform,
        expected_quote_provider=expected_quote_provider,
        statement_digest=statement_digest,
        response_signing_key_id=response_signing_key_id,
        expected_attested_claims=expected_attested_claims,
        max_age_seconds=max_age_seconds,
        now=now,
    )
    control_plane_authorization = verify_control_plane_authorization_receipt(
        embedded_receipt,
        trusted_public_key_pem=trusted_control_plane_response_signing_public_key_pem,
        expected_trusted_public_key_id=expected_control_plane_response_signing_public_key_id,
        expected_release_authority=release_authority,
        expected_principal_id=expected_principal_id,
        expected_route_id=matched_route_id,
        expected_runtime_manifest_digest=expected_runtime_manifest_digest,
        expected_policy_digest=expected_policy_digest,
        expected_provenance_digest=expected_release_digest,
        expected_image_signatures_digest=expected_image_signatures_digest,
        expected_source_tree_digest=expected_source_tree_digest,
        expected_authorization_binding=authorization_binding,
    )
    verify_route_authorization_evidence(
        matched_route,
        release_authority,
        control_plane_authorization,
        label=label,
    )
    verify_streaming_dispatch_quota_commitments(embedded_receipt, authorization_binding["shared_quotas"])
    control_plane_key_id = control_plane_authorization["signing_key_id"]
    for proof_role, proof_key_id in (
        ("external collector", collector_signing_key_id),
        ("response statement signer", response_signing_key_id),
        ("vendor TEE verifier", vendor_summary["trusted_verifier_key_id"]),
    ):
        require(
            not hmac.compare_digest(control_plane_key_id, proof_key_id),
            f"control-plane response signing trust root must be independent from the streaming proxy proof {proof_role} key",
        )
    return {
        "proof_contract": "streaming-v1",
        "apiVersion": document.get("apiVersion"),
        "server_statement_api_version": statement.get("apiVersion"),
        "server_statement_sha256": statement_digest,
        "streaming_response_statement_sha256": statement_digest,
        "runtime_proof_sha256": runtime_proof_digest,
        "captured_at_unix": captured_at,
        "issued_at_unix": issued_at,
        "client_nonce_sha256": sha256_prefixed_bytes(nonce_bytes),
        "client_request_digest": client_request_digest,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "principal_id": expected_principal_id,
        "route_id": matched_route_id,
        "release_authority": release_authority,
        "compiled_route_authority_verified": True,
        "authorization_binding_digest": authorization_binding_digest,
        "authorization_binding_commitment": authorization_binding,
        "control_plane_response_signing_key_id": control_plane_key_id,
        "control_plane_authorization_receipt": control_plane_authorization,
        "upstream_response": upstream_response,
        "status": released_response["status"],
        "selected_response_headers_digest": released_response["selected_wire_headers_digest"],
        "emitted_body_digest": released_response["body_digest"],
        "emitted_body_bytes": released_response["body_bytes"],
        "streamed_body_artifact_sha256": streamed_body_snapshot.sha256,
        **bindings,
        "server_instance_id": expected_server_instance_id,
        "server_instance_identity_digest": server_instance_identity_digest,
        "tls_channel_binding_sha256": sha256_prefixed_json(tls_channel_binding),
        "tls_peer_spiffe_id": tls_peer["spiffe_id"],
        "tls_peer_leaf_certificate_sha256": tls_peer_leaf_digest,
        "collector_signing_key_id": collector_signing_key_id,
        "response_signing_key_id": response_signing_key_id,
        "vendor_tee_platform": vendor_summary["platform"],
        "vendor_quote_provider": vendor_summary["provider"],
        "vendor_quote_sha256": vendor_summary["quote_sha256"],
        "trusted_verifier_key_id": vendor_summary["trusted_verifier_key_id"],
        "vendor_quote_verified": True,
        "trusted_verifier_outcome": "verified",
        "collector_signature_verified": True,
        "server_statement_signature_verified": True,
        "fresh_client_nonce_bound": True,
        "authenticated_external_client_capture_bound": True,
        "release_authority_bound": True,
        "authorization_binding_commitment_bound": True,
        "embedded_control_plane_authorization_receipt_bound": True,
        "signed_policy_route_bound": True,
        "signed_policy_response_headers_bound": True,
        "upstream_response_bound": True,
        "released_body_artifact_bound": True,
        "stream_completion_bound": True,
        "release_artifacts_bound": True,
    }


def verify_production_buffered_proxy_response_proof(
    document: dict[str, Any],
    *,
    trusted_verifier_public_key_pem: str,
    trusted_collector_public_key_pem: str,
    trusted_control_plane_response_signing_public_key_pem: str,
    expected_control_plane_response_signing_public_key_id: str,
    policy_snapshot: PolicySnapshot,
    expected_principal_id: str,
    expected_server_instance_id: str,
    expected_client_nonce: str,
    expected_client_request_digest: str,
    expected_request_digest: str,
    expected_operation_digest: str,
    expected_tls_channel_binding: str,
    expected_policy_digest: str,
    expected_runtime_manifest_digest: str,
    expected_binary_digest: str,
    expected_release_digest: str,
    expected_image_signatures_digest: str,
    expected_source_tree_digest: str,
    expected_response_signing_key_id: str,
    expected_tee_platform: str,
    expected_quote_provider: str,
    max_age_seconds: int,
) -> dict[str, Any]:
    assert_no_secret_fields(document)
    require(
        1 <= max_age_seconds <= PROXY_PROOF_MAX_AGE_LIMIT_SECONDS,
        f"proxy proof max age must be between 1 and {PROXY_PROOF_MAX_AGE_LIMIT_SECONDS} seconds",
    )
    require(document.get("apiVersion") == "serverware.proxyResponseProof/v3", "proxy response proof has wrong apiVersion")
    require(document.get("kind") == "ServerwareProxyResponseProof", "proxy response proof has wrong kind")
    require_exact_object_fields(
        document,
        {
            "apiVersion",
            "kind",
            "external_capture",
            "collector_signature",
            "server_statement",
            "server_signature",
            "vendor_tee",
        },
        "proxy response proof",
    )

    require(
        isinstance(expected_server_instance_id, str)
        and expected_server_instance_id.startswith("spiffe://")
        and len(expected_server_instance_id) > len("spiffe://"),
        "expected proxy server instance identity must be a SPIFFE ID",
    )

    expected_nonce_bytes = require_base64url_bytes(
        expected_client_nonce,
        "expected proxy proof client nonce",
        minimum_bytes=32,
    )
    require(
        len(expected_nonce_bytes) == 32,
        "expected proxy proof client nonce must contain exactly 32 bytes",
    )
    require_sha256(expected_request_digest, "expected proxy request digest")
    require_sha256(expected_operation_digest, "expected proxy operation digest")
    expected_bindings = {
        "policy_digest": require_sha256(expected_policy_digest, "expected proxy policy digest"),
        "runtime_manifest_digest": require_sha256(
            expected_runtime_manifest_digest,
            "expected proxy runtime manifest digest",
        ),
        "data_plane_binary_digest": require_sha256(expected_binary_digest, "expected proxy data-plane binary digest"),
        "release_digest": require_sha256(expected_release_digest, "expected proxy release digest"),
    }
    expected_tls_bytes = require_base64url_bytes(
        expected_tls_channel_binding,
        "expected proxy TLS channel binding",
        minimum_bytes=32,
    )
    expected_client_request_digest = require_sha256(
        expected_client_request_digest,
        "expected proxy client request digest",
    )

    external_capture = document.get("external_capture") if isinstance(document.get("external_capture"), dict) else {}
    require(
        external_capture.get("apiVersion") == "serverware.proxyResponseCapture/v2",
        "proxy response external capture has wrong apiVersion",
    )
    require_exact_object_fields(
        external_capture,
        {
            "apiVersion",
            "environment",
            "collection_mode",
            "captured_at_unix",
            "client_nonce",
            "client_request_digest",
            "principal_id",
            "route_id",
            "request_digest",
            "operation_digest",
            "release_authority",
            "control_plane_authorization_receipt",
            "upstream_response",
            "response",
            "tls_channel_binding",
            "tls_peer",
            "server_statement_sha256",
        },
        "proxy response external capture",
    )
    require(external_capture.get("environment") == "production", "proxy response external capture is not production evidence")
    require(
        external_capture.get("collection_mode") == "external-client-capture",
        "proxy response external capture is absent, dev, or self-reported",
    )
    captured_at = require_unix_time(
        external_capture.get("captured_at_unix"),
        "proxy response external capture time",
    )
    now = int(time.time())
    require(
        captured_at <= now + PROXY_PROOF_FUTURE_SKEW_SECONDS,
        "proxy response external capture time is in the future",
    )
    require(now - captured_at <= max_age_seconds, "proxy response external capture is stale")

    nonce = external_capture.get("client_nonce")
    nonce_bytes = require_base64url_bytes(nonce, "proxy response external capture client nonce", minimum_bytes=32)
    require(
        nonce == expected_client_nonce and nonce_bytes == expected_nonce_bytes,
        "proxy response external capture client nonce mismatch",
    )
    require(
        external_capture.get("principal_id") == expected_principal_id,
        "proxy response external capture principal ID does not match the independently configured expected proxy principal",
    )
    matched_route_id, expected_raw_policy_header_names = match_proxy_policy_route(
        policy_snapshot,
        principal_id=expected_principal_id,
        route_id=external_capture.get("route_id"),
    )
    matched_route = require_proxy_policy_route(
        policy_snapshot,
        principal_id=expected_principal_id,
        route_id=matched_route_id,
    )
    require(
        external_capture.get("route_id") == matched_route_id,
        "proxy response external capture route ID does not match the independently matched signed policy route",
    )
    client_request_digest = require_sha256(
        external_capture.get("client_request_digest"),
        "proxy response external client request digest",
    )
    require(
        client_request_digest == expected_client_request_digest,
        "proxy response external client request digest does not match the independently supplied client commitment",
    )
    request_digest = require_sha256(
        external_capture.get("request_digest"),
        "proxy response external capture canonical request digest",
    )
    operation_digest = require_sha256(
        external_capture.get("operation_digest"),
        "proxy response external capture operation digest",
    )
    require(request_digest == expected_request_digest, "proxy response external capture canonical request digest mismatch")
    require(operation_digest == expected_operation_digest, "proxy response external capture operation digest mismatch")
    release_authority = verify_proxy_release_authority(
        external_capture.get("release_authority"),
        expected_request_digest=request_digest,
        expected_operation_digest=operation_digest,
        latest_observation_at_unix=captured_at,
    )

    response = external_capture.get("response") if isinstance(external_capture.get("response"), dict) else {}
    require_exact_object_fields(
        response,
        {"status", "selected_headers", "selected_headers_digest", "body_digest"},
        "proxy response external capture response",
    )
    status = response.get("status")
    require(isinstance(status, int) and not isinstance(status, bool), "proxy response external capture status must be an integer")
    require(200 <= status < 300, "proxy response external capture did not bind a successful production response status")
    upstream_response = verify_proxy_upstream_response(
        external_capture.get("upstream_response"),
        expected_status=status,
        expected_header_names=expected_raw_policy_header_names,
    )
    selected_headers = response.get("selected_headers")
    require(
        isinstance(selected_headers, dict) and bool(selected_headers),
        "proxy response external capture is missing selected response headers",
    )
    require(len(selected_headers) <= 64, "proxy response external capture selected too many response headers")
    for name, value in selected_headers.items():
        require(
            isinstance(name, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) is not None,
            "proxy response external capture header names must be canonical lowercase HTTP field names",
        )
        require(
            isinstance(value, str) and "\r" not in value and "\n" not in value,
            f"proxy response external capture header {name} is invalid",
        )
    selected_headers_digest = require_sha256(
        response.get("selected_headers_digest"),
        "proxy response external capture selected response headers digest",
    )
    require(
        selected_headers_digest == sha256_prefixed_json(selected_headers),
        "proxy response external capture selected response headers digest mismatch",
    )
    body_digest = require_sha256(response.get("body_digest"), "proxy response external capture emitted body digest")
    required_selected_headers = {
        "content-length",
        "x-serverware-client-request-digest",
        "x-serverware-policy-hash",
        "x-serverware-request-digest",
        "x-serverware-operation-digest",
        "x-serverware-response-body-sha256",
    }
    selected_header_names = set(selected_headers)
    missing_selected_headers = sorted(required_selected_headers - selected_header_names)
    unexpected_selected_headers = sorted(
        selected_header_names - required_selected_headers - {"content-type"}
    )
    require(
        not missing_selected_headers,
        f"proxy response external capture is missing required selected response headers: {missing_selected_headers}",
    )
    require(
        not unexpected_selected_headers,
        f"proxy response external capture has unexpected selected response headers: {unexpected_selected_headers}",
    )
    require(
        re.fullmatch(r"0|[1-9][0-9]*", selected_headers["content-length"]) is not None,
        "proxy response external capture content-length header is not canonical",
    )
    require(
        selected_headers["x-serverware-client-request-digest"] == client_request_digest,
        "proxy response external client request digest header mismatch",
    )
    require(
        selected_headers["x-serverware-request-digest"] == request_digest,
        "proxy response external capture request digest header mismatch",
    )
    require(
        selected_headers["x-serverware-operation-digest"] == operation_digest,
        "proxy response external capture operation digest header mismatch",
    )
    require(
        selected_headers["x-serverware-response-body-sha256"] == body_digest,
        "proxy response external capture body digest header mismatch",
    )

    tls_channel_binding = (
        external_capture.get("tls_channel_binding")
        if isinstance(external_capture.get("tls_channel_binding"), dict)
        else {}
    )
    require_exact_object_fields(
        tls_channel_binding,
        {"type", "value"},
        "proxy response external capture TLS channel binding",
    )
    require(
        tls_channel_binding.get("type") == "tls-exporter",
        "proxy response external capture did not use a TLS exporter channel binding",
    )
    tls_value = tls_channel_binding.get("value")
    tls_bytes = require_base64url_bytes(
        tls_value,
        "proxy response external capture TLS channel binding",
        minimum_bytes=32,
    )
    require(
        tls_value == expected_tls_channel_binding and tls_bytes == expected_tls_bytes,
        "proxy response external capture TLS channel binding mismatch",
    )

    tls_peer = external_capture.get("tls_peer") if isinstance(external_capture.get("tls_peer"), dict) else {}
    require_exact_object_fields(
        tls_peer,
        {"spiffe_id", "leaf_certificate_sha256"},
        "proxy response external capture TLS peer",
    )
    tls_peer_spiffe_id = tls_peer.get("spiffe_id")
    require(
        isinstance(tls_peer_spiffe_id, str)
        and tls_peer_spiffe_id.startswith("spiffe://")
        and len(tls_peer_spiffe_id) > len("spiffe://"),
        "proxy response external capture TLS peer identity must be a SPIFFE ID",
    )
    require(
        tls_peer_spiffe_id == expected_server_instance_id,
        "proxy response external capture TLS peer SPIFFE ID does not match expected server instance",
    )
    tls_peer_leaf_certificate_digest = require_sha256(
        tls_peer.get("leaf_certificate_sha256"),
        "proxy response external capture TLS peer leaf certificate digest",
    )

    collector_signature = (
        document.get("collector_signature") if isinstance(document.get("collector_signature"), dict) else {}
    )
    require_exact_object_fields(
        collector_signature,
        {"algorithm", "key_id", "public_key_pem", "signature"},
        "proxy response collector signature",
    )
    require(
        collector_signature.get("algorithm") == "Ed25519",
        "proxy response collector signature algorithm is not Ed25519",
    )
    collector_public_key_pem = collector_signature.get("public_key_pem")
    collector_signature_value = collector_signature.get("signature")
    require(
        isinstance(collector_public_key_pem, str) and collector_public_key_pem,
        "proxy response external capture is missing its collector public key",
    )
    require(
        isinstance(collector_signature_value, str) and collector_signature_value,
        "proxy response external capture is missing its collector signature",
    )
    collector_public_key_der = ed25519_public_key_der(
        collector_public_key_pem,
        "proxy response external capture collector",
    )
    trusted_collector_public_key_der = ed25519_public_key_der(
        trusted_collector_public_key_pem,
        "trusted proxy response collector",
    )
    require(
        collector_public_key_der == trusted_collector_public_key_der,
        "proxy response collector signing key does not match the configured trust root",
    )
    collector_signing_key_id = sha256_prefixed_bytes(collector_public_key_der)
    require(
        collector_signature.get("key_id") == collector_signing_key_id,
        "proxy response collector signing key id mismatch",
    )
    verify_ed25519(
        collector_public_key_pem,
        collector_signature_value,
        canonical_json(external_capture).encode("utf-8"),
        "proxy response external capture collector",
    )

    server_statement = document.get("server_statement") if isinstance(document.get("server_statement"), dict) else {}
    require(
        server_statement.get("apiVersion") == "serverware.proxyResponseStatement/v2",
        "proxy response server statement has wrong apiVersion",
    )
    require_exact_object_fields(
        server_statement,
        {
            "apiVersion",
            "issued_at_unix",
            "client_nonce",
            "client_request_digest",
            "principal_id",
            "route_id",
            "request_digest",
            "operation_digest",
            "release_authority",
            "control_plane_authorization_receipt",
            "upstream_response",
            "response",
            "tls_channel_binding",
            "policy_digest",
            "runtime_manifest_digest",
            "data_plane_binary_digest",
            "release_digest",
            "server_instance",
        },
        "proxy response server statement",
    )
    issued_at = require_unix_time(
        server_statement.get("issued_at_unix"),
        "proxy response server statement issue time",
    )
    require(
        issued_at <= now + PROXY_PROOF_FUTURE_SKEW_SECONDS,
        "proxy response server statement issue time is in the future",
    )
    require(now - issued_at <= max_age_seconds, "proxy response server statement is stale")
    require(
        issued_at <= captured_at + PROXY_PROOF_FUTURE_SKEW_SECONDS,
        "proxy response server statement was issued after the external capture",
    )

    server_statement_digest = require_sha256(
        external_capture.get("server_statement_sha256"),
        "proxy response external capture server statement digest",
    )
    require(
        server_statement_digest == sha256_prefixed_json(server_statement),
        "proxy response external capture server statement digest mismatch",
    )

    server_signature = document.get("server_signature") if isinstance(document.get("server_signature"), dict) else {}
    require_exact_object_fields(
        server_signature,
        {"algorithm", "key_id", "public_key_pem", "signature"},
        "proxy response server signature",
    )
    require(server_signature.get("algorithm") == "Ed25519", "proxy response server signature algorithm is not Ed25519")
    response_public_key_pem = server_signature.get("public_key_pem")
    server_signature_value = server_signature.get("signature")
    require(
        isinstance(response_public_key_pem, str) and response_public_key_pem,
        "proxy response server statement is missing its signing public key",
    )
    require(
        isinstance(server_signature_value, str) and server_signature_value,
        "proxy response server statement is missing its signature",
    )
    response_signing_key_id = ed25519_public_key_id(response_public_key_pem, "proxy response server statement")
    require(
        server_signature.get("key_id") == response_signing_key_id,
        "proxy response server statement signing key id mismatch",
    )
    require(
        response_signing_key_id == require_sha256(
            expected_response_signing_key_id,
            "expected proxy response signing key id",
        ),
        "proxy response signing key does not match the fresh attested runtime",
    )
    verify_ed25519(
        response_public_key_pem,
        server_signature_value,
        canonical_json(server_statement).encode("utf-8"),
        "proxy response server statement",
    )

    statement_nonce = server_statement.get("client_nonce")
    require_base64url_bytes(statement_nonce, "proxy response server statement client nonce", minimum_bytes=32)
    require(
        statement_nonce == nonce,
        "proxy response external capture client_nonce does not match server statement",
    )
    require(
        server_statement.get("principal_id") == expected_principal_id,
        "proxy response server statement principal ID does not match the independently configured expected proxy principal",
    )
    require(
        server_statement.get("route_id") == matched_route_id,
        "proxy response server statement route ID does not match the independently matched signed policy route",
    )
    statement_request_digest = require_sha256(
        server_statement.get("request_digest"),
        "proxy response server statement canonical request digest",
    )
    require(
        statement_request_digest == request_digest,
        "proxy response external capture request_digest does not match server statement",
    )
    require(
        require_sha256(
            server_statement.get("client_request_digest"),
            "proxy response server statement client request digest",
        )
        == client_request_digest,
        "proxy response external client request digest does not match server statement",
    )
    statement_operation_digest = require_sha256(
        server_statement.get("operation_digest"),
        "proxy response server statement operation digest",
    )
    require(
        statement_operation_digest == operation_digest,
        "proxy response external capture operation_digest does not match server statement",
    )
    statement_release_authority = verify_proxy_release_authority(
        server_statement.get("release_authority"),
        expected_request_digest=statement_request_digest,
        expected_operation_digest=statement_operation_digest,
        latest_observation_at_unix=issued_at,
    )
    require(
        statement_release_authority == release_authority,
        "proxy response external capture release authority does not match server statement",
    )
    statement_upstream_response = verify_proxy_upstream_response(
        server_statement.get("upstream_response"),
        expected_status=status,
        expected_header_names=expected_raw_policy_header_names,
    )
    require(
        statement_upstream_response == upstream_response,
        "proxy response external capture upstream response does not match server statement",
    )
    embedded_control_plane_authorization_receipt = server_statement.get(
        "control_plane_authorization_receipt"
    )
    require(
        external_capture.get("control_plane_authorization_receipt")
        == embedded_control_plane_authorization_receipt,
        "proxy response external capture control-plane authorization receipt does not match server statement",
    )

    statement_response = (
        server_statement.get("response") if isinstance(server_statement.get("response"), dict) else {}
    )
    require_exact_object_fields(
        statement_response,
        {"status", "selected_headers", "selected_headers_digest", "body_digest"},
        "proxy response server statement response",
    )
    require(
        statement_response == response,
        "proxy response external capture response does not match server statement",
    )
    statement_tls_channel_binding = (
        server_statement.get("tls_channel_binding")
        if isinstance(server_statement.get("tls_channel_binding"), dict)
        else {}
    )
    require_exact_object_fields(
        statement_tls_channel_binding,
        {"type", "value"},
        "proxy response server statement TLS channel binding",
    )
    require(
        statement_tls_channel_binding == tls_channel_binding,
        "proxy response external capture tls_channel_binding does not match server statement",
    )

    bindings = {
        "policy_digest": require_sha256(
            server_statement.get("policy_digest"),
            "proxy response server statement policy digest",
        ),
        "runtime_manifest_digest": require_sha256(
            server_statement.get("runtime_manifest_digest"),
            "proxy response server statement runtime manifest digest",
        ),
        "data_plane_binary_digest": require_sha256(
            server_statement.get("data_plane_binary_digest"),
            "proxy response server statement data-plane binary digest",
        ),
        "release_digest": require_sha256(
            server_statement.get("release_digest"),
            "proxy response server statement release digest",
        ),
    }
    for field, expected in expected_bindings.items():
        require(bindings[field] == expected, f"proxy response server statement {field.replace('_', ' ')} mismatch")
    require(
        selected_headers["x-serverware-policy-hash"] == bindings["policy_digest"],
        "proxy response external capture policy hash header mismatch",
    )

    server_instance = (
        server_statement.get("server_instance")
        if isinstance(server_statement.get("server_instance"), dict)
        else {}
    )
    require_exact_object_fields(server_instance, {"id", "identity_digest"}, "proxy response server instance")
    server_instance_id = server_instance.get("id")
    require(
        isinstance(server_instance_id, str) and server_instance_id.startswith("spiffe://") and len(server_instance_id) > len("spiffe://"),
        "proxy response server statement server instance identity must be a SPIFFE ID",
    )
    require(
        server_instance_id == expected_server_instance_id,
        "proxy response server statement server instance does not match expected SPIFFE ID",
    )
    require(
        server_instance_id == tls_peer_spiffe_id,
        "proxy response server statement server instance does not match external capture TLS peer SPIFFE ID",
    )
    server_instance_identity_digest = require_sha256(
        server_instance.get("identity_digest"),
        "proxy response server statement server instance identity digest",
    )
    require(
        server_instance_identity_digest == sha256_prefixed_bytes(server_instance_id.encode("utf-8")),
        "proxy response server statement server instance identity digest mismatch",
    )

    vendor_tee = document.get("vendor_tee") if isinstance(document.get("vendor_tee"), dict) else {}
    tee_platform = require_production_identifier(vendor_tee.get("platform"), "proxy response vendor TEE platform")
    quote_provider = require_production_identifier(vendor_tee.get("provider"), "proxy response vendor quote provider")
    require(tee_platform == expected_tee_platform, "proxy response vendor TEE platform does not match release attestation")
    require(quote_provider == expected_quote_provider, "proxy response vendor quote provider does not match release attestation")
    quote = vendor_tee.get("quote") if isinstance(vendor_tee.get("quote"), dict) else {}
    require(bool(quote), "proxy response proof is missing a non-null vendor TEE quote")
    require_production_identifier(quote.get("format"), "proxy response vendor quote format")
    quote_body = require_base64url_bytes(
        quote.get("body_b64"),
        "proxy response vendor quote body",
        minimum_bytes=64,
    )
    require(
        len(quote_body) <= MAX_VENDOR_QUOTE_BYTES,
        "proxy response vendor quote body exceeds the schema size limit",
    )
    vendor_quote_digest = require_sha256(vendor_tee.get("quote_sha256"), "proxy response vendor quote digest")
    require(vendor_quote_digest == sha256_prefixed_json(quote), "proxy response vendor quote digest mismatch")

    trusted_verifier_key_id = ed25519_public_key_id(
        trusted_verifier_public_key_pem,
        "trusted proxy proof vendor verifier",
    )
    trusted_verifier = (
        vendor_tee.get("trusted_verifier") if isinstance(vendor_tee.get("trusted_verifier"), dict) else {}
    )
    require(
        trusted_verifier.get("apiVersion") == "serverware.vendorTeeVerification/v1",
        "proxy response vendor verifier result has wrong apiVersion",
    )
    require(
        trusted_verifier.get("kind") == "ServerwareVendorTeeVerification",
        "proxy response vendor verifier result has wrong kind",
    )
    verifier_statement = (
        trusted_verifier.get("statement") if isinstance(trusted_verifier.get("statement"), dict) else {}
    )
    verifier_signature = trusted_verifier.get("signature")
    require(bool(verifier_statement), "proxy response proof is missing a trusted vendor verifier statement")
    require(isinstance(verifier_signature, str) and verifier_signature, "proxy response proof is missing a trusted vendor verifier signature")
    require(
        verifier_statement.get("verifier_key_id") == trusted_verifier_key_id,
        "proxy response vendor verifier key is not the configured trust root",
    )
    verify_ed25519(
        trusted_verifier_public_key_pem,
        verifier_signature,
        canonical_json(verifier_statement).encode("utf-8"),
        "proxy response trusted vendor verifier",
    )
    require(verifier_statement.get("outcome") == "verified", "proxy response vendor TEE verification outcome is not verified")
    require(verifier_statement.get("environment") == "production", "proxy response vendor TEE verification is not production")
    require(
        verifier_statement.get("trust_basis") == "vendor-root-certificate-chain",
        "proxy response vendor TEE verifier did not use a vendor trust root",
    )
    require(verifier_statement.get("vendor_quote_verified") is True, "proxy response vendor quote was not verified")
    require(verifier_statement.get("certificate_chain_verified") is True, "proxy response vendor certificate chain was not verified")
    require(verifier_statement.get("revocation_checked") is True, "proxy response vendor quote revocation status was not checked")
    require(verifier_statement.get("debug") is False, "proxy response vendor TEE verification accepted debug mode")
    verified_at = require_unix_time(verifier_statement.get("verified_at_unix"), "proxy response vendor verification time")
    expires_at = require_unix_time(verifier_statement.get("expires_at_unix"), "proxy response vendor verification expiry")
    require(verified_at <= now + PROXY_PROOF_FUTURE_SKEW_SECONDS, "proxy response vendor verification time is in the future")
    require(now - verified_at <= max_age_seconds, "proxy response trusted vendor verifier receipt is stale")
    require(expires_at > verified_at, "proxy response vendor verifier validity window is invalid")
    require(expires_at >= now, "proxy response trusted vendor verifier receipt is expired")
    require(
        expires_at - verified_at <= PROXY_PROOF_MAX_AGE_LIMIT_SECONDS,
        "proxy response vendor verifier validity window is too long",
    )
    require(verifier_statement.get("tee_platform") == tee_platform, "proxy response vendor verifier TEE platform mismatch")
    require(verifier_statement.get("quote_provider") == quote_provider, "proxy response vendor verifier quote provider mismatch")
    require(
        verifier_statement.get("vendor_quote_sha256") == vendor_quote_digest,
        "proxy response vendor verifier quote digest mismatch",
    )
    require(
        "proof_evidence_sha256" not in verifier_statement,
        "proxy response vendor verifier used the legacy proof evidence digest binding",
    )
    require(
        verifier_statement.get("server_statement_sha256") == server_statement_digest,
        "proxy response vendor verifier server statement digest mismatch",
    )
    require(
        verifier_statement.get("response_signing_key_id") == response_signing_key_id,
        "proxy response vendor verifier did not bind the response signing key",
    )

    attested_claims = (
        verifier_statement.get("attested_claims")
        if isinstance(verifier_statement.get("attested_claims"), dict)
        else {}
    )
    expected_attested_claims: dict[str, Any] = {
        "server_statement_sha256": server_statement_digest,
        "server_statement_api_version": server_statement["apiVersion"],
        "issued_at_unix": issued_at,
        "client_nonce_sha256": sha256_prefixed_bytes(nonce_bytes),
        "client_request_digest": client_request_digest,
        "principal_id": expected_principal_id,
        "route_id": matched_route_id,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "release_authority": release_authority,
        "control_plane_authorization_receipt_sha256": (
            sha256_prefixed_json(embedded_control_plane_authorization_receipt)
        ),
        "upstream_response": upstream_response,
        "response_status": status,
        "selected_response_headers_digest": selected_headers_digest,
        "response_body_digest": body_digest,
        **bindings,
        "server_instance_id": server_instance_id,
        "server_instance_identity_digest": server_instance_identity_digest,
        "tls_channel_binding_type": tls_channel_binding["type"],
        "tls_channel_binding_sha256": sha256_prefixed_json(tls_channel_binding),
        "response_signing_key_id": response_signing_key_id,
    }
    for field, expected in expected_attested_claims.items():
        require(attested_claims.get(field) == expected, f"proxy response vendor TEE attested claim {field} mismatch")
    require(
        set(attested_claims) == set(expected_attested_claims),
        "proxy response vendor TEE attested claims do not exactly match the server statement",
    )
    control_plane_authorization = verify_control_plane_authorization_receipt(
        embedded_control_plane_authorization_receipt,
        trusted_public_key_pem=trusted_control_plane_response_signing_public_key_pem,
        expected_trusted_public_key_id=(
            expected_control_plane_response_signing_public_key_id
        ),
        expected_release_authority=release_authority,
        expected_principal_id=expected_principal_id,
        expected_route_id=matched_route_id,
        expected_runtime_manifest_digest=expected_runtime_manifest_digest,
        expected_policy_digest=expected_policy_digest,
        expected_provenance_digest=expected_release_digest,
        expected_image_signatures_digest=expected_image_signatures_digest,
        expected_source_tree_digest=expected_source_tree_digest,
        custody_authorization_envelope={
            "statement": server_statement,
            "statement_sha256": server_statement_digest,
            "signature": server_signature,
        },
        expected_custody_signing_key_id=expected_response_signing_key_id,
    )
    verify_route_authorization_evidence(
        matched_route,
        release_authority,
        control_plane_authorization,
        label="buffered proxy response proof",
    )
    control_plane_authorization_key_id = control_plane_authorization[
        "signing_key_id"
    ]
    for proof_role, proof_key_id in (
        ("external collector", collector_signing_key_id),
        ("response statement signer", response_signing_key_id),
        ("vendor TEE verifier", trusted_verifier_key_id),
    ):
        require(
            not hmac.compare_digest(
                control_plane_authorization_key_id, proof_key_id
            ),
            "control-plane response signing trust root must be independent "
            f"from the proxy proof {proof_role} key",
        )

    return {
        "proof_contract": "buffered-v3",
        "apiVersion": document.get("apiVersion"),
        "server_statement_api_version": server_statement.get("apiVersion"),
        "server_statement_sha256": server_statement_digest,
        "captured_at_unix": captured_at,
        "issued_at_unix": issued_at,
        "client_nonce_sha256": sha256_prefixed_bytes(nonce_bytes),
        "client_request_digest": client_request_digest,
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "principal_id": expected_principal_id,
        "route_id": matched_route_id,
        "release_authority": release_authority,
        "compiled_route_authority_verified": True,
        "control_plane_response_signing_key_id": (
            control_plane_authorization_key_id
        ),
        "control_plane_authorization_receipt": control_plane_authorization,
        "upstream_response": upstream_response,
        "status": status,
        "selected_response_headers_digest": selected_headers_digest,
        "emitted_body_digest": body_digest,
        **bindings,
        "server_instance_id": server_instance_id,
        "server_instance_identity_digest": server_instance_identity_digest,
        "tls_channel_binding_sha256": sha256_prefixed_json(tls_channel_binding),
        "tls_peer_spiffe_id": tls_peer_spiffe_id,
        "tls_peer_leaf_certificate_sha256": tls_peer_leaf_certificate_digest,
        "collector_signing_key_id": collector_signing_key_id,
        "response_signing_key_id": response_signing_key_id,
        "vendor_tee_platform": tee_platform,
        "vendor_quote_provider": quote_provider,
        "vendor_quote_sha256": vendor_quote_digest,
        "trusted_verifier_key_id": trusted_verifier_key_id,
        "vendor_quote_verified": True,
        "trusted_verifier_outcome": "verified",
        "collector_signature_verified": True,
        "server_statement_signature_verified": True,
        "fresh_client_nonce_bound": True,
        "authenticated_external_client_capture_bound": True,
        "release_authority_bound": True,
        "embedded_control_plane_authorization_receipt_bound": True,
        "signed_policy_route_bound": True,
        "signed_policy_response_headers_bound": True,
        "upstream_response_bound": True,
        "release_artifacts_bound": True,
    }


OBSERVATION_STATEMENT_API_VERSION = "serverware.responseObservationStatement/v1"
OBSERVATION_RUNTIME_PROOF_API_VERSION = "serverware.responseObservationRuntimeProof/v1"
OBSERVATION_TLS_EXPORTER_LABEL = "EXPORTER-Serverware-Response-Observation-v1"
OBSERVATION_MAX_BODY_BYTES = MAX_PROXY_OBSERVATION_BODY_BYTES
OBSERVATION_RESPONSE_PATHS = {
    "local-reject-no-upstream-attempt",
    "dispatch-denied-no-upstream-attempt",
    "authorized-not-attempted",
    "upstream-attempt-outcome-unknown",
    "complete-upstream-response-released",
    "complete-upstream-response-blocked",
    "post-dispatch-local-failure",
}
OBSERVATION_UPSTREAM_ATTEMPTS = {
    "not-started",
    "started-no-response",
    "headers-observed-body-incomplete",
    "complete",
}


def require_observation_count(value: Any, label: str, *, maximum: int) -> int:
    count = require_uint64(value, label)
    require(count <= maximum, f"{label} exceeds the observation contract limit")
    return count


def require_observation_identifier(value: Any, label: str) -> str:
    require(
        isinstance(value, str)
        and 1 <= len(value) <= 256
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", value) is not None,
        f"{label} is invalid",
    )
    return value


def verify_observation_request(value: Any, *, statement_form: bool) -> dict[str, Any]:
    label = "response observation statement request" if statement_form else "response observation collector request"
    require(isinstance(value, dict), f"{label} must be an object")
    request = dict(value)
    fields = {
        "method",
        "target_digest",
        "query_present",
        "query_digest",
        "headers_digest",
        "header_count",
        "body_digest",
        "body_bytes",
        "aggregate_digest",
    }
    if statement_form:
        fields.add("body_observation")
    require_exact_object_fields(request, fields, label)
    method = request.get("method")
    require(
        isinstance(method, str)
        and 1 <= len(method) <= 64
        and re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Z-]+", method) is not None,
        f"{label} method is invalid",
    )
    for field in ("target_digest", "query_digest", "headers_digest", "body_digest"):
        require_sha256(request.get(field), f"{label} {field.replace('_', ' ')}")
    require(isinstance(request.get("query_present"), bool), f"{label} query presence is invalid")
    require_observation_count(request.get("header_count"), f"{label} header count", maximum=65535)
    require_observation_count(
        request.get("body_bytes"),
        f"{label} body byte count",
        maximum=OBSERVATION_MAX_BODY_BYTES,
    )
    if statement_form:
        require(
            request.get("body_observation") == "complete-buffered",
            f"{label} does not prove complete buffered request-body observation",
        )
    aggregate_digest = require_sha256(request.get("aggregate_digest"), f"{label} aggregate digest")
    aggregate = {field: request[field] for field in request if field != "aggregate_digest"}
    if not statement_form:
        # The public collector view omits this constant field, but its digest is
        # the statement aggregate over the complete-buffered observation.
        aggregate["body_observation"] = "complete-buffered"
    require(
        aggregate_digest == sha256_prefixed_json(aggregate),
        f"{label} aggregate digest mismatch",
    )
    return request


def verify_observation_response(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    response = dict(value)
    require_exact_object_fields(
        response,
        {
            "status",
            "headers_digest",
            "header_count",
            "body_digest",
            "body_bytes",
            "aggregate_digest",
        },
        label,
    )
    status = require_uint64(response.get("status"), f"{label} status")
    require(200 <= status <= 599, f"{label} status is invalid")
    require_sha256(response.get("headers_digest"), f"{label} headers digest")
    require_observation_count(response.get("header_count"), f"{label} header count", maximum=65535)
    require_sha256(response.get("body_digest"), f"{label} body digest")
    require_observation_count(
        response.get("body_bytes"),
        f"{label} body byte count",
        maximum=OBSERVATION_MAX_BODY_BYTES,
    )
    aggregate_digest = require_sha256(response.get("aggregate_digest"), f"{label} aggregate digest")
    require(
        aggregate_digest
        == sha256_prefixed_json({field: response[field] for field in response if field != "aggregate_digest"}),
        f"{label} aggregate digest mismatch",
    )
    return response


def verify_observation_upstream(value: Any, *, attempt: str) -> dict[str, Any] | None:
    label = "response observation upstream observation"
    if attempt in {"not-started", "started-no-response"}:
        require(value is None, f"{label} must be null before response headers are observed")
        return None
    require(isinstance(value, dict), f"{label} must be an object after response headers are observed")
    upstream = dict(value)
    require_exact_object_fields(
        upstream,
        {
            "status",
            "headers_digest",
            "header_count",
            "body_state",
            "body_digest",
            "body_bytes",
            "aggregate_digest",
        },
        label,
    )
    status = require_uint64(upstream.get("status"), f"{label} status")
    require(200 <= status <= 599, f"{label} status is invalid")
    require_sha256(upstream.get("headers_digest"), f"{label} headers digest")
    require_observation_count(upstream.get("header_count"), f"{label} header count", maximum=65535)
    body_state = upstream.get("body_state")
    require(body_state in {"unread", "incomplete", "complete"}, f"{label} body state is invalid")
    if body_state == "unread":
        require(
            upstream.get("body_digest") is None and upstream.get("body_bytes") is None,
            f"{label} unread body must not carry body commitments",
        )
    else:
        require_sha256(upstream.get("body_digest"), f"{label} body digest")
        require_observation_count(
            upstream.get("body_bytes"),
            f"{label} body byte count",
            maximum=OBSERVATION_MAX_BODY_BYTES,
        )
    require(
        (attempt == "complete" and body_state == "complete")
        or (attempt == "headers-observed-body-incomplete" and body_state in {"unread", "incomplete"}),
        f"{label} body state does not match upstream attempt state",
    )
    aggregate_digest = require_sha256(upstream.get("aggregate_digest"), f"{label} aggregate digest")
    require(
        aggregate_digest
        == sha256_prefixed_json({field: upstream[field] for field in upstream if field != "aggregate_digest"}),
        f"{label} aggregate digest mismatch",
    )
    return upstream


def verify_observation_vendor_tee(
    value: Any,
    *,
    trusted_verifier_public_key_pem: str,
    expected_tee_platform: str,
    expected_quote_provider: str,
    statement_digest: str,
    response_signing_key_id: str,
    expected_attested_claims: dict[str, Any],
    max_age_seconds: int,
    now: int,
) -> dict[str, Any]:
    label = "response observation vendor TEE"
    require(isinstance(value, dict), f"{label} must be an object")
    vendor = dict(value)
    require_exact_object_fields(
        vendor,
        {"platform", "provider", "quote_sha256", "quote", "trusted_verifier"},
        label,
    )
    platform_value = require_production_identifier(vendor.get("platform"), f"{label} platform")
    provider = require_production_identifier(vendor.get("provider"), f"{label} provider")
    require(platform_value == expected_tee_platform, f"{label} platform does not match release attestation")
    require(provider == expected_quote_provider, f"{label} provider does not match release attestation")
    quote = vendor.get("quote")
    require(isinstance(quote, dict), f"{label} quote must be an object")
    require_exact_object_fields(quote, {"format", "body_b64"}, f"{label} quote")
    require_production_identifier(quote.get("format"), f"{label} quote format")
    quote_body = require_base64url_bytes(
        quote.get("body_b64"),
        f"{label} quote body",
        minimum_bytes=64,
    )
    require(
        len(quote_body) <= MAX_VENDOR_QUOTE_BYTES,
        f"{label} quote body exceeds the schema size limit",
    )
    quote_digest = require_sha256(vendor.get("quote_sha256"), f"{label} quote digest")
    require(quote_digest == sha256_prefixed_json(quote), f"{label} quote digest mismatch")

    trusted = vendor.get("trusted_verifier")
    require(isinstance(trusted, dict), f"{label} trusted verifier must be an object")
    require_exact_object_fields(
        trusted,
        {"apiVersion", "kind", "statement", "signature"},
        f"{label} trusted verifier",
    )
    require(
        trusted.get("apiVersion") == "serverware.vendorTeeVerification/v1"
        and trusted.get("kind") == "ServerwareVendorTeeVerification",
        f"{label} trusted verifier type mismatch",
    )
    verifier_statement = trusted.get("statement")
    require(isinstance(verifier_statement, dict), f"{label} verifier statement must be an object")
    require_exact_object_fields(
        verifier_statement,
        {
            "verifier_key_id",
            "outcome",
            "environment",
            "trust_basis",
            "vendor_quote_verified",
            "certificate_chain_verified",
            "revocation_checked",
            "debug",
            "verified_at_unix",
            "expires_at_unix",
            "tee_platform",
            "quote_provider",
            "vendor_quote_sha256",
            "server_statement_sha256",
            "response_signing_key_id",
            "attested_claims",
        },
        f"{label} verifier statement",
    )
    verifier_key_id = ed25519_public_key_id(
        trusted_verifier_public_key_pem,
        f"{label} trust root",
    )
    require(
        verifier_statement.get("verifier_key_id") == verifier_key_id,
        f"{label} verifier key is not the configured trust root",
    )
    verify_ed25519(
        trusted_verifier_public_key_pem,
        str(trusted.get("signature") or ""),
        canonical_json(verifier_statement).encode("utf-8"),
        f"{label} trusted verifier",
    )
    exact = {
        "outcome": "verified",
        "environment": "production",
        "trust_basis": "vendor-root-certificate-chain",
        "vendor_quote_verified": True,
        "certificate_chain_verified": True,
        "revocation_checked": True,
        "debug": False,
        "tee_platform": platform_value,
        "quote_provider": provider,
        "vendor_quote_sha256": quote_digest,
        "server_statement_sha256": statement_digest,
        "response_signing_key_id": response_signing_key_id,
        "attested_claims": expected_attested_claims,
    }
    for field, expected in exact.items():
        require(verifier_statement.get(field) == expected, f"{label} verifier {field} mismatch")
    verified_at = require_unix_time(verifier_statement.get("verified_at_unix"), f"{label} verification time")
    expires_at = require_unix_time(verifier_statement.get("expires_at_unix"), f"{label} verification expiry")
    require(verified_at <= now + PROXY_PROOF_FUTURE_SKEW_SECONDS, f"{label} verification time is in the future")
    require(now - verified_at <= max_age_seconds, f"{label} verifier receipt is stale")
    require(expires_at >= now and expires_at > verified_at, f"{label} verifier receipt is expired")
    require(
        expires_at - verified_at <= PROXY_PROOF_MAX_AGE_LIMIT_SECONDS,
        f"{label} verifier validity window is too long",
    )
    return {
        "platform": platform_value,
        "provider": provider,
        "quote_sha256": quote_digest,
        "trusted_verifier_key_id": verifier_key_id,
        "verified_at_unix": verified_at,
        "expires_at_unix": expires_at,
    }


def verify_production_response_observation_proof(
    document: dict[str, Any],
    *,
    observation_body_snapshot: FileSnapshot,
    trusted_verifier_public_key_pem: str,
    trusted_collector_public_key_pem: str,
    trusted_control_plane_response_signing_public_key_pem: str,
    expected_control_plane_response_signing_public_key_id: str,
    policy_snapshot: PolicySnapshot,
    expected_principal_id: str,
    expected_server_instance_id: str,
    expected_client_nonce: str,
    expected_client_request_digest: str,
    expected_request_digest: str,
    expected_operation_digest: str,
    expected_tls_channel_binding: str,
    expected_policy_digest: str,
    expected_runtime_manifest_digest: str,
    expected_binary_digest: str,
    expected_release_digest: str,
    expected_image_signatures_digest: str,
    expected_source_tree_digest: str,
    expected_response_signing_key_id: str,
    expected_tee_platform: str,
    expected_quote_provider: str,
    max_age_seconds: int,
) -> dict[str, Any]:
    label = "response observation proof"
    assert_no_secret_fields(document)
    require(1 <= max_age_seconds <= PROXY_PROOF_MAX_AGE_LIMIT_SECONDS, f"{label} max age is invalid")
    require(isinstance(document, dict), f"{label} must be an object")
    require_exact_object_fields(
        document,
        {"apiVersion", "kind", "captured_at_unix", "request", "response", "runtime_proof", "collector"},
        label,
    )
    require(
        document.get("apiVersion") == "serverware.responseObservationProof/v1"
        and document.get("kind") == "ServerwareResponseObservationProof",
        f"{label} has the wrong type",
    )
    now = int(time.time())
    captured_at = require_unix_time(document.get("captured_at_unix"), f"{label} capture time")
    require(captured_at <= now + PROXY_PROOF_FUTURE_SKEW_SECONDS, f"{label} capture time is in the future")
    require(now - captured_at <= max_age_seconds, f"{label} capture is stale")
    nonce_bytes = require_base64url_bytes(expected_client_nonce, f"{label} expected nonce", minimum_bytes=32)
    require(len(nonce_bytes) == 32, f"{label} expected nonce must contain exactly 32 bytes")
    nonce_expires_at = int.from_bytes(
        nonce_bytes[:RESPONSE_OBSERVATION_NONCE_EXPIRY_BYTES], "big"
    )
    require(
        any(nonce_bytes[RESPONSE_OBSERVATION_NONCE_EXPIRY_BYTES:]),
        f"{label} expected nonce random bytes must not be all zero",
    )
    require(
        nonce_expires_at + PROXY_PROOF_FUTURE_SKEW_SECONDS >= captured_at,
        f"{label} expected nonce expired before the response capture",
    )
    require(
        nonce_expires_at
        <= captured_at
        + RESPONSE_OBSERVATION_NONCE_MAX_LIFETIME_SECONDS
        + PROXY_PROOF_FUTURE_SKEW_SECONDS,
        f"{label} expected nonce expiry exceeds the bounded freshness window",
    )
    tls_bytes = require_base64url_bytes(
        expected_tls_channel_binding,
        f"{label} expected TLS exporter",
        minimum_bytes=32,
    )
    require(len(tls_bytes) == 32, f"{label} expected TLS exporter must contain exactly 32 bytes")

    external_request = verify_observation_request(document.get("request"), statement_form=False)
    external_response = verify_observation_response(document.get("response"), f"{label} collector response")
    require(
        external_response["body_digest"] == observation_body_snapshot.sha256,
        f"{label} collector response body digest does not match the separately published body",
    )
    require(
        external_response["body_bytes"] == len(observation_body_snapshot.data),
        f"{label} collector response body byte count does not match the separately published body",
    )
    expected_client_request_digest = require_sha256(
        expected_client_request_digest,
        f"{label} expected client request digest",
    )
    require(
        external_request["aggregate_digest"] == expected_client_request_digest,
        f"{label} request aggregate does not match the independently pinned client request digest",
    )

    collector = document.get("collector")
    require(isinstance(collector, dict), f"{label} collector must be an object")
    require_exact_object_fields(
        collector,
        {"algorithm", "key_id", "public_key_pem", "signature", "capture_digest"},
        f"{label} collector",
    )
    require(collector.get("algorithm") == "Ed25519", f"{label} collector algorithm mismatch")
    collector_public_key_pem = collector.get("public_key_pem")
    require(isinstance(collector_public_key_pem, str), f"{label} collector public key is missing")
    collector_der = ed25519_public_key_der(collector_public_key_pem, f"{label} collector")
    trusted_collector_der = ed25519_public_key_der(
        trusted_collector_public_key_pem,
        f"{label} trusted collector",
    )
    require(collector_der == trusted_collector_der, f"{label} collector key is not the configured trust root")
    collector_key_id = sha256_prefixed_bytes(collector_der)
    require(collector.get("key_id") == collector_key_id, f"{label} collector key ID mismatch")
    capture = {field: document[field] for field in document if field != "collector"}
    capture_digest = require_sha256(collector.get("capture_digest"), f"{label} collector capture digest")
    require(capture_digest == sha256_prefixed_json(capture), f"{label} collector capture digest mismatch")
    verify_ed25519(
        collector_public_key_pem,
        str(collector.get("signature") or ""),
        canonical_json(capture).encode("utf-8"),
        f"{label} collector",
    )

    runtime = document.get("runtime_proof")
    require(isinstance(runtime, dict), f"{label} runtime proof must be an object; terminal proof evidence is required")
    require_exact_object_fields(
        runtime,
        {"apiVersion", "kind", "server_statement", "server_statement_sha256", "server_signature", "vendor_tee"},
        f"{label} runtime proof",
    )
    require(
        runtime.get("apiVersion") == OBSERVATION_RUNTIME_PROOF_API_VERSION
        and runtime.get("kind") == "ServerwareResponseObservationRuntimeProof",
        f"{label} runtime proof has the wrong type",
    )
    statement = runtime.get("server_statement")
    require(isinstance(statement, dict), f"{label} server statement must be an object")
    require_exact_object_fields(
        statement,
        {
            "apiVersion",
            "issued_at_unix",
            "observation_id",
            "client_nonce",
            "request",
            "policy",
            "principal_id",
            "route_id",
            "request_digest",
            "operation_digest",
            "credential",
            "authorization",
            "response_path",
            "upstream_attempt",
            "upstream_observation",
            "emitted_response",
            "runtime_manifest_digest",
            "data_plane_binary_digest",
            "release_digest",
            "server_instance",
            "tls_channel_binding",
            "observation_authority",
        },
        f"{label} server statement",
    )
    require(statement.get("apiVersion") == OBSERVATION_STATEMENT_API_VERSION, f"{label} statement version mismatch")
    issued_at = require_unix_time(statement.get("issued_at_unix"), f"{label} statement issue time")
    require(issued_at <= now + PROXY_PROOF_FUTURE_SKEW_SECONDS, f"{label} statement issue time is in the future")
    require(now - issued_at <= max_age_seconds, f"{label} statement is stale")
    require(issued_at <= captured_at + PROXY_PROOF_FUTURE_SKEW_SECONDS, f"{label} statement postdates capture")
    require(statement.get("client_nonce") == expected_client_nonce, f"{label} statement nonce mismatch")
    observation_id = require_sha256(statement.get("observation_id"), f"{label} observation ID")
    require(
        observation_id
        == sha256_prefixed_json(
            {"client_nonce": expected_client_nonce, "contract": OBSERVATION_STATEMENT_API_VERSION}
        ),
        f"{label} observation ID commitment mismatch",
    )

    statement_request = verify_observation_request(statement.get("request"), statement_form=True)
    require(
        external_request
        == {field: value for field, value in statement_request.items() if field != "body_observation"},
        f"{label} collector request does not exactly match the signed request commitments",
    )
    emitted_response = verify_observation_response(
        statement.get("emitted_response"),
        f"{label} emitted response",
    )
    require(external_response == emitted_response, f"{label} collector response does not exactly match emitted response")

    policy = statement.get("policy")
    require(isinstance(policy, dict), f"{label} policy observation must be an object")
    require_exact_object_fields(
        policy,
        {"digest", "snapshot_epoch", "decision_state", "completion_state"},
        f"{label} policy observation",
    )
    policy_digest = require_sha256(policy.get("digest"), f"{label} policy digest")
    require(policy_digest == expected_policy_digest == policy_snapshot.hash, f"{label} policy digest mismatch")
    require_uint64(policy.get("snapshot_epoch"), f"{label} policy snapshot epoch")
    require(
        policy.get("decision_state") == "allowed" and policy.get("completion_state") == "same-active",
        f"{label} production completion requires an allowed decision from the same active policy snapshot",
    )
    principal_id = require_observation_identifier(statement.get("principal_id"), f"{label} principal ID")
    route_id = require_observation_identifier(statement.get("route_id"), f"{label} route ID")
    require(principal_id == expected_principal_id, f"{label} principal mismatch")
    matched_route = require_proxy_policy_route(
        policy_snapshot,
        principal_id=principal_id,
        route_id=route_id,
    )
    matched_route_id = matched_route.id
    require(route_id == matched_route_id, f"{label} route mismatch")
    request_digest = require_sha256(statement.get("request_digest"), f"{label} dispatched request digest")
    operation_digest = require_sha256(statement.get("operation_digest"), f"{label} operation digest")
    require(request_digest == expected_request_digest, f"{label} dispatched request digest mismatch")
    require(operation_digest == expected_operation_digest, f"{label} operation digest mismatch")

    credential = statement.get("credential")
    require(isinstance(credential, dict), f"{label} credential observation must be an object")
    require_exact_object_fields(credential, {"state", "binding_digest"}, f"{label} credential observation")
    credential_state = credential.get("state")
    require(credential_state in {"not-required", "injected"}, f"{label} credential was not dispatch-ready")
    if matched_route.credential_ref is None:
        require(
            credential_state == "not-required"
            and credential.get("binding_digest") is None,
            f"{label} credential evidence does not match the credentialless signed route",
        )
    else:
        require(
            credential_state == "injected",
            f"{label} credentialed signed route lacks injected credential evidence",
        )

    authorization = statement.get("authorization")
    require(isinstance(authorization, dict), f"{label} authorization observation must be an object")
    require_exact_object_fields(
        authorization,
        {
            "state",
            "binding_digest",
            "release_authority",
            "control_plane_authorization_receipt",
            "control_plane_authorization_receipt_sha256",
        },
        f"{label} authorization observation",
    )
    authorization_state = authorization.get("state")
    require(
        authorization_state
        in {
            "not-evaluated",
            "denied",
            "reserved",
            "dispatching",
            "completed-forwarded",
            "completion-unknown",
        },
        f"{label} authorization state is invalid",
    )
    full_authorization_states = {"dispatching", "completed-forwarded", "completion-unknown"}
    full_authorization = authorization_state in full_authorization_states
    require(
        full_authorization or not route_requires_atomic_authorization(matched_route),
        f"{label} signed route requires atomic credential, JIT, or shared-quota authorization evidence",
    )
    authorization_fields = (
        authorization.get("binding_digest"),
        authorization.get("release_authority"),
        authorization.get("control_plane_authorization_receipt"),
        authorization.get("control_plane_authorization_receipt_sha256"),
    )
    require(
        all(value is not None for value in authorization_fields)
        if full_authorization
        else all(value is None for value in authorization_fields),
        f"{label} authorization evidence nullability does not match authorization state",
    )
    release_authority: dict[str, Any] | None = None
    authorization_binding_digest: str | None = None
    receipt: Any = None
    receipt_digest: str | None = None
    if full_authorization:
        release_authority = verify_proxy_release_authority(
            authorization.get("release_authority"),
            expected_request_digest=request_digest,
            expected_operation_digest=operation_digest,
            latest_observation_at_unix=issued_at,
        )
        require(
            release_authority["credential_ref"] == matched_route.credential_ref,
            f"{label} release authority credential does not match the signed route",
        )
        jit_required = (matched_route.jit or {}).get("required") is True
        require(
            (
                release_authority["grant_id"] is not None
                and release_authority["approval_id"] is not None
            )
            == jit_required,
            f"{label} release authority JIT evidence does not match the signed route",
        )
        authorization_binding_digest = require_sha256(
            authorization.get("binding_digest"),
            f"{label} authorization binding digest",
        )
        require(
            authorization_binding_digest == release_authority["consumption_identity_digest"],
            f"{label} authorization binding digest mismatch",
        )
        receipt = authorization.get("control_plane_authorization_receipt")
        receipt_digest = require_sha256(
            authorization.get("control_plane_authorization_receipt_sha256"),
            f"{label} control-plane authorization receipt digest",
        )
        require(
            receipt_digest == sha256_prefixed_json(receipt),
            f"{label} control-plane authorization receipt digest mismatch",
        )
        if credential_state == "not-required":
            require(
                credential.get("binding_digest") is None
                and release_authority["credential_ref"] is None
                and release_authority["credential_version"] == 0,
                f"{label} credential-free observation disagrees with release authority",
            )
        else:
            credential_binding = require_sha256(
                credential.get("binding_digest"),
                f"{label} credential binding digest",
            )
            require(
                credential_binding
                == sha256_prefixed_json(
                    {
                        "credential_ref": release_authority["credential_ref"],
                        "credential_version": release_authority["credential_version"],
                    }
                ),
                f"{label} credential binding digest mismatch",
            )
    else:
        require(
            credential_state == "not-required" and credential.get("binding_digest") is None,
            f"{label} dispatch without atomic authorization must be credentialless",
        )

    response_path = statement.get("response_path")
    upstream_attempt = statement.get("upstream_attempt")
    require(response_path in OBSERVATION_RESPONSE_PATHS, f"{label} response path is invalid")
    require(upstream_attempt in OBSERVATION_UPSTREAM_ATTEMPTS, f"{label} upstream attempt state is invalid")
    require(
        response_path in {"complete-upstream-response-released", "complete-upstream-response-blocked"}
        and upstream_attempt == "complete",
        f"{label} production completion requires a complete upstream response observation",
    )
    require(
        authorization_state not in {"denied", "reserved"},
        f"{label} denied or reserved authorization cannot accompany a post-dispatch response path",
    )
    upstream = verify_observation_upstream(
        statement.get("upstream_observation"),
        attempt=upstream_attempt,
    )

    server_instance = statement.get("server_instance")
    require(isinstance(server_instance, dict), f"{label} server instance must be an object")
    require_exact_object_fields(server_instance, {"id", "identity_digest"}, f"{label} server instance")
    require(server_instance.get("id") == expected_server_instance_id, f"{label} server instance mismatch")
    server_identity_digest = require_sha256(
        server_instance.get("identity_digest"),
        f"{label} server instance identity digest",
    )
    require(
        server_identity_digest == sha256_prefixed_bytes(expected_server_instance_id.encode("utf-8")),
        f"{label} server instance identity digest mismatch",
    )
    tls = statement.get("tls_channel_binding")
    require(isinstance(tls, dict), f"{label} TLS channel binding must be an object")
    require_exact_object_fields(tls, {"type", "label", "value"}, f"{label} TLS channel binding")
    require(
        tls
        == {
            "type": "tls-exporter",
            "label": OBSERVATION_TLS_EXPORTER_LABEL,
            "value": expected_tls_channel_binding,
        },
        f"{label} TLS exporter binding mismatch",
    )
    authority = statement.get("observation_authority")
    require(isinstance(authority, dict), f"{label} observation authority must be an object")
    require_exact_object_fields(
        authority,
        {"source", "upstream_truth", "downstream_delivery"},
        f"{label} observation authority",
    )
    require(
        authority
        == {
            "source": "gate-authored",
            "upstream_truth": "not-independently-observed",
            "downstream_delivery": "not-claimed",
        },
        f"{label} observation authority overclaims its evidence",
    )
    bindings = {
        "runtime_manifest_digest": require_sha256(
            statement.get("runtime_manifest_digest"),
            f"{label} runtime manifest digest",
        ),
        "data_plane_binary_digest": require_sha256(
            statement.get("data_plane_binary_digest"),
            f"{label} data-plane binary digest",
        ),
        "release_digest": require_sha256(statement.get("release_digest"), f"{label} release digest"),
    }
    require(bindings["runtime_manifest_digest"] == expected_runtime_manifest_digest, f"{label} runtime manifest mismatch")
    require(bindings["data_plane_binary_digest"] == expected_binary_digest, f"{label} data-plane binary mismatch")
    require(bindings["release_digest"] == expected_release_digest, f"{label} release digest mismatch")

    statement_digest = require_sha256(runtime.get("server_statement_sha256"), f"{label} statement digest")
    require(statement_digest == sha256_prefixed_json(statement), f"{label} statement digest mismatch")
    server_signature = runtime.get("server_signature")
    require(isinstance(server_signature, dict), f"{label} server signature must be an object")
    require_exact_object_fields(
        server_signature,
        {"algorithm", "key_id", "public_key_pem", "signature"},
        f"{label} server signature",
    )
    require(server_signature.get("algorithm") == "Ed25519", f"{label} server signature algorithm mismatch")
    response_public_key_pem = server_signature.get("public_key_pem")
    require(isinstance(response_public_key_pem, str), f"{label} response signing public key is missing")
    response_signing_key_id = ed25519_public_key_id(response_public_key_pem, f"{label} response signer")
    require(server_signature.get("key_id") == response_signing_key_id, f"{label} response signer key ID mismatch")
    require(response_signing_key_id == expected_response_signing_key_id, f"{label} response signer does not match attested runtime")
    verify_ed25519(
        response_public_key_pem,
        str(server_signature.get("signature") or ""),
        canonical_json(statement).encode("utf-8"),
        f"{label} server statement",
    )

    expected_attested_claims = {
        "server_statement_sha256": statement_digest,
        "server_statement_api_version": OBSERVATION_STATEMENT_API_VERSION,
        "issued_at_unix": issued_at,
        "observation_id": observation_id,
        "client_nonce_sha256": sha256_prefixed_bytes(nonce_bytes),
        "request_aggregate_digest": statement_request["aggregate_digest"],
        "response_path": response_path,
        "upstream_attempt": upstream_attempt,
        "upstream_observation_digest": upstream["aggregate_digest"] if upstream is not None else None,
        "emitted_response_digest": emitted_response["aggregate_digest"],
        "policy_digest": policy_digest,
        **bindings,
        "server_instance_id": expected_server_instance_id,
        "server_instance_identity_digest": server_identity_digest,
        "tls_exporter_label": OBSERVATION_TLS_EXPORTER_LABEL,
        "tls_channel_binding_sha256": sha256_prefixed_bytes(expected_tls_channel_binding.encode("utf-8")),
        "response_signing_key_id": response_signing_key_id,
        "observation_source": "gate-authored",
    }
    vendor_summary = verify_observation_vendor_tee(
        runtime.get("vendor_tee"),
        trusted_verifier_public_key_pem=trusted_verifier_public_key_pem,
        expected_tee_platform=expected_tee_platform,
        expected_quote_provider=expected_quote_provider,
        statement_digest=statement_digest,
        response_signing_key_id=response_signing_key_id,
        expected_attested_claims=expected_attested_claims,
        max_age_seconds=max_age_seconds,
        now=now,
    )
    control_plane_key_id = ed25519_public_key_id(
        trusted_control_plane_response_signing_public_key_pem,
        f"{label} control-plane response signing trust root",
    )
    require(
        control_plane_key_id == expected_control_plane_response_signing_public_key_id,
        f"{label} control-plane response signing trust root ID mismatch",
    )
    control_plane: dict[str, Any] | None = None
    if full_authorization:
        control_plane = verify_control_plane_authorization_receipt(
            receipt,
            trusted_public_key_pem=trusted_control_plane_response_signing_public_key_pem,
            expected_trusted_public_key_id=expected_control_plane_response_signing_public_key_id,
            expected_release_authority=release_authority,
            expected_principal_id=expected_principal_id,
            expected_route_id=matched_route_id,
            expected_runtime_manifest_digest=expected_runtime_manifest_digest,
            expected_policy_digest=expected_policy_digest,
            expected_provenance_digest=expected_release_digest,
            expected_image_signatures_digest=expected_image_signatures_digest,
            expected_source_tree_digest=expected_source_tree_digest,
            custody_authorization_envelope={
                "statement": statement,
                "statement_sha256": statement_digest,
                "signature": server_signature,
            },
            expected_custody_signing_key_id=expected_response_signing_key_id,
        )
        require(
            control_plane["signing_key_id"] == control_plane_key_id,
            f"{label} control-plane receipt signer mismatch",
        )
        verify_route_authorization_evidence(
            matched_route,
            release_authority,
            control_plane,
            label=label,
        )
    for proof_role, proof_key_id in (
        ("external collector", collector_key_id),
        ("response statement signer", response_signing_key_id),
        ("vendor TEE verifier", vendor_summary["trusted_verifier_key_id"]),
    ):
        require(
            not hmac.compare_digest(control_plane_key_id, proof_key_id),
            f"control-plane response signing trust root must be independent from the observation proof {proof_role} key",
        )
    return {
        "proof_contract": "observation-v1",
        "apiVersion": document.get("apiVersion"),
        "server_statement_api_version": statement.get("apiVersion"),
        "server_statement_sha256": statement_digest,
        "captured_at_unix": captured_at,
        "issued_at_unix": issued_at,
        "observation_id": observation_id,
        "client_nonce_sha256": sha256_prefixed_bytes(nonce_bytes),
        "client_request_digest": external_request["aggregate_digest"],
        "request_digest": request_digest,
        "operation_digest": operation_digest,
        "principal_id": principal_id,
        "route_id": route_id,
        "compiled_route_authority_verified": full_authorization,
        "response_path": response_path,
        "upstream_attempt": upstream_attempt,
        "authorization_state": authorization_state,
        "observation_authority": authority,
        "upstream_status": upstream["status"] if upstream is not None else None,
        "emitted_response_status": emitted_response["status"],
        "emitted_body_digest": emitted_response["body_digest"],
        "emitted_body_bytes": emitted_response["body_bytes"],
        "observed_body_artifact_sha256": observation_body_snapshot.sha256,
        "observed_body_artifact_bytes": len(observation_body_snapshot.data),
        "release_authority": release_authority,
        "authorization_binding_digest": authorization_binding_digest,
        "control_plane_response_signing_key_id": control_plane_key_id,
        "control_plane_authorization_receipt": control_plane,
        "control_plane_authorization_receipt_sha256": receipt_digest,
        **bindings,
        "server_instance_id": expected_server_instance_id,
        "tls_channel_binding_sha256": sha256_prefixed_bytes(expected_tls_channel_binding.encode("utf-8")),
        "collector_signing_key_id": collector_key_id,
        "response_signing_key_id": response_signing_key_id,
        "trusted_verifier_key_id": vendor_summary["trusted_verifier_key_id"],
        "vendor_tee_platform": vendor_summary["platform"],
        "vendor_quote_provider": vendor_summary["provider"],
        "vendor_quote_sha256": vendor_summary["quote_sha256"],
        "collector_signature_verified": True,
        "server_statement_signature_verified": True,
        "vendor_quote_verified": True,
        "terminal_runtime_proof_bound": True,
        "strict_collector_capture_bound": True,
        "credentialless_dispatch_bound": not full_authorization,
        "release_authority_bound": full_authorization,
        "embedded_control_plane_authorization_receipt_bound": full_authorization,
        "signed_policy_route_bound": True,
        "release_artifacts_bound": True,
    }


def verify_production_proxy_response_proof(
    document: dict[str, Any],
    *,
    proof_contract: str = "buffered-v3",
    streamed_body_snapshot: FileSnapshot | None = None,
    observation_body_snapshot: FileSnapshot | None = None,
    expected_operation_context_digest: str | None = None,
    **verification_inputs: Any,
) -> dict[str, Any]:
    require(
        proof_contract in PROXY_PROOF_CONTRACTS,
        "proxy proof contract must be independently selected as buffered-v3, observation-v1, or streaming-v1",
    )
    if proof_contract == "buffered-v3":
        require(
            streamed_body_snapshot is None,
            "buffered-v3 verification must not consume a streaming body artifact",
        )
        require(
            expected_operation_context_digest is None,
            "buffered-v3 verification must not select a streaming operation context digest",
        )
        require(
            observation_body_snapshot is None,
            "buffered-v3 verification must not consume an observation body artifact",
        )
        return verify_production_buffered_proxy_response_proof(
            document,
            **verification_inputs,
        )
    if proof_contract == "observation-v1":
        require(
            streamed_body_snapshot is None,
            "observation-v1 verification must not consume a streaming body artifact",
        )
        require(
            expected_operation_context_digest is None,
            "observation-v1 verification must not select a streaming operation context digest",
        )
        require(
            observation_body_snapshot is not None,
            "observation-v1 verification requires a separately snapshotted body artifact",
        )
        return verify_production_response_observation_proof(
            document,
            observation_body_snapshot=observation_body_snapshot,
            **verification_inputs,
        )
    require(
        observation_body_snapshot is None,
        "streaming-v1 verification must not consume an observation body artifact",
    )
    require(
        streamed_body_snapshot is not None,
        "streaming-v1 verification requires a separately snapshotted body artifact",
    )
    require(
        expected_operation_context_digest is not None,
        "streaming-v1 verification requires an independently pinned operation context digest",
    )
    return verify_production_streaming_proxy_response_proof(
        document,
        streamed_body_snapshot=streamed_body_snapshot,
        expected_operation_context_digest=expected_operation_context_digest,
        **verification_inputs,
    )


def completion_proof_digest_path(path: Path, generation: str) -> Path:
    require(
        re.fullmatch(r"[0-9a-f]{32}", generation) is not None,
        "completion proof checksum generation is invalid",
    )
    return path.with_name(f"{path.name}.sha256.{generation}")


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def verify_private_output_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.lstat()
    require(stat.S_ISDIR(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode), "completion proof output directory must be a non-symlink directory")
    require(metadata.st_uid == os.geteuid(), "completion proof output directory must be owned by the verifier user")
    require(not stat.S_IMODE(metadata.st_mode) & 0o022, "completion proof output directory must not be writable by group/other")


def validate_existing_private_output(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    require(stat.S_ISREG(metadata.st_mode) and not stat.S_ISLNK(metadata.st_mode), f"{label} must be a regular non-symlink file")
    require(metadata.st_uid == os.geteuid(), f"{label} must be owned by the verifier user")
    require(stat.S_IMODE(metadata.st_mode) == 0o600, f"{label} must use mode 0600")


def cleanup_stale_completion_checksums(path: Path, current_generation: str, *, retain: int = 3) -> None:
    candidates: list[tuple[int, Path]] = []
    pattern = re.compile(rf"^{re.escape(path.name)}\.sha256\.([0-9a-f]{{32}})$")
    for candidate in path.parent.iterdir():
        match = pattern.fullmatch(candidate.name)
        if match is None or match.group(1) == current_generation:
            continue
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            continue
        if (
            stat.S_ISREG(metadata.st_mode)
            and not stat.S_ISLNK(metadata.st_mode)
            and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) == 0o600
        ):
            candidates.append((metadata.st_mtime_ns, candidate))
    candidates.sort(reverse=True)
    for _mtime, candidate in candidates[max(retain - 1, 0) :]:
        candidate.unlink(missing_ok=True)
    fsync_directory(path.parent)


def write_output(
    path: Path,
    proof: dict[str, Any],
    *,
    fail_after_checksum_publish: bool = False,
    before_output_publication: Any | None = None,
) -> str:
    payload = canonical_json(proof).encode("utf-8") + b"\n"
    proof_digest = sha256_prefixed_bytes(payload)
    integrity = proof.get("integrity_metadata")
    require(isinstance(integrity, dict), "completion proof is missing integrity metadata")
    generation = integrity.get("generation")
    require(isinstance(generation, str), "completion proof checksum generation is invalid")
    digest_path = completion_proof_digest_path(path, generation)
    require(
        integrity.get("detached_sha256_path") == str(digest_path),
        "completion proof checksum path does not match its generation",
    )
    digest_payload = f"{proof_digest}\n".encode("ascii")
    verify_private_output_directory(path.parent)
    lock_path = path.with_name(f".{path.name}.writer.lock")
    lock_flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        lock_descriptor = os.open(lock_path, lock_flags, 0o600)
    except OSError as exc:
        raise ValueError("completion proof writer lock could not be opened without following symlinks") from exc
    try:
        lock_metadata = os.fstat(lock_descriptor)
        require(stat.S_ISREG(lock_metadata.st_mode), "completion proof writer lock must be a regular file")
        require(lock_metadata.st_uid == os.geteuid(), "completion proof writer lock must be owned by the verifier user")
        require(stat.S_IMODE(lock_metadata.st_mode) == 0o600, "completion proof writer lock must use mode 0600")
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        validate_existing_private_output(path, "completion proof output")
        try:
            digest_path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise ValueError("completion proof checksum generation already exists")
        temporary_paths: list[Path] = []
        try:
            staged: dict[Path, Path] = {}
            for destination, content in ((digest_path, digest_payload), (path, payload)):
                with tempfile.NamedTemporaryFile(
                    mode="wb",
                    dir=path.parent,
                    prefix=f".{destination.name}.",
                    delete=False,
                ) as temporary:
                    temporary_path = Path(temporary.name)
                    temporary_paths.append(temporary_path)
                    os.fchmod(temporary.fileno(), 0o600)
                    temporary.write(content)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                    staged[destination] = temporary_path
            if before_output_publication is not None:
                before_output_publication()
            os.replace(staged[digest_path], digest_path)
            temporary_paths.remove(staged[digest_path])
            fsync_directory(path.parent)
            if fail_after_checksum_publish:
                raise RuntimeError("injected failure after checksum publication")
            if before_output_publication is not None:
                try:
                    before_output_publication()
                except Exception:
                    digest_path.unlink(missing_ok=True)
                    fsync_directory(path.parent)
                    raise
            os.replace(staged[path], path)
            temporary_paths.remove(staged[path])
            fsync_directory(path.parent)
            cleanup_stale_completion_checksums(path, generation)
        finally:
            for temporary_path in temporary_paths:
                temporary_path.unlink(missing_ok=True)
    finally:
        os.close(lock_descriptor)
    return proof_digest


def consume_final_challenge_once(
    ledger_path: Path,
    *,
    challenge_nonce_sha256: str,
    completion_identity_sha256: str,
    consumed_at_unix: int | None = None,
) -> dict[str, Any]:
    challenge_digest = require_sha256(challenge_nonce_sha256, "final completion challenge digest")
    completion_digest = require_sha256(completion_identity_sha256, "final completion identity digest")
    require(ledger_path.parent.is_dir(), "final challenge ledger parent directory does not exist")
    parent_stat = ledger_path.parent.stat()
    require(parent_stat.st_uid == os.geteuid(), "final challenge ledger directory must be owned by the verifier user")
    require(
        parent_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH) == 0,
        "final challenge ledger directory must not be group- or world-writable",
    )
    require(not ledger_path.is_symlink(), "final challenge ledger must not be a symlink")
    lock_path = ledger_path.with_name(ledger_path.name + ".lock")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    lock_fd = os.open(lock_path, flags, 0o600)
    temporary_path: Path | None = None
    try:
        with os.fdopen(lock_fd, "r+b", closefd=True) as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            if ledger_path.exists():
                ledger_fd = os.open(ledger_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                try:
                    ledger_stat = os.fstat(ledger_fd)
                    require(stat.S_ISREG(ledger_stat.st_mode), "final challenge consumption ledger must be a regular file")
                    require(
                        ledger_stat.st_uid == os.geteuid(),
                        "final challenge consumption ledger must be owned by the verifier user",
                    )
                    require(
                        ledger_stat.st_mode & (stat.S_IRWXG | stat.S_IRWXO) == 0,
                        "final challenge consumption ledger must not grant group or world access",
                    )
                    with os.fdopen(ledger_fd, "r", encoding="utf-8", closefd=False) as ledger_file:
                        ledger = json.load(ledger_file, object_pairs_hook=reject_duplicate_json_object_keys)
                except (OSError, json.JSONDecodeError) as exc:
                    raise ValueError("final challenge consumption ledger is invalid JSON") from exc
                finally:
                    os.close(ledger_fd)
                require(isinstance(ledger, dict), "final challenge consumption ledger must be an object")
                require_exact_keys(
                    ledger,
                    {"apiVersion", "max_entries", "entries"},
                    "final challenge consumption ledger",
                )
                require(
                    ledger.get("apiVersion") == FINAL_CHALLENGE_LEDGER_API_VERSION,
                    "final challenge consumption ledger apiVersion mismatch",
                )
                require(
                    ledger.get("max_entries") == FINAL_CHALLENGE_LEDGER_MAX_ENTRIES,
                    "final challenge consumption ledger bound mismatch",
                )
                entries = ledger.get("entries")
                require(isinstance(entries, list), "final challenge consumption ledger entries must be a list")
            else:
                entries = []
            require(
                len(entries) <= FINAL_CHALLENGE_LEDGER_MAX_ENTRIES,
                "final challenge consumption ledger exceeds its configured bound",
            )
            for index, entry in enumerate(entries):
                require(isinstance(entry, dict), f"final challenge consumption ledger entry {index} must be an object")
                require_exact_keys(
                    entry,
                    {"challenge_nonce_sha256", "completion_identity_sha256", "consumed_at_unix"},
                    f"final challenge consumption ledger entry {index}",
                )
                existing_challenge = require_sha256(
                    entry.get("challenge_nonce_sha256"),
                    f"final challenge consumption ledger entry {index} challenge digest",
                )
                require(
                    not hmac.compare_digest(existing_challenge, challenge_digest),
                    "final completion challenge was already consumed",
                )
                require_sha256(
                    entry.get("completion_identity_sha256"),
                    f"final challenge consumption ledger entry {index} completion identity digest",
                )
                require(
                    isinstance(entry.get("consumed_at_unix"), int)
                    and not isinstance(entry.get("consumed_at_unix"), bool),
                    f"final challenge consumption ledger entry {index} timestamp is invalid",
                )
            require(
                len(entries) < FINAL_CHALLENGE_LEDGER_MAX_ENTRIES,
                "final challenge consumption ledger is full; rotate it explicitly before issuing another challenge",
            )
            consumed_at = int(time.time()) if consumed_at_unix is None else consumed_at_unix
            require(
                isinstance(consumed_at, int) and not isinstance(consumed_at, bool),
                "final challenge consumption time is invalid",
            )
            updated_entries = [
                *entries,
                {
                    "challenge_nonce_sha256": challenge_digest,
                    "completion_identity_sha256": completion_digest,
                    "consumed_at_unix": consumed_at,
                },
            ]
            updated_ledger = {
                "apiVersion": FINAL_CHALLENGE_LEDGER_API_VERSION,
                "max_entries": FINAL_CHALLENGE_LEDGER_MAX_ENTRIES,
                "entries": updated_entries,
            }
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=ledger_path.parent,
                prefix=f".{ledger_path.name}.",
                delete=False,
            ) as temporary:
                temporary_path = Path(temporary.name)
                os.fchmod(temporary.fileno(), 0o600)
                temporary.write(canonical_json(updated_ledger) + "\n")
                temporary.flush()
                os.fsync(temporary.fileno())
            os.replace(temporary_path, ledger_path)
            temporary_path = None
            directory_fd = os.open(ledger_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return {
                "consumed": True,
                "challenge_nonce_sha256": challenge_digest,
                "completion_identity_sha256": completion_digest,
                "ledger_path": str(ledger_path),
                "ledger_entries": len(updated_entries),
                "ledger_max_entries": FINAL_CHALLENGE_LEDGER_MAX_ENTRIES,
                "ledger_trust": "verifier-owned external durable storage; host rollback resistance is supplied by that storage",
            }
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def final_completion_identity(
    hardware_assurance: dict[str, Any],
    *,
    bootstrap_receipt: dict[str, Any],
    current_host_identity_sha256: str,
    key_custody_evidence_sha256: str,
    monotonic_witness_sha256: str,
    production_continuity_sha256: str,
    production_release_identity_sha256: str,
    proxy_server_statement_sha256: str,
    security_role_map_sha256: str,
) -> dict[str, Any]:
    raise VerificationError(
        "legacy full-file completion identity assembly is incompatible with "
        "serverware.finalCompletionIdentity/v3; construct the identity only "
        "from authenticated identity-free cores in the Manifest v6 public "
        "Nitro bridge"
    )


def verify_final_challenge_receipt(
    document: dict[str, Any],
    *,
    trusted_public_key_pem: str,
    expected_trusted_public_key_id: str,
    final_challenge_receipt_sha256: str,
    expected_provider: str,
    expected_challenge_nonce_sha256: str,
    expected_completion_identity_sha256: str,
    expected_release_identity_sha256: str,
    expected_hardware_verifier_key_id: str,
    expected_current_host_identity_sha256: str,
    expected_proxy_server_statement_sha256: str,
    hardware_assurance_issued_at_unix: int,
    now_unix: int | None = None,
) -> dict[str, Any]:
    require_exact_keys(
        document,
        {"apiVersion", "kind", "statement", "signing_key_id", "signature"},
        "final challenge receipt",
    )
    require(
        document.get("apiVersion") == FINAL_CHALLENGE_RECEIPT_API_VERSION,
        "final challenge receipt apiVersion mismatch",
    )
    require(document.get("kind") == "FinalChallengeConsumption", "final challenge receipt kind mismatch")
    statement = document.get("statement") if isinstance(document.get("statement"), dict) else {}
    require_exact_keys(
        statement,
        {
            "authority_provider",
            "consumption_id",
            "status",
            "issued_at_unix",
            "expires_at_unix",
            "challenge_nonce_sha256",
            "completion_identity_sha256",
            "release_identity_sha256",
            "hardware_verifier_key_id",
            "current_host_identity_sha256",
            "proxy_server_statement_sha256",
        },
        "final challenge receipt statement",
    )
    provider = statement.get("authority_provider")
    consumption_id = statement.get("consumption_id")
    require(isinstance(provider, str) and 1 <= len(provider) <= 256, "final challenge authority provider is invalid")
    require(provider == expected_provider, "final challenge receipt authority provider mismatch")
    require(
        isinstance(consumption_id, str) and 1 <= len(consumption_id) <= 128,
        "final challenge receipt consumption id is invalid",
    )
    require(statement.get("status") == "consumed", "final challenge receipt did not consume the challenge")
    issued_at = statement.get("issued_at_unix")
    expires_at = statement.get("expires_at_unix")
    require(
        isinstance(issued_at, int) and not isinstance(issued_at, bool),
        "final challenge receipt issued_at_unix is invalid",
    )
    require(
        isinstance(expires_at, int) and not isinstance(expires_at, bool),
        "final challenge receipt expires_at_unix is invalid",
    )
    now = int(time.time()) if now_unix is None else now_unix
    require(issued_at <= now + HARDWARE_PROOF_FUTURE_SKEW_SECONDS, "final challenge receipt is issued in the future")
    require(expires_at > now, "final challenge receipt is expired")
    require(expires_at > issued_at, "final challenge receipt validity interval is invalid")
    require(
        expires_at - issued_at <= FINAL_CHALLENGE_RECEIPT_MAX_AGE_SECONDS,
        "final challenge receipt validity interval is too long",
    )
    require(
        issued_at >= hardware_assurance_issued_at_unix,
        "final challenge receipt predates the hardware assurance",
    )
    expected_fields = {
        "challenge_nonce_sha256": require_sha256(
            expected_challenge_nonce_sha256, "expected final challenge digest"
        ),
        "completion_identity_sha256": require_sha256(
            expected_completion_identity_sha256, "expected final completion identity digest"
        ),
        "release_identity_sha256": require_sha256(
            expected_release_identity_sha256, "expected final release identity digest"
        ),
        "hardware_verifier_key_id": require_sha256(
            expected_hardware_verifier_key_id, "expected hardware verifier key id"
        ),
        "current_host_identity_sha256": require_sha256(
            expected_current_host_identity_sha256, "expected current host identity digest"
        ),
        "proxy_server_statement_sha256": require_sha256(
            expected_proxy_server_statement_sha256, "expected proxy server statement digest"
        ),
    }
    for field, expected in expected_fields.items():
        actual = require_sha256(statement.get(field), f"final challenge receipt {field}")
        require(hmac.compare_digest(actual, expected), f"final challenge receipt {field} mismatch")
    trusted_key_id = release_public_key_id(trusted_public_key_pem)
    expected_authority_key_id = require_sha256(
        expected_trusted_public_key_id,
        "expected final challenge authority public key id",
    )
    require(
        hmac.compare_digest(trusted_key_id, expected_authority_key_id),
        "final challenge authority key bytes do not match the independently configured SPKI identity",
    )
    require(
        document.get("signing_key_id") == trusted_key_id,
        "final challenge receipt is not signed by the independently trusted authority key",
    )
    signed_statement_bytes = canonical_json(statement).encode("utf-8")
    verify_ed25519(
        trusted_public_key_pem,
        str(document.get("signature") or ""),
        signed_statement_bytes,
        "final challenge receipt",
    )
    return {
        "consumed": True,
        "authority_provider": provider,
        "authority_key_id": trusted_key_id,
        "consumption_id": consumption_id,
        "issued_at_unix": issued_at,
        "expires_at_unix": expires_at,
        "challenge_nonce_sha256": expected_fields["challenge_nonce_sha256"],
        "completion_identity_sha256": expected_fields["completion_identity_sha256"],
        "receipt_sha256": require_sha256(
            final_challenge_receipt_sha256,
            "final challenge receipt document digest",
        ),
        "receipt_signed_statement_sha256": sha256_prefixed_bytes(signed_statement_bytes),
        "trust_boundary": "off-host authority atomically consumes challenges and signs receipts",
    }


def verify_release_security_evidence(
    *,
    snapshots: dict[str, FileSnapshot],
    production_build: dict[str, Any],
    benchmark: dict[str, Any],
    attested_runtime: dict[str, Any],
    preflight: dict[str, Any],
    directly_verified_builders: dict[str, Any] | None = None,
) -> dict[str, Any]:
    identity = verify_production_policy_identity.verify_persisted_report_bytes(
        bundle_bytes=snapshots["policy_bundle"].data,
        trusted_public_key_bytes=snapshots["policy_trusted_public_key"].data,
        report_bytes=snapshots["policy_identity_verification"].data,
    )
    require(identity["policyHash"] == benchmark["policy_hash"], "identity-verified policy does not match benchmark policy")
    require(identity["policyHash"] == attested_runtime["policy_digest"], "identity-verified policy does not match Nitro-attested policy")

    activation = production_release_input_preflight.verify_externally_signed_report_bytes(
        report_bytes=snapshots["policy_activation_verification"].data,
        signature_bytes=snapshots["policy_activation_signature"].data,
        trusted_public_key_bytes=snapshots["policy_activation_trusted_public_key"].data,
        purpose=production_release_input_preflight.ACTIVATION_PURPOSE,
        api_version=production_release_input_preflight.ACTIVATION_API_VERSION,
        kind=production_release_input_preflight.ACTIVATION_KIND,
    )
    activation_report = activation["report"]
    require(activation_report.get("production_mode") is True, "policy activation report is not production evidence")
    require(activation_report.get("environment") == "production", "policy activation environment is not production")
    require(
        activation_report.get("candidate_policy_hash") == identity["policyHash"],
        "activated candidate does not match the identity-verified policy",
    )

    reproducibility = production_release_input_preflight.verify_externally_signed_report_bytes(
        report_bytes=snapshots["reproducible_build_verification"].data,
        signature_bytes=snapshots["reproducible_build_signature"].data,
        trusted_public_key_bytes=snapshots["reproducible_build_trusted_public_key"].data,
        purpose=production_release_input_preflight.REPRODUCIBILITY_PURPOSE,
        api_version=REPRODUCIBLE_BUILD_VERIFICATION_API_VERSION,
        kind=production_release_input_preflight.REPRODUCIBILITY_KIND,
    )
    reproducibility_report = reproducibility["report"]
    require(
        reproducibility_report.get("apiVersion")
        == REPRODUCIBLE_BUILD_VERIFICATION_API_VERSION
        and reproducibility_report.get("kind")
        == "ReproducibleBuildVerification",
        "reproducible-build report must use "
        + REPRODUCIBLE_BUILD_VERIFICATION_API_VERSION,
    )
    reproducibility_scope = reproducibility_report.get("scope")
    require(isinstance(reproducibility_scope, dict), "reproducible-build report scope is missing")
    if directly_verified_builders is None:
        require(
            reproducibility_report.get("reproducible") is True
            and reproducibility_scope.get("independent_execution_proven") is True,
            "readiness reproducible-build report did not report two independent matching builds",
        )
    reproducibility_inputs = reproducibility_report.get("inputs")
    require(
        isinstance(reproducibility_inputs, dict)
        and set(reproducibility_inputs) == {"left", "right"},
        "reproducible-build report must bind exactly two builder inputs",
    )
    builder_records: list[dict[str, str]] = []
    for side in ("left", "right"):
        input_record = reproducibility_inputs.get(side)
        attestation = (
            input_record.get("attestation")
            if isinstance(input_record, dict)
            and isinstance(input_record.get("attestation"), dict)
            else {}
        )
        reported_builder = {
            "builder_id": attestation.get("builder_id"),
            "key_id": attestation.get("key_id"),
        }
        if directly_verified_builders is None:
            require(
                attestation.get("signature_verified") is True
                and attestation.get("operator_trusted") is True,
                f"readiness reproducible-build {side} builder was not reported as signature-verified and trusted",
            )
        else:
            direct = directly_verified_builders.get(side)
            require(
                isinstance(direct, dict)
                and reported_builder
                == {
                    "builder_id": direct.get("builder_id"),
                    "key_id": direct.get("signing_key_id"),
                },
                f"reproducible-build {side} identity differs from the directly verified raw statement and transcript",
            )
        builder_records.append(reported_builder)
    reproducible_builders = verified_reproducible_builder_identities(
        builder_records,
        "verified reproducible-build report builders",
    )
    require(
        reproducibility_report.get("source_tree_digest") == production_build["source_tree_digest"],
        "reproducible-build source digest does not match the production build",
    )
    expected_images = {
        item.get("service"): item.get("image_id")
        for item in production_build.get("images") or []
        if isinstance(item, dict)
    }
    reproduced_images = {
        item.get("service"): item.get("image_id")
        for item in reproducibility_report.get("images") or []
        if isinstance(item, dict)
    }
    require(reproduced_images == expected_images, "reproducible-build image IDs do not match the production build")
    production_gate = next(
        (item for item in production_build.get("images") or [] if item.get("service") == "serverware-decision-gate"),
        {},
    )
    reproduced_gate = next(
        (item for item in reproducibility_report.get("images") or [] if item.get("service") == "serverware-decision-gate"),
        {},
    )
    require(
        reproduced_gate.get("rust_binary_sha256") == production_gate.get("binary_digest"),
        "reproducible-build Rust binary digest does not match the production build",
    )
    production_launcher_binary_digest = require_sha256(
        production_gate.get("launcher_binary_digest"),
        "production build launcher binary digest",
    )
    require(
        reproduced_gate.get("launcher_binary_sha256")
        == production_launcher_binary_digest,
        "reproducible-build launcher binary digest does not match the production build",
    )
    reproducible_launch_authority = require_launch_authority_binding(
        reproduced_gate,
        "reproducible-build decision-gate image",
    )
    require(
        reproducible_launch_authority == production_build["launch_authority"],
        "reproducible-build launch-authority binding does not match the production build",
    )
    preflight_security = preflight.get("release_security_evidence") or {}
    require(preflight_security.get("policy_identity") == identity, "completion policy identity differs from host preflight")
    require(
        (preflight_security.get("policy_activation") or {}).get("reportSha256") == activation["reportSha256"],
        "completion activation evidence differs from host preflight",
    )
    require(
        (preflight_security.get("reproducible_builds") or {}).get("reportSha256") == reproducibility["reportSha256"],
        "completion reproducibility evidence differs from host preflight",
    )
    return {
        "trust_roots": preflight_security.get("trust_roots") or {},
        "policy_identity": identity,
        "policy_activation": {key: value for key, value in activation.items() if key != "report"},
        "reproducible_builds": {
            **{key: value for key, value in reproducibility.items() if key != "report"},
            "scope": reproducibility_scope,
            "sourceTreeDigest": reproducibility_report.get("source_tree_digest"),
            "productionLauncherBinaryDigest": production_launcher_binary_digest,
            "launchAuthority": reproducible_launch_authority,
            "builders": reproducible_builders,
            "builder_authentication": (
                "direct-raw-statements-and-transcripts"
                if directly_verified_builders is not None
                else "signed-readiness-report-only"
            ),
            "productionBuildBound": True,
        },
        "benchmarkPolicyBound": True,
        "nitroAttestedPolicyBound": True,
    }


def _decode_launch_ed25519_spki(
    value: Any,
    label: str,
) -> tuple[Ed25519PublicKey, str]:
    der = decode_canonical_base64url(value, label)
    try:
        public_key = serialization.load_der_public_key(der)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} is not canonical Ed25519 SPKI DER") from exc
    require(
        isinstance(public_key, Ed25519PublicKey)
        and public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        == der,
        f"{label} is not canonical Ed25519 SPKI DER",
    )
    return public_key, sha256_prefixed_bytes(der)


def verify_launcher_nonce_rollback_manifest_v3(
    bootstrap_receipt: dict[str, Any],
    retained_assurance: dict[str, Any],
) -> dict[str, Any]:
    run_production_readiness.validate_bootstrap_receipt_summary(
        bootstrap_receipt
    )
    require(
        retained_assurance.get("verified") is True
        and retained_assurance.get("enforcement")
        == "native-launcher-measured-retained-snapshot",
        "launcher manifest verification requires a verified retained nonce rollback assurance snapshot",
    )
    receipt_manifest = bootstrap_receipt["manifest"]
    manifest_path = Path(str(receipt_manifest.get("path", "")))
    require(
        manifest_path.is_absolute()
        and manifest_path == Path("/etc/serverware") / manifest_path.name,
        "sealed launcher receipt manifest path is not a direct /etc/serverware artifact",
    )
    manifest_bytes, manifest_metadata = (
        run_production_readiness.read_regular_file_once(
            manifest_path,
            "production launch manifest v3",
            max_bytes=run_production_readiness.MAX_BOOTSTRAP_RECEIPT_BYTES,
            owner_only=True,
        )
    )
    require(
        manifest_metadata.st_uid == 0
        and stat.S_IMODE(manifest_metadata.st_mode) == 0o400,
        "production launch manifest v3 must remain root-owned mode 0400",
    )
    manifest_sha256 = sha256_prefixed_bytes(manifest_bytes)
    request = bootstrap_receipt["launchAuthorization"]["request"]
    require(
        manifest_sha256
        == receipt_manifest.get("sha256")
        == request.get("manifestSha256"),
        "production launch manifest v3 digest differs from the sealed receipt or signed launch request",
    )
    manifest = load_json_bytes(
        manifest_bytes,
        manifest_path,
        "production launch manifest v3",
    )
    require(
        set(manifest)
        == {
            "apiVersion",
            "kind",
            "releaseRoot",
            "stateDirectory",
            "sourceTreeDigest",
            "authorization",
            "launchAttemptJournal",
            "globalRoleRegistry",
            "nonceRollbackAssurance",
            "productionEnv",
            "python",
            "scripts",
            "composeFile",
            "inputs",
            "outputs",
        },
        "production launch manifest v3 does not use the closed top-level contract",
    )
    require(
        manifest.get("apiVersion")
        == "serverware.productionReadinessLaunch/v3"
        and manifest.get("kind") == "ProductionReadinessLaunch",
        "legacy v2 launch manifests cannot satisfy launcher-enforced nonce rollback assurance",
    )
    require(
        manifest_bytes == canonical_json(manifest).encode("ascii") + b"\n",
        "production launch manifest v3 is not canonical JSON plus LF",
    )
    authorization = manifest.get("authorization")
    require(
        isinstance(authorization, dict)
        and set(authorization)
        == {
            "authorizationScope",
            "deploymentAudience",
            "deploymentIdentitySha256",
            "freshnessAuthority",
            "monotonicWitness",
            "releaseSequence",
            "rollbackEpoch",
        }
        and authorization["authorizationScope"]
        == request["authorizationScope"]
        == "trusted-host-readiness"
        and authorization["deploymentAudience"]
        == request["deploymentAudience"]
        and authorization["deploymentIdentitySha256"]
        == request["deploymentIdentitySha256"]
        and authorization["freshnessAuthority"]
        == request["freshnessAuthority"]
        == "trusted-host-wall-clock"
        and authorization["releaseSequence"] == request["releaseSequence"]
        and authorization["rollbackEpoch"] == request["rollbackEpoch"],
        "production launch manifest authorization differs from the signed launch request",
    )
    require(
        "useLimit" not in canonical_json(manifest)
        and "use_limit" not in canonical_json(manifest),
        "production launch manifest contains an obsolete use-limit contract",
    )
    require(
        manifest.get("sourceTreeDigest")
        == bootstrap_receipt.get("sourceTreeDigest")
        == request.get("sourceTreeDigest"),
        "production launch manifest source tree differs from the sealed launch identity",
    )
    require(
        manifest.get("stateDirectory")
        == "/var/lib/serverware/production-proof",
        "production launch manifest stateDirectory is not the fixed production proof directory",
    )
    journal = manifest.get("launchAttemptJournal")
    expected_journal_path = (
        "/var/lib/serverware/production-proof/"
        "launch-authorization-attempt.v1.json"
    )
    expected_journal_lock_path = (
        "/var/lib/serverware/production-proof/"
        "launch-authorization-attempt.v1.lock"
    )
    require(
        isinstance(journal, dict)
        and set(journal)
        == {
            "apiVersion",
            "path",
            "lockPath",
            "domain",
            "maxBytes",
            "consistencyScope",
            "rollbackAuthority",
        }
        and journal["apiVersion"]
        == "serverware.launchAuthorizationAttemptJournal/v1"
        and journal["path"] == expected_journal_path
        and journal["lockPath"] == expected_journal_lock_path
        and journal["domain"]
        == request["launchAttemptJournalDomain"]
        == "serverware.launchAuthorizationAttemptJournal/v1"
        and journal["maxBytes"] == 64 * 1024
        and journal["consistencyScope"]
        == "trusted-host-readiness-availability-and-consistency-only"
        and journal["rollbackAuthority"] == "external-monotonic-witness",
        "production launch manifest launch-attempt journal is not the fixed v1 contract",
    )
    recovery_identity = {
        "domain": request["launchAttemptJournalDomain"],
        "launcherNonce": request["launcherNonce"],
        "witnessChallenge": request["launchAuthorityWitnessChallenge"],
        "bootIdSha256": request["bootIdSha256"],
        "manifestSha256": request["manifestSha256"],
        "globalRoleRegistrySha256": request[
            "globalRoleRegistrySha256"
        ],
    }
    recovery_identity_sha256 = sha256_prefixed_bytes(
        b"serverware.launchAuthorizationAttemptRecoveryIdentity/v1\0"
        + canonical_json(recovery_identity).encode("ascii")
    )
    require(
        request["launchAttemptRecoveryIdentitySha256"]
        == recovery_identity_sha256,
        "launch-attempt journal recovery identity crossed the signed request",
    )
    role_binding = manifest.get("globalRoleRegistry")
    require(
        isinstance(role_binding, dict)
        and set(role_binding)
        == {
            "apiVersion",
            "canonicalProfile",
            "claimScope",
            "registry",
            "registrySha256",
            "pinsFile",
        }
        and role_binding["apiVersion"]
        == "serverware.productionLaunchGlobalRoleRegistryBinding/v1"
        and role_binding["canonicalProfile"] == CANONICAL_JSON_PROFILE
        and role_binding["claimScope"]
        == "roles-present-in-native-launch-contract"
        and role_binding["registry"] == request["globalRoleRegistry"],
        "production launch manifest global-role registry is not the closed v1 binding",
    )
    role_registry = role_binding["registry"]
    require(
        isinstance(role_registry, dict)
        and set(role_registry)
        == {"apiVersion", "claimScope", "roles", "rolesOutsideClaim"}
        and role_registry["apiVersion"]
        == "serverware.productionLaunchGlobalRoleRegistry/v1"
        and role_registry["claimScope"]
        == "roles-present-in-native-launch-contract"
        and isinstance(role_registry["roles"], dict)
        and set(role_registry["roles"]) == LAUNCH_GLOBAL_ROLE_NAMES
        and all(
            isinstance(key_id, str) and SHA256_RE.fullmatch(key_id) is not None
            for key_id in role_registry["roles"].values()
        )
        and len(set(role_registry["roles"].values()))
        == len(role_registry["roles"])
        and role_registry["rolesOutsideClaim"]
        == list(LAUNCH_GLOBAL_ROLES_OUTSIDE_CLAIM),
        "production launch global-role registry core is open, malformed, or colliding",
    )
    role_registry_sha256 = sha256_prefixed_json(role_registry)
    role_pins_sha256 = sha256_prefixed_bytes(
        canonical_json(role_registry).encode("ascii") + b"\n"
    )
    role_pins_file = role_binding["pinsFile"]
    role_pins_path = PurePosixPath(
        str(role_pins_file.get("path", ""))
        if isinstance(role_pins_file, dict)
        else ""
    )
    require(
        isinstance(role_pins_file, dict)
        and set(role_pins_file) == {"path", "sha256"}
        and role_pins_path.is_absolute()
        and str(role_pins_path) == role_pins_file["path"]
        and role_pins_path != PurePosixPath("/etc/serverware")
        and PurePosixPath("/etc/serverware") in role_pins_path.parents
        and role_registry_sha256
        == role_binding["registrySha256"]
        == request["globalRoleRegistrySha256"]
        and role_pins_sha256
        == role_pins_file["sha256"]
        == request["globalRoleRegistryPinsSha256"],
        "production launch global-role registry bytes, digest, or measured pins were substituted",
    )
    roles = role_registry["roles"]
    require(
        len(set(roles.values())) == len(roles)
        and roles["launchAuthority"]
        == bootstrap_receipt["launchAuthorityKeyId"],
        "production launch global-role registry reused or crossed the launch-authority role",
    )
    authorization_envelope = bootstrap_receipt["launchAuthorization"][
        "envelope"
    ]
    authorization_statement = authorization_envelope["statement"]
    witness_envelope = authorization_statement["monotonicWitness"]
    witness_statement = witness_envelope["statement"]
    witness_configuration = authorization["monotonicWitness"]
    require(
        isinstance(witness_configuration, dict)
        and set(witness_configuration)
        == {
            "administrativeDomainSha256",
            "identitySha256",
            "signingKeyId",
            "signingPublicKeySpkiDerBase64url",
            "storeAssurance",
            "storeAssuranceIssuerKeyId",
            "storeAssuranceIssuerPublicKeySpkiDerBase64url",
            "storeAssuranceSha256",
        },
        "production launch monotonic-witness configuration is not closed",
    )
    witness_public_key, witness_key_id = _decode_launch_ed25519_spki(
        witness_configuration["signingPublicKeySpkiDerBase64url"],
        "production launch monotonic-witness signing key",
    )
    require(
        witness_configuration["signingPublicKeySpkiDerBase64url"]
        == bootstrap_receipt["launchAuthorization"][
            "witnessPublicKeySpkiDerBase64url"
        ]
        and witness_configuration["signingKeyId"]
        == witness_key_id
        == request["launchAuthorityWitnessKeyId"]
        == roles["launchAuthorityWitness"]
        and witness_configuration["identitySha256"]
        == request["launchAuthorityWitnessIdentitySha256"]
        and witness_configuration["administrativeDomainSha256"]
        == request[
            "launchAuthorityWitnessAdministrativeDomainSha256"
        ]
        and witness_configuration["storeAssuranceSha256"]
        == request["launchAuthorityWitnessStoreAssuranceSha256"],
        "production launch monotonic-witness key or identity crossed the signed request",
    )
    store_assurance = witness_configuration["storeAssurance"]
    require(
        isinstance(store_assurance, dict)
        and set(store_assurance)
        == {"apiVersion", "kind", "statement", "signature"}
        and store_assurance["apiVersion"]
        == "serverware.launchAuthorityWitnessStoreAssurance/v1"
        and store_assurance["kind"]
        == "LaunchAuthorityWitnessStoreAssurance",
        "production launch witness-store assurance envelope is not closed",
    )
    store_statement = store_assurance["statement"]
    require(
        isinstance(store_statement, dict)
        and set(store_statement)
        == {
            "assuranceIssuerKeyId",
            "witnessKeyId",
            "witnessIdentitySha256",
            "witnessAdministrativeDomainSha256",
            "storeIdentitySha256",
            "storeAdministrativeDomainSha256",
            "storeClass",
            "rollbackResistance",
            "independentAdministration",
        }
        and store_statement["witnessKeyId"] == witness_key_id
        and store_statement["witnessIdentitySha256"]
        == witness_configuration["identitySha256"]
        and store_statement["witnessAdministrativeDomainSha256"]
        == witness_configuration["administrativeDomainSha256"]
        and store_statement["storeClass"]
        in {
            "hardwareMonotonicCounter",
            "independentlyAdministeredLinearizableCas",
            "appendOnlyTransparencyLedger",
        }
        and store_statement["rollbackResistance"]
        == "externally-witnessed-monotonic"
        and store_statement["independentAdministration"] is True,
        "production launch witness-store assurance statement is not the exact rollback-resistant contract",
    )
    store_issuer_key, store_issuer_key_id = _decode_launch_ed25519_spki(
        witness_configuration[
            "storeAssuranceIssuerPublicKeySpkiDerBase64url"
        ],
        "production launch witness-store assurance issuer key",
    )
    for field in (
        "assuranceIssuerKeyId",
        "witnessKeyId",
        "witnessIdentitySha256",
        "witnessAdministrativeDomainSha256",
        "storeIdentitySha256",
        "storeAdministrativeDomainSha256",
    ):
        require_sha256(
            store_statement[field],
            f"production launch witness-store assurance {field}",
        )
    require(
        store_issuer_key_id
        == witness_configuration["storeAssuranceIssuerKeyId"]
        == store_statement["assuranceIssuerKeyId"]
        == roles["launchAuthorityWitnessStoreAssurance"]
        and store_issuer_key_id
        not in {witness_key_id, bootstrap_receipt["launchAuthorityKeyId"]}
        and store_statement["storeIdentitySha256"]
        not in {
            store_statement["witnessIdentitySha256"],
            store_statement["witnessAdministrativeDomainSha256"],
        }
        and store_statement["storeAdministrativeDomainSha256"]
        != store_statement["witnessAdministrativeDomainSha256"],
        "production launch witness-store assurance is not independently pinned",
    )
    store_assurance_sha256 = sha256_prefixed_json(store_assurance)
    require(
        store_assurance_sha256
        == witness_configuration["storeAssuranceSha256"]
        == request["launchAuthorityWitnessStoreAssuranceSha256"],
        "production launch witness-store assurance digest was substituted",
    )
    store_unsigned = dict(store_assurance)
    store_signature = store_unsigned.pop("signature")
    try:
        store_issuer_key.verify(
            decode_ed25519_signature(
                store_signature,
                "production launch witness-store assurance signature",
            ),
            b"serverware.launchAuthorityWitnessStoreAssurance/v1\0"
            + canonical_json(store_unsigned).encode("ascii"),
        )
    except InvalidSignature as exc:
        raise ValueError(
            "production launch witness-store assurance signature verification failed"
        ) from exc
    require(
        authorization_statement["authorizationScope"]
        == witness_statement["authorizationScope"]
        == authorization["authorizationScope"]
        and authorization_statement["freshnessAuthority"]
        == authorization["freshnessAuthority"]
        and authorization_statement["capabilitySemantics"]
        == "time-bounded-idempotent-readiness-authorization"
        and authorization_statement["globalRoleRegistrySha256"]
        == role_registry_sha256
        and witness_statement["operation"]
        == "authorize-trusted-host-readiness"
        and witness_statement["operationId"] == request["launcherNonce"]
        and witness_statement["authorizationId"]
        == authorization_statement["authorizationId"]
        and witness_statement["requestSha256"]
        == bootstrap_receipt["launchAuthorization"]["requestSha256"]
        == authorization_statement["requestSha256"]
        and witness_statement["challenge"]
        == request["launchAuthorityWitnessChallenge"]
        and witness_statement["authorityKeyId"]
        == bootstrap_receipt["launchAuthorityKeyId"]
        and witness_statement["witnessKeyId"] == witness_key_id
        and witness_statement["witnessIdentitySha256"]
        == witness_configuration["identitySha256"]
        and witness_statement["witnessAdministrativeDomainSha256"]
        == witness_configuration["administrativeDomainSha256"]
        and witness_statement["storeAssuranceSha256"]
        == store_assurance_sha256
        and witness_statement["deploymentAudience"]
        == authorization["deploymentAudience"]
        and witness_statement["deploymentIdentitySha256"]
        == authorization["deploymentIdentitySha256"]
        and witness_statement["releaseSequence"]
        == authorization["releaseSequence"]
        and witness_statement["rollbackEpoch"]
        == authorization["rollbackEpoch"]
        and witness_statement["stateTransitionCommitted"] is True
        and witness_statement["predecessorStateSha256"]
        != witness_statement["successorStateSha256"],
        "production launch authorization crossed its readiness scope, freshness authority, witness, or v7 saga projection",
    )
    for field in (
        "registrySha256",
        "predecessorStateSha256",
        "successorStateSha256",
    ):
        require_sha256(
            witness_statement[field],
            f"production launch witness {field}",
        )
    for field in ("registryGeneration", "checkpointSequence"):
        require_bounded_uint(
            witness_statement[field],
            f"production launch witness {field}",
            minimum=1,
        )
    witness_unsigned = dict(witness_envelope)
    witness_signature = witness_unsigned.pop("signature")
    try:
        witness_public_key.verify(
            decode_ed25519_signature(
                witness_signature,
                "production launch monotonic-witness signature",
            ),
            b"serverware.launchAuthorityWitnessTransition/v1\0"
            + canonical_json(witness_unsigned).encode("ascii"),
        )
    except InvalidSignature as exc:
        raise ValueError(
            "production launch monotonic-witness signature verification failed"
        ) from exc
    binding = manifest.get("nonceRollbackAssurance")
    require(
        isinstance(binding, dict)
        and set(binding)
        == {
            "apiVersion",
            "canonicalProfile",
            "contract",
            "contractSha256",
            "enforcement",
            "pinsFile",
            "purpose",
        }
        and binding["apiVersion"]
        == run_production_readiness.NONCE_ROLLBACK_ASSURANCE_BINDING_API_VERSION
        and binding["canonicalProfile"]
        == "serverware.canonicalJson/integer-string-bool-null-array-object-nfc-v1"
        and binding["enforcement"] == "native-launcher-measured"
        and binding["purpose"] == "readiness-only",
        "production launch manifest has an invalid nonce rollback assurance binding",
    )
    contract = run_production_readiness.validate_nonce_rollback_assurance_contract(
        binding["contract"]
    )
    public_config = contract["publicConfigPins"]
    _, nonce_assurance_evidence_key_id = _decode_launch_ed25519_spki(
        public_config[
            "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
        ],
        "production launch nonce-assurance evidence key",
    )
    _, nonce_verifier_state_key_id = _decode_launch_ed25519_spki(
        public_config[
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
        ],
        "production launch nonce verifier-state key",
    )
    _, nonce_store_attestation_key_id = _decode_launch_ed25519_spki(
        public_config[
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
        ],
        "production launch nonce verifier-state store-attestation key",
    )
    require(
        roles["nonceAuthorityAssuranceEvidence"]
        == nonce_assurance_evidence_key_id
        and roles["nonceAuthorityVerifierState"]
        == nonce_verifier_state_key_id
        and roles["nonceAuthorityVerifierStateStoreAttestation"]
        == nonce_store_attestation_key_id,
        "production launch global-role registry crossed the exact nonce-assurance keys",
    )
    verifier_state_service = {
        "signingPublicKeySpkiDerBase64url": public_config[
            "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
        ],
        "storeAdministrativeDomainSha256": public_config[
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        ],
        "storeAssuranceEvidenceSha256": public_config[
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        ],
        "storeAttestationPublicKeySpkiDerBase64url": public_config[
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
        ],
        "storeIdentitySha256": public_config[
            "nonceAuthorityVerifierStateStoreIdentitySha256"
        ],
    }
    canonical_contract = canonical_json(contract).encode("ascii")
    contract_sha256 = sha256_prefixed_bytes(canonical_contract)
    pins_sha256 = sha256_prefixed_bytes(canonical_contract + b"\n")
    receipt_binding = bootstrap_receipt["nonceRollbackAssurance"]
    receipt_pins_file = receipt_binding["pinsFile"]
    manifest_pins_file = binding["pinsFile"]
    require(
        isinstance(manifest_pins_file, dict)
        and set(manifest_pins_file) == {"path", "sha256"}
        and manifest_pins_file["path"] == receipt_pins_file["path"]
        and manifest_pins_file["sha256"] == receipt_pins_file["sha256"]
        and contract_sha256
        == binding["contractSha256"]
        == receipt_binding["contractSha256"]
        == retained_assurance["contractSha256"]
        == request["nonceRollbackAssuranceContractSha256"]
        and pins_sha256
        == manifest_pins_file["sha256"]
        == receipt_binding["retainedSnapshotSha256"]
        == retained_assurance["retainedSnapshotSha256"]
        == request["nonceRollbackAssurancePinsSha256"],
        "production launch manifest nonce rollback contract or pin-file binding was substituted",
    )
    require(
        receipt_binding["verifierStateService"]
        == retained_assurance["verifierStateService"]
        == verifier_state_service,
        "production launch verifier-state service configuration was substituted",
    )
    return {
        "apiVersion": "serverware.productionReadinessLaunch/v3",
        "manifestSha256": manifest_sha256,
        "authorizationScope": authorization["authorizationScope"],
        "freshnessAuthority": authorization["freshnessAuthority"],
        "capabilitySemantics": authorization_statement[
            "capabilitySemantics"
        ],
        "launchAttemptJournal": journal,
        "launchAttemptRecoveryIdentitySha256": (
            recovery_identity_sha256
        ),
        "globalRoleRegistry": role_registry,
        "globalRoleRegistrySha256": role_registry_sha256,
        "globalRoleRegistryPinsFile": role_pins_file,
        "monotonicWitness": {
            "sha256": sha256_prefixed_json(witness_envelope),
            "signingKeyId": witness_key_id,
            "identitySha256": witness_configuration["identitySha256"],
            "administrativeDomainSha256": witness_configuration[
                "administrativeDomainSha256"
            ],
            "storeAssuranceSha256": store_assurance_sha256,
            "storeAssuranceIssuerKeyId": store_issuer_key_id,
            "registryGeneration": witness_statement[
                "registryGeneration"
            ],
            "registrySha256": witness_statement["registrySha256"],
            "predecessorStateSha256": witness_statement[
                "predecessorStateSha256"
            ],
            "successorStateSha256": witness_statement[
                "successorStateSha256"
            ],
            "checkpointSequence": witness_statement[
                "checkpointSequence"
            ],
            "stateTransitionCommitted": True,
        },
        "launchAuthorityIssuanceSaga": {
            "ledgerSchemaVersion": 7,
            "requestSha256": bootstrap_receipt["launchAuthorization"][
                "requestSha256"
            ],
            "authorizationId": authorization_statement[
                "authorizationId"
            ],
            "recoveryIdentitySha256": recovery_identity_sha256,
            "registryGeneration": witness_statement[
                "registryGeneration"
            ],
            "registrySha256": witness_statement["registrySha256"],
            "predecessorStateSha256": witness_statement[
                "predecessorStateSha256"
            ],
            "successorStateSha256": witness_statement[
                "successorStateSha256"
            ],
            "checkpointSequence": witness_statement[
                "checkpointSequence"
            ],
            "witnessTransitionSha256": sha256_prefixed_json(
                witness_envelope
            ),
            "stateTransitionCommitted": True,
        },
        "contractSha256": contract_sha256,
        "pinsFile": {
            "path": manifest_pins_file["path"],
            "sha256": pins_sha256,
        },
        "verifierStateService": verifier_state_service,
        "purpose": "readiness-only",
        "verified": True,
    }


def verify_bootstrap_launcher_authorization(
    bootstrap_receipt: dict[str, Any],
    *,
    signed_provenance_digest: str,
    independently_reproduced_digest: str,
) -> dict[str, Any]:
    receipt_launcher = bootstrap_receipt.get("launcher")
    require(isinstance(receipt_launcher, dict), "sealed launcher receipt has no launcher identity")
    receipt_launcher_digest = require_sha256(
        receipt_launcher.get("sha256"),
        "sealed launcher receipt executable digest",
    )
    signed_provenance_digest = require_sha256(
        signed_provenance_digest,
        "signed provenance production launcher digest",
    )
    independently_reproduced_digest = require_sha256(
        independently_reproduced_digest,
        "independent-build production launcher digest",
    )
    require(
        receipt_launcher_digest
        == signed_provenance_digest
        == independently_reproduced_digest,
        "executed launcher digest does not match signed provenance and independent-build evidence",
    )
    expected_launcher_path = (
        "/opt/serverware/launchers/sha256-"
        + receipt_launcher_digest.removeprefix("sha256:")
        + "/serverware-production-launcher"
    )
    require(
        receipt_launcher.get("path") == expected_launcher_path,
        "executed launcher path is not content-addressed by the independently authorized digest",
    )
    return {
        "sha256": receipt_launcher_digest,
        "path": expected_launcher_path,
        "signed_provenance_bound": True,
        "independent_build_bound": True,
        "content_addressed_path_bound": True,
    }


def verify_bootstrap_launch_authorization_bindings(
    bootstrap_receipt: dict[str, Any],
    *,
    signed_provenance_digest: str,
    signed_source_tree_digest: str,
    release_provenance_sha256: str,
    reproducible_build_verification_sha256: str,
    current_host_identity_sha256: str,
    release_artifact_launch_authority: dict[str, str],
    nonce_rollback_assurance: dict[str, Any],
    launch_manifest_v3: dict[str, Any],
) -> dict[str, Any]:
    # Direct legacy-readiness callers do not pass through main()'s mode
    # dispatch. Reuse its dependency loader without changing the active import
    # roots; native-launcher retained-descriptor isolation remains in force.
    # Final-v1 dispatch never calls this readiness-only helper or this loader.
    load_readiness_dependencies()
    run_production_readiness.validate_bootstrap_receipt_summary(bootstrap_receipt)
    identity = run_production_readiness.bootstrap_launch_authorization_identity(
        bootstrap_receipt
    )
    expected = {
        "provenance_digest": require_sha256(
            signed_provenance_digest,
            "signed launch authorization provenance digest",
        ),
        "source_tree_digest": require_sha256(
            signed_source_tree_digest,
            "signed launch authorization source tree digest",
        ),
        "release_provenance_sha256": require_sha256(
            release_provenance_sha256,
            "measured launch authorization release provenance file digest",
        ),
        "reproducible_build_verification_sha256": require_sha256(
            reproducible_build_verification_sha256,
            "measured launch authorization reproducible-build file digest",
        ),
        "deployment_identity_sha256": require_sha256(
            current_host_identity_sha256,
            "launch authorization current-host deployment identity digest",
        ),
        "nonce_rollback_assurance_contract_sha256": require_sha256(
            nonce_rollback_assurance.get("contractSha256"),
            "launch authorization nonce rollback assurance contract digest",
        ),
        "nonce_rollback_assurance_pins_sha256": require_sha256(
            nonce_rollback_assurance.get("retainedSnapshotSha256"),
            "launch authorization nonce rollback assurance pins digest",
        ),
    }
    for field, expected_value in expected.items():
        require(
            hmac.compare_digest(str(identity[field]), expected_value),
            f"launch authorization {field} does not match independently verified completion evidence",
        )
    artifact_authority = require_launch_authority_binding(
        release_artifact_launch_authority,
        "release artifact launch authority",
    )
    require(
        identity["authority_key_id"]
        == artifact_authority["launch_authority_key_id"],
        "launch authorization key ID does not match release artifact bindings",
    )
    require(
        identity["authority_root_sha256"]
        == artifact_authority["launch_authority_root_sha256"],
        "launch authorization root digest does not match release artifact bindings",
    )
    require(
        launch_manifest_v3.get("verified") is True
        and launch_manifest_v3.get("manifestSha256")
        == bootstrap_receipt["manifest"]["sha256"]
        and launch_manifest_v3.get("contractSha256")
        == identity["nonce_rollback_assurance_contract_sha256"]
        and nested(launch_manifest_v3, "pinsFile", "sha256")
        == identity["nonce_rollback_assurance_pins_sha256"]
        and launch_manifest_v3.get("verifierStateService")
        == nonce_rollback_assurance.get("verifierStateService")
        == bootstrap_receipt["nonceRollbackAssurance"][
            "verifierStateService"
        ],
        "launch authorization is not bound to the independently remeasured v3 launch manifest",
    )
    request = bootstrap_receipt["launchAuthorization"]["request"]
    statement = bootstrap_receipt["launchAuthorization"]["envelope"][
        "statement"
    ]
    witness_statement = statement["monotonicWitness"]["statement"]
    manifest_witness = launch_manifest_v3.get("monotonicWitness")
    manifest_saga = launch_manifest_v3.get(
        "launchAuthorityIssuanceSaga"
    )
    require(
        launch_manifest_v3.get("authorizationScope")
        == request["authorizationScope"]
        == statement["authorizationScope"]
        == witness_statement["authorizationScope"]
        == "trusted-host-readiness"
        and launch_manifest_v3.get("freshnessAuthority")
        == request["freshnessAuthority"]
        == statement["freshnessAuthority"]
        == "trusted-host-wall-clock"
        and launch_manifest_v3.get("capabilitySemantics")
        == statement["capabilitySemantics"]
        == "time-bounded-idempotent-readiness-authorization"
        and launch_manifest_v3.get("globalRoleRegistry")
        == request["globalRoleRegistry"]
        and launch_manifest_v3.get("globalRoleRegistrySha256")
        == request["globalRoleRegistrySha256"]
        == statement["globalRoleRegistrySha256"]
        and nested(
            launch_manifest_v3,
            "globalRoleRegistryPinsFile",
            "sha256",
        )
        == request["globalRoleRegistryPinsSha256"]
        and nested(
            launch_manifest_v3,
            "launchAttemptJournal",
            "domain",
        )
        == request["launchAttemptJournalDomain"]
        and launch_manifest_v3.get(
            "launchAttemptRecoveryIdentitySha256"
        )
        == request["launchAttemptRecoveryIdentitySha256"]
        and isinstance(manifest_witness, dict)
        and manifest_witness.get("sha256")
        == sha256_prefixed_json(statement["monotonicWitness"])
        and manifest_witness.get("signingKeyId")
        == request["launchAuthorityWitnessKeyId"]
        == witness_statement["witnessKeyId"]
        and manifest_witness.get("identitySha256")
        == request["launchAuthorityWitnessIdentitySha256"]
        == witness_statement["witnessIdentitySha256"]
        and manifest_witness.get("administrativeDomainSha256")
        == request[
            "launchAuthorityWitnessAdministrativeDomainSha256"
        ]
        == witness_statement["witnessAdministrativeDomainSha256"]
        and manifest_witness.get("storeAssuranceSha256")
        == request["launchAuthorityWitnessStoreAssuranceSha256"]
        == witness_statement["storeAssuranceSha256"]
        and manifest_witness.get("storeAssuranceIssuerKeyId")
        == request["globalRoleRegistry"]["roles"][
            "launchAuthorityWitnessStoreAssurance"
        ]
        and manifest_witness.get("registryGeneration")
        == witness_statement["registryGeneration"]
        and manifest_witness.get("registrySha256")
        == witness_statement["registrySha256"]
        and manifest_witness.get("predecessorStateSha256")
        == witness_statement["predecessorStateSha256"]
        and manifest_witness.get("successorStateSha256")
        == witness_statement["successorStateSha256"]
        and manifest_witness.get("checkpointSequence")
        == witness_statement["checkpointSequence"]
        and manifest_witness.get("stateTransitionCommitted") is True
        and isinstance(manifest_saga, dict)
        and manifest_saga
        == {
            "ledgerSchemaVersion": 7,
            "requestSha256": bootstrap_receipt[
                "launchAuthorization"
            ]["requestSha256"],
            "authorizationId": statement["authorizationId"],
            "recoveryIdentitySha256": request[
                "launchAttemptRecoveryIdentitySha256"
            ],
            "registryGeneration": witness_statement[
                "registryGeneration"
            ],
            "registrySha256": witness_statement["registrySha256"],
            "predecessorStateSha256": witness_statement[
                "predecessorStateSha256"
            ],
            "successorStateSha256": witness_statement[
                "successorStateSha256"
            ],
            "checkpointSequence": witness_statement[
                "checkpointSequence"
            ],
            "witnessTransitionSha256": sha256_prefixed_json(
                statement["monotonicWitness"]
            ),
            "stateTransitionCommitted": True,
        },
        "launch authorization is not bound to the fixed journal, global-role registry, trusted-host scope/freshness, or v7 witnessed issuance saga",
    )
    return {
        **identity,
        "canonical_request_digest_verified": True,
        "canonical_envelope_digest_verified": True,
        "authority_signature_verified_at_launch": True,
        "signed_provenance_bound": True,
        "signed_source_tree_bound": True,
        "measured_release_provenance_bound": True,
        "independent_build_report_bound": True,
        "current_host_deployment_identity_bound": True,
        "release_artifact_authority_bound": True,
        "nonce_rollback_assurance_bound": True,
        "launch_manifest_v3_bound": True,
        "launch_attempt_journal_bound": True,
        "global_role_registry_bound": True,
        "trusted_host_scope_and_freshness_bound": True,
        "monotonic_witness_bound": True,
        "launch_authority_v7_saga_bound": True,
    }


def verify_launch_authority_key_role_separation(
    launch_authority_key_id: str,
    role_key_ids: dict[str, Any],
) -> dict[str, Any]:
    authority_key_id = require_sha256(
        launch_authority_key_id,
        "launch authority signing key ID",
    )
    require(
        set(role_key_ids) == set(SECURITY_ROLE_NAMES),
        "security role key map does not match the closed release/final role set",
    )
    verified_roles = {
        "launch_authority_signer": authority_key_id,
        **{
            role: require_sha256(role_key_ids[role], f"{role} key ID")
            for role in SECURITY_ROLE_NAMES
        },
    }
    roles_by_key: dict[str, list[str]] = {}
    for role, key_id in verified_roles.items():
        roles_by_key.setdefault(key_id, []).append(role)
    reused = [roles for roles in roles_by_key.values() if len(roles) > 1]
    require(
        not reused,
        "security roles must use pairwise-distinct key identities; reused by "
        + ", ".join("/".join(sorted(roles)) for roles in reused),
    )
    canonical_roles = {
        role: verified_roles[role] for role in sorted(verified_roles)
    }
    digest_input = {
        "apiVersion": SECURITY_ROLE_MAP_API_VERSION,
        "roles": canonical_roles,
    }
    return {
        "apiVersion": SECURITY_ROLE_MAP_API_VERSION,
        "verified": True,
        "roles": canonical_roles,
        "sha256": sha256_prefixed_json(digest_input),
    }


def load_final_v6_canonical_json(
    raw_path: str,
    label: str,
) -> tuple[dict[str, Any], bytes]:
    document, raw = verify_nitro_tee.load_json_file(Path(raw_path), label)
    require(isinstance(document, dict), f"{label} must be a JSON object")
    validate_canonical_json_profile(document, label=label)
    require(
        raw == verify_nitro_tee.canonical_json_bytes(document) + b"\n",
        f"{label} must use exact {CANONICAL_JSON_PROFILE} bytes plus LF",
    )
    return document, raw


def reconstruct_final_v6_completion_identity(
    expectations: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    identity = verify_nitro_tee.verify_completion_identity(
        expectations["completionIdentity"],
        expectations["completionIdentitySha256"],
        label="independently expected completion identity",
    )
    identity_sha256 = verify_nitro_tee.sha256_json(identity)
    require(
        hmac.compare_digest(
            identity_sha256,
            expectations["completionIdentitySha256"],
        ),
        "canonical completionIdentity does not match the independently expected completionIdentitySha256",
    )
    return identity, identity_sha256


def validate_final_v6_completion_identity(
    value: Any,
) -> tuple[dict[str, Any], str]:
    expected_fields = {
        "apiVersion",
        "challengeNonceSha256",
        "coreDigests",
        "pipeline",
        "releaseGeneration",
        "rollbackEpoch",
    }
    require(
        isinstance(value, dict) and set(value) == expected_fields,
        "final completion identity does not match the closed v3 field set",
    )
    require(
        value["apiVersion"] == FINAL_COMPLETION_IDENTITY_API_VERSION
        and value["pipeline"] == MANIFEST_V6_PIPELINE,
        "final completion identity version or pipeline is invalid",
    )
    require_sha256(
        value["challengeNonceSha256"],
        "final completion challenge nonce",
    )
    core_digests = value["coreDigests"]
    require(
        isinstance(core_digests, dict)
        and set(core_digests) == FINAL_V6_COMPLETION_CORE_FIELDS,
        "final completion identity core-digest inventory is invalid",
    )
    for name, digest_value in core_digests.items():
        require_sha256(
            digest_value,
            f"final completion {name} core digest",
        )
    for field in ("releaseGeneration", "rollbackEpoch"):
        require(
            type(value[field]) is int
            and 0 <= value[field] <= CANONICAL_JSON_SIGNED_MAX,
            f"final completion identity {field} is invalid",
        )
    return value, verify_nitro_tee.sha256_json(value)


def _require_digest_fields(
    value: dict[str, Any],
    fields: set[str] | frozenset[str],
    label: str,
) -> None:
    for field in fields:
        require_sha256(value.get(field), f"{label} {field}")


def _validate_final_state_commit(
    value: Any,
    *,
    role_key_ids: dict[str, str],
) -> dict[str, Any]:
    fields = {
        "apiVersion",
        "status",
        "actionable",
        "redemptionVerified",
        "commitId",
        "storeId",
        "signingKeyId",
        "stateStoreSigningKeyId",
        "receiptFileSha256",
        "receiptPayloadSha256",
        "priorStateSha256",
        "currentStateSha256",
        "transitionSha256",
        "challengeConsumptionSha256",
        "currentHeadAuthorizationId",
        "currentHeadAuthorizationFileSha256",
        "currentHeadAuthorizationKeyId",
        "currentHeadSha256",
        "currentHeadVerifierNonceSha256",
        "currentHeadReservationId",
        "currentHeadRedemptionId",
        "currentHeadRedemptionReceiptFileSha256",
        "currentHeadRedemptionReceiptIdentitySha256",
        "currentHeadRedemptionVerifierNonceSha256",
        "currentHeadRedemptionKeyId",
        "currentFinalHeadSha256",
        "currentHeadOneUseSequence",
        "verifierStateKeyId",
        "storeAssuranceKeyId",
        "tlsReleaseKeyId",
        "rollbackResistanceBoundary",
    }
    require(
        isinstance(value, dict)
        and set(value) == fields
        and value["apiVersion"] == FINAL_V6_STATE_COMMIT_API_VERSION
        and value["status"] == "redemption-verified-non-actionable"
        and value["actionable"] is False
        and value["redemptionVerified"] is True,
        "public Nitro state commit does not match the closed non-actionable contract",
    )
    _require_digest_fields(
        value,
        {
            "signingKeyId",
            "stateStoreSigningKeyId",
            "receiptFileSha256",
            "receiptPayloadSha256",
            "priorStateSha256",
            "currentStateSha256",
            "transitionSha256",
            "challengeConsumptionSha256",
            "currentHeadAuthorizationFileSha256",
            "currentHeadAuthorizationKeyId",
            "currentHeadSha256",
            "currentHeadVerifierNonceSha256",
            "currentHeadRedemptionReceiptFileSha256",
            "currentHeadRedemptionReceiptIdentitySha256",
            "currentHeadRedemptionVerifierNonceSha256",
            "currentHeadRedemptionKeyId",
            "currentFinalHeadSha256",
            "verifierStateKeyId",
            "storeAssuranceKeyId",
            "tlsReleaseKeyId",
        },
        "public Nitro state commit",
    )
    require(
        type(value["currentHeadOneUseSequence"]) is int
        and 0
        < value["currentHeadOneUseSequence"]
        <= CANONICAL_JSON_SIGNED_MAX,
        "public Nitro state commit one-use sequence is invalid",
    )
    for field in (
        "commitId",
        "storeId",
        "currentHeadAuthorizationId",
        "currentHeadReservationId",
        "currentHeadRedemptionId",
    ):
        require_final_v1_identifier(
            value[field],
            f"public Nitro state commit {field}",
        )
    require_final_v1_non_empty_string(
        value["rollbackResistanceBoundary"],
        "public Nitro state commit rollbackResistanceBoundary",
    )
    require(
        value["signingKeyId"] == role_key_ids["stateCommit"]
        and value["stateStoreSigningKeyId"] == role_key_ids["stateStore"]
        and value["currentHeadAuthorizationKeyId"]
        == role_key_ids["currentHeadAuthorization"]
        and value["currentHeadRedemptionKeyId"]
        == role_key_ids["currentHeadRedemption"]
        and value["verifierStateKeyId"] == role_key_ids["verifierState"]
        and value["storeAssuranceKeyId"] == role_key_ids["storeAssurance"]
        and value["tlsReleaseKeyId"] == role_key_ids["tlsRelease"],
        "public Nitro state commit crossed its pinned store, authorization, or TLS roles",
    )
    return value


def _validate_public_nitro_live_result(value: Any) -> dict[str, Any]:
    fields = {
        "apiVersion",
        "verificationOk",
        "finalCompletionVerified",
        "actionAuthorization",
        "okForAction",
        "status",
        "pipeline",
        "canonicalProfile",
        "verifiedAtUnix",
        "evidenceBundleFileSha256",
        "expectationsFileSha256",
        "trustRootBundleFileSha256",
        "completionIdentity",
        "completionIdentitySha256",
        "completionCoreDigests",
        "candidateManifestFileSha256",
        "candidateManifestPayloadSha256",
        "sourceInputManifestFileSha256",
        "sourceClosureSha256",
        "buildWatchdogReceiptFileSha256",
        "promotionReceiptFileSha256",
        "promotedManifestFileSha256",
        "productionIdentitySha256",
        "runtimeStateFileSha256",
        "runtimeKeyCustodyFileSha256",
        "candidateToEifBuildStatementFileSha256",
        "eifSha384",
        "pcrs",
        "nitroAttestationDocumentSha256",
        "attestationRequestSha256",
        "requestSha256",
        "responseBytesSha256",
        "tlsExporterSha256",
        "tlsSpkiSha256",
        "tlsPeerSpkiSha256",
        "tlsStackMeasurementSha256",
        "kmsAuditProofSha256s",
        "witness",
        "nextClientState",
        "stateTransition",
        "stateCommit",
        "roleKeyIds",
        "roleRegistrySha256",
    }
    require(
        fields == verify_nitro_tee.PUBLIC_NITRO_RESULT_FIELDS,
        "final-v1 and native public Nitro result field inventories diverged",
    )
    require(
        CANONICAL_JSON_SIGNED_MAX
        == PUBLIC_NITRO_CANONICAL_INTEGER_MAX,
        "final-v1 and native public Nitro integer domains diverged",
    )
    verify_nitro_tee.validate_public_nitro_final_result_contract(value)
    require(
        isinstance(value, dict)
        and set(value) == fields
        and value["apiVersion"] == verify_nitro_tee.RESULT_VERSION
        and value["verificationOk"] is True
        and value["finalCompletionVerified"] is True
        and value["actionAuthorization"] is None
        and value["okForAction"] is False
        and value["status"] == "redemption-verified-non-actionable"
        and value["pipeline"] == MANIFEST_V6_PIPELINE
        and value["canonicalProfile"] == CANONICAL_JSON_PROFILE,
        "signed public Nitro result is not the current final non-actionable contract",
    )
    require(
        type(value["verifiedAtUnix"]) is int
        and 0 < value["verifiedAtUnix"] <= CANONICAL_JSON_SIGNED_MAX,
        "signed public Nitro result verification time is invalid",
    )
    completion_identity, completion_identity_sha256 = (
        validate_final_v6_completion_identity(value["completionIdentity"])
    )
    require(
        value["completionIdentitySha256"] == completion_identity_sha256
        and value["completionCoreDigests"] == completion_identity["coreDigests"],
        "signed public Nitro result crossed its completion identity",
    )
    _require_digest_fields(
        value,
        {
            "evidenceBundleFileSha256",
            "expectationsFileSha256",
            "trustRootBundleFileSha256",
            "completionIdentitySha256",
            "candidateManifestFileSha256",
            "candidateManifestPayloadSha256",
            "sourceInputManifestFileSha256",
            "sourceClosureSha256",
            "buildWatchdogReceiptFileSha256",
            "promotionReceiptFileSha256",
            "promotedManifestFileSha256",
            "productionIdentitySha256",
            "runtimeStateFileSha256",
            "runtimeKeyCustodyFileSha256",
            "candidateToEifBuildStatementFileSha256",
            "nitroAttestationDocumentSha256",
            "attestationRequestSha256",
            "requestSha256",
            "responseBytesSha256",
            "tlsExporterSha256",
            "tlsSpkiSha256",
            "tlsPeerSpkiSha256",
            "tlsStackMeasurementSha256",
            "roleRegistrySha256",
        },
        "signed public Nitro result",
    )
    require_sha384(value["eifSha384"], "signed public Nitro EIF digest")
    pcrs = value["pcrs"]
    require(
        isinstance(pcrs, dict) and set(pcrs) == {"PCR0", "PCR1", "PCR2"},
        "signed public Nitro result PCR inventory is invalid",
    )
    for name, digest_value in pcrs.items():
        require_sha384(digest_value, f"signed public Nitro {name}")
    validate_final_v1_digest_map(
        value["kmsAuditProofSha256s"],
        "signed public Nitro KMS audit digest inventory",
    )
    role_key_ids = value["roleKeyIds"]
    require(
        isinstance(role_key_ids, dict)
        and set(role_key_ids) == FINAL_PUBLIC_RESULT_ROLE_NAMES,
        "signed public Nitro result role map omitted or added a final input role",
    )
    normalized_roles = {
        role: require_sha256(role_key_ids[role], f"{role} role key ID")
        for role in sorted(role_key_ids)
    }
    require(
        len(set(normalized_roles.values())) == len(normalized_roles),
        "signed public Nitro result reused a key across final input roles",
    )
    expected_public_role_digest = verify_nitro_tee.sha256_json(
        {
            "apiVersion": PUBLIC_NITRO_ROLE_REGISTRY_API_VERSION,
            "roles": normalized_roles,
        }
    )
    require(
        value["roleRegistrySha256"] == expected_public_role_digest,
        "signed public Nitro result role registry digest is invalid",
    )
    witness = value["witness"]
    witness_fields = {
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
    require(
        isinstance(witness, dict)
        and set(witness) == witness_fields
        and witness["witnessKeyId"] == normalized_roles["witness"]
        and witness["witnessStoreKeyId"] == normalized_roles["witnessStore"],
        "signed public Nitro witness omitted or crossed its witness/store roles",
    )
    _require_digest_fields(
        witness,
        {
            "checkpointSha256",
            "challengeConsumptionSha256",
            "rootHash",
            "witnessKeyId",
            "witnessStoreKeyId",
            "witnessStoreIdentitySha256",
            "witnessStoreAssuranceSha256",
        },
        "signed public Nitro witness",
    )
    for field in (
        "leafIndex",
        "releaseGeneration",
        "rollbackEpoch",
        "sequence",
        "treeSize",
    ):
        require(
            type(witness[field]) is int
            and 0 <= witness[field] <= CANONICAL_JSON_SIGNED_MAX,
            f"signed public Nitro witness {field} is invalid",
        )
    next_state = verify_nitro_tee.load_client_state(value["nextClientState"])
    require_final_v1_identifier(
        next_state["provider"],
        "signed public Nitro next-client-state provider",
    )
    transition = value["stateTransition"]
    require(
        isinstance(transition, dict)
        and set(transition)
        == {"oldStateSha256", "newStateSha256", "transitionSha256"},
        "signed public Nitro state transition is invalid",
    )
    _require_digest_fields(
        transition,
        {"oldStateSha256", "newStateSha256", "transitionSha256"},
        "signed public Nitro state transition",
    )
    transition_core = {
        "oldStateSha256": transition["oldStateSha256"],
        "newStateSha256": transition["newStateSha256"],
    }
    require(
        transition["newStateSha256"] == next_state["stateSha256"]
        and transition["transitionSha256"]
        == verify_nitro_tee.sha256_json(transition_core)
        and next_state["challengeConsumptionSha256"]
        == witness["challengeConsumptionSha256"],
        "signed public Nitro state transition crossed the witness high-water",
    )
    state_commit = _validate_final_state_commit(
        value["stateCommit"],
        role_key_ids=normalized_roles,
    )
    require(
        state_commit["priorStateSha256"] == transition["oldStateSha256"]
        and state_commit["currentStateSha256"] == transition["newStateSha256"]
        and state_commit["transitionSha256"] == transition["transitionSha256"]
        and state_commit["challengeConsumptionSha256"]
        == witness["challengeConsumptionSha256"],
        "signed public Nitro state commit crossed its transition or witness",
    )
    return value


def verify_signed_public_nitro_result_envelope(
    value: Any,
    *,
    trusted_public_key_pem: str,
    expected_provider: str,
    expected_key_id: str,
    expected_spki_sha256: str,
) -> dict[str, Any]:
    fields = {
        "apiVersion",
        "provider",
        "signingKeyId",
        "signingKeySpkiSha256",
        "result",
        "resultSha256",
        "signature",
    }
    require(
        isinstance(value, dict)
        and set(value) == fields
        and value["apiVersion"]
        == PUBLIC_NITRO_LIVE_RESULT_ENVELOPE_API_VERSION,
        "public Nitro live result envelope does not match the closed v1 contract",
    )
    calculated_key_id = release_public_key_id(trusted_public_key_pem)
    pinned_provider = require_public_nitro_provider(
        expected_provider,
        "expected public Nitro result provider",
    )
    envelope_provider = require_public_nitro_provider(
        value["provider"],
        "public Nitro result provider",
    )
    require(
        envelope_provider == pinned_provider
        and value["signingKeyId"]
        == require_sha256(expected_key_id, "expected public Nitro result key ID")
        == calculated_key_id
        and value["signingKeySpkiSha256"]
        == require_sha256(
            expected_spki_sha256,
            "expected public Nitro result SPKI digest",
        )
        == calculated_key_id,
        "public Nitro live result signer does not match caller-pinned provider/key/SPKI",
    )
    result = _validate_public_nitro_live_result(value["result"])
    require(
        result["roleKeyIds"]["publicNitroResult"] == calculated_key_id,
        "public Nitro result signer differs from its global role",
    )
    result_sha256 = verify_nitro_tee.sha256_json(result)
    require(
        value["resultSha256"] == result_sha256,
        "public Nitro live result digest does not match its canonical result",
    )
    signed_envelope = dict(value)
    signature = signed_envelope.pop("signature")
    verify_ed25519(
        trusted_public_key_pem,
        str(signature),
        PUBLIC_NITRO_LIVE_RESULT_SIGNATURE_DOMAIN
        + verify_nitro_tee.canonical_json_bytes(signed_envelope),
        "public Nitro live result",
    )
    return result


def host_readiness_completion_proof_v6_core(
    value: dict[str, Any],
) -> dict[str, Any]:
    require(
        HOST_READINESS_V6_ENVELOPE_FIELDS.issubset(value),
        "completionProof/v6 is missing its persisted envelope fields",
    )
    return {
        key: child
        for key, child in value.items()
        if key not in HOST_READINESS_V6_ENVELOPE_FIELDS
    }


def _schema_object_without_duplicates(
    pairs: list[tuple[str, Any]],
    label: str,
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        require(key not in value, f"{label} duplicates field {key!r}")
        value[key] = child
    return value


def _reject_schema_noninteger_number(value: str, label: str) -> None:
    raise ValueError(f"{label} contains non-integer number {value!r}")


def host_readiness_completion_proof_v6_schema_validator() -> Any:
    global _HOST_READINESS_V6_SCHEMA_VALIDATOR
    if _HOST_READINESS_V6_SCHEMA_VALIDATOR is not None:
        return _HOST_READINESS_V6_SCHEMA_VALIDATOR
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise ValueError(
            "jsonschema is required to validate completionProof/v6"
        ) from exc
    schema_path = (
        Path(__file__).resolve().parent.parent
        / "schemas"
        / "completion-proof.v6.schema.json"
    )
    schema_raw = verify_nitro_tee.read_regular(
        schema_path,
        label="completionProof/v6 schema",
        max_bytes=1024 * 1024,
    )
    try:
        schema_text = schema_raw.decode("utf-8")
        schema = json.loads(
            schema_text,
            object_pairs_hook=lambda pairs: _schema_object_without_duplicates(
                pairs,
                "completionProof/v6 schema",
            ),
            parse_float=lambda value: _reject_schema_noninteger_number(
                value,
                "completionProof/v6 schema",
            ),
            parse_constant=lambda value: _reject_schema_noninteger_number(
                value,
                "completionProof/v6 schema",
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "completionProof/v6 schema is not strict UTF-8 JSON"
        ) from exc
    require(
        isinstance(schema, dict),
        "completionProof/v6 schema must be a JSON object",
    )
    Draft202012Validator.check_schema(schema)
    _HOST_READINESS_V6_SCHEMA_VALIDATOR = Draft202012Validator(schema)
    return _HOST_READINESS_V6_SCHEMA_VALIDATOR


def validate_host_readiness_completion_proof_v6(value: Any) -> dict[str, Any]:
    fields = {
        "apiVersion",
        "kind",
        "verificationOk",
        "finalCompletionVerified",
        "actionAuthorization",
        "okForAction",
        "verification_passed",
        "verification_mode",
        "result_scope",
        "readiness_only",
        "readiness_ok",
        "completion_status",
        "release_completion",
        "hardware_proof",
        "assurance_ceiling",
        "generated_at_unix",
        "artifacts",
        "production_readiness",
        "production_readiness_config",
        "current_completion_host",
        "production_env_binding",
        "running_production_containers",
        "production_host_preflight",
        "bootstrap_launcher",
        "nonce_rollback_assurance",
        "nitro_kms_evidence",
        "nitro_evidence_binding",
        "hardware_assurance_evidence",
        "final_challenge_consumption",
        "production_images_build",
        "production_images_published",
        "release_provenance",
        "image_signatures",
        "benchmark",
        "release_security_evidence",
        "production_proxy_response_proof",
        "production_continuity",
        "proof_core_sha256",
        "independently_authenticated",
        "aggregate_authentication",
        "proof_path",
        "integrity_metadata",
    }
    validate_canonical_json_profile(
        value,
        label="completionProof/v6",
    )
    schema_error = next(
        host_readiness_completion_proof_v6_schema_validator().iter_errors(
            value
        ),
        None,
    )
    require(
        schema_error is None,
        "completionProof/v6 failed its closed schema: "
        + (schema_error.message if schema_error is not None else ""),
    )
    require(
        isinstance(value, dict)
        and set(value) == fields
        and value["apiVersion"] == COMPLETION_PROOF_API_VERSION
        and value["kind"] == "ServerwarePreEnclaveReadiness"
        and value["verificationOk"] is True
        and value["finalCompletionVerified"] is False
        and value["actionAuthorization"] is None
        and value["okForAction"] is False
        and value["verification_passed"] is True
        and value["verification_mode"] == "readiness"
        and value["result_scope"] == "readiness-only"
        and value["readiness_only"] is True
        and value["readiness_ok"] is True
        and value["completion_status"] == "pre-enclave-readiness"
        and value["release_completion"] == "not-final"
        and value["hardware_proof"] is False
        and value["independently_authenticated"] is False
        and value["final_challenge_consumption"]
        == {"required": False, "consumed": False}
        and value["aggregate_authentication"]
        == {
            "required": False,
            "independently_authenticated": False,
            "scope": "readiness-only",
        },
        "completionProof/v6 is strictly a trusted-host readiness contract",
    )
    require_sha256(
        value["proof_core_sha256"],
        "host readiness proof core digest",
    )
    integrity = value["integrity_metadata"]
    require(
        isinstance(integrity, dict)
        and set(integrity)
        == {
            "generation",
            "detached_sha256_path",
            "scope",
            "independently_authenticated",
            "authenticity_requires_external_signature_or_checkpoint",
        }
        and integrity["scope"] == "checksum-only"
        and integrity["independently_authenticated"] is False
        and integrity[
            "authenticity_requires_external_signature_or_checkpoint"
        ]
        is True,
        "host readiness proof integrity metadata is not the closed v6 wire shape",
    )
    proof_core = host_readiness_completion_proof_v6_core(value)
    require(
        hmac.compare_digest(
            value["proof_core_sha256"],
            sha256_prefixed_json(proof_core),
        ),
        "completionProof/v6 proof core digest does not match the fully "
        "validated nested readiness core",
    )
    require(
        "public_verifier_bridge" not in canonical_json(value)
        and "completionProofFileB64" not in canonical_json(value),
        "completionProof/v6 contains obsolete final bridge injection",
    )
    return value


def _validate_final_role_registry(
    value: Any,
    *,
    public_result_roles: dict[str, str],
    public_result_signer_key_id: str,
    result_signer_key_id: str,
    launch_authority_key_id: str | None,
    expected_registry_sha256: str,
) -> dict[str, Any]:
    require(
        isinstance(value, dict)
        and set(value) == {"apiVersion", "roles", "registrySha256"}
        and value["apiVersion"] == FINAL_ROLE_REGISTRY_API_VERSION,
        "final role registry does not match the closed v1 contract",
    )
    expected_roles = set(FINAL_REQUIRED_ROLE_NAMES)
    if launch_authority_key_id is not None:
        expected_roles.add("launchAuthority")
    roles = value["roles"]
    require(
        isinstance(roles, dict) and set(roles) == expected_roles,
        "final role registry omitted or added a role visible in final inputs",
    )
    normalized_roles = {
        role: require_sha256(roles[role], f"final {role} role key ID")
        for role in sorted(roles)
    }
    require(
        len(set(normalized_roles.values())) == len(normalized_roles),
        "final role registry reused a key across security roles",
    )
    require(
        {
            role: normalized_roles[role]
            for role in FINAL_PUBLIC_RESULT_ROLE_NAMES
        }
        == public_result_roles
        and normalized_roles["publicNitroResult"]
        == public_result_signer_key_id
        and normalized_roles["releaseCompletionResult"]
        == result_signer_key_id
        and (
            launch_authority_key_id is None
            or normalized_roles["launchAuthority"]
            == launch_authority_key_id
        ),
        "final role registry crossed a signed result, result signer, or supplied launch authority",
    )
    digest_payload = {
        "apiVersion": FINAL_ROLE_REGISTRY_API_VERSION,
        "roles": normalized_roles,
    }
    registry_sha256 = verify_nitro_tee.sha256_json(digest_payload)
    require(
        value["registrySha256"] == registry_sha256
        and registry_sha256
        == require_sha256(
            expected_registry_sha256,
            "expected final role registry",
        ),
        "final role registry does not match the independently pinned digest",
    )
    return value


def _verify_final_result_authenticity(
    authenticity: Any,
    *,
    result_core: dict[str, Any],
    result_sha256: str,
    trusted_public_key_pem: str,
    expected_provider: str,
    expected_key_id: str,
    expected_spki_sha256: str,
) -> None:
    require(
        isinstance(authenticity, dict)
        and set(authenticity)
        == {
            "apiVersion",
            "provider",
            "signingKeyId",
            "signingKeySpkiSha256",
            "resultSha256",
            "signature",
        }
        and authenticity["apiVersion"]
        == FINAL_RESULT_AUTHENTICITY_API_VERSION,
        "final result authenticity does not match the closed signature envelope",
    )
    calculated_key_id = release_public_key_id(trusted_public_key_pem)
    pinned_provider = require_final_v1_identifier(
        expected_provider,
        "expected final result provider",
    )
    envelope_provider = require_final_v1_identifier(
        authenticity["provider"],
        "final result provider",
    )
    require(
        envelope_provider == pinned_provider
        and authenticity["signingKeyId"]
        == require_sha256(expected_key_id, "expected final result key ID")
        == calculated_key_id
        and authenticity["signingKeySpkiSha256"]
        == require_sha256(
            expected_spki_sha256,
            "expected final result SPKI digest",
        )
        == calculated_key_id
        and authenticity["resultSha256"] == result_sha256,
        "final result signer does not match caller-pinned provider/key/SPKI or result digest",
    )
    verify_ed25519(
        trusted_public_key_pem,
        str(authenticity["signature"]),
        FINAL_RESULT_SIGNATURE_DOMAIN
        + verify_nitro_tee.canonical_json_bytes(result_core),
        "release completion result",
    )


def validate_release_completion_verification_v1(
    value: Any,
    *,
    trusted_result_public_key_pem: str,
    expected_result_provider: str,
    expected_result_key_id: str,
    expected_result_spki_sha256: str,
    trusted_public_nitro_result_public_key_pem: str,
    expected_public_nitro_result_provider: str,
    expected_public_nitro_result_key_id: str,
    expected_public_nitro_result_spki_sha256: str,
    expected_final_role_registry_sha256: str,
) -> dict[str, Any]:
    fields = {
        "apiVersion",
        "verificationOk",
        "finalCompletionVerified",
        "actionAuthorization",
        "okForAction",
        "verificationMode",
        "redemptionVerified",
        "readinessOnly",
        "independentlyAuthenticated",
        "pipeline",
        "canonicalProfile",
        "verifiedAtUnix",
        "publicNitroVerification",
        "aggregateAuthentication",
        "completionIdentity",
        "completionIdentitySha256",
        "nextClientState",
        "stateCommit",
        "hostReadinessContext",
        "hostBootstrapBoundary",
        "globalRoleRegistry",
        "externalPinProvenanceBoundary",
        "externalProvisioningBoundary",
        "resultSha256",
        "authenticity",
    }
    require(
        isinstance(value, dict) and set(value) == fields,
        "final verification result does not match the closed v1 field set",
    )
    require(
        not {
            "ok",
            "finalCompletion",
            "final_completion",
            "stateCommitRequired",
            "public_verifier_bridge",
            "completionProofFileSha256",
        }.intersection(value),
        "final verification result contains an obsolete authority alias",
    )
    require(
        value["apiVersion"] == FINAL_V6_RESULT_API_VERSION
        and value["verificationOk"] is True
        and value["finalCompletionVerified"] is True
        and value["actionAuthorization"] is None
        and value["okForAction"] is False
        and value["verificationMode"] == "final"
        and value["redemptionVerified"] is True
        and value["readinessOnly"] is False
        and value["independentlyAuthenticated"] is True
        and value["pipeline"] == MANIFEST_V6_PIPELINE
        and value["canonicalProfile"] == CANONICAL_JSON_PROFILE,
        "final verification result is not the current authenticated historical non-actionable contract",
    )
    require(
        type(value["verifiedAtUnix"]) is int
        and 0 < value["verifiedAtUnix"] <= CANONICAL_JSON_SIGNED_MAX,
        "final verification time is invalid",
    )
    completion_identity, completion_identity_sha256 = (
        validate_final_v6_completion_identity(value["completionIdentity"])
    )
    require(
        value["completionIdentitySha256"] == completion_identity_sha256,
        "final verification result crossed its completion identity digest",
    )
    public_verification = value["publicNitroVerification"]
    require(
        isinstance(public_verification, dict)
        and set(public_verification)
        == {
            "envelope",
            "envelopeFileSha256",
            "resultSha256",
            "evidenceBundleFileSha256",
            "expectationsFileSha256",
            "trustRootBundleFileSha256",
        },
        "final result public Nitro verification binding is invalid",
    )
    public_result = verify_signed_public_nitro_result_envelope(
        public_verification["envelope"],
        trusted_public_key_pem=trusted_public_nitro_result_public_key_pem,
        expected_provider=expected_public_nitro_result_provider,
        expected_key_id=expected_public_nitro_result_key_id,
        expected_spki_sha256=expected_public_nitro_result_spki_sha256,
    )
    public_envelope_file_sha256 = verify_nitro_tee.sha256(
        verify_nitro_tee.canonical_json_bytes(
            public_verification["envelope"]
        )
        + b"\n"
    )
    require(
        public_verification["envelopeFileSha256"]
        == public_envelope_file_sha256
        and public_verification["resultSha256"]
        == public_verification["envelope"]["resultSha256"]
        == verify_nitro_tee.sha256_json(public_result)
        and public_verification["evidenceBundleFileSha256"]
        == public_result["evidenceBundleFileSha256"]
        and public_verification["expectationsFileSha256"]
        == public_result["expectationsFileSha256"]
        and public_verification["trustRootBundleFileSha256"]
        == public_result["trustRootBundleFileSha256"]
        and public_result["completionIdentity"] == completion_identity
        and public_result["completionIdentitySha256"]
        == completion_identity_sha256,
        "final result crossed a signed public Nitro result or input digest",
    )
    _require_digest_fields(
        public_verification,
        {
            "envelopeFileSha256",
            "resultSha256",
            "evidenceBundleFileSha256",
            "expectationsFileSha256",
            "trustRootBundleFileSha256",
        },
        "final public Nitro verification",
    )
    require(
        value["nextClientState"] == public_result["nextClientState"]
        and value["stateCommit"] == public_result["stateCommit"],
        "final result crossed the signed public Nitro state transition",
    )
    context = value["hostReadinessContext"]
    require(
        isinstance(context, dict)
        and set(context)
        == {
            "apiVersion",
            "provided",
            "completionProofApiVersion",
            "completionProofFileSha256",
            "completionProofCoreSha256",
            "generatedAtUnix",
            "launchAuthorityKeyId",
            "authoritativeForFinalCompletion",
        }
        and context["apiVersion"] == HOST_READINESS_CONTEXT_API_VERSION
        and context["authoritativeForFinalCompletion"] is False,
        "host readiness context does not match its closed non-authoritative contract",
    )
    if context["provided"] is True:
        require(
            context["completionProofApiVersion"] == COMPLETION_PROOF_API_VERSION
            and type(context["generatedAtUnix"]) is int
            and context["generatedAtUnix"] > 0,
            "provided host readiness context is invalid",
        )
        require_sha256(
            context["completionProofFileSha256"],
            "host readiness completion proof file",
        )
        require_sha256(
            context["completionProofCoreSha256"],
            "host readiness completion proof core",
        )
        if context["launchAuthorityKeyId"] is not None:
            require_sha256(
                context["launchAuthorityKeyId"],
                "host readiness launch authority",
            )
    else:
        require(
            context
            == {
                "apiVersion": HOST_READINESS_CONTEXT_API_VERSION,
                "provided": False,
                "completionProofApiVersion": None,
                "completionProofFileSha256": None,
                "completionProofCoreSha256": None,
                "generatedAtUnix": None,
                "launchAuthorityKeyId": None,
                "authoritativeForFinalCompletion": False,
            },
            "absent host readiness context contains an authority claim",
        )
    context_sha256 = verify_nitro_tee.sha256_json(context)
    boundary = value["hostBootstrapBoundary"]
    require(
        isinstance(boundary, dict)
        and set(boundary) == FINAL_V6_HOST_BOOTSTRAP_BOUNDARY_FIELDS
        and boundary["apiVersion"]
        == FINAL_V6_HOST_BOOTSTRAP_BOUNDARY_API_VERSION
        and boundary["launchManifestApiVersion"]
        == "serverware.productionReadinessLaunch/v3"
        and boundary["launchAuthorizationRequestApiVersion"]
        == "serverware.launchAuthorizationRequest/v2"
        and boundary["launchAuthorizationApiVersion"]
        == "serverware.launchAuthorization/v2"
        and boundary["bootstrapReceiptApiVersion"]
        == "serverware.bootstrapReceipt/v3"
        and boundary["nonceRollbackAssuranceBindingApiVersion"]
        == "serverware.productionNonceRollbackAssuranceBinding/v1"
        and boundary["authorizationScope"] == "trusted-host-readiness"
        and boundary["freshnessAuthority"] == "trusted-host-wall-clock"
        and boundary["evidenceProvidedToFinalVerifier"]
        is context["provided"]
        and boundary["hostReadinessContextSha256"] == context_sha256
        and boundary["hostReadinessCompletionProofFileSha256"]
        == context["completionProofFileSha256"]
        and boundary["launchAuthorityKeyId"]
        == context["launchAuthorityKeyId"]
        and boundary["authoritativeForFinalCompletion"] is False
        and boundary["requiredForFinalCompletion"] is False
        and boundary["relationship"]
        == "non-authoritative-readiness-context-only"
        and boundary["finalAuthority"]
        == "independent-manifest-v6-public-nitro-verifier-and-protected-state"
        and boundary["completionIdentitySha256"]
        == completion_identity_sha256
        and boundary["bindingMechanism"]
        == "signed-final-result-core-non-authoritative-context-binding",
        "host bootstrap boundary exceeded or crossed its non-authoritative role",
    )
    boundary_core = dict(boundary)
    boundary_sha256 = boundary_core.pop("boundarySha256")
    expected_boundary_sha256 = verify_nitro_tee.sha256_json(boundary_core)
    require(
        boundary_sha256 == expected_boundary_sha256,
        "host bootstrap boundary digest does not match its canonical fields",
    )
    result_key_id = release_public_key_id(trusted_result_public_key_pem)
    public_result_key_id = release_public_key_id(
        trusted_public_nitro_result_public_key_pem
    )
    _validate_final_role_registry(
        value["globalRoleRegistry"],
        public_result_roles=public_result["roleKeyIds"],
        public_result_signer_key_id=public_result_key_id,
        result_signer_key_id=result_key_id,
        launch_authority_key_id=context["launchAuthorityKeyId"],
        expected_registry_sha256=expected_final_role_registry_sha256,
    )
    aggregate = value["aggregateAuthentication"]
    require(
        isinstance(aggregate, dict)
        and set(aggregate)
        == {
            "independentlyAuthenticated",
            "publicNitroResultEnvelopeSha256",
            "publicNitroResultSha256",
            "completionIdentitySha256",
            "stateTransitionSha256",
            "stateCommitReceiptSha256",
            "hostBootstrapBoundarySha256",
            "globalRoleRegistrySha256",
            "releaseCompletionResultKeyId",
            "allResultDigestsCrossBound",
        }
        and aggregate["independentlyAuthenticated"] is True
        and aggregate["allResultDigestsCrossBound"] is True
        and aggregate["publicNitroResultEnvelopeSha256"]
        == public_envelope_file_sha256
        and aggregate["publicNitroResultSha256"]
        == public_verification["resultSha256"]
        and aggregate["completionIdentitySha256"]
        == completion_identity_sha256
        and aggregate["stateTransitionSha256"]
        == public_result["stateTransition"]["transitionSha256"]
        and aggregate["stateCommitReceiptSha256"]
        == public_result["stateCommit"]["receiptFileSha256"]
        and aggregate["hostBootstrapBoundarySha256"]
        == expected_boundary_sha256
        and aggregate["globalRoleRegistrySha256"]
        == value["globalRoleRegistry"]["registrySha256"]
        and aggregate["releaseCompletionResultKeyId"] == result_key_id,
        "aggregate authentication crossed a final result digest",
    )
    _require_digest_fields(
        aggregate,
        set(aggregate)
        - {"independentlyAuthenticated", "allResultDigestsCrossBound"},
        "aggregate authentication",
    )
    require(
        value["externalPinProvenanceBoundary"]
        == FINAL_V6_EXTERNAL_PIN_PROVENANCE_BOUNDARY
        and value["externalProvisioningBoundary"]
        == FINAL_V6_EXTERNAL_PROVISIONING_BOUNDARY,
        "final verification result changed its external trust boundary",
    )
    result_core = dict(value)
    authenticity = result_core.pop("authenticity")
    result_sha256 = result_core.pop("resultSha256")
    expected_result_sha256 = verify_nitro_tee.sha256_json(result_core)
    require(
        result_sha256 == expected_result_sha256,
        "final verification result digest does not match its exact core",
    )
    _verify_final_result_authenticity(
        authenticity,
        result_core=result_core,
        result_sha256=result_sha256,
        trusted_public_key_pem=trusted_result_public_key_pem,
        expected_provider=expected_result_provider,
        expected_key_id=expected_result_key_id,
        expected_spki_sha256=expected_result_spki_sha256,
    )
    require(
        result_key_id not in set(public_result["roleKeyIds"].values()),
        "releaseCompletionResult signer is not distinct from every final input role",
    )
    return value


def final_v6_completion_bound_artifact(
    artifact: dict[str, Any],
    *,
    completion_identity: dict[str, Any],
    completion_identity_sha256: str,
    label: str,
) -> dict[str, Any]:
    binding = {
        "artifact": artifact,
        "completionIdentity": completion_identity,
        "completionIdentitySha256": completion_identity_sha256,
        "label": label,
    }
    return {
        **binding,
        "bindingSha256": verify_nitro_tee.sha256_json(binding),
    }


def load_final_v6_pinned_ed25519_key(
    raw_path: str,
    *,
    expected_key_id: str,
    label: str,
) -> tuple[Ed25519PublicKey, str, str]:
    raw = verify_nitro_tee.read_regular(
        Path(raw_path),
        label=label,
        max_bytes=8192,
    )
    try:
        pem = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} must be ASCII PEM") from exc
    key, key_id = verify_nitro_tee.load_ed25519_key(pem, label)
    require(
        expected_key_id == key_id,
        f"{label} does not match the independently expected key ID",
    )
    return key, key_id, verify_nitro_tee.sha256(raw)


def verify_protected_final_v6_client_state(
    *,
    state_document: dict[str, Any],
    state_raw: bytes,
    checkpoint_document: dict[str, Any],
    checkpoint_raw: bytes,
    state_key: Ed25519PublicKey,
    state_key_id: str,
    state_key_file_sha256: str,
    checkpoint_key: Ed25519PublicKey,
    checkpoint_key_id: str,
    checkpoint_key_file_sha256: str,
    trust_root_bundle_sha256: str,
    trust_root_pin_id: str,
    trust_key_ids: dict[str, str],
    now: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    require(
        state_key_id != checkpoint_key_id,
        "protected client-state signer and checkpoint root must be distinct",
    )
    require(
        state_key_id == trust_key_ids.get("clientState")
        and checkpoint_key_id
        == trust_key_ids.get("clientStateCheckpoint"),
        "protected client-state keys do not match their pinned public verifier roles",
    )
    evidence_key_ids = {
        key_id
        for role, key_id in trust_key_ids.items()
        if role not in {"clientState", "clientStateCheckpoint"}
    }
    require(
        state_key_id not in evidence_key_ids
        and checkpoint_key_id not in evidence_key_ids,
        "protected client-state keys must be separate from every evidence trust-root role",
    )
    state_payload, state_document_sha256 = verify_nitro_tee.verify_standard_envelope(
        state_document,
        api_version=PROTECTED_CLIENT_STATE_API_VERSION,
        domain=PROTECTED_CLIENT_STATE_SIGNATURE_DOMAIN,
        key=state_key,
        key_id=state_key_id,
        label="protected prior client state",
    )
    verify_nitro_tee.exact_keys(
        state_payload,
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
        state_document_sha256 == verify_nitro_tee.sha256(state_raw),
        "protected prior client-state envelope byte digest mismatch",
    )
    require(
        state_payload["canonicalProfile"] == CANONICAL_JSON_PROFILE,
        "protected prior client state selects an unsupported canonical profile",
    )
    protected_state_id = verify_nitro_tee.require_identifier(
        state_payload["protectedClientStateId"],
        "protected client-state ID",
    )
    require(
        state_payload["provenanceBoundary"]
        == PROTECTED_CLIENT_STATE_PROVENANCE_BOUNDARY,
        "protected client-state provenance boundary mismatch",
    )
    require(
        state_payload["trustRootBundleSha256"] == trust_root_bundle_sha256
        and state_payload["trustRootPinId"] == trust_root_pin_id,
        "protected client state crossed the externally pinned trust-root bundle",
    )
    prior_state = verify_nitro_tee.load_client_state(state_payload["clientState"])
    prior_state_sha256 = verify_nitro_tee.sha256_json(prior_state)
    require(
        state_payload["clientStateSha256"] == prior_state_sha256,
        "protected prior client-state digest mismatch",
    )
    state_issued = verify_nitro_tee.require_uint(
        state_payload["issuedAtUnix"],
        "protected client-state issue time",
    )
    state_expires = verify_nitro_tee.require_uint(
        state_payload["expiresAtUnix"],
        "protected client-state expiry",
    )
    require(
        state_issued <= now <= state_expires
        and 0 < state_expires - state_issued <= FINAL_V6_MAX_VALIDITY_SECONDS,
        "protected prior client state is future, stale, or overlong",
    )

    checkpoint_payload, checkpoint_document_sha256 = (
        verify_nitro_tee.verify_standard_envelope(
            checkpoint_document,
            api_version=PROTECTED_CLIENT_STATE_CHECKPOINT_API_VERSION,
            domain=PROTECTED_CLIENT_STATE_CHECKPOINT_SIGNATURE_DOMAIN,
            key=checkpoint_key,
            key_id=checkpoint_key_id,
            label="protected client-state checkpoint",
        )
    )
    verify_nitro_tee.exact_keys(
        checkpoint_payload,
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
        "protected client-state checkpoint payload",
    )
    require(
        checkpoint_document_sha256 == verify_nitro_tee.sha256(checkpoint_raw),
        "protected client-state checkpoint byte digest mismatch",
    )
    require(
        checkpoint_payload["canonicalProfile"] == CANONICAL_JSON_PROFILE,
        "protected client-state checkpoint selects an unsupported canonical profile",
    )
    require(
        checkpoint_payload["protectedClientStateId"] == protected_state_id
        and checkpoint_payload["protectedClientStatePayloadSha256"]
        == state_document["payloadSha256"]
        and checkpoint_payload["clientStateSha256"] == prior_state_sha256,
        "protected client-state checkpoint crossed the signed state identity",
    )
    require(
        checkpoint_payload["trustRootBundleSha256"] == trust_root_bundle_sha256
        and checkpoint_payload["trustRootPinId"] == trust_root_pin_id,
        "protected client-state checkpoint crossed the pinned trust-root bundle",
    )
    require(
        checkpoint_payload["logId"] == checkpoint_key_id,
        "protected client-state checkpoint log is not the independently pinned root",
    )
    require(
        isinstance(checkpoint_payload["provider"], str)
        and 1 <= len(checkpoint_payload["provider"]) <= 128,
        "protected client-state checkpoint provider is invalid",
    )
    checkpoint_issued = verify_nitro_tee.require_uint(
        checkpoint_payload["issuedAtUnix"],
        "protected client-state checkpoint issue time",
    )
    checkpoint_expires = verify_nitro_tee.require_uint(
        checkpoint_payload["expiresAtUnix"],
        "protected client-state checkpoint expiry",
    )
    require(
        state_issued <= checkpoint_issued <= now <= checkpoint_expires
        and 0
        < checkpoint_expires - checkpoint_issued
        <= FINAL_V6_MAX_VALIDITY_SECONDS,
        "protected client-state checkpoint is future, stale, or overlong",
    )
    tree_size = verify_nitro_tee.require_uint(
        checkpoint_payload["treeSize"],
        "protected client-state checkpoint tree size",
    )
    leaf_index = verify_nitro_tee.require_uint(
        checkpoint_payload["leafIndex"],
        "protected client-state checkpoint leaf index",
    )
    require(tree_size > 0, "protected client-state checkpoint tree is empty")
    inclusion_proof = checkpoint_payload["inclusionProof"]
    require(
        isinstance(inclusion_proof, list)
        and len(inclusion_proof) <= 64
        and all(
            isinstance(item, str)
            and SHA256_RE.fullmatch(item) is not None
            for item in inclusion_proof
        ),
        "protected client-state checkpoint inclusion proof is invalid",
    )
    state_leaf = {
        "apiVersion": PROTECTED_CLIENT_STATE_LEAF_API_VERSION,
        "canonicalProfile": CANONICAL_JSON_PROFILE,
        "clientStateSha256": prior_state_sha256,
        "protectedClientStateId": protected_state_id,
        "protectedClientStatePayloadSha256": state_document["payloadSha256"],
        "trustRootBundleSha256": trust_root_bundle_sha256,
        "trustRootPinId": trust_root_pin_id,
    }
    expected_leaf_sha256 = (
        "sha256:" + verify_nitro_tee.merkle_leaf_hash(state_leaf).hex()
    )
    require(
        checkpoint_payload["leafSha256"] == expected_leaf_sha256,
        "protected client-state checkpoint leaf mismatch",
    )
    verify_nitro_tee.verify_inclusion(
        leaf=state_leaf,
        leaf_index=leaf_index,
        tree_size=tree_size,
        proof=inclusion_proof,
        expected_root=checkpoint_payload["rootHashSha256"],
    )
    protected_identity = {
        "apiVersion": "serverware.protectedNitroClientStateIdentity/v1",
        "canonicalProfile": CANONICAL_JSON_PROFILE,
        "protectedClientStateId": protected_state_id,
        "stateEnvelopeFileSha256": state_document_sha256,
        "statePayloadSha256": state_document["payloadSha256"],
        "clientStateSha256": prior_state_sha256,
        "stateSigningKeyId": state_key_id,
        "stateSigningKeyFileSha256": state_key_file_sha256,
        "checkpointFileSha256": checkpoint_document_sha256,
        "checkpointPayloadSha256": checkpoint_document["payloadSha256"],
        "checkpointKeyId": checkpoint_key_id,
        "checkpointKeyFileSha256": checkpoint_key_file_sha256,
        "checkpointProvider": checkpoint_payload["provider"],
        "checkpointTreeSize": tree_size,
        "checkpointRootHashSha256": checkpoint_payload["rootHashSha256"],
        "trustRootBundleSha256": trust_root_bundle_sha256,
        "trustRootPinId": trust_root_pin_id,
        "provenanceBoundary": PROTECTED_CLIENT_STATE_PROVENANCE_BOUNDARY,
    }
    protected_identity["identitySha256"] = verify_nitro_tee.sha256_json(
        protected_identity
    )
    return prior_state, protected_identity


def write_final_v6_result(path: Path, result: dict[str, Any]) -> str:
    require(path.name not in {"", ".", ".."}, "final result output path is invalid")
    payload = verify_nitro_tee.canonical_json_bytes(result) + b"\n"
    digest = verify_nitro_tee.sha256(payload)
    verify_private_output_directory(path.parent)
    validate_existing_private_output(path, "final verification result")
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            os.fchmod(temporary.fileno(), 0o600)
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
        fsync_directory(path.parent)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
    return digest


def final_v6_dependency_role(name: str) -> str:
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


def final_v6_process(name: str) -> dict[str, Any]:
    if name == "npm-publish-companion":
        return {
            "argv": [],
            "cwd": "/work",
            "dynamicEnvironment": [],
            "entrypoint": [
                "/opt/serverware/node/bin/node",
                FINAL_V6_NPM_ENTRYPOINT_IMAGE,
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
            FINAL_V6_PYTHON_ENTRYPOINT_IMAGE,
        ]
        argv = ["--role", name]
    return {
        "argv": argv,
        "cwd": "/work",
        "dynamicEnvironment": (
            list(FINAL_V6_PORTAL_DYNAMIC_ENVIRONMENT)
            if name == "portal-browser-oauth"
            else []
        ),
        "entrypoint": entrypoint,
        "environment": dict(FINAL_V6_BASE_ENVIRONMENT),
        "gid": 65532,
        "uid": 65532,
    }


def final_v6_source_set(name: str) -> dict[str, list[str]]:
    if name == "npm-publish-companion":
        return {"exact": [FINAL_V6_NPM_ENTRYPOINT_SOURCE], "prefixes": []}
    configured = FINAL_V6_SOURCE_CONTRACTS[name]
    exact = set(configured["exact"])
    if name != "rust-decision-gate-tests":
        exact.add(FINAL_V6_PYTHON_ENTRYPOINT_SOURCE)
    return {
        "exact": sorted(exact),
        "prefixes": list(configured["prefixes"]),
    }


def final_v6_network(name: str) -> dict[str, Any]:
    if name == "portal-browser-oauth":
        return {
            "egress": "none",
            "mode": "internal",
            "namespace": "private-anchor",
            "role": "portal-npm-private",
        }
    if name == "npm-publish-companion":
        return {
            "egress": "none",
            "mode": "join",
            "namespace": "lane:portal-browser-oauth",
            "role": "portal-npm-private",
        }
    return {
        "egress": "none",
        "mode": "none",
        "namespace": "private",
        "role": None,
    }


def final_v6_isolation(
    name: str,
    *,
    apparmor_sha256: str,
    seccomp_sha256: str,
) -> dict[str, Any]:
    return {
        "apparmorProfileSha256": apparmor_sha256,
        "capDrop": ["ALL"],
        "cpuQuotaMicros": 1_000_000,
        "memoryBytes": (
            1024 * 1024 * 1024
            if name == "portal-browser-oauth"
            else 512 * 1024 * 1024
        ),
        "mounts": [
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
        ],
        "noNewPrivileges": True,
        "outputStderrBytes": 16 * 1024 * 1024,
        "outputStdoutBytes": 32 * 1024 * 1024,
        "pidsLimit": 256,
        "readOnlyRootfs": True,
        "seccompProfileSha256": seccomp_sha256,
        "tmpfs": [
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
        ],
        "timeoutSeconds": (
            900
            if name == "portal-browser-oauth"
            else 120
            if name == "npm-publish-companion"
            else 300
        ),
    }


def final_v6_capability_probes(name: str) -> list[str]:
    if name in {
        "browser-python-compatibility",
        "host-python-compatibility",
        "proxy-python-compatibility",
    }:
        return list(FINAL_V6_PYTHON_CAPABILITY_PROBES)
    if name == "chromium-compatibility":
        return ["chromium-startup-no-network"]
    return []


def final_v6_dockerfile(
    process: dict[str, Any],
    base_image_digest: str,
) -> str:
    environment = " ".join(
        f"{name}={json.dumps(value, ensure_ascii=True)}"
        for name, value in sorted(process["environment"].items())
    )
    return "\n".join(
        (
            "FROM scratch",
            f"ARG SERVERWARE_BASE_IMAGE_DIGEST={base_image_digest}",
            "ARG SOURCE_DATE_EPOCH=0",
            "COPY --chown=0:0 rootfs/ /",
            f"ENV {environment}",
            f"WORKDIR {json.dumps(process['cwd'])}",
            f"USER {process['uid']}:{process['gid']}",
            "ENTRYPOINT "
            + json.dumps(
                process["entrypoint"],
                ensure_ascii=True,
                separators=(",", ":"),
            ),
            "CMD "
            + json.dumps(
                process["argv"],
                ensure_ascii=True,
                separators=(",", ":"),
            ),
            "",
        )
    )


def verify_final_v6_candidate_execution_contract(
    candidate: dict[str, Any],
    source: dict[str, Any],
    *,
    expected_apparmor_sha256: str,
    expected_seccomp_sha256: str,
) -> dict[str, Any]:
    continuity = verify_nitro_tee.exact_keys(
        candidate["buildContinuity"],
        {
            "buildBundle",
            "buildPlan",
            "buildWatchdogReceipt",
            "dependencyBundle",
            "sourceSnapshot",
        },
        "Candidate Manifest v6 build continuity",
    )
    plan = continuity["buildPlan"]
    lanes = plan.get("lanes")
    require(
        isinstance(lanes, dict)
        and list(lanes) == list(verify_nitro_tee.LANE_ORDER)
        and candidate.get("lanes") == lanes,
        "Candidate lane definitions differ from the exact build plan",
    )
    dependencies = continuity["dependencyBundle"]
    dependency_bundles = dependencies.get("bundles")
    require(
        isinstance(dependency_bundles, dict)
        and set(dependency_bundles) == set(FINAL_V6_DEPENDENCY_CAPABILITIES),
        "Candidate dependency bundle role inventory is not exact",
    )
    selected_entries = source.get("entries")
    require(
        isinstance(selected_entries, list) and selected_entries,
        "signed source-input entry inventory is missing",
    )
    frozen_entries = [
        {
            key: value
            for key, value in entry.items()
            if key not in {"classification", "provenance"}
        }
        for entry in selected_entries
    ]
    source_snapshot = verify_nitro_tee.exact_keys(
        plan["sourceSnapshot"],
        {
            "sourceClosureSha256",
            "sourceEvidence",
            "sourceEvidenceSha256",
            "sourceFileInventorySha256",
            "sourceGitInventoryPayloadSha256",
            "sourceManifest",
            "sourceManifestFileSha256",
            "sourceManifestPayloadSha256",
            "sourcePathListSha256",
            "sourceSelectionManifestFileSha256",
            "sourceSelectionManifestPayloadSha256",
            "sourceSelectionModel",
            "sourceUntrackedApprovalPayloadSha256",
        },
        "Candidate build-plan source snapshot",
    )
    require(
        source_snapshot == candidate["sourceSnapshot"]
        and continuity["sourceSnapshot"] == source_snapshot,
        "Candidate source snapshot differs between the plan, continuity, and top-level identity",
    )
    source_manifest = verify_nitro_tee.exact_keys(
        source_snapshot["sourceManifest"],
        {
            "aggregateBytes",
            "apiVersion",
            "closureSha256",
            "entries",
            "entryCount",
            "fileCount",
            "selection",
            "selectionManifestFileSha256",
            "selectionManifestPayloadSha256",
            "symlinkCount",
        },
        "Candidate embedded source manifest",
    )
    require(
        source_manifest["apiVersion"]
        == verify_nitro_tee.SOURCE_SNAPSHOT_VERSION,
        "Candidate embedded source manifest version mismatch",
    )
    expected_directories: set[str] = set()
    for entry in selected_entries:
        parts = PurePosixPath(entry["path"]).parts
        for end in range(1, len(parts)):
            expected_directories.add(
                PurePosixPath(*parts[:end]).as_posix()
            )
    expected_snapshot_entries = [
        {"mode": 0o500, "path": path, "type": "directory"}
        for path in expected_directories
    ] + frozen_entries
    expected_snapshot_entries.sort(
        key=lambda item: (
            len(PurePosixPath(item["path"]).parts),
            item["path"],
            item["type"],
        )
    )
    require(
        source_manifest["selection"] == source
        and source_manifest["entries"] == expected_snapshot_entries
        and source_manifest["selectionManifestPayloadSha256"]
        == source["payloadSha256"]
        and source_snapshot["sourceSelectionManifestPayloadSha256"]
        == source["payloadSha256"],
        "Candidate embedded source snapshot does not exactly equal the signed source selection and entries",
    )
    security_profiles = verify_nitro_tee.exact_keys(
        plan.get("securityProfiles"),
        {"apparmor", "seccomp"},
        "Manifest v6 security profiles",
    )
    for name, expected in (
        ("apparmor", expected_apparmor_sha256),
        ("seccomp", expected_seccomp_sha256),
    ):
        profile = verify_nitro_tee.exact_keys(
            security_profiles[name],
            {"path", "sha256", "size"},
            f"Manifest v6 {name} profile",
        )
        require(
            profile["sha256"] == expected
            and isinstance(profile["path"], str)
            and profile["path"]
            and type(profile["size"]) is int
            and profile["size"] > 0,
            f"Manifest v6 {name} profile differs from the independent pin",
        )

    def validate_semantic_contract(
        dependency: dict[str, Any],
        *,
        dependency_role: str,
    ) -> str | None:
        semantic = dependency.get("semanticContract")
        if dependency_role != "clean-room-runtime":
            require(
                semantic is None,
                f"{dependency_role} unexpectedly carries a semantic contract",
            )
            return None
        semantic = verify_nitro_tee.exact_keys(
            semantic,
            {
                "apiVersion",
                "contractSha256",
                "derivedEntries",
                "derivedInstallationSha256",
                "exerciseScenarios",
                "installContractSha256",
                "payloadClosureSha256",
                "requirementsResolution",
                "requirementsResolutionSha256",
                "wheelRecords",
                "wheelRecordsSha256",
                "wheelhouseManifestPayloadSha256",
            },
            "clean-room semantic contract",
        )
        payload = dict(semantic)
        supplied = payload.pop("contractSha256")
        require(
            semantic["apiVersion"]
            == "serverware.cleanRoomExpectedDerivation/v1"
            and supplied == verify_nitro_tee.sha256_json(payload)
            and isinstance(semantic["derivedEntries"], list)
            and bool(semantic["derivedEntries"])
            and semantic["derivedInstallationSha256"]
            == verify_nitro_tee.sha256_json(semantic["derivedEntries"])
            and isinstance(semantic["requirementsResolution"], list)
            and semantic["requirementsResolutionSha256"]
            == verify_nitro_tee.sha256_json(
                semantic["requirementsResolution"]
            ),
            "clean-room semantic contract digest or derived closure is invalid",
        )
        for field in (
            "derivedInstallationSha256",
            "installContractSha256",
            "payloadClosureSha256",
            "requirementsResolutionSha256",
            "wheelRecordsSha256",
            "wheelhouseManifestPayloadSha256",
        ):
            verify_nitro_tee.require_sha256(
                semantic[field],
                f"clean-room semantic contract {field}",
            )
        return supplied

    def validate_execution(
        execution: Any,
        *,
        name: str,
        npm_companion: bool,
    ) -> dict[str, Any]:
        required_fields = {
            "build",
            "imageRole",
            "installedSourceFiles",
            "isolation",
            "network",
            "process",
            "runtime",
            "sourceFiles",
            "sourceSet",
        }
        if not npm_companion:
            required_fields |= {"capabilityProbes", "name"}
        execution = verify_nitro_tee.exact_keys(
            execution,
            required_fields,
            f"{name} execution contract",
        )
        expected_role = (
            "npm-publish-companion"
            if npm_companion
            else f"lane-{name}"
        )
        require(
            execution["imageRole"] == expected_role
            and (npm_companion or execution["name"] == name),
            f"{name} execution identity mismatch",
        )
        expected_process = final_v6_process(name)
        expected_network = final_v6_network(name)
        expected_source_set = final_v6_source_set(name)
        require(
            execution["process"] == expected_process
            and execution["network"] == expected_network
            and execution["sourceSet"] == expected_source_set
            and (
                npm_companion
                or execution["capabilityProbes"]
                == final_v6_capability_probes(name)
            ),
            f"{name} process, argv, environment, network, source-set, or capability probes are not the fixed v6 contract",
        )
        expected_source_files = [
            entry
            for entry in frozen_entries
            if entry.get("type") == "file"
            and (
                entry.get("path") in expected_source_set["exact"]
                or any(
                    str(entry.get("path") or "").startswith(prefix)
                    for prefix in expected_source_set["prefixes"]
                )
            )
        ]
        selected_paths = {
            str(entry["path"]) for entry in expected_source_files
        }
        require(
            bool(expected_source_files)
            and all(
                path in selected_paths
                for path in expected_source_set["exact"]
            )
            and all(
                any(path.startswith(prefix) for path in selected_paths)
                for prefix in expected_source_set["prefixes"]
            )
            and execution["sourceFiles"] == expected_source_files,
            f"{name} sourceFiles are empty, incomplete, reordered, or differ from the fixed signed source selection",
        )
        expected_installed_sources = [
            {
                "imagePath": "/opt/serverware/src/" + entry["path"],
                "mode": 0o444,
                "source": entry,
            }
            for entry in expected_source_files
        ]
        require(
            bool(expected_installed_sources)
            and execution["installedSourceFiles"]
            == expected_installed_sources,
            f"{name} installedSourceFiles do not exactly install the fixed source closure",
        )
        dependency_role = final_v6_dependency_role(name)
        dependency = dependency_bundles[dependency_role]
        require(
            dependency.get("capabilities")
            == FINAL_V6_DEPENDENCY_CAPABILITIES[dependency_role],
            f"{name} dependency capabilities are not the fixed v6 set",
        )
        semantic_sha256 = validate_semantic_contract(
            dependency,
            dependency_role=dependency_role,
        )
        expected_runtime = {
            "dependencyCapabilityCatalogSha256": dependency[
                "capabilityCatalogSha256"
            ],
            "dependencyCapabilities": FINAL_V6_DEPENDENCY_CAPABILITIES[
                dependency_role
            ],
            "dependencyClosureSha256": dependency["closureSha256"],
            "dependencyFileManifestSha256": dependency[
                "fileManifestSha256"
            ],
            "dependencyRole": dependency_role,
            "semanticContractSha256": semantic_sha256,
        }
        require(
            execution["runtime"] == expected_runtime,
            f"{name} runtime or semanticContractSha256 was not independently rederived",
        )
        expected_isolation = final_v6_isolation(
            name,
            apparmor_sha256=expected_apparmor_sha256,
            seccomp_sha256=expected_seccomp_sha256,
        )
        require(
            execution["isolation"] == expected_isolation,
            f"{name} isolation is not the fixed independently pinned v6 contract",
        )
        dependency_paths = {
            item["path"]
            for item in dependency.get("files", [])
            if isinstance(item, dict) and isinstance(item.get("path"), str)
        }
        require(
            not any(
                installed["imagePath"] in dependency_paths
                for installed in expected_installed_sources
            ),
            f"{name} fixed source collides with its dependency closure",
        )
        installed_entrypoint = (
            {
                "imagePath": expected_process["entrypoint"][0],
                "origin": "rust-runtime-bundle",
            }
            if name == "rust-decision-gate-tests"
            else {
                "imagePath": (
                    FINAL_V6_NPM_ENTRYPOINT_IMAGE
                    if npm_companion
                    else FINAL_V6_PYTHON_ENTRYPOINT_IMAGE
                ),
                "mode": 0o444,
                "source": next(
                    item
                    for item in expected_source_files
                    if item["path"]
                    == (
                        FINAL_V6_NPM_ENTRYPOINT_SOURCE
                        if npm_companion
                        else FINAL_V6_PYTHON_ENTRYPOINT_SOURCE
                    )
                ),
            }
        )
        context_payload = {
            "dependencyBundle": {
                "capabilities": dependency["capabilities"],
                "closureSha256": dependency["closureSha256"],
                "fileManifestSha256": dependency["fileManifestSha256"],
                "role": dependency_role,
            },
            "installedEntrypoint": installed_entrypoint,
            "installedSourceFiles": expected_installed_sources,
            "sourceFiles": expected_source_files,
        }
        dockerfile = final_v6_dockerfile(
            expected_process,
            dependency["baseImageDigest"],
        )
        expected_build = {
            "baseImageDigest": dependency["baseImageDigest"],
            "contextManifestSha256": verify_nitro_tee.sha256_json(
                context_payload
            ),
            "dependencyRole": dependency_role,
            "dockerfile": dockerfile,
            "dockerfileSha256": verify_nitro_tee.sha256(
                dockerfile.encode("ascii")
            ),
            "network": "none",
            "platform": {"architecture": "amd64", "os": "linux"},
            "sourceDateEpoch": 0,
        }
        require(
            execution["build"] == expected_build,
            f"{name} Dockerfile, context, dependency, platform, or no-network build contract was not rederived",
        )
        return execution

    verified_lanes = {
        name: validate_execution(
            lanes[name],
            name=name,
            npm_companion=False,
        )
        for name in verify_nitro_tee.LANE_ORDER
    }
    npm_plan = validate_execution(
        plan.get("npmCompanion"),
        name="npm-publish-companion",
        npm_companion=True,
    )
    expected_companions = {
        "npmPublish": {
            "imageRole": "npm-publish-companion",
            "inputProtocol": (
                "one-canonical-json-frame-on-stdin-no-generic-command"
            ),
            "isolation": npm_plan["isolation"],
            "network": npm_plan["network"],
            "npmVersion": "11.8.0",
            "operation": "npm.publish.fixture",
            "operationCount": 2,
            "plan": npm_plan,
            "retryEquality": {
                "canonicalHttpRequestBytes": "identical",
                "operationInputBytes": "identical",
                "rawHttpRequestBytes": "different-only-by-npm-session",
                "requestBodyBytes": "identical",
            },
        }
    }
    require(
        candidate.get("companions") == expected_companions,
        "Candidate npm companion behavior differs from the fixed v6 protocol",
    )
    semantic_contract = {
        "apiVersion": "serverware.manifestV6SemanticExecutionContract/v1",
        "imageOrder": list(verify_nitro_tee.IMAGE_ORDER),
        "laneOrder": list(verify_nitro_tee.LANE_ORDER),
        "lanes": verified_lanes,
        "npmCompanion": npm_plan,
        "securityProfiles": {
            "apparmorSha256": expected_apparmor_sha256,
            "seccompSha256": expected_seccomp_sha256,
        },
    }
    semantic_contract_sha256 = verify_nitro_tee.sha256_json(
        semantic_contract
    )
    return {
        "commandContractSha256": semantic_contract_sha256,
        "semanticContractSha256": semantic_contract_sha256,
        "dependencyManifestFileSha256": verify_nitro_tee.sha256(
            verify_nitro_tee.canonical_json_bytes(dependencies) + b"\n"
        ),
        "dependencyManifestPayloadSha256": dependencies["manifestSha256"],
        "planSha256": plan["planSha256"],
        "sourceClosureSha256": plan["sourceSnapshot"][
            "sourceClosureSha256"
        ],
        "sourceFilesSha256": verify_nitro_tee.sha256_json(
            {
                **{
                    name: verified_lanes[name]["sourceFiles"]
                    for name in verify_nitro_tee.LANE_ORDER
                },
                "npm-publish-companion": npm_plan["sourceFiles"],
            }
        ),
        "installedSourceFilesSha256": verify_nitro_tee.sha256_json(
            {
                **{
                    name: verified_lanes[name]["installedSourceFiles"]
                    for name in verify_nitro_tee.LANE_ORDER
                },
                "npm-publish-companion": npm_plan[
                    "installedSourceFiles"
                ],
            }
        ),
    }


def verify_final_v6_watchdog_and_builder_grammar(
    *,
    candidate: dict[str, Any],
    watchdog: dict[str, Any],
    builders: Any,
    execution: dict[str, Any],
) -> dict[str, Any]:
    continuity = candidate["buildContinuity"]
    plan = continuity["buildPlan"]
    build_bundle = verify_nitro_tee.exact_keys(
        continuity["buildBundle"],
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
    require(
        build_bundle["apiVersion"] == "serverware.ociBuildBundle/v2"
        and build_bundle["planSha256"] == plan["planSha256"]
        and isinstance(build_bundle["images"], dict)
        and list(build_bundle["images"]) == list(verify_nitro_tee.IMAGE_ORDER),
        "Candidate OCI build bundle inventory or plan binding mismatch",
    )
    payload = verify_nitro_tee.exact_keys(
        watchdog.get("payload"),
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
    lease = verify_nitro_tee.exact_keys(
        payload["lease"],
        {"capabilitySha256", "challengeSha256", "id"},
        "build-watchdog lease",
    )
    require(
        lease["id"] == build_bundle["buildLeaseId"],
        "build-watchdog lease differs from the exact build bundle",
    )
    source_snapshot = plan["sourceSnapshot"]
    output_identities = verify_nitro_tee.candidate_image_identities(candidate)
    output_identities_sha256 = verify_nitro_tee.sha256_json(output_identities)
    candidate_request = {
        "dependencyBundleSha256": continuity["dependencyBundle"][
            "manifestSha256"
        ],
        "imageRoles": list(verify_nitro_tee.IMAGE_ORDER),
        "network": "none",
        "outputIdentitiesSha256": output_identities_sha256,
        "planSha256": plan["planSha256"],
        "platform": {"architecture": "amd64", "os": "linux"},
        "sourceClosureSha256": source_snapshot["sourceClosureSha256"],
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
    candidate_request_sha256 = verify_nitro_tee.sha256_json(candidate_request)
    require(
        payload["candidateRequest"] == candidate_request
        and payload["candidateRequestSha256"] == candidate_request_sha256
        and build_bundle["candidateRequestSha256"]
        == candidate_request_sha256
        and payload["planSha256"] == plan["planSha256"]
        and payload["buildBundleSha256"] == build_bundle["bundleSha256"],
        "build-watchdog did not rederive the exact source, dependency, plan, bundle, and output request",
    )
    watchdog_contract = plan["buildWatchdogContract"]
    request = {
        "buildBundleSha256": build_bundle["bundleSha256"],
        "candidateRequestSha256": candidate_request_sha256,
        "challengeSha256": lease["challengeSha256"],
        "contractSha256": watchdog_contract["contractSha256"],
        "leaseCapabilitySha256": lease["capabilitySha256"],
        "leaseId": lease["id"],
        "operation": "build-all-oci-v3",
    }
    request_sha256 = verify_nitro_tee.sha256_json(request)
    require(
        payload["request"] == request
        and payload["requestSha256"] == request_sha256,
        "build-watchdog request differs from the exact lease and contract request",
    )
    for identity_name, service_unit_field in (
        ("serviceIdentity", "serviceUnit"),
        ("daemonIdentity", "daemonServiceUnit"),
    ):
        identity = verify_nitro_tee.exact_keys(
            payload[identity_name],
            {
                "bootId",
                "cgroup",
                "exeSha256",
                "pid",
                "pidStartTime",
                "serviceUnit",
            },
            f"build-watchdog {identity_name}",
        )
        require(
            identity["bootId"] == payload["bootId"]
            and identity["serviceUnit"] == watchdog_contract[service_unit_field]
            and isinstance(identity["cgroup"], str)
            and identity["cgroup"].startswith("/")
            and type(identity["pid"]) is int
            and identity["pid"] > 0
            and isinstance(identity["pidStartTime"], str)
            and bool(identity["pidStartTime"])
            and payload[identity_name + "Sha256"]
            == verify_nitro_tee.sha256_json(identity),
            f"build-watchdog {identity_name} is not exactly rederived",
        )
        verify_nitro_tee.require_sha256(
            identity["exeSha256"],
            f"build-watchdog {identity_name} executable",
        )

    resources: dict[tuple[str, str], dict[str, Any]] = {}
    cleanup_log: list[dict[str, Any]] = []
    event_types: list[str] = []
    for record in payload["events"]:
        event = record["event"]
        event_type = event.get("type")
        require(
            isinstance(event_type, str),
            "build-watchdog event type is invalid",
        )
        event_types.append(event_type)
        if event_type == "resource-created":
            resource = event["resource"]
            key = (resource["kind"], resource["id"])
            require(
                key not in resources,
                "build-watchdog resource identity is duplicated",
            )
            resources[key] = resource
        elif event_type == "cleanup-action":
            cleanup_log.append(
                {
                    "action": event["action"],
                    "resource": event["resource"],
                    "result": event["result"],
                }
            )
    require(
        event_types[0] == "lease-begin"
        and event_types[-1] == "lease-finished"
        and event_types.count("lease-begin") == 1
        and event_types.count("cleanup-started") == 1
        and event_types.count("lease-finished") == 1,
        "build-watchdog lease phases are not exact",
    )
    cleanup_index = event_types.index("cleanup-started")
    absence_indices = [
        index
        for index, event_type in enumerate(event_types)
        if event_type == "daemon-inventory-absence"
    ]
    require(
        absence_indices
        == [
            len(event_types) - 4,
            len(event_types) - 3,
            len(event_types) - 2,
        ]
        and cleanup_index < absence_indices[0]
        and all(
            event_type == "resource-created"
            for event_type in event_types[1:cleanup_index]
        )
        and all(
            event_type == "cleanup-action"
            for event_type in event_types[
                cleanup_index + 1 : absence_indices[0]
            ]
        ),
        "build-watchdog cleanup must finish before exactly three terminal absence observations",
    )
    expected_cleanup: list[dict[str, Any]] = []
    for key in sorted(resources):
        resource = resources[key]
        reference = {"id": resource["id"], "kind": resource["kind"]}
        expected_cleanup.append(
            {
                "action": "inspect",
                "resource": reference,
                "result": "present-or-already-absent",
            }
        )
        if resource["kind"] in {"builder", "container", "task"}:
            expected_cleanup.append(
                {
                    "action": "kill",
                    "resource": reference,
                    "result": "killed-reaped-or-already-absent",
                }
            )
        expected_cleanup.append(
            {
                "action": "remove",
                "resource": reference,
                "result": "removed-or-already-absent",
            }
        )
    require(
        cleanup_log == expected_cleanup,
        "build-watchdog cleanup actions are not complete and exactly ordered",
    )

    require(
        isinstance(builders, list) and len(builders) == 2,
        "exactly two builder transcripts are required",
    )
    transcript_grammar_digests: list[str] = []
    for index, wrapper in enumerate(builders):
        role = ("builderA", "builderB")[index]
        wrapper = verify_nitro_tee.exact_keys(
            wrapper,
            {"statement", "transcript"},
            f"{role} raw builder evidence",
        )
        transcript = wrapper["transcript"]
        statement_payload = wrapper["statement"]["payload"]
        output_events = [
            {
                "ordinal": ordinal,
                "outputSha256": verify_nitro_tee.sha256_json(
                    transcript["imageOutputs"][image_role]
                ),
                "role": image_role,
                "type": "output-measured",
            }
            for ordinal, image_role in enumerate(
                verify_nitro_tee.IMAGE_ORDER,
                start=1,
            )
        ]
        expected_events = [
            {
                "builderId": transcript["builderId"],
                "candidateManifestFileSha256": statement_payload[
                    "candidateManifestFileSha256"
                ],
                "candidateManifestPayloadSha256": statement_payload[
                    "candidateManifestPayloadSha256"
                ],
                "candidateImagesSha256": statement_payload[
                    "imageOutputsSha256"
                ],
                "dependencyManifestFileSha256": execution[
                    "dependencyManifestFileSha256"
                ],
                "dependencyManifestPayloadSha256": execution[
                    "dependencyManifestPayloadSha256"
                ],
                "dependencyRoleClosuresSha256": transcript["dependencies"][
                    "roleClosuresSha256"
                ],
                "gitInventoryPayloadSha256": transcript["source"][
                    "gitInventoryPayloadSha256"
                ],
                "invocationId": transcript["invocationId"],
                "planSha256": execution["planSha256"],
                "sourceClosureSha256": execution["sourceClosureSha256"],
                "sourceInputManifestFileSha256": transcript["source"][
                    "sourceInputManifestFileSha256"
                ],
                "sourceInputManifestPayloadSha256": transcript["source"][
                    "sourceInputManifestPayloadSha256"
                ],
                "startedAtUnix": transcript["startedAtUnix"],
                "type": "build-started",
                "untrackedApprovalPayloadSha256": transcript["source"][
                    "untrackedApprovalPayloadSha256"
                ],
            },
            {
                "commandContractSha256": execution[
                    "commandContractSha256"
                ],
                "type": "command-measured",
            },
            {
                "environmentSha256": transcript["sandbox"][
                    "environmentSha256"
                ],
                "type": "environment-measured",
            },
            {
                "sandboxSha256": verify_nitro_tee.sha256_json(
                    transcript["sandbox"]
                ),
                "type": "sandbox-measured",
            },
            {
                "networkSha256": verify_nitro_tee.sha256_json(
                    {"mode": "none", "observedEndpoints": []}
                ),
                "type": "network-measured",
            },
            *output_events,
            {
                "exitCode": 0,
                "success": True,
                "type": "process-exited",
            },
            {
                "completedAtUnix": transcript["completedAtUnix"],
                "imageOutputsSha256": verify_nitro_tee.sha256_json(
                    transcript["imageOutputs"]
                ),
                "type": "build-completed",
            },
        ]
        actual_events = [record["event"] for record in transcript["events"]]
        require(
            actual_events == expected_events,
            f"{role} transcript does not use the exact measured start, command, environment, sandbox, no-network, outputs, success-exit, completion grammar",
        )
        require(
            statement_payload["environmentSha256"]
            == transcript["sandbox"]["environmentSha256"]
            and statement_payload["imageOutputsSha256"]
            == verify_nitro_tee.sha256_json(transcript["imageOutputs"])
            and statement_payload["completionIdentity"]
            == transcript["completionIdentity"]
            and statement_payload["completionIdentitySha256"]
            == transcript["completionIdentitySha256"]
            == verify_nitro_tee.sha256_json(
                statement_payload["completionIdentity"]
            ),
            f"{role} statement crossed transcript environment or output identities",
        )
        transcript_grammar_digests.append(
            verify_nitro_tee.sha256_json(actual_events)
        )
    return {
        "builderEventGrammarSha256": verify_nitro_tee.sha256_json(
            transcript_grammar_digests
        ),
        "candidateRequestSha256": candidate_request_sha256,
        "outputIdentitiesSha256": output_identities_sha256,
        "requestSha256": request_sha256,
        "watchdogEventOrderSha256": verify_nitro_tee.sha256_json(
            event_types
        ),
    }


def verify_final_v6_promotion_acceptance(
    *,
    candidate: dict[str, Any],
    promoted_manifest: dict[str, Any],
) -> dict[str, Any]:
    promotion = verify_nitro_tee.exact_keys(
        promoted_manifest["promotion"],
        {
            "acceptanceSha256",
            "apiVersion",
            "candidatePromotionContractSha256",
        },
        "promoted Manifest v6 acceptance",
    )
    canonical_payload = {
        "apiVersion": verify_nitro_tee.PROMOTION_ACCEPTANCE_VERSION,
        "candidatePromotionContractSha256": candidate[
            "promotionContract"
        ]["contractSha256"],
    }
    acceptance_sha256 = verify_nitro_tee.sha256_json(canonical_payload)
    require(
        promotion
        == {
            **canonical_payload,
            "acceptanceSha256": acceptance_sha256,
        },
        "promotion acceptance is not the single canonical payload used by the public verifier",
    )
    inspection_digests: dict[str, str] = {}
    for role in verify_nitro_tee.IMAGE_ORDER:
        imported = promoted_manifest["images"][role]
        inspection_digests[role] = verify_nitro_tee.require_sha256(
            imported["independentInspectionSha256"],
            f"{role} independent promotion inspection",
        )
    return {
        "acceptanceSha256": acceptance_sha256,
        "canonicalPayload": canonical_payload,
        "canonicalPayloadSha256": acceptance_sha256,
        "imageMappingsSha256": verify_nitro_tee.sha256_json(
            promoted_manifest["imageMappings"]
        ),
        "inspectionInventorySha256": verify_nitro_tee.sha256_json(
            inspection_digests
        ),
    }


def verify_final_v6_candidate_to_eif(
    document: dict[str, Any],
    raw: bytes,
    *,
    public_key: Ed25519PublicKey,
    public_key_id: str,
    public_key_file_sha256: str,
    candidate: dict[str, Any],
    candidate_raw: bytes,
    source: dict[str, Any],
    source_raw: bytes,
    watchdog: dict[str, Any],
    watchdog_raw: bytes,
    promotion_receipt: dict[str, Any],
    promotion_receipt_raw: bytes,
    promoted_manifest: dict[str, Any],
    builders: list[dict[str, Any]],
    expectations: dict[str, Any],
    trust_key_ids: dict[str, str],
) -> dict[str, Any]:
    payload, measured_file_sha256 = verify_nitro_tee.verify_existing_envelope(
        document,
        api_version=MANIFEST_V6_EIF_BUILD_API_VERSION,
        domain=MANIFEST_V6_EIF_BUILD_SIGNATURE_DOMAIN,
        key=public_key,
        key_id=public_key_id,
        key_file_sha256=public_key_file_sha256,
        raw_key_sha256=verify_nitro_tee.ed25519_raw_key_id(public_key),
        label="Manifest v6 candidate-to-EIF build statement",
    )
    require(
        measured_file_sha256 == verify_nitro_tee.sha256(raw),
        "candidate-to-EIF statement canonical file digest mismatch",
    )
    payload = verify_nitro_tee.exact_keys(
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
        payload["pipeline"] == MANIFEST_V6_PIPELINE
        and payload["legacyDockerNsmAccepted"] is False,
        "candidate-to-EIF statement selected or accepted a legacy pipeline",
    )
    verify_nitro_tee.require_uint(
        payload["releaseGeneration"],
        "candidate-to-EIF release generation",
    )
    verify_nitro_tee.require_uint(
        payload["rollbackEpoch"],
        "candidate-to-EIF rollback epoch",
    )
    dependency_bundles = candidate["buildContinuity"][
        "dependencyBundle"
    ]["bundles"]
    dependency_role_closures = {
        role: dependency_bundles[role]["closureSha256"]
        for role in sorted(dependency_bundles)
    }
    builder_summaries: dict[str, dict[str, Any]] = {}
    for side, trust_role, wrapper in zip(
        ("left", "right"),
        ("builderA", "builderB"),
        builders,
        strict=True,
    ):
        wrapper = verify_nitro_tee.exact_keys(
            wrapper,
            {"statement", "transcript"},
            f"{side} candidate-to-EIF builder evidence",
        )
        statement = wrapper["statement"]
        transcript = wrapper["transcript"]
        statement_payload = statement["payload"]
        builder_summaries[side] = {
            "file_sha256": verify_nitro_tee.sha256(
                verify_nitro_tee.canonical_json_bytes(statement) + b"\n"
            ),
            "payload_sha256": statement["payloadSha256"],
            "signing_key_id": trust_key_ids[trust_role],
            "builder_id": statement_payload["builderId"],
            "operator_id": statement_payload["operatorId"],
            "invocation_id": statement_payload["invocationId"],
            "transcript_file_sha256": verify_nitro_tee.sha256(
                verify_nitro_tee.canonical_json_bytes(transcript) + b"\n"
            ),
            "transcript_payload_sha256": transcript["transcriptSha256"],
            "completion_identity": statement_payload[
                "completionIdentity"
            ],
            "completion_identity_sha256": statement_payload[
                "completionIdentitySha256"
            ],
            "issued_at_unix": statement_payload["issuedAtUnix"],
            "expires_at_unix": statement_payload["expiresAtUnix"],
        }
    builders_sha256 = verify_nitro_tee.sha256_json(builder_summaries)
    expected_bindings = {
        "builderStatementsSha256": builders_sha256,
        "candidateManifestFileSha256": verify_nitro_tee.sha256(
            candidate_raw
        ),
        "candidateManifestPayloadSha256": candidate[
            "candidateManifestPayloadSha256"
        ],
        "completionIdentity": expectations["completionIdentity"],
        "completionIdentitySha256": expectations[
            "completionIdentitySha256"
        ],
        "dependencyClosureSha256": verify_nitro_tee.sha256_json(
            dependency_role_closures
        ),
        "eifFileSha384": expectations["eifSha384"],
        "importedImageMappingsSha256": verify_nitro_tee.sha256_json(
            promoted_manifest["imageMappings"]
        ),
        "pcrs": expectations["pcrs"],
        "promotionReceiptFileSha256": verify_nitro_tee.sha256(
            promotion_receipt_raw
        ),
        "promotionReceiptPayloadSha256": promotion_receipt[
            "payloadSha256"
        ],
        "releaseGeneration": expectations["releaseGeneration"],
        "rollbackEpoch": expectations["rollbackEpoch"],
        "sourceClosureSha256": candidate["sourceSnapshot"][
            "sourceClosureSha256"
        ],
        "sourceInputManifestFileSha256": verify_nitro_tee.sha256(
            source_raw
        ),
        "sourceInputManifestPayloadSha256": source["payloadSha256"],
        "watchdogReceiptFileSha256": verify_nitro_tee.sha256(
            watchdog_raw
        ),
        "watchdogReceiptPayloadSha256": watchdog["payloadSha256"],
    }
    for field, expected in expected_bindings.items():
        require(
            payload[field] == expected,
            f"candidate-to-EIF {field} crossed candidate, source, dependencies, promotion, imported images, or measured EIF state",
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
        "candidate-to-EIF statement differs from the independently pinned file or payload digest",
    )
    return {
        "fileSha256": measured_file_sha256,
        "payloadSha256": document["payloadSha256"],
        "signingKeyId": public_key_id,
        "signingKeyFileSha256": public_key_file_sha256,
        "builderStatementsSha256": builders_sha256,
        "completionIdentity": payload["completionIdentity"],
        "completionIdentitySha256": payload[
            "completionIdentitySha256"
        ],
        "dependencyClosureSha256": payload["dependencyClosureSha256"],
        "importedImageMappingsSha256": payload[
            "importedImageMappingsSha256"
        ],
        "eifSha384": payload["eifFileSha384"],
        "pcrs": payload["pcrs"],
        "releaseGeneration": payload["releaseGeneration"],
        "rollbackEpoch": payload["rollbackEpoch"],
    }


def verify_final_v6_public_handoff(
    *,
    bundle: dict[str, Any],
    protected_state: dict[str, Any],
    protected_checkpoint: dict[str, Any],
    trust_bundle_sha256: str,
    trust_root_pin_id: str,
    candidate_to_eif_document: dict[str, Any],
    candidate_to_eif_raw: bytes,
) -> dict[str, Any]:
    embedded_eif_document, embedded_eif_raw = (
        verify_nitro_tee.decode_canonical_json_file_b64(
            bundle.get("candidateToEifBuildStatementFileB64"),
            "public candidate-to-EIF build statement",
        )
    )
    require(
        embedded_eif_document == candidate_to_eif_document
        and embedded_eif_raw == candidate_to_eif_raw,
        "public bundle candidate-to-EIF artifact differs from the independently pinned final input",
    )
    runtime_custody, _ = verify_nitro_tee.decode_canonical_json_file_b64(
        bundle["runtimeKeyCustodyFileB64"],
        "public runtime key-custody file",
    )
    require(
        runtime_custody.get("apiVersion")
        == FINAL_V6_RUNTIME_CUSTODY_API_VERSION,
        "public bundle uses legacy runtime custody rather than custody v3",
    )
    tls_evidence = bundle["tlsEvidence"]
    trusted_scope = tls_evidence.get("trustedScope")
    require(
        tls_evidence.get("apiVersion")
        == "serverware.liveEnclaveTlsEvidence/v2"
        and isinstance(trusted_scope, dict)
        and trusted_scope.get("apiVersion")
        == FINAL_V6_TLS_SCOPE_API_VERSION,
        "public bundle does not carry TLS evidence v2 and TLS scope v2",
    )
    response_proof = bundle["responseProof"]
    response_bytes = verify_nitro_tee.b64url_decode(
        response_proof.get("responseBodyB64"),
        "exact HTTP response body",
        max_bytes=verify_nitro_tee.MAX_RESPONSE_BYTES,
    )
    statement = verify_nitro_tee.exact_keys(
        response_proof.get("statement"),
        {
            "apiVersion",
            "bodySha256",
            "challengeId",
            "challengeSha256",
            "httpResponse",
            "issuedAtUnix",
            "keyGenerations",
            "policy",
            "quoteSha256",
            "release",
            "requestSha256",
            "responseSigningKeyId",
            "tlsBindingSha256",
        },
        "attestation response statement v2",
    )
    require(
        statement["apiVersion"]
        == FINAL_V6_RESPONSE_STATEMENT_API_VERSION,
        "public bundle does not carry response statement v2",
    )
    http_response = verify_nitro_tee.exact_keys(
        statement.get("httpResponse"),
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
        "exact attestation HTTP response envelope",
    )
    expected_header_names = [
        "cache-control",
        "pragma",
        "content-type",
        "content-length",
        "x-serverware-attestation-body-sha256",
        "x-serverware-attestation-key-id",
        "x-serverware-attestation-request-sha256",
        "x-serverware-attestation-tls-binding-sha256",
        "x-serverware-attestation-quote-sha256",
    ]
    headers = http_response["coreHeaders"]
    expected_headers = [
        {"name": "cache-control", "value": "no-store"},
        {"name": "pragma", "value": "no-cache"},
        {"name": "content-type", "value": "application/json"},
        {"name": "content-length", "value": str(len(response_bytes))},
        {
            "name": "x-serverware-attestation-body-sha256",
            "value": verify_nitro_tee.sha256(response_bytes),
        },
        {
            "name": "x-serverware-attestation-key-id",
            "value": statement["responseSigningKeyId"],
        },
        {
            "name": "x-serverware-attestation-request-sha256",
            "value": statement["requestSha256"],
        },
        {
            "name": "x-serverware-attestation-tls-binding-sha256",
            "value": statement["tlsBindingSha256"],
        },
        {
            "name": "x-serverware-attestation-quote-sha256",
            "value": statement["quoteSha256"],
        },
    ]
    expected_detached_headers = {
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
    require(
        http_response["apiVersion"] == FINAL_V6_HTTP_RESPONSE_API_VERSION
        and http_response["status"] == 200
        and http_response["ordinaryHostTlsAccepted"] is False
        and http_response["transport"]
        == "enclave-owned-tls-stack-with-authenticated-asgi-extension"
        and http_response["bodyLength"] == len(response_bytes)
        and http_response["bodySha256"]
        == verify_nitro_tee.sha256(response_bytes)
        and statement["bodySha256"] == http_response["bodySha256"]
        and headers == expected_headers
        and [item["name"] for item in headers] == expected_header_names
        and http_response["detachedProofHeaders"]
        == expected_detached_headers,
        "response statement does not bind the exact status, ordered headers, and body bytes returned by the enclave TLS stack",
    )
    return {
        "httpResponseEnvelopeSha256": verify_nitro_tee.sha256_json(
            {
                "bodySha256": verify_nitro_tee.sha256(response_bytes),
                "httpResponse": http_response,
                "statementSha256": verify_nitro_tee.sha256_json(statement),
            }
        ),
        "runtimeCustodyApiVersion": FINAL_V6_RUNTIME_CUSTODY_API_VERSION,
        "tlsScopeApiVersion": FINAL_V6_TLS_SCOPE_API_VERSION,
        "responseStatementApiVersion": (
            FINAL_V6_RESPONSE_STATEMENT_API_VERSION
        ),
        "protectedPriorClientStateEnvelopeSha256": (
            verify_nitro_tee.sha256(
                verify_nitro_tee.canonical_json_bytes(protected_state)
                + b"\n"
            )
        ),
        "protectedPriorClientStateCheckpointSha256": (
            verify_nitro_tee.sha256(
                verify_nitro_tee.canonical_json_bytes(
                    protected_checkpoint
                )
                + b"\n"
            )
        ),
        "trustRootBundleSha256": trust_bundle_sha256,
        "trustRootPinId": trust_root_pin_id,
        "candidateToEifBuildStatementFileSha256": (
            verify_nitro_tee.sha256(candidate_to_eif_raw)
        ),
    }


def verify_final_v6_state_commit(
    *,
    commit_receipt: dict[str, Any],
    commit_receipt_raw: bytes,
    current_head_authorization: dict[str, Any],
    current_head_authorization_raw: bytes,
    current_head_verifier_nonce: bytes,
    current_head_redemption_receipt: dict[str, Any],
    current_head_redemption_receipt_raw: bytes,
    current_head_redemption_verifier_nonce: bytes,
    pending_result: dict[str, Any],
    prior_state: dict[str, Any],
    trust: dict[str, Any],
    challenge_consumption_sha256: str,
    now: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    next_state = verify_nitro_tee.load_client_state(
        pending_result.get("nextClientState")
    )
    transition = pending_result.get("stateTransition")
    expected_transition = {
        "oldStateSha256": prior_state["stateSha256"],
        "newStateSha256": next_state["stateSha256"],
    }
    expected_transition["transitionSha256"] = (
        verify_nitro_tee.sha256_json(expected_transition)
    )
    require(
        "ok" not in pending_result
        and pending_result.get("okForAction") is False
        and pending_result.get("status") == "pending-state-commit"
        and pending_result.get("stateCommitRequired")
        == (
            "persist nextClientState with durable compare-and-swap before "
            "accepting or acting on the response"
        )
        and transition == expected_transition
        and next_state["challengeConsumptionSha256"]
        == challenge_consumption_sha256,
        "public verifier did not return the exact non-actionable pending-state-commit transition",
    )
    witness = pending_result.get("witness")
    require(
        isinstance(witness, dict)
        and next_state["checkpointSha256"] == witness["checkpointSha256"]
        and next_state["releaseGeneration"]
        == witness["releaseGeneration"]
        and next_state["rollbackEpoch"] == witness["rollbackEpoch"]
        and next_state["rootHash"] == witness["rootHash"]
        and next_state["sequence"] == witness["sequence"]
        and next_state["treeSize"] == witness["treeSize"],
        "pending next state does not exactly equal the verified current witness high-water",
    )
    require(
        next_state["sequence"] > prior_state["sequence"]
        and next_state["treeSize"] > prior_state["treeSize"]
        and next_state["releaseGeneration"]
        >= prior_state["releaseGeneration"]
        and next_state["rollbackEpoch"] >= prior_state["rollbackEpoch"],
        "pending state transition does not monotonically advance the rollback-resistant high-water",
    )
    post_cas_result = verify_nitro_tee.finalize_state_commit(
        pending_result,
        commit_receipt,
        trust=trust,
        now=now,
    )
    require(
        "ok" not in post_cas_result
        and post_cas_result.get("okForAction") is False
        and post_cas_result.get("status")
        == "pending-current-head-authorization"
        and "stateCommitRequired" not in post_cas_result
        and post_cas_result.get("stateCommitPhase")
        == "committed-awaiting-current-head-authorization"
        and post_cas_result.get("currentHeadAuthorizationRequired")
        and post_cas_result.get("nextClientState") == next_state
        and post_cas_result.get("stateTransition") == expected_transition
        and post_cas_result.get("stateCommitReceiptSha256")
        == verify_nitro_tee.sha256(commit_receipt_raw),
        "public verifier treated the CAS receipt as current-head authority",
    )
    authorized_result = verify_nitro_tee.authorize_current_head(
        post_cas_result,
        current_head_authorization,
        verifier_nonce=current_head_verifier_nonce,
        trust=trust,
        now=now,
    )
    require(
        "ok" not in authorized_result
        and authorized_result.get("okForAction") is False
        and authorized_result.get("status")
        == "pending-current-head-redemption"
        and authorized_result.get("currentHeadAuthorizationRequired")
        is False
        and authorized_result.get("currentHeadRedemptionRequired")
        and authorized_result.get("currentHeadAuthorizationFileSha256")
        == verify_nitro_tee.sha256(current_head_authorization_raw)
        and authorized_result.get("currentHeadVerifierNonceSha256")
        == verify_nitro_tee.sha256(current_head_verifier_nonce),
        "public verifier treated reservation as redemption or crossed the fresh authorization",
    )
    verified_redemption_result = (
        verify_nitro_tee.finalize_current_head_redemption(
            authorized_result,
            current_head_redemption_receipt,
            verifier_nonce=current_head_redemption_verifier_nonce,
            trust=trust,
            now=now,
        )
    )
    require(
        verified_redemption_result.get("verificationOk") is True
        and verified_redemption_result.get("finalCompletionVerified")
        is True
        and verified_redemption_result.get("actionAuthorization") is None
        and verified_redemption_result.get("okForAction") is False
        and "ok" not in verified_redemption_result
        and "finalCompletion" not in verified_redemption_result
        and "stateCommitRequired" not in verified_redemption_result
        and verified_redemption_result.get("status")
        == "redemption-verified-non-actionable"
        and verified_redemption_result.get(
            "currentHeadRedemptionVerified"
        )
        is True
        and verified_redemption_result.get(
            "currentHeadRedemptionRequired"
        )
        is False
        and verified_redemption_result.get(
            "currentHeadRedemptionReceiptFileSha256"
        )
        == verify_nitro_tee.sha256(
            current_head_redemption_receipt_raw
        )
        and verified_redemption_result.get(
            "currentHeadRedemptionVerifierNonceSha256"
        )
        == verify_nitro_tee.sha256(
            current_head_redemption_verifier_nonce
        ),
        "public verifier did not verify the exact atomic current-head redemption as non-actionable evidence",
    )
    summary = {
        "apiVersion": FINAL_V6_STATE_COMMIT_API_VERSION,
        "status": "redemption-verified-non-actionable",
        "actionable": False,
        "redemptionVerified": True,
        "commitId": verified_redemption_result["stateCommitId"],
        "storeId": verified_redemption_result["stateStoreId"],
        "signingKeyId": trust["keyIds"]["stateCommit"],
        "receiptFileSha256": verified_redemption_result[
            "stateCommitReceiptSha256"
        ],
        "receiptPayloadSha256": commit_receipt["payloadSha256"],
        "priorStateSha256": prior_state["stateSha256"],
        "currentStateSha256": next_state["stateSha256"],
        "transitionSha256": expected_transition["transitionSha256"],
        "challengeConsumptionSha256": challenge_consumption_sha256,
        "currentHeadAuthorizationId": verified_redemption_result[
            "currentHeadAuthorizationId"
        ],
        "currentHeadAuthorizationFileSha256": verified_redemption_result[
            "currentHeadAuthorizationFileSha256"
        ],
        "currentHeadSha256": verified_redemption_result[
            "currentHeadSha256"
        ],
        "currentHeadVerifierNonceSha256": verified_redemption_result[
            "currentHeadVerifierNonceSha256"
        ],
        "currentHeadReservationId": verified_redemption_result[
            "currentHeadReservationId"
        ],
        "currentHeadRedemptionId": verified_redemption_result[
            "currentHeadRedemptionId"
        ],
        "currentHeadRedemptionReceiptFileSha256": verified_redemption_result[
            "currentHeadRedemptionReceiptFileSha256"
        ],
        "currentHeadRedemptionReceiptIdentitySha256": (
            verified_redemption_result[
                "currentHeadRedemptionReceiptIdentitySha256"
            ]
        ),
        "currentHeadRedemptionVerifierNonceSha256": verified_redemption_result[
            "currentHeadRedemptionVerifierNonceSha256"
        ],
        "currentFinalHeadSha256": verified_redemption_result[
            "currentFinalHeadSha256"
        ],
        "currentHeadOneUseSequence": verified_redemption_result[
            "currentHeadOneUseSequence"
        ],
        "rollbackResistanceBoundary": verified_redemption_result[
            "rollbackResistanceBoundary"
        ],
    }
    return verified_redemption_result, summary


def _removed_final_shaped_v6_compatibility_path(
    bundle_document: dict[str, Any],
) -> None:
    raise ValueError(
        "final-shaped completionProof/v6 and public_verifier_bridge are obsolete and rejected"
    )
    for field, label in (
        ("sourceInputManifestFileB64", "source-input manifest file"),
        ("candidateManifestFileB64", "Candidate Manifest v6 file"),
        ("buildWatchdogReceiptFileB64", "build-watchdog receipt file"),
        ("promotionReceiptFileB64", "promotion receipt file"),
        ("promotedManifestFileB64", "promoted Manifest v6 file"),
        ("productionIdentityFileB64", "production attestation identity file"),
        ("runtimeStateFileB64", "production runtime state file"),
        ("runtimeKeyCustodyFileB64", "runtime key-custody file"),
    ):
        embedded_document, _ = (
            verify_nitro_tee.decode_canonical_json_file_b64(
                bundle_document.get(field),
                label,
            )
        )
        validate_canonical_json_profile(embedded_document, label=label)
    completion_proof, _ = verify_nitro_tee.decode_canonical_json_file_b64(
        bundle_document.get("completionProofFileB64"),
        "completionProof/v6 file",
    )
    validate_canonical_json_profile(
        completion_proof,
        label="completionProof/v6",
    )
    require(
        "proof_path" not in completion_proof
        and "integrity_metadata" not in completion_proof,
        "Manifest v6 final proof must not bind local proof paths or legacy detached-file state",
    )
    require(
        completion_proof.get("readiness_ok") is False
        and completion_proof.get("readiness_only") is False
        and completion_proof.get("verification_mode") == "final"
        and completion_proof.get("result_scope") == "final-completion",
        "Manifest v6 final proof crossed readiness semantics",
    )
    verify_nitro_tee.validate_non_actionable_final_result(
        completion_proof,
        label="Manifest v6 completion proof",
    )
    legacy_slots = (
        "artifacts",
        "authentication_artifacts",
        "benchmark",
        "bootstrap_launcher",
        "current_completion_host",
        "final_challenge_consumption",
        "hardware_assurance_evidence",
        "image_signatures",
        "nitro_evidence_binding",
        "nitro_kms_evidence",
        "production_env_binding",
        "production_host_preflight",
        "production_images_build",
        "production_images_published",
        "production_proxy_response_proof",
        "production_readiness",
        "production_readiness_config",
        "release_provenance",
        "release_security_evidence",
        "running_production_containers",
    )
    for field in legacy_slots:
        expected = {
            "apiVersion": "serverware.manifestV6LegacyCompatibilitySlot/v1",
            "consumed": False,
            "field": field,
            "pipeline": MANIFEST_V6_PIPELINE,
        }
        require(
            completion_proof.get(field) == expected,
            f"Manifest v6 final proof {field} must be an exact inert compatibility slot",
        )


def verify_final_v6_witness_handoff(
    *,
    pending_public_result: dict[str, Any],
    witness_payload: dict[str, Any],
) -> dict[str, Any]:
    inclusion = verify_nitro_tee.exact_keys(
        witness_payload["inclusion"],
        {
            "leafIndex",
            "leafSha256",
            "proof",
            "rootHash",
            "treeSize",
        },
        "indexed witness inclusion",
    )
    leaf_index = verify_nitro_tee.require_uint(
        inclusion["leafIndex"],
        "witness inclusion leaf index",
    )
    verified_leaf_index = verify_nitro_tee.require_uint(
        pending_public_result["witness"]["leafIndex"],
        "verified witness leaf index",
    )
    tree_size = verify_nitro_tee.require_uint(
        inclusion["treeSize"],
        "witness inclusion tree size",
    )
    proof = inclusion["proof"]
    require(
        leaf_index < tree_size
        and verified_leaf_index == leaf_index
        and isinstance(proof, list)
        and len(proof) <= 256
        and all(
            isinstance(step, str)
            and SHA256_RE.fullmatch(step) is not None
            for step in proof
        ),
        "witness inclusion handoff is not exact, indexed, and bounded",
    )
    release_leaf = {
        "releaseGeneration": witness_payload["releaseGeneration"],
        "releaseCoreSha256": witness_payload["releaseCoreSha256"],
        "rollbackEpoch": witness_payload["rollbackEpoch"],
    }
    expected_leaf_sha256 = verify_nitro_tee.sha256(
        b"\x00" + verify_nitro_tee.canonical_json_bytes(release_leaf)
    )
    require(
        inclusion["leafSha256"] == expected_leaf_sha256
        and inclusion["rootHash"] == witness_payload["rootHash"]
        and tree_size == witness_payload["treeSize"],
        "indexed witness inclusion crossed the exact release leaf or checkpoint",
    )
    verify_nitro_tee.verify_indexed_merkle_inclusion(
        leaf_sha256=expected_leaf_sha256,
        leaf_index=leaf_index,
        tree_size=tree_size,
        proof=proof,
        root_sha256=inclusion["rootHash"],
        label="final completion witness",
    )
    return {
        "leafIndex": leaf_index,
        "leafSha256": expected_leaf_sha256,
        "rootHash": inclusion["rootHash"],
        "treeSize": tree_size,
    }


def _removed_verify_manifest_v6_final_bridge_path(
    args: argparse.Namespace,
) -> None:
    raise ValueError(
        "final-shaped completionProof/v6 and public_verifier_bridge are obsolete and rejected"
    )
    required_inputs = {
        "--public-nitro-evidence-bundle": args.public_nitro_evidence_bundle,
        "--public-nitro-expectations": args.public_nitro_expectations,
        "--public-nitro-trust-roots": args.public_nitro_trust_roots,
        "--expected-public-nitro-trust-roots-sha256": (
            args.expected_public_nitro_trust_roots_sha256
        ),
        "--public-nitro-trust-root-pin-id": (
            args.public_nitro_trust_root_pin_id
        ),
        "--public-nitro-state-commit-receipt": (
            args.public_nitro_state_commit_receipt
        ),
        "--public-nitro-current-head-authorization": (
            args.public_nitro_current_head_authorization
        ),
        "--public-nitro-current-head-verifier-nonce": (
            args.public_nitro_current_head_verifier_nonce
        ),
        "--public-nitro-current-head-redemption-receipt": (
            args.public_nitro_current_head_redemption_receipt
        ),
        "--public-nitro-current-head-redemption-verifier-nonce": (
            args.public_nitro_current_head_redemption_verifier_nonce
        ),
        "--manifest-v6-eif-build": args.manifest_v6_eif_build,
        "--manifest-v6-eif-builder-public-key": (
            args.manifest_v6_eif_builder_public_key
        ),
        "--expected-final-v6-apparmor-profile-sha256": (
            args.expected_final_v6_apparmor_profile_sha256
        ),
        "--expected-final-v6-seccomp-profile-sha256": (
            args.expected_final_v6_seccomp_profile_sha256
        ),
        "--protected-client-state": args.protected_client_state,
        "--protected-client-state-public-key": (
            args.protected_client_state_public_key
        ),
        "--expected-protected-client-state-public-key-id": (
            args.expected_protected_client_state_public_key_id
        ),
        "--protected-client-state-checkpoint": (
            args.protected_client_state_checkpoint
        ),
        "--protected-client-state-checkpoint-public-key": (
            args.protected_client_state_checkpoint_public_key
        ),
        "--expected-protected-client-state-checkpoint-public-key-id": (
            args.expected_protected_client_state_checkpoint_public_key_id
        ),
        "--public-nitro-challenge": args.public_nitro_challenge,
    }
    missing = [option for option, value in required_inputs.items() if not value]
    require(
        not missing,
        "final Manifest v6 verification requires: " + ", ".join(missing),
    )
    forbidden_legacy_inputs = {
        "--docker-executable": args.docker_executable,
        "--docker-compose-plugin-executable": (
            args.docker_compose_plugin_executable
        ),
        "--docker-unix-socket": args.docker_unix_socket,
        "--docker-daemon-id": args.docker_daemon_id,
        "--production-host-preflight-signing-public-key": (
            args.production_host_preflight_signing_public_key
        ),
        "--production-host-preflight-signing-key-id": (
            args.production_host_preflight_signing_key_id
        ),
        "--production-host-preflight-max-age-seconds": (
            args.production_host_preflight_max_age_seconds
        ),
        "--hardware-assurance": args.hardware_assurance,
        "--hardware-assurance-trusted-public-key": (
            args.hardware_assurance_trusted_public_key
        ),
        "--hardware-assurance-trusted-public-key-id": (
            args.hardware_assurance_trusted_public_key_id
        ),
        "--hardware-assurance-expected-challenge-nonce": (
            args.hardware_assurance_expected_challenge_nonce
        ),
        "--hardware-assurance-expected-challenge-nonce-sha256": (
            args.hardware_assurance_expected_challenge_nonce_sha256
        ),
        "--final-challenge-receipt": args.final_challenge_receipt,
        "--final-challenge-authority-public-key": (
            args.final_challenge_authority_public_key
        ),
        "--final-challenge-authority-public-key-id": (
            args.final_challenge_authority_public_key_id
        ),
        "--final-challenge-authority-provider": (
            args.final_challenge_authority_provider
        ),
        "--candidate-manifest-v6": args.candidate_manifest_v6,
        "--source-input-manifest": args.source_input_manifest,
        "--source-git-inventory-public-key": (
            args.source_git_inventory_public_key
        ),
        "--source-untracked-approval-public-key": (
            args.source_untracked_approval_public_key
        ),
        "--dependency-closure": args.dependency_closure,
        "--build-watchdog-receipt": args.build_watchdog_receipt,
        "--build-watchdog-public-key": args.build_watchdog_public_key,
        "--promotion-receipt": args.promotion_receipt,
        "--promotion-public-key": args.promotion_public_key,
        "--builder-left-statement": args.builder_left_statement,
        "--builder-left-transcript": args.builder_left_transcript,
        "--builder-left-public-key": args.builder_left_public_key,
        "--builder-right-statement": args.builder_right_statement,
        "--builder-right-transcript": args.builder_right_transcript,
        "--builder-right-public-key": args.builder_right_public_key,
        "--promotion-acceptance-evidence": (
            args.promotion_acceptance_evidence
        ),
        "--key-custody-evidence": args.key_custody_evidence,
        "--key-custody-public-key": args.key_custody_public_key,
        "--monotonic-witness": args.monotonic_witness,
        "--monotonic-witness-public-key": (
            args.monotonic_witness_public_key
        ),
        "--prior-witness-state": args.prior_witness_state,
        "--completion-proof-authentication": (
            args.completion_proof_authentication
        ),
        "--completion-authentication-public-key": (
            args.completion_authentication_public_key
        ),
        "--completion-proof-checkpoint": args.completion_proof_checkpoint,
        "--completion-checkpoint-public-key": (
            args.completion_checkpoint_public_key
        ),
        "--control-plane-response-signing-public-key": (
            args.control_plane_response_signing_public_key
        ),
        "--control-plane-response-signing-public-key-id": (
            args.control_plane_response_signing_public_key_id
        ),
        "--proxy-response-proof": args.proxy_response_proof,
        "--proxy-proof-contract": args.proxy_proof_contract,
        "--proxy-stream-body": args.proxy_stream_body,
        "--proxy-observation-body": args.proxy_observation_body,
        "--proxy-proof-verifier-public-key": (
            args.proxy_proof_verifier_public_key
        ),
        "--proxy-collector-public-key": args.proxy_collector_public_key,
        "--proxy-server-instance-id": args.proxy_server_instance_id,
        "--proxy-client-nonce": args.proxy_client_nonce,
        "--proxy-client-request-digest": args.proxy_client_request_digest,
        "--proxy-request-digest": args.proxy_request_digest,
        "--proxy-operation-digest": args.proxy_operation_digest,
        "--proxy-operation-context-digest": (
            args.proxy_operation_context_digest
        ),
        "--proxy-tls-channel-binding": args.proxy_tls_channel_binding,
        "--proxy-proof-max-age-seconds": args.proxy_proof_max_age_seconds,
        "--p99-limit-ms": args.p99_limit_ms,
        "--policy-bundle": args.policy_bundle,
        "--policy-trusted-public-key": args.policy_trusted_public_key,
        "--policy-identity-verification": args.policy_identity_verification,
        "--policy-activation-verification": (
            args.policy_activation_verification
        ),
        "--policy-activation-signature": args.policy_activation_signature,
        "--policy-activation-trusted-public-key": (
            args.policy_activation_trusted_public_key
        ),
        "--reproducible-build-verification": (
            args.reproducible_build_verification
        ),
        "--reproducible-build-signature": args.reproducible_build_signature,
        "--reproducible-build-trusted-public-key": (
            args.reproducible_build_trusted_public_key
        ),
        "--release-provenance-trusted-public-key": (
            args.release_provenance_trusted_public_key
        ),
        "--sigstore-trusted-public-key": args.sigstore_trusted_public_key,
        "--rekor-trusted-public-key": args.rekor_trusted_public_key,
        "--external-checkpoint-provider": args.external_checkpoint_provider,
        "--external-checkpoint-trusted-public-key": (
            args.external_checkpoint_trusted_public_key
        ),
    }
    supplied_legacy_inputs = [
        option
        for option, value in forbidden_legacy_inputs.items()
        if value is not None
    ]
    require(
        not supplied_legacy_inputs,
        "Manifest v6 final mode rejects legacy readiness inputs: "
        + ", ".join(supplied_legacy_inputs),
    )
    require(
        not args.skip_current_host_check,
        "final Manifest v6 verification forbids --skip-current-host-check",
    )
    expected_trust_bundle_sha256 = require_sha256(
        args.expected_public_nitro_trust_roots_sha256,
        "expected public Nitro trust-root bundle",
    )
    trust_root_pin_id = verify_nitro_tee.require_identifier(
        args.public_nitro_trust_root_pin_id,
        "public Nitro trust-root pin ID",
    )
    bundle_document, bundle_raw = load_final_v6_canonical_json(
        args.public_nitro_evidence_bundle,
        "public Nitro evidence bundle",
    )
    expectations_document, expectations_raw = load_final_v6_canonical_json(
        args.public_nitro_expectations,
        "independent production expectations",
    )
    trust_document, trust_raw = load_final_v6_canonical_json(
        args.public_nitro_trust_roots,
        "closed public Nitro trust-root bundle",
    )
    state_commit_receipt_document, state_commit_receipt_raw = (
        load_final_v6_canonical_json(
            args.public_nitro_state_commit_receipt,
            "rollback-resistant public Nitro state CAS receipt",
        )
    )
    (
        current_head_authorization_document,
        current_head_authorization_raw,
    ) = load_final_v6_canonical_json(
        args.public_nitro_current_head_authorization,
        "fresh one-use current-head authorization",
    )
    current_head_verifier_nonce = verify_nitro_tee.b64url_decode(
        args.public_nitro_current_head_verifier_nonce,
        "fresh current-head verifier nonce",
        max_bytes=32,
    )
    require(
        len(current_head_verifier_nonce) == 32,
        "current-head verifier nonce must contain exactly 32 bytes",
    )
    (
        current_head_redemption_receipt_document,
        current_head_redemption_receipt_raw,
    ) = load_final_v6_canonical_json(
        args.public_nitro_current_head_redemption_receipt,
        "atomic current-head redemption receipt",
    )
    current_head_redemption_verifier_nonce = (
        verify_nitro_tee.b64url_decode(
            args.public_nitro_current_head_redemption_verifier_nonce,
            "fresh current-head redemption verifier nonce",
            max_bytes=32,
        )
    )
    require(
        len(current_head_redemption_verifier_nonce) == 32,
        "current-head redemption verifier nonce must contain exactly 32 bytes",
    )
    trust_bundle_sha256 = verify_nitro_tee.sha256(trust_raw)
    require(
        hmac.compare_digest(
            trust_bundle_sha256,
            expected_trust_bundle_sha256,
        ),
        "public Nitro trust-root bundle differs from the external expected digest",
    )
    expectations = verify_nitro_tee.load_expectations(
        expectations_document
    )
    completion_identity, completion_identity_sha256 = (
        reconstruct_final_v6_completion_identity(expectations)
    )
    trust = verify_nitro_tee.load_trust_roots(
        trust_document,
        trust_raw,
        independently_expected_sha256=expected_trust_bundle_sha256,
    )
    require(
        trust["trustRootBundleSha256"] == trust_bundle_sha256,
        "shared public verifier loaded a different trust-root bundle",
    )
    _removed_final_shaped_v6_compatibility_path(bundle_document)
    source_document, source_raw = verify_nitro_tee.decode_canonical_json_file_b64(
        bundle_document["sourceInputManifestFileB64"],
        "source-input manifest file",
    )
    candidate_document, candidate_raw = (
        verify_nitro_tee.decode_canonical_json_file_b64(
            bundle_document["candidateManifestFileB64"],
            "Candidate Manifest v6 file",
        )
    )
    watchdog_document, watchdog_raw = (
        verify_nitro_tee.decode_canonical_json_file_b64(
            bundle_document["buildWatchdogReceiptFileB64"],
            "build-watchdog receipt file",
        )
    )
    promotion_receipt_document, promotion_receipt_raw = (
        verify_nitro_tee.decode_canonical_json_file_b64(
            bundle_document["promotionReceiptFileB64"],
            "promotion receipt file",
        )
    )
    promoted_manifest_document, promoted_manifest_raw = (
        verify_nitro_tee.decode_canonical_json_file_b64(
            bundle_document["promotedManifestFileB64"],
            "promoted Manifest v6 file",
        )
    )
    promotion_acceptance = verify_final_v6_promotion_acceptance(
        candidate=candidate_document,
        promoted_manifest=promoted_manifest_document,
    )
    production_identity_document, production_identity_raw = (
        verify_nitro_tee.decode_canonical_json_file_b64(
            bundle_document["productionIdentityFileB64"],
            "production attestation identity file",
        )
    )
    runtime_state_document, runtime_state_raw = (
        verify_nitro_tee.decode_canonical_json_file_b64(
            bundle_document["runtimeStateFileB64"],
            "production runtime state file",
        )
    )
    runtime_custody_document, runtime_custody_raw = (
        verify_nitro_tee.decode_canonical_json_file_b64(
            bundle_document["runtimeKeyCustodyFileB64"],
            "runtime key-custody file",
        )
    )
    completion_proof_document, completion_proof_raw = (
        verify_nitro_tee.decode_canonical_json_file_b64(
            bundle_document["completionProofFileB64"],
            "completionProof/v6 file",
        )
    )
    completion_authentication_payload = verify_nitro_tee.exact_keys(
        bundle_document["completionProofAuthentication"]["payload"],
        {
            "completionIdentity",
            "completionIdentitySha256",
            "expiresAtUnix",
            "issuedAtUnix",
            "keyCustodyEvidenceSha256",
            "productionReleaseIdentitySha256",
            "proofApiVersion",
            "proofCoreSha256",
            "witnessEvidenceSha256",
        },
        "completion proof authentication payload",
    )
    completion_bridge = verify_nitro_tee.exact_keys(
        completion_proof_document["public_verifier_bridge"],
        {
            "apiVersion",
            "candidateManifestFileSha256",
            "candidateManifestPayloadSha256",
            "completionIdentity",
            "completionIdentitySha256",
            "eifFileSha384",
            "keyCustodyEvidenceSha256",
            "monotonicWitnessSha256",
            "pcrs",
            "pipeline",
            "productionContinuitySha256",
            "productionReleaseIdentitySha256",
            "promotionReceiptSha256",
            "releaseGeneration",
            "rollbackEpoch",
            "sourceClosureSha256",
        },
        "completion proof public-verifier bridge",
    )
    completion_claim = verify_nitro_tee.exact_keys(
        bundle_document["claims"]["completion"],
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
    completion_identity_occurrences = [
        production_identity_document["completionIdentity"],
        runtime_state_document["completionIdentity"],
        runtime_custody_document["completionIdentity"],
        completion_authentication_payload["completionIdentity"],
        completion_bridge["completionIdentity"],
        completion_claim["completionIdentity"],
        *[
            wrapper["statement"]["payload"]["completionIdentity"]
            for wrapper in bundle_document["builders"]
        ],
        *[
            wrapper["transcript"]["completionIdentity"]
            for wrapper in bundle_document["builders"]
        ],
    ]
    completion_digest_occurrences = [
        production_identity_document["completionIdentitySha256"],
        runtime_state_document["completionIdentitySha256"],
        runtime_custody_document["completionIdentitySha256"],
        completion_authentication_payload["completionIdentitySha256"],
        completion_bridge["completionIdentitySha256"],
        completion_claim["completionIdentitySha256"],
        *[
            wrapper["statement"]["payload"]["completionIdentitySha256"]
            for wrapper in bundle_document["builders"]
        ],
        *[
            wrapper["transcript"]["completionIdentitySha256"]
            for wrapper in bundle_document["builders"]
        ],
    ]
    require(
        completion_identity_occurrences
        and all(
            value == completion_identity
            for value in completion_identity_occurrences
        )
        and completion_digest_occurrences
        and all(
            hmac.compare_digest(value, completion_identity_sha256)
            for value in completion_digest_occurrences
        ),
        "production identity, runtime, custody, Nitro claim, builders, and completion proof do not share the exact closed completionIdentity object and canonical digest",
    )
    execution_contract = verify_final_v6_candidate_execution_contract(
        candidate_document,
        source_document,
        expected_apparmor_sha256=require_sha256(
            args.expected_final_v6_apparmor_profile_sha256,
            "independently expected Manifest v6 AppArmor profile",
        ),
        expected_seccomp_sha256=require_sha256(
            args.expected_final_v6_seccomp_profile_sha256,
            "independently expected Manifest v6 seccomp profile",
        ),
    )
    build_grammar = verify_final_v6_watchdog_and_builder_grammar(
        candidate=candidate_document,
        watchdog=watchdog_document,
        builders=bundle_document["builders"],
        execution=execution_contract,
    )
    protected_state_document, protected_state_raw = (
        load_final_v6_canonical_json(
            args.protected_client_state,
            "protected prior client state",
        )
    )
    protected_checkpoint_document, protected_checkpoint_raw = (
        load_final_v6_canonical_json(
            args.protected_client_state_checkpoint,
            "protected client-state checkpoint",
        )
    )
    candidate_to_eif_document, candidate_to_eif_raw = (
        load_final_v6_canonical_json(
            args.manifest_v6_eif_build,
            "Manifest v6 candidate-to-EIF build statement",
        )
    )
    candidate_to_eif_key, candidate_to_eif_key_id, candidate_to_eif_key_file_sha256 = (
        load_final_v6_pinned_ed25519_key(
            args.manifest_v6_eif_builder_public_key,
            expected_key_id=trust["keyIds"]["manifestV6EifBuilder"],
            label="Manifest v6 candidate-to-EIF builder trust root",
        )
    )
    candidate_to_eif_key_raw = verify_nitro_tee.read_regular(
        Path(args.manifest_v6_eif_builder_public_key),
        label="Manifest v6 candidate-to-EIF builder trust root",
        max_bytes=8192,
    )
    try:
        candidate_to_eif_key_pem = candidate_to_eif_key_raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "Manifest v6 candidate-to-EIF builder trust root must be ASCII PEM"
        ) from exc
    require(
        trust_document["keys"]["manifestV6EifBuilder"]
        == candidate_to_eif_key_pem,
        "candidate-to-EIF builder key differs from the externally pinned public trust bundle",
    )
    state_key, state_key_id, state_key_file_sha256 = (
        load_final_v6_pinned_ed25519_key(
            args.protected_client_state_public_key,
            expected_key_id=(
                args.expected_protected_client_state_public_key_id
            ),
            label="protected client-state signing trust root",
        )
    )
    checkpoint_key, checkpoint_key_id, checkpoint_key_file_sha256 = (
        load_final_v6_pinned_ed25519_key(
            args.protected_client_state_checkpoint_public_key,
            expected_key_id=(
                args.expected_protected_client_state_checkpoint_public_key_id
            ),
            label="protected client-state checkpoint trust root",
        )
    )
    require(
        state_key_id == trust["keyIds"]["clientState"]
        and checkpoint_key_id == trust["keyIds"]["clientStateCheckpoint"],
        "protected state keys differ from the externally pinned public verifier roles",
    )
    now = int(time.time())
    prior_state, protected_state_identity = (
        verify_protected_final_v6_client_state(
            state_document=protected_state_document,
            state_raw=protected_state_raw,
            checkpoint_document=protected_checkpoint_document,
            checkpoint_raw=protected_checkpoint_raw,
            state_key=state_key,
            state_key_id=state_key_id,
            state_key_file_sha256=state_key_file_sha256,
            checkpoint_key=checkpoint_key,
            checkpoint_key_id=checkpoint_key_id,
            checkpoint_key_file_sha256=checkpoint_key_file_sha256,
            trust_root_bundle_sha256=trust_bundle_sha256,
            trust_root_pin_id=trust_root_pin_id,
            trust_key_ids=trust["keyIds"],
            now=now,
        )
    )
    public_handoff = verify_final_v6_public_handoff(
        bundle=bundle_document,
        protected_state=protected_state_document,
        protected_checkpoint=protected_checkpoint_document,
        trust_bundle_sha256=trust_bundle_sha256,
        trust_root_pin_id=trust_root_pin_id,
        candidate_to_eif_document=candidate_to_eif_document,
        candidate_to_eif_raw=candidate_to_eif_raw,
    )
    candidate_to_eif = verify_final_v6_candidate_to_eif(
        candidate_to_eif_document,
        candidate_to_eif_raw,
        public_key=candidate_to_eif_key,
        public_key_id=candidate_to_eif_key_id,
        public_key_file_sha256=candidate_to_eif_key_file_sha256,
        candidate=candidate_document,
        candidate_raw=candidate_raw,
        source=source_document,
        source_raw=source_raw,
        watchdog=watchdog_document,
        watchdog_raw=watchdog_raw,
        promotion_receipt=promotion_receipt_document,
        promotion_receipt_raw=promotion_receipt_raw,
        promoted_manifest=promoted_manifest_document,
        builders=bundle_document["builders"],
        expectations=expectations,
        trust_key_ids=trust["keyIds"],
    )
    require(
        candidate_to_eif["completionIdentity"] == completion_identity
        and candidate_to_eif["completionIdentitySha256"]
        == completion_identity_sha256,
        "candidate-to-EIF mapping crossed the exact closed completion identity",
    )
    challenge = verify_nitro_tee.b64url_decode(
        args.public_nitro_challenge,
        "independently generated public Nitro challenge",
        max_bytes=32,
    )
    require(
        len(challenge) == 32,
        "public Nitro challenge must contain exactly 32 bytes",
    )
    pending_public_result = verify_nitro_tee.verify_bundle(
        bundle_document,
        expectations=expectations,
        trust=trust,
        prior_state=prior_state,
        challenge=challenge,
        now=now,
    )
    require(
        "ok" not in pending_public_result
        and pending_public_result.get("okForAction") is False
        and pending_public_result.get("status")
        == "pending-state-commit"
        and pending_public_result.get("apiVersion")
        == verify_nitro_tee.RESULT_VERSION
        and pending_public_result.get("pipeline")
        == MANIFEST_V6_PIPELINE,
        "raw public Nitro verifier did not establish a non-actionable Manifest v6 pending-state-commit result",
    )
    require(
        pending_public_result.get(
            "candidateToEifBuildStatementFileSha256"
        )
        == candidate_to_eif["fileSha256"]
        and pending_public_result.get("completionIdentity")
        == completion_identity
        and pending_public_result.get("completionIdentitySha256")
        == completion_identity_sha256,
        "public verifier did not authenticate the exact candidate-to-EIF statement and closed completion identity",
    )
    reconstructed_completion_identity = (
        verify_nitro_tee.reconstruct_completion_identity(
            core_digests=pending_public_result["completionCoreDigests"],
            challenge_nonce_sha256=verify_nitro_tee.sha256(challenge),
            release_generation=completion_identity["releaseGeneration"],
            rollback_epoch=completion_identity["rollbackEpoch"],
        )
    )
    reconstructed_completion_identity_sha256 = (
        verify_nitro_tee.sha256_json(reconstructed_completion_identity)
    )
    require(
        reconstructed_completion_identity == completion_identity
        and hmac.compare_digest(
            reconstructed_completion_identity_sha256,
            completion_identity_sha256,
        )
        and pending_public_result["completionIdentity"]
        == reconstructed_completion_identity
        and pending_public_result["completionIdentitySha256"]
        == reconstructed_completion_identity_sha256,
        "release completion did not reconstruct every authenticated core before constructing completionIdentity",
    )
    completion_identity = reconstructed_completion_identity
    completion_identity_sha256 = reconstructed_completion_identity_sha256
    completion_key_id = trust["keyIds"]["completion"]
    completion_checkpoint_key_id = trust["keyIds"]["completionCheckpoint"]
    require(
        completion_key_id != completion_checkpoint_key_id,
        "aggregate completion signature and checkpoint keys are not independent",
    )
    witness_payload = bundle_document["witness"]["payload"]
    witness_handoff = verify_final_v6_witness_handoff(
        pending_public_result=pending_public_result,
        witness_payload=witness_payload,
    )
    challenge_consumption_sha256 = verify_nitro_tee.sha256_json(
        witness_payload["challengeConsumption"]
    )
    witness_result = pending_public_result["witness"]
    require(
        witness_result["challengeConsumptionSha256"]
        == challenge_consumption_sha256
        and witness_result["leafIndex"] == witness_handoff["leafIndex"]
        and witness_result["sequence"] > prior_state["sequence"]
        and witness_result["treeSize"] > prior_state["treeSize"]
        and witness_result["releaseGeneration"]
        >= prior_state["releaseGeneration"]
        and witness_result["rollbackEpoch"] >= prior_state["rollbackEpoch"],
        "witness did not advance sequence/tree/challenge or attempted a generation/epoch rollback",
    )
    require(
        pending_public_result["nextClientState"][
            "challengeConsumptionSha256"
        ]
        == challenge_consumption_sha256,
        "public verifier next state omitted or crossed challengeConsumptionSha256",
    )
    public_result, state_commit = verify_final_v6_state_commit(
        commit_receipt=state_commit_receipt_document,
        commit_receipt_raw=state_commit_receipt_raw,
        current_head_authorization=current_head_authorization_document,
        current_head_authorization_raw=current_head_authorization_raw,
        current_head_verifier_nonce=current_head_verifier_nonce,
        current_head_redemption_receipt=(
            current_head_redemption_receipt_document
        ),
        current_head_redemption_receipt_raw=(
            current_head_redemption_receipt_raw
        ),
        current_head_redemption_verifier_nonce=(
            current_head_redemption_verifier_nonce
        ),
        pending_result=pending_public_result,
        prior_state=prior_state,
        trust=trust,
        challenge_consumption_sha256=challenge_consumption_sha256,
        now=now,
    )
    builder_artifact_bindings: dict[str, dict[str, Any]] = {}
    for side, wrapper in zip(
        ("left", "right"),
        bundle_document["builders"],
        strict=True,
    ):
        statement = wrapper["statement"]
        transcript = wrapper["transcript"]
        builder_artifact_bindings[side] = (
            final_v6_completion_bound_artifact(
                {
                    "statementFileSha256": verify_nitro_tee.sha256(
                        verify_nitro_tee.canonical_json_bytes(statement)
                        + b"\n"
                    ),
                    "statementPayloadSha256": statement["payloadSha256"],
                    "transcriptFileSha256": verify_nitro_tee.sha256(
                        verify_nitro_tee.canonical_json_bytes(transcript)
                        + b"\n"
                    ),
                    "transcriptPayloadSha256": transcript[
                        "transcriptSha256"
                    ],
                },
                completion_identity=completion_identity,
                completion_identity_sha256=completion_identity_sha256,
                label=f"{side}-raw-builder-statement-and-transcript",
            )
        )
    artifact_bindings_payload = {
        "apiVersion": FINAL_V6_ARTIFACT_BINDINGS_API_VERSION,
        "builders": builder_artifact_bindings,
        "candidateManifestAndSource": final_v6_completion_bound_artifact(
            {
                "candidateManifestFileSha256": verify_nitro_tee.sha256(
                    candidate_raw
                ),
                "candidateManifestPayloadSha256": candidate_document[
                    "candidateManifestPayloadSha256"
                ],
                "sourceClosureSha256": expectations[
                    "sourceClosureSha256"
                ],
                "sourceInputManifestFileSha256": verify_nitro_tee.sha256(
                    source_raw
                ),
                "sourceInputManifestPayloadSha256": source_document[
                    "payloadSha256"
                ],
                "watchdogReceiptFileSha256": verify_nitro_tee.sha256(
                    watchdog_raw
                ),
                "watchdogReceiptPayloadSha256": watchdog_document[
                    "payloadSha256"
                ],
            },
            completion_identity=completion_identity,
            completion_identity_sha256=completion_identity_sha256,
            label="candidate-manifest-source-and-watchdog",
        ),
        "completionIdentity": completion_identity,
        "completionIdentitySha256": completion_identity_sha256,
        "completionProof": final_v6_completion_bound_artifact(
            {
                "authenticationPayloadSha256": bundle_document[
                    "completionProofAuthentication"
                ]["payloadSha256"],
                "fileSha256": verify_nitro_tee.sha256(
                    completion_proof_raw
                ),
                "proofCoreSha256": completion_proof_document[
                    "proof_core_sha256"
                ],
                "publicVerifierBridgeSha256": verify_nitro_tee.sha256_json(
                    completion_bridge
                ),
            },
            completion_identity=completion_identity,
            completion_identity_sha256=completion_identity_sha256,
            label="completion-proof-v6",
        ),
        "eifMapping": final_v6_completion_bound_artifact(
            {
                "candidateToEifBuildStatementFileSha256": candidate_to_eif[
                    "fileSha256"
                ],
                "candidateToEifBuildStatementPayloadSha256": (
                    candidate_to_eif["payloadSha256"]
                ),
                "candidateToEifBuilderKeyId": candidate_to_eif[
                    "signingKeyId"
                ],
                "eifSha384": candidate_to_eif["eifSha384"],
                "pcrs": candidate_to_eif["pcrs"],
            },
            completion_identity=completion_identity,
            completion_identity_sha256=completion_identity_sha256,
            label="candidate-promotion-to-eif-mapping",
        ),
        "productionIdentity": final_v6_completion_bound_artifact(
            {
                "productionIdentityFileSha256": verify_nitro_tee.sha256(
                    production_identity_raw
                ),
                "productionReleaseIdentitySha256": (
                    production_identity_document[
                        "productionReleaseIdentitySha256"
                    ]
                ),
                "runtimeCustodyFileSha256": verify_nitro_tee.sha256(
                    runtime_custody_raw
                ),
                "runtimeStateFileSha256": verify_nitro_tee.sha256(
                    runtime_state_raw
                ),
            },
            completion_identity=completion_identity,
            completion_identity_sha256=completion_identity_sha256,
            label="production-identity-runtime-and-custody",
        ),
        "promotion": final_v6_completion_bound_artifact(
            {
                "importedImageMappingsSha256": promotion_acceptance[
                    "imageMappingsSha256"
                ],
                "promotedManifestFileSha256": verify_nitro_tee.sha256(
                    promoted_manifest_raw
                ),
                "promotedManifestPayloadSha256": promoted_manifest_document[
                    "manifestSha256"
                ],
                "promotionAcceptanceSha256": promotion_acceptance[
                    "acceptanceSha256"
                ],
                "promotionReceiptFileSha256": verify_nitro_tee.sha256(
                    promotion_receipt_raw
                ),
                "promotionReceiptPayloadSha256": (
                    promotion_receipt_document["payloadSha256"]
                ),
            },
            completion_identity=completion_identity,
            completion_identity_sha256=completion_identity_sha256,
            label="promotion-receipt-and-imported-image-mappings",
        ),
    }
    release_artifact_bindings = {
        **artifact_bindings_payload,
        "artifactBindingsSha256": verify_nitro_tee.sha256_json(
            artifact_bindings_payload
        ),
    }
    public_result_sha256 = verify_nitro_tee.sha256_json(public_result)
    host_bootstrap_boundary_payload = {
        "apiVersion": FINAL_V6_HOST_BOOTSTRAP_BOUNDARY_API_VERSION,
        "launchManifestApiVersion": "serverware.productionReadinessLaunch/v3",
        "launchAuthorizationRequestApiVersion": (
            "serverware.launchAuthorizationRequest/v2"
        ),
        "launchAuthorizationApiVersion": "serverware.launchAuthorization/v2",
        "bootstrapReceiptApiVersion": "serverware.bootstrapReceipt/v3",
        "nonceRollbackAssuranceBindingApiVersion": (
            "serverware.productionNonceRollbackAssuranceBinding/v1"
        ),
        "authorizationScope": "trusted-host-readiness",
        "freshnessAuthority": "trusted-host-wall-clock",
        "evidenceProvidedToFinalVerifier": False,
        "authoritativeForFinalCompletion": False,
        "requiredForFinalCompletion": False,
        "relationship": "non-authoritative-readiness-context-only",
        "finalAuthority": (
            "independent-manifest-v6-public-nitro-verifier-and-protected-state"
        ),
        "completionIdentitySha256": completion_identity_sha256,
        "bindingMechanism": (
            "verifier-validated-canonical-binding-to-authenticated-completion-identity"
        ),
    }
    host_bootstrap_boundary = {
        **host_bootstrap_boundary_payload,
        "boundarySha256": verify_nitro_tee.sha256_json(
            host_bootstrap_boundary_payload
        ),
    }
    production_identity = {
        "apiVersion": FINAL_V6_IDENTITY_API_VERSION,
        "canonicalProfile": CANONICAL_JSON_PROFILE,
        "pipeline": MANIFEST_V6_PIPELINE,
        "legacyDockerNsmAccepted": False,
        "completionIdentity": completion_identity,
        "completionIdentitySha256": completion_identity_sha256,
        "releaseArtifactBindings": release_artifact_bindings,
        "publicNitroEvidenceBundleFileSha256": verify_nitro_tee.sha256(
            bundle_raw
        ),
        "publicNitroExpectationsFileSha256": verify_nitro_tee.sha256(
            expectations_raw
        ),
        "publicVerifierResultSha256": public_result_sha256,
        "productionIdentitySha256": public_result[
            "productionIdentitySha256"
        ],
        "candidateManifestFileSha256": public_result[
            "candidateManifestFileSha256"
        ],
        "candidateManifestPayloadSha256": expectations[
            "candidateManifestPayloadSha256"
        ],
        "sourceInputManifestFileSha256": expectations[
            "sourceInputManifestFileSha256"
        ],
        "sourceClosureSha256": public_result["sourceClosureSha256"],
        "buildWatchdogReceiptFileSha256": public_result[
            "buildWatchdogReceiptFileSha256"
        ],
        "promotionReceiptFileSha256": public_result[
            "promotionReceiptFileSha256"
        ],
        "promotedManifestFileSha256": expectations[
            "promotedManifestFileSha256"
        ],
        "promotedManifestPayloadSha256": promoted_manifest_document[
            "manifestSha256"
        ],
        "promotedManifestMeasuredFileSha256": verify_nitro_tee.sha256(
            promoted_manifest_raw
        ),
        "candidateToEif": candidate_to_eif,
        "runtimeStateFileSha256": expectations["runtimeStateFileSha256"],
        "runtimeKeyCustodyFileSha256": public_result[
            "runtimeKeyCustodyFileSha256"
        ],
        "enclaveInstanceId": runtime_state_document["enclaveInstanceId"],
        "enclaveBootId": runtime_state_document["enclaveBootId"],
        "runtimeKeyGenerations": runtime_state_document["keyGenerations"],
        "releaseGeneration": expectations["releaseGeneration"],
        "rollbackEpoch": expectations["rollbackEpoch"],
        "policyHash": expectations["policyHash"],
        "policySequence": expectations["policySequence"],
        "caSpkiSha256": expectations["caSpkiSha256"],
        "eifSha384": public_result["eifSha384"],
        "pcrs": public_result["pcrs"],
        "rawNitroAttestationDocumentSha256": public_result[
            "nitroAttestationDocumentSha256"
        ],
        "tlsExporterSha256": public_result["tlsExporterSha256"],
        "tlsSpkiSha256": public_result["tlsSpkiSha256"],
        "tlsPeerSpkiSha256": expectations["liveTlsPeerSpkiSha256"],
        "tlsStackMeasurementSha256": expectations[
            "tlsStackMeasurementSha256"
        ],
        "attestationRequestSha256": expectations[
            "attestationRequestSha256"
        ],
        "requestSha256": public_result["requestSha256"],
        "responseBytesSha256": public_result["responseBytesSha256"],
        "releaseKeyCustodyEvidenceSha256": public_result[
            "runtimeKeyCustodyFileSha256"
        ],
        "kmsAuditProofSha256s": public_result[
            "kmsAuditProofSha256s"
        ],
        "completionProofFileSha256": public_result[
            "completionProofFileSha256"
        ],
        "completionAuthenticationKeyId": completion_key_id,
        "completionCheckpointKeyId": completion_checkpoint_key_id,
        "hostBootstrapBoundarySha256": host_bootstrap_boundary[
            "boundarySha256"
        ],
        "witnessCheckpointSha256": public_result["witness"][
            "checkpointSha256"
        ],
        "witnessChallengeConsumptionSha256": public_result["witness"][
            "challengeConsumptionSha256"
        ],
        "witnessLeafIndex": public_result["witness"]["leafIndex"],
        "challengeSha256": verify_nitro_tee.sha256(challenge),
        "candidateExecutionContract": execution_contract,
        "watchdogAndBuilderGrammar": build_grammar,
        "promotionAcceptance": promotion_acceptance,
        "publicHandoff": public_handoff,
        "protectedPriorClientState": protected_state_identity,
        "stateCommit": state_commit,
        "trustRootPin": {
            "bundleFileSha256": trust_bundle_sha256,
            "expectedBundleFileSha256": expected_trust_bundle_sha256,
            "pinId": trust_root_pin_id,
            "keyIds": {
                role: trust["keyIds"][role]
                for role in sorted(trust["keyIds"])
            },
            "provenanceBoundary": (
                "Only a client or out-of-band comparison of the expected "
                "bundle digest and key IDs establishes provenance; these "
                "on-host CLI paths are transport only."
            ),
        },
    }
    production_identity["identitySha256"] = verify_nitro_tee.sha256_json(
        production_identity
    )
    final_result = {
        "apiVersion": FINAL_V6_RESULT_API_VERSION,
        "verificationOk": True,
        "finalCompletionVerified": True,
        "actionAuthorization": None,
        "okForAction": False,
        "verificationMode": "final",
        "redemptionVerified": True,
        "readinessOnly": False,
        "independentlyAuthenticated": True,
        "pipeline": MANIFEST_V6_PIPELINE,
        "canonicalProfile": CANONICAL_JSON_PROFILE,
        "verifiedAtUnix": now,
        "productionReleaseIdentity": production_identity,
        "publicVerifierResult": public_result,
        "aggregateAuthentication": {
            "independentlyAuthenticated": True,
            "completionIdentity": completion_identity,
            "completionIdentitySha256": completion_identity_sha256,
            "completionProofFileSha256": public_result[
                "completionProofFileSha256"
            ],
            "completionAuthenticationKeyId": completion_key_id,
            "completionCheckpointKeyId": completion_checkpoint_key_id,
            "hostBootstrapBoundarySha256": host_bootstrap_boundary[
                "boundarySha256"
            ],
            "keysAreDistinct": True,
        },
        "completionIdentity": completion_identity,
        "completionIdentitySha256": completion_identity_sha256,
        "releaseArtifactBindings": release_artifact_bindings,
        "nextClientState": public_result["nextClientState"],
        "stateCommit": state_commit,
        "hostBootstrapBoundary": host_bootstrap_boundary,
        "externalPinProvenanceBoundary": (
            FINAL_V6_EXTERNAL_PIN_PROVENANCE_BOUNDARY
        ),
        "externalProvisioningBoundary": (
            FINAL_V6_EXTERNAL_PROVISIONING_BOUNDARY
        ),
    }
    verify_nitro_tee.validate_non_actionable_final_result(
        final_result,
        label="final Manifest v6 verification result",
    )
    final_result["resultSha256"] = verify_nitro_tee.sha256_json(final_result)
    raise ValueError(
        "obsolete final-shaped completionProof/v6 bridge cannot emit final v1"
    )
    if args.out:
        output_digest = write_final_v6_result(Path(args.out), final_result)
        require(
            output_digest
            == verify_nitro_tee.sha256(
                verify_nitro_tee.canonical_json_bytes(final_result) + b"\n"
            ),
            "final verification result output digest mismatch",
        )
    sys.stdout.buffer.write(
        verify_nitro_tee.canonical_json_bytes(final_result) + b"\n"
    )


def _reject_obsolete_final_v6_injection(
    value: Any,
    *,
    path: str = "$",
) -> None:
    if isinstance(value, dict):
        forbidden = {
            "completionProofFileB64",
            "completionProofAuthentication",
            "completionProofCheckpoint",
            "public_verifier_bridge",
        }.intersection(value)
        require(
            not forbidden,
            "public Nitro final input contains obsolete final-shaped v6 "
            f"bridge injection at {path}: {', '.join(sorted(forbidden))}",
        )
        for key, child in value.items():
            _reject_obsolete_final_v6_injection(
                child,
                path=f"{path}.{key}",
            )
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_obsolete_final_v6_injection(
                child,
                path=f"{path}[{index}]",
            )


def _load_pinned_ed25519_pem(
    raw_path: str,
    *,
    expected_key_id: str,
    expected_spki_sha256: str,
    label: str,
) -> tuple[str, str]:
    raw = verify_nitro_tee.read_regular(
        Path(raw_path),
        label=label,
        max_bytes=8192,
    )
    try:
        pem = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} must be ASCII PEM") from exc
    calculated_key_id = release_public_key_id(pem)
    require(
        calculated_key_id
        == require_sha256(expected_key_id, f"{label} expected key ID")
        == require_sha256(
            expected_spki_sha256,
            f"{label} expected SPKI digest",
        ),
        f"{label} does not match caller-pinned key and SPKI identities",
    )
    key = serialization.load_pem_public_key(pem.encode("ascii"))
    require(isinstance(key, Ed25519PublicKey), f"{label} is not Ed25519")
    return pem, calculated_key_id


def _load_host_readiness_context(
    raw_path: str | None,
) -> dict[str, Any]:
    if raw_path is None:
        return {
            "apiVersion": HOST_READINESS_CONTEXT_API_VERSION,
            "provided": False,
            "completionProofApiVersion": None,
            "completionProofFileSha256": None,
            "completionProofCoreSha256": None,
            "generatedAtUnix": None,
            "launchAuthorityKeyId": None,
            "authoritativeForFinalCompletion": False,
        }
    proof, raw = load_final_v6_canonical_json(
        raw_path,
        "optional trusted-host readiness completionProof/v6",
    )
    validate_host_readiness_completion_proof_v6(proof)
    bootstrap = proof["bootstrap_launcher"]
    launch_authority_key_id: str | None = None
    if isinstance(bootstrap, dict) and bootstrap.get("sealed") is True:
        launch_authority_key_id = require_sha256(
            bootstrap.get("launchAuthorityKeyId"),
            "host readiness launch authority",
        )
    return {
        "apiVersion": HOST_READINESS_CONTEXT_API_VERSION,
        "provided": True,
        "completionProofApiVersion": COMPLETION_PROOF_API_VERSION,
        "completionProofFileSha256": verify_nitro_tee.sha256(raw),
        "completionProofCoreSha256": proof["proof_core_sha256"],
        "generatedAtUnix": proof["generated_at_unix"],
        "launchAuthorityKeyId": launch_authority_key_id,
        "authoritativeForFinalCompletion": False,
    }


def build_release_completion_verification_v1_core(
    *,
    public_envelope: dict[str, Any],
    public_envelope_file_sha256: str,
    public_result: dict[str, Any],
    evidence_bundle_file_sha256: str,
    expectations_file_sha256: str,
    trust_root_bundle_file_sha256: str,
    completion_identity: dict[str, Any],
    completion_identity_sha256: str,
    host_context: dict[str, Any],
    host_boundary: dict[str, Any],
    global_role_registry: dict[str, Any],
    result_signer_key_id: str,
) -> dict[str, Any]:
    return {
        "apiVersion": FINAL_V6_RESULT_API_VERSION,
        "verificationOk": True,
        "finalCompletionVerified": True,
        "actionAuthorization": None,
        "okForAction": False,
        "verificationMode": "final",
        "redemptionVerified": True,
        "readinessOnly": False,
        "independentlyAuthenticated": True,
        "pipeline": MANIFEST_V6_PIPELINE,
        "canonicalProfile": CANONICAL_JSON_PROFILE,
        "verifiedAtUnix": public_result["verifiedAtUnix"],
        "publicNitroVerification": {
            "envelope": public_envelope,
            "envelopeFileSha256": public_envelope_file_sha256,
            "resultSha256": public_envelope["resultSha256"],
            "evidenceBundleFileSha256": evidence_bundle_file_sha256,
            "expectationsFileSha256": expectations_file_sha256,
            "trustRootBundleFileSha256": trust_root_bundle_file_sha256,
        },
        "aggregateAuthentication": {
            "independentlyAuthenticated": True,
            "publicNitroResultEnvelopeSha256": (
                public_envelope_file_sha256
            ),
            "publicNitroResultSha256": public_envelope["resultSha256"],
            "completionIdentitySha256": completion_identity_sha256,
            "stateTransitionSha256": public_result["stateTransition"][
                "transitionSha256"
            ],
            "stateCommitReceiptSha256": public_result["stateCommit"][
                "receiptFileSha256"
            ],
            "hostBootstrapBoundarySha256": host_boundary[
                "boundarySha256"
            ],
            "globalRoleRegistrySha256": global_role_registry[
                "registrySha256"
            ],
            "releaseCompletionResultKeyId": result_signer_key_id,
            "allResultDigestsCrossBound": True,
        },
        "completionIdentity": completion_identity,
        "completionIdentitySha256": completion_identity_sha256,
        "nextClientState": public_result["nextClientState"],
        "stateCommit": public_result["stateCommit"],
        "hostReadinessContext": host_context,
        "hostBootstrapBoundary": host_boundary,
        "globalRoleRegistry": global_role_registry,
        "externalPinProvenanceBoundary": (
            FINAL_V6_EXTERNAL_PIN_PROVENANCE_BOUNDARY
        ),
        "externalProvisioningBoundary": (
            FINAL_V6_EXTERNAL_PROVISIONING_BOUNDARY
        ),
    }


def build_release_completion_result_signing_request(
    result_core: dict[str, Any],
    *,
    provider: str,
    signing_key_id: str,
    signing_key_spki_sha256: str,
    global_role_registry_sha256: str,
) -> dict[str, Any]:
    validate_canonical_json_profile(
        result_core,
        label="release completion result signing core",
    )
    provider = require_final_v1_identifier(
        provider,
        "release completion signing provider",
    )
    signing_key_id = require_sha256(
        signing_key_id,
        "release completion signing key ID",
    )
    signing_key_spki_sha256 = require_sha256(
        signing_key_spki_sha256,
        "release completion signing SPKI digest",
    )
    global_role_registry_sha256 = require_sha256(
        global_role_registry_sha256,
        "release completion signing global role registry",
    )
    require(
        signing_key_id == signing_key_spki_sha256
        and nested(
            result_core,
            "globalRoleRegistry",
            "registrySha256",
        )
        == global_role_registry_sha256
        and nested(
            result_core,
            "aggregateAuthentication",
            "globalRoleRegistrySha256",
        )
        == global_role_registry_sha256
        and nested(
            result_core,
            "globalRoleRegistry",
            "roles",
            "releaseCompletionResult",
        )
        == signing_key_id
        and nested(
            result_core,
            "aggregateAuthentication",
            "releaseCompletionResultKeyId",
        )
        == signing_key_id,
        "release completion signing request crossed its signer or global role registry",
    )
    result_sha256 = verify_nitro_tee.sha256_json(result_core)
    signing_bytes = (
        FINAL_RESULT_SIGNATURE_DOMAIN
        + verify_nitro_tee.canonical_json_bytes(result_core)
    )
    signing_bytes_sha256 = verify_nitro_tee.sha256(signing_bytes)
    idempotency_binding = {
        "apiVersion": FINAL_RESULT_SIGNING_REQUEST_API_VERSION,
        "operation": FINAL_RESULT_SIGNING_OPERATION,
        "provider": provider,
        "signingKeyId": signing_key_id,
        "signingKeySpkiSha256": signing_key_spki_sha256,
        "globalRoleRegistrySha256": global_role_registry_sha256,
        "resultSha256": result_sha256,
        "signingBytesSha256": signing_bytes_sha256,
    }
    request_core = {
        "apiVersion": FINAL_RESULT_SIGNING_REQUEST_API_VERSION,
        "kind": FINAL_RESULT_SIGNING_REQUEST_KIND,
        "operation": FINAL_RESULT_SIGNING_OPERATION,
        "provider": provider,
        "signingKeyId": signing_key_id,
        "signingKeySpkiSha256": signing_key_spki_sha256,
        "globalRoleRegistrySha256": global_role_registry_sha256,
        "resultCore": result_core,
        "resultSha256": result_sha256,
        "signingBytesBase64url": base64.urlsafe_b64encode(
            signing_bytes
        ).decode("ascii").rstrip("="),
        "signingBytesSha256": signing_bytes_sha256,
        "idempotencyKey": verify_nitro_tee.sha256_json(idempotency_binding),
        "retrySemantics": FINAL_RESULT_SIGNING_RETRY_SEMANTICS,
        "lostResponseRecovery": FINAL_RESULT_SIGNING_LOST_RESPONSE_RECOVERY,
        "conflictSemantics": FINAL_RESULT_SIGNING_CONFLICT_SEMANTICS,
    }
    return {
        **request_core,
        "requestSha256": verify_nitro_tee.sha256_json(request_core),
    }


def validate_release_completion_result_signing_request(
    value: Any,
    *,
    expected_result_core: dict[str, Any],
    expected_provider: str,
    expected_signing_key_id: str,
    expected_signing_key_spki_sha256: str,
    expected_global_role_registry_sha256: str,
) -> dict[str, Any]:
    expected = build_release_completion_result_signing_request(
        expected_result_core,
        provider=expected_provider,
        signing_key_id=expected_signing_key_id,
        signing_key_spki_sha256=expected_signing_key_spki_sha256,
        global_role_registry_sha256=(
            expected_global_role_registry_sha256
        ),
    )
    require(
        isinstance(value, dict) and value == expected,
        "release completion signing request is not the exact deterministic request",
    )
    return value


def verify_release_completion_result_signing_response(
    value: Any,
    *,
    signing_request: dict[str, Any],
    trusted_public_key_pem: str,
    expected_provider: str,
    expected_signing_key_id: str,
    expected_signing_key_spki_sha256: str,
    expected_global_role_registry_sha256: str,
) -> dict[str, Any]:
    signing_request = validate_release_completion_result_signing_request(
        signing_request,
        expected_result_core=(
            signing_request.get("resultCore")
            if isinstance(signing_request, dict)
            else {}
        ),
        expected_provider=expected_provider,
        expected_signing_key_id=expected_signing_key_id,
        expected_signing_key_spki_sha256=expected_signing_key_spki_sha256,
        expected_global_role_registry_sha256=(
            expected_global_role_registry_sha256
        ),
    )
    fields = {
        "apiVersion",
        "kind",
        "operation",
        "status",
        "requestSha256",
        "idempotencyKey",
        "provider",
        "signingKeyId",
        "signingKeySpkiSha256",
        "globalRoleRegistrySha256",
        "resultSha256",
        "signingBytesSha256",
        "signature",
    }
    require(
        isinstance(value, dict)
        and set(value) == fields
        and value["apiVersion"]
        == FINAL_RESULT_SIGNING_RESPONSE_API_VERSION
        and value["kind"] == FINAL_RESULT_SIGNING_RESPONSE_KIND
        and value["operation"] == FINAL_RESULT_SIGNING_OPERATION
        and value["status"] == "signed",
        "release completion signing response does not match the closed v1 contract",
    )
    provider = require_final_v1_identifier(
        value["provider"],
        "release completion signing response provider",
    )
    pinned_provider = require_final_v1_identifier(
        expected_provider,
        "expected release completion signing response provider",
    )
    signing_key_id = require_sha256(
        value["signingKeyId"],
        "release completion signing response key ID",
    )
    signing_key_spki_sha256 = require_sha256(
        value["signingKeySpkiSha256"],
        "release completion signing response SPKI digest",
    )
    calculated_key_id = release_public_key_id(trusted_public_key_pem)
    require(
        provider == pinned_provider == signing_request["provider"]
        and signing_key_id
        == require_sha256(
            expected_signing_key_id,
            "expected release completion signing response key ID",
        )
        == signing_request["signingKeyId"]
        == calculated_key_id
        and signing_key_spki_sha256
        == require_sha256(
            expected_signing_key_spki_sha256,
            "expected release completion signing response SPKI digest",
        )
        == signing_request["signingKeySpkiSha256"]
        == calculated_key_id
        and value["globalRoleRegistrySha256"]
        == require_sha256(
            expected_global_role_registry_sha256,
            "expected release completion signing response global role registry",
        )
        == signing_request["globalRoleRegistrySha256"]
        and value["requestSha256"] == signing_request["requestSha256"]
        and value["idempotencyKey"] == signing_request["idempotencyKey"]
        and value["resultSha256"] == signing_request["resultSha256"]
        and value["signingBytesSha256"]
        == signing_request["signingBytesSha256"],
        "release completion signing response crossed its exact request, signer, or role registry",
    )
    require(
        isinstance(value["signature"], str)
        and re.fullmatch(
            r"ed25519:[A-Za-z0-9_-]{86}",
            value["signature"],
            re.ASCII,
        )
        is not None,
        "release completion signing response signature is not canonical Ed25519",
    )
    signing_bytes = decode_canonical_base64url(
        signing_request["signingBytesBase64url"],
        "release completion signing request bytes",
    )
    require(
        verify_nitro_tee.sha256(signing_bytes)
        == signing_request["signingBytesSha256"],
        "release completion signing request bytes changed after preparation",
    )
    verify_ed25519(
        trusted_public_key_pem,
        value["signature"],
        signing_bytes,
        "release completion signing response",
    )
    return {
        "apiVersion": FINAL_RESULT_AUTHENTICITY_API_VERSION,
        "provider": provider,
        "signingKeyId": signing_key_id,
        "signingKeySpkiSha256": signing_key_spki_sha256,
        "resultSha256": value["resultSha256"],
        "signature": value["signature"],
    }


def finalize_release_completion_verification_v1(
    result_core: dict[str, Any],
    signing_response: dict[str, Any],
    *,
    trusted_result_public_key_pem: str,
    expected_result_provider: str,
    expected_result_key_id: str,
    expected_result_spki_sha256: str,
    trusted_public_nitro_result_public_key_pem: str,
    expected_public_nitro_result_provider: str,
    expected_public_nitro_result_key_id: str,
    expected_public_nitro_result_spki_sha256: str,
    expected_final_role_registry_sha256: str,
) -> dict[str, Any]:
    signing_request = build_release_completion_result_signing_request(
        result_core,
        provider=expected_result_provider,
        signing_key_id=expected_result_key_id,
        signing_key_spki_sha256=expected_result_spki_sha256,
        global_role_registry_sha256=(
            expected_final_role_registry_sha256
        ),
    )
    authenticity = verify_release_completion_result_signing_response(
        signing_response,
        signing_request=signing_request,
        trusted_public_key_pem=trusted_result_public_key_pem,
        expected_provider=expected_result_provider,
        expected_signing_key_id=expected_result_key_id,
        expected_signing_key_spki_sha256=(
            expected_result_spki_sha256
        ),
        expected_global_role_registry_sha256=(
            expected_final_role_registry_sha256
        ),
    )
    final_result = {
        **result_core,
        "resultSha256": signing_request["resultSha256"],
        "authenticity": authenticity,
    }
    return validate_release_completion_verification_v1(
        final_result,
        trusted_result_public_key_pem=trusted_result_public_key_pem,
        expected_result_provider=expected_result_provider,
        expected_result_key_id=expected_result_key_id,
        expected_result_spki_sha256=expected_result_spki_sha256,
        trusted_public_nitro_result_public_key_pem=(
            trusted_public_nitro_result_public_key_pem
        ),
        expected_public_nitro_result_provider=(
            expected_public_nitro_result_provider
        ),
        expected_public_nitro_result_key_id=(
            expected_public_nitro_result_key_id
        ),
        expected_public_nitro_result_spki_sha256=(
            expected_public_nitro_result_spki_sha256
        ),
        expected_final_role_registry_sha256=(
            expected_final_role_registry_sha256
        ),
    )


def validate_final_result_signer_phase(args: argparse.Namespace) -> str:
    phase = getattr(args, "final_result_phase", None)
    require(
        phase in {"prepare", "finalize"},
        "final Manifest v6 verification requires an explicit supported signer phase",
    )
    signing_response_path = getattr(
        args,
        "release_completion_result_signature",
        None,
    )
    signing_request_path = getattr(
        args,
        "release_completion_result_signing_request",
        None,
    )
    if phase == "prepare":
        require(
            signing_response_path is None,
            "final signer prepare phase rejects a preexisting signed response",
        )
        require(
            signing_request_path is None,
            "final signer prepare phase rejects a preexisting prepared request",
        )
    else:
        require(
            bool(signing_response_path),
            "final signer finalize phase requires --release-completion-result-signature",
        )
        require(
            bool(signing_request_path),
            "final signer finalize phase requires --release-completion-result-signing-request",
        )
    require(
        bool(getattr(args, "out", None)),
        "final signer prepare and finalize phases require --out for a durable artifact",
    )
    reject_final_protocol_output_collisions(args)
    return phase


def final_protocol_paths_have_same_identity(
    left: str,
    right: str,
) -> bool:
    left_identity = os.path.normcase(
        os.path.realpath(os.path.abspath(left))
    )
    right_identity = os.path.normcase(
        os.path.realpath(os.path.abspath(right))
    )
    if left_identity == right_identity:
        return True
    try:
        return os.path.samefile(left, right)
    except (FileNotFoundError, OSError):
        return False


def reject_final_protocol_output_collisions(
    args: argparse.Namespace,
) -> None:
    output_path = getattr(args, "out", None)
    require(
        type(output_path) is str and bool(output_path),
        "final protocol output path is absent",
    )
    final_protocol_inputs = (
        (
            "--public-nitro-evidence-bundle",
            "public_nitro_evidence_bundle",
        ),
        ("--public-nitro-expectations", "public_nitro_expectations"),
        ("--public-nitro-trust-roots", "public_nitro_trust_roots"),
        (
            "--public-nitro-verification-result",
            "public_nitro_verification_result",
        ),
        (
            "--public-nitro-verification-result-public-key",
            "public_nitro_verification_result_public_key",
        ),
        (
            "--host-readiness-completion-proof",
            "host_readiness_completion_proof",
        ),
        (
            "--release-completion-result-public-key",
            "release_completion_result_public_key",
        ),
        (
            "--release-completion-result-signature",
            "release_completion_result_signature",
        ),
        (
            "--release-completion-result-signing-request",
            "release_completion_result_signing_request",
        ),
    )
    for option, attribute in final_protocol_inputs:
        input_path = getattr(args, attribute, None)
        if input_path is None:
            continue
        require(
            type(input_path) is str and bool(input_path),
            f"{option} path is invalid",
        )
        require(
            not final_protocol_paths_have_same_identity(
                output_path,
                input_path,
            ),
            f"--out must be a distinct artifact and must not collide with {option}",
        )


def emit_release_completion_result_signer_phase(
    args: argparse.Namespace,
    result_core: dict[str, Any],
    *,
    trusted_result_public_key_pem: str,
    trusted_public_nitro_result_public_key_pem: str,
) -> dict[str, Any]:
    phase = validate_final_result_signer_phase(args)
    signing_request = build_release_completion_result_signing_request(
        result_core,
        provider=args.expected_release_completion_result_provider,
        signing_key_id=args.expected_release_completion_result_key_id,
        signing_key_spki_sha256=(
            args.expected_release_completion_result_spki_sha256
        ),
        global_role_registry_sha256=(
            args.expected_final_role_registry_sha256
        ),
    )
    if phase == "prepare":
        document = signing_request
        output_label = "release completion signing request"
    else:
        retained_signing_request, _ = load_final_v6_canonical_json(
            args.release_completion_result_signing_request,
            "retained release completion signing request",
        )
        validate_release_completion_result_signing_request(
            retained_signing_request,
            expected_result_core=result_core,
            expected_provider=(
                args.expected_release_completion_result_provider
            ),
            expected_signing_key_id=(
                args.expected_release_completion_result_key_id
            ),
            expected_signing_key_spki_sha256=(
                args.expected_release_completion_result_spki_sha256
            ),
            expected_global_role_registry_sha256=(
                args.expected_final_role_registry_sha256
            ),
        )
        signing_response, _ = load_final_v6_canonical_json(
            args.release_completion_result_signature,
            "release completion result signed response",
        )
        document = finalize_release_completion_verification_v1(
            result_core,
            signing_response,
            trusted_result_public_key_pem=trusted_result_public_key_pem,
            expected_result_provider=(
                args.expected_release_completion_result_provider
            ),
            expected_result_key_id=(
                args.expected_release_completion_result_key_id
            ),
            expected_result_spki_sha256=(
                args.expected_release_completion_result_spki_sha256
            ),
            trusted_public_nitro_result_public_key_pem=(
                trusted_public_nitro_result_public_key_pem
            ),
            expected_public_nitro_result_provider=(
                args.expected_public_nitro_verification_result_provider
            ),
            expected_public_nitro_result_key_id=(
                args.expected_public_nitro_verification_result_key_id
            ),
            expected_public_nitro_result_spki_sha256=(
                args.expected_public_nitro_verification_result_spki_sha256
            ),
            expected_final_role_registry_sha256=(
                args.expected_final_role_registry_sha256
            ),
        )
        output_label = "final verification result"
    if args.out:
        reject_final_protocol_output_collisions(args)
        output_digest = write_final_v6_result(Path(args.out), document)
        require(
            output_digest
            == verify_nitro_tee.sha256(
                verify_nitro_tee.canonical_json_bytes(document) + b"\n"
            ),
            f"{output_label} output digest mismatch",
        )
    sys.stdout.buffer.write(
        verify_nitro_tee.canonical_json_bytes(document) + b"\n"
    )
    return document


def verify_manifest_v6_final(args: argparse.Namespace) -> None:
    required_inputs = {
        "--public-nitro-evidence-bundle": args.public_nitro_evidence_bundle,
        "--public-nitro-expectations": args.public_nitro_expectations,
        "--public-nitro-trust-roots": args.public_nitro_trust_roots,
        "--expected-public-nitro-trust-roots-sha256": (
            args.expected_public_nitro_trust_roots_sha256
        ),
        "--public-nitro-verification-result": (
            args.public_nitro_verification_result
        ),
        "--public-nitro-verification-result-public-key": (
            args.public_nitro_verification_result_public_key
        ),
        "--expected-public-nitro-verification-result-provider": (
            args.expected_public_nitro_verification_result_provider
        ),
        "--expected-public-nitro-verification-result-key-id": (
            args.expected_public_nitro_verification_result_key_id
        ),
        "--expected-public-nitro-verification-result-spki-sha256": (
            args.expected_public_nitro_verification_result_spki_sha256
        ),
        "--expected-final-role-registry-sha256": (
            args.expected_final_role_registry_sha256
        ),
        "--release-completion-result-public-key": (
            args.release_completion_result_public_key
        ),
        "--expected-release-completion-result-provider": (
            args.expected_release_completion_result_provider
        ),
        "--expected-release-completion-result-key-id": (
            args.expected_release_completion_result_key_id
        ),
        "--expected-release-completion-result-spki-sha256": (
            args.expected_release_completion_result_spki_sha256
        ),
    }
    missing = [option for option, value in required_inputs.items() if not value]
    require(
        not missing,
        "final Manifest v6 verification requires: " + ", ".join(missing),
    )
    validate_final_result_signer_phase(args)
    obsolete_final_inputs = {
        "--public-nitro-trust-root-pin-id": (
            args.public_nitro_trust_root_pin_id
        ),
        "--public-nitro-state-commit-receipt": (
            args.public_nitro_state_commit_receipt
        ),
        "--public-nitro-current-head-authorization": (
            args.public_nitro_current_head_authorization
        ),
        "--public-nitro-current-head-verifier-nonce": (
            args.public_nitro_current_head_verifier_nonce
        ),
        "--public-nitro-current-head-redemption-receipt": (
            args.public_nitro_current_head_redemption_receipt
        ),
        "--public-nitro-current-head-redemption-verifier-nonce": (
            args.public_nitro_current_head_redemption_verifier_nonce
        ),
        "--promotion-acceptance-evidence": (
            args.promotion_acceptance_evidence
        ),
        "--protected-client-state": args.protected_client_state,
        "--protected-client-state-public-key": (
            args.protected_client_state_public_key
        ),
        "--expected-protected-client-state-public-key-id": (
            args.expected_protected_client_state_public_key_id
        ),
        "--protected-client-state-checkpoint": (
            args.protected_client_state_checkpoint
        ),
        "--protected-client-state-checkpoint-public-key": (
            args.protected_client_state_checkpoint_public_key
        ),
        "--expected-protected-client-state-checkpoint-public-key-id": (
            args.expected_protected_client_state_checkpoint_public_key_id
        ),
        "--public-nitro-challenge": args.public_nitro_challenge,
        "--final-challenge-receipt": args.final_challenge_receipt,
        "--final-challenge-authority-public-key": (
            args.final_challenge_authority_public_key
        ),
        "--final-challenge-authority-public-key-id": (
            args.final_challenge_authority_public_key_id
        ),
        "--final-challenge-authority-provider": (
            args.final_challenge_authority_provider
        ),
        "--candidate-manifest-v6": args.candidate_manifest_v6,
        "--source-input-manifest": args.source_input_manifest,
        "--source-git-inventory-public-key": (
            args.source_git_inventory_public_key
        ),
        "--source-untracked-approval-public-key": (
            args.source_untracked_approval_public_key
        ),
        "--dependency-closure": args.dependency_closure,
        "--build-watchdog-receipt": args.build_watchdog_receipt,
        "--build-watchdog-public-key": args.build_watchdog_public_key,
        "--promotion-receipt": args.promotion_receipt,
        "--promotion-public-key": args.promotion_public_key,
        "--builder-left-statement": args.builder_left_statement,
        "--builder-left-transcript": args.builder_left_transcript,
        "--builder-left-public-key": args.builder_left_public_key,
        "--builder-right-statement": args.builder_right_statement,
        "--builder-right-transcript": args.builder_right_transcript,
        "--builder-right-public-key": args.builder_right_public_key,
        "--manifest-v6-eif-build": args.manifest_v6_eif_build,
        "--manifest-v6-eif-builder-public-key": (
            args.manifest_v6_eif_builder_public_key
        ),
        "--expected-final-v6-apparmor-profile-sha256": (
            args.expected_final_v6_apparmor_profile_sha256
        ),
        "--expected-final-v6-seccomp-profile-sha256": (
            args.expected_final_v6_seccomp_profile_sha256
        ),
        "--key-custody-evidence": args.key_custody_evidence,
        "--key-custody-public-key": args.key_custody_public_key,
        "--monotonic-witness": args.monotonic_witness,
        "--monotonic-witness-public-key": (
            args.monotonic_witness_public_key
        ),
        "--prior-witness-state": args.prior_witness_state,
        "--completion-proof-authentication": (
            args.completion_proof_authentication
        ),
        "--completion-authentication-public-key": (
            args.completion_authentication_public_key
        ),
        "--completion-proof-checkpoint": args.completion_proof_checkpoint,
        "--completion-checkpoint-public-key": (
            args.completion_checkpoint_public_key
        ),
    }
    supplied_obsolete = [
        option
        for option, supplied in obsolete_final_inputs.items()
        if supplied is not None
    ]
    require(
        not supplied_obsolete,
        "final verification consumes the signed public-Nitro live result; "
        "obsolete local finalization or completionProof/v6 inputs are rejected: "
        + ", ".join(supplied_obsolete),
    )
    require(
        not args.skip_current_host_check,
        "final Manifest v6 verification forbids --skip-current-host-check",
    )
    bundle_document, bundle_raw = load_final_v6_canonical_json(
        args.public_nitro_evidence_bundle,
        "public Nitro evidence bundle",
    )
    expectations_document, expectations_raw = load_final_v6_canonical_json(
        args.public_nitro_expectations,
        "independent production expectations",
    )
    trust_document, trust_raw = load_final_v6_canonical_json(
        args.public_nitro_trust_roots,
        "closed public Nitro trust-root bundle",
    )
    _reject_obsolete_final_v6_injection(bundle_document)
    _reject_obsolete_final_v6_injection(expectations_document)
    _reject_obsolete_final_v6_injection(trust_document)
    trust_bundle_file_sha256 = verify_nitro_tee.sha256(trust_raw)
    require(
        trust_bundle_file_sha256
        == require_sha256(
            args.expected_public_nitro_trust_roots_sha256,
            "expected public Nitro trust-root bundle",
        ),
        "public Nitro trust-root bundle differs from the caller-pinned digest",
    )
    public_envelope, public_envelope_raw = load_final_v6_canonical_json(
        args.public_nitro_verification_result,
        "signed public Nitro live verification result",
    )
    _reject_obsolete_final_v6_injection(public_envelope)
    public_result_pem, public_result_key_id = _load_pinned_ed25519_pem(
        args.public_nitro_verification_result_public_key,
        expected_key_id=(
            args.expected_public_nitro_verification_result_key_id
        ),
        expected_spki_sha256=(
            args.expected_public_nitro_verification_result_spki_sha256
        ),
        label="public Nitro live result trust root",
    )
    public_result = verify_signed_public_nitro_result_envelope(
        public_envelope,
        trusted_public_key_pem=public_result_pem,
        expected_provider=(
            args.expected_public_nitro_verification_result_provider
        ),
        expected_key_id=(
            args.expected_public_nitro_verification_result_key_id
        ),
        expected_spki_sha256=(
            args.expected_public_nitro_verification_result_spki_sha256
        ),
    )
    evidence_bundle_file_sha256 = verify_nitro_tee.sha256(bundle_raw)
    expectations_file_sha256 = verify_nitro_tee.sha256(expectations_raw)
    require(
        public_result["evidenceBundleFileSha256"]
        == evidence_bundle_file_sha256
        and public_result["expectationsFileSha256"]
        == expectations_file_sha256
        and public_result["trustRootBundleFileSha256"]
        == trust_bundle_file_sha256,
        "signed public Nitro result crossed its exact bundle, expectations, or trust-root bytes",
    )
    completion_identity, completion_identity_sha256 = (
        validate_final_v6_completion_identity(
            public_result["completionIdentity"]
        )
    )
    host_context = _load_host_readiness_context(
        args.host_readiness_completion_proof
    )
    host_context_sha256 = verify_nitro_tee.sha256_json(host_context)
    host_boundary_core = {
        "apiVersion": FINAL_V6_HOST_BOOTSTRAP_BOUNDARY_API_VERSION,
        "launchManifestApiVersion": "serverware.productionReadinessLaunch/v3",
        "launchAuthorizationRequestApiVersion": (
            "serverware.launchAuthorizationRequest/v2"
        ),
        "launchAuthorizationApiVersion": "serverware.launchAuthorization/v2",
        "bootstrapReceiptApiVersion": "serverware.bootstrapReceipt/v3",
        "nonceRollbackAssuranceBindingApiVersion": (
            "serverware.productionNonceRollbackAssuranceBinding/v1"
        ),
        "authorizationScope": "trusted-host-readiness",
        "freshnessAuthority": "trusted-host-wall-clock",
        "evidenceProvidedToFinalVerifier": host_context["provided"],
        "hostReadinessContextSha256": host_context_sha256,
        "hostReadinessCompletionProofFileSha256": host_context[
            "completionProofFileSha256"
        ],
        "launchAuthorityKeyId": host_context["launchAuthorityKeyId"],
        "authoritativeForFinalCompletion": False,
        "requiredForFinalCompletion": False,
        "relationship": "non-authoritative-readiness-context-only",
        "finalAuthority": (
            "independent-manifest-v6-public-nitro-verifier-and-protected-state"
        ),
        "completionIdentitySha256": completion_identity_sha256,
        "bindingMechanism": (
            "signed-final-result-core-non-authoritative-context-binding"
        ),
    }
    host_boundary = {
        **host_boundary_core,
        "boundarySha256": verify_nitro_tee.sha256_json(host_boundary_core),
    }
    result_signer_pem, result_signer_key_id = _load_pinned_ed25519_pem(
        args.release_completion_result_public_key,
        expected_key_id=args.expected_release_completion_result_key_id,
        expected_spki_sha256=(
            args.expected_release_completion_result_spki_sha256
        ),
        label="release completion result trust root",
    )
    roles = {
        role: public_result["roleKeyIds"][role]
        for role in sorted(FINAL_PUBLIC_RESULT_ROLE_NAMES)
    }
    roles["releaseCompletionResult"] = result_signer_key_id
    if host_context["launchAuthorityKeyId"] is not None:
        roles["launchAuthority"] = host_context["launchAuthorityKeyId"]
    roles = {role: roles[role] for role in sorted(roles)}
    role_registry_core = {
        "apiVersion": FINAL_ROLE_REGISTRY_API_VERSION,
        "roles": roles,
    }
    global_role_registry = {
        **role_registry_core,
        "registrySha256": verify_nitro_tee.sha256_json(role_registry_core),
    }
    _validate_final_role_registry(
        global_role_registry,
        public_result_roles=public_result["roleKeyIds"],
        public_result_signer_key_id=public_result_key_id,
        result_signer_key_id=result_signer_key_id,
        launch_authority_key_id=host_context["launchAuthorityKeyId"],
        expected_registry_sha256=args.expected_final_role_registry_sha256,
    )
    public_envelope_file_sha256 = verify_nitro_tee.sha256(
        public_envelope_raw
    )
    final_core = build_release_completion_verification_v1_core(
        public_envelope=public_envelope,
        public_envelope_file_sha256=public_envelope_file_sha256,
        public_result=public_result,
        evidence_bundle_file_sha256=evidence_bundle_file_sha256,
        expectations_file_sha256=expectations_file_sha256,
        trust_root_bundle_file_sha256=trust_bundle_file_sha256,
        completion_identity=completion_identity,
        completion_identity_sha256=completion_identity_sha256,
        host_context=host_context,
        host_boundary=host_boundary,
        global_role_registry=global_role_registry,
        result_signer_key_id=result_signer_key_id,
    )
    emit_release_completion_result_signer_phase(
        args,
        final_core,
        trusted_result_public_key_pem=result_signer_pem,
        trusted_public_nitro_result_public_key_pem=public_result_pem,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify Serverware release readiness and independently proven final completion.")
    parser.add_argument(
        "--verification-mode",
        choices=("readiness", "final"),
        default="readiness",
        help="Readiness never claims final completion; final fails closed unless all final evidence and one-use state pass.",
    )
    parser.add_argument(
        "--final-result-phase",
        choices=("prepare", "finalize"),
        default="finalize",
        help=(
            "Prepare emits the deterministic external-signer request; finalize "
            "verifies the exact signed response and emits final v1."
        ),
    )
    parser.add_argument("--public-nitro-evidence-bundle", default=None)
    parser.add_argument("--public-nitro-expectations", default=None)
    parser.add_argument("--public-nitro-trust-roots", default=None)
    parser.add_argument(
        "--expected-public-nitro-trust-roots-sha256",
        default=None,
        help=(
            "Closed trust-root bundle digest obtained from a client or "
            "out-of-band pin; an on-host path alone is not provenance."
        ),
    )
    parser.add_argument("--public-nitro-trust-root-pin-id", default=None)
    parser.add_argument("--public-nitro-verification-result", default=None)
    parser.add_argument(
        "--public-nitro-verification-result-public-key",
        default=None,
    )
    parser.add_argument(
        "--expected-public-nitro-verification-result-provider",
        default=None,
    )
    parser.add_argument(
        "--expected-public-nitro-verification-result-key-id",
        default=None,
    )
    parser.add_argument(
        "--expected-public-nitro-verification-result-spki-sha256",
        default=None,
    )
    parser.add_argument(
        "--host-readiness-completion-proof",
        default=None,
        help=(
            "Optional completionProof/v6 trusted-host readiness context. "
            "It is validated as readiness-only and never contributes final authority."
        ),
    )
    parser.add_argument(
        "--expected-final-role-registry-sha256",
        default=None,
    )
    parser.add_argument(
        "--release-completion-result-signing-request",
        default=None,
        help=(
            "Retained canonical releaseCompletionResultSigningRequest/v1 "
            "emitted by prepare; finalize requires and revalidates these exact bytes."
        ),
    )
    parser.add_argument(
        "--release-completion-result-signature",
        default=None,
        help=(
            "Canonical external HSM/KMS/TEE signed response to the exact "
            "releaseCompletionResultSigningRequest/v1 emitted by prepare."
        ),
    )
    parser.add_argument(
        "--release-completion-result-public-key",
        default=None,
    )
    parser.add_argument(
        "--expected-release-completion-result-provider",
        default=None,
    )
    parser.add_argument(
        "--expected-release-completion-result-key-id",
        default=None,
    )
    parser.add_argument(
        "--expected-release-completion-result-spki-sha256",
        default=None,
    )
    parser.add_argument(
        "--public-nitro-state-commit-receipt",
        default=None,
        help=(
            "Canonical signed rollback-resistant CAS receipt for finalizing "
            "the exact pending public-verifier state transition."
        ),
    )
    parser.add_argument(
        "--public-nitro-current-head-authorization",
        default=None,
        help=(
            "Canonical signed one-use current-head authorization issued by "
            "the external state store only after the exact CAS receipt is "
            "verified."
        ),
    )
    parser.add_argument(
        "--public-nitro-current-head-verifier-nonce",
        default=None,
        help=(
            "Fresh independently generated exactly 32-byte unpadded base64url "
            "nonce consumed by the external store for current-head "
            "authorization."
        ),
    )
    parser.add_argument(
        "--public-nitro-current-head-redemption-receipt",
        default=None,
        help=(
            "Canonical signed receipt from the atomic compare-current-head-"
            "and-redeem operation performed after authorization."
        ),
    )
    parser.add_argument(
        "--public-nitro-current-head-redemption-verifier-nonce",
        default=None,
        help=(
            "Fresh independently generated exactly 32-byte unpadded base64url "
            "nonce created only after current-head authorization and consumed "
            "by the atomic redemption operation."
        ),
    )
    parser.add_argument("--promotion-acceptance-evidence", default=None)
    parser.add_argument("--protected-client-state", default=None)
    parser.add_argument("--protected-client-state-public-key", default=None)
    parser.add_argument(
        "--expected-protected-client-state-public-key-id",
        default=None,
    )
    parser.add_argument("--protected-client-state-checkpoint", default=None)
    parser.add_argument(
        "--protected-client-state-checkpoint-public-key",
        default=None,
    )
    parser.add_argument(
        "--expected-protected-client-state-checkpoint-public-key-id",
        default=None,
    )
    parser.add_argument(
        "--public-nitro-challenge",
        default=None,
        help="Independent fresh exactly 32-byte unpadded base64url challenge.",
    )
    parser.add_argument("--final-challenge-receipt", default=None)
    parser.add_argument("--final-challenge-authority-public-key", default=None)
    parser.add_argument("--final-challenge-authority-public-key-id", default=None)
    parser.add_argument("--final-challenge-authority-provider", default=None)
    parser.add_argument("--candidate-manifest-v6", default=None)
    parser.add_argument("--source-input-manifest", default=None)
    parser.add_argument("--source-git-inventory-public-key", default=None)
    parser.add_argument("--source-untracked-approval-public-key", default=None)
    parser.add_argument("--dependency-closure", default=None)
    parser.add_argument("--build-watchdog-receipt", default=None)
    parser.add_argument("--build-watchdog-public-key", default=None)
    parser.add_argument("--promotion-receipt", default=None)
    parser.add_argument("--promotion-public-key", default=None)
    parser.add_argument("--builder-left-statement", default=None)
    parser.add_argument("--builder-left-transcript", default=None)
    parser.add_argument("--builder-left-public-key", default=None)
    parser.add_argument("--builder-right-statement", default=None)
    parser.add_argument("--builder-right-transcript", default=None)
    parser.add_argument("--builder-right-public-key", default=None)
    parser.add_argument("--manifest-v6-eif-build", default=None)
    parser.add_argument("--manifest-v6-eif-builder-public-key", default=None)
    parser.add_argument(
        "--expected-final-v6-apparmor-profile-sha256",
        default=None,
        help="Out-of-band pin for the exact fixed Manifest v6 AppArmor profile.",
    )
    parser.add_argument(
        "--expected-final-v6-seccomp-profile-sha256",
        default=None,
        help="Out-of-band pin for the exact fixed Manifest v6 seccomp profile.",
    )
    parser.add_argument("--key-custody-evidence", default=None)
    parser.add_argument("--key-custody-public-key", default=None)
    parser.add_argument("--monotonic-witness", default=None)
    parser.add_argument("--monotonic-witness-public-key", default=None)
    parser.add_argument("--prior-witness-state", default=None)
    parser.add_argument("--completion-proof-authentication", default=None)
    parser.add_argument("--completion-authentication-public-key", default=None)
    parser.add_argument("--completion-proof-checkpoint", default=None)
    parser.add_argument("--completion-checkpoint-public-key", default=None)
    parser.add_argument("--production-readiness", default=".tmp/production-readiness.json")
    parser.add_argument("--production-readiness-config", default=".tmp/production-readiness-config.json")
    parser.add_argument("--production-readiness-env", default="ops/production-readiness.env")
    parser.add_argument(
        "--launcher-trusted-production-env-path",
        default=os.getenv(
            "SERVERWARE_LAUNCHER_TRUSTED_PRODUCTION_ENV_PATH"
        ),
    )
    parser.add_argument(
        "--launcher-trusted-production-env-sha256",
        default=os.getenv(
            "SERVERWARE_LAUNCHER_TRUSTED_PRODUCTION_ENV_SHA256"
        ),
    )
    parser.add_argument(
        "--launcher-nonce-rollback-assurance-pins",
        default=None,
    )
    parser.add_argument(
        "--launcher-nonce-rollback-assurance-pins-sha256",
        default=None,
    )
    parser.add_argument(
        "--launcher-nonce-rollback-assurance-contract-sha256",
        default=None,
    )
    parser.add_argument("--docker-executable", default=None)
    parser.add_argument("--docker-compose-plugin-executable", default=None)
    parser.add_argument("--docker-unix-socket", default=None)
    parser.add_argument("--docker-daemon-id", default=None)
    parser.add_argument("--production-host-preflight-signing-public-key", default=None)
    parser.add_argument("--production-host-preflight-signing-key-id", default=None)
    parser.add_argument("--production-host-preflight-max-age-seconds", type=int, default=None)
    parser.add_argument("--compose-file", default="docker-compose.production.yml")
    parser.add_argument("--production-host-preflight", default=".tmp/production-host-preflight.json")
    parser.add_argument("--nitro-evidence", default=".tmp/nitro-kms-evidence.json")
    parser.add_argument("--hardware-assurance", default=None)
    parser.add_argument("--hardware-assurance-trusted-public-key", default=None)
    parser.add_argument("--hardware-assurance-trusted-public-key-id", default=None)
    parser.add_argument(
        "--hardware-assurance-expected-challenge-nonce",
        default=None,
        help="Expected hardware-verifier challenge as unpadded base64url.",
    )
    parser.add_argument(
        "--hardware-assurance-expected-challenge-nonce-sha256",
        default=None,
        help="Expected hardware-verifier challenge digest as sha256:<64 lowercase hex>.",
    )
    parser.add_argument("--production-images-build", default=".tmp/production-images-build.json")
    parser.add_argument("--production-images-env", default=".tmp/production-images.env")
    parser.add_argument("--production-images-published", default=".tmp/production-images-published.json")
    parser.add_argument("--release-provenance-summary", default=".tmp/release-provenance-summary.json")
    parser.add_argument("--release-provenance", default=".tmp/release-provenance.json")
    parser.add_argument("--release-provenance-trusted-public-key", default=None)
    parser.add_argument("--image-signatures-summary", default=".tmp/image-signatures-summary.json")
    parser.add_argument("--image-signatures", default=".tmp/image-signatures.json")
    parser.add_argument("--sigstore-trusted-public-key", default=None)
    parser.add_argument("--rekor-trusted-public-key", default=None)
    parser.add_argument("--external-checkpoint-provider", default=None)
    parser.add_argument("--external-checkpoint-trusted-public-key", default=None)
    parser.add_argument("--bench", default=".tmp/decision-gate-rs-bench.json")
    parser.add_argument("--policy-bundle", default=None)
    parser.add_argument("--policy-trusted-public-key", default=None)
    parser.add_argument("--policy-trusted-public-key-id", default=None)
    parser.add_argument("--policy-identity-verification", default=None)
    parser.add_argument("--policy-activation-verification", default=None)
    parser.add_argument("--policy-activation-signature", default=None)
    parser.add_argument("--policy-activation-trusted-public-key", default=None)
    parser.add_argument("--policy-activation-trusted-public-key-id", default=None)
    parser.add_argument("--reproducible-build-verification", default=None)
    parser.add_argument("--reproducible-build-signature", default=None)
    parser.add_argument("--reproducible-build-trusted-public-key", default=None)
    parser.add_argument("--reproducible-build-trusted-public-key-id", default=None)
    parser.add_argument("--kms-materials", default="/etc/serverware/kms-materials.json")
    parser.add_argument(
        "--control-plane-response-signing-public-key",
        default=None,
    )
    parser.add_argument(
        "--control-plane-response-signing-public-key-id",
        default=None,
    )
    parser.add_argument("--proxy-response-proof", default=None)
    parser.add_argument("--proxy-proof-contract", choices=sorted(PROXY_PROOF_CONTRACTS), default=None)
    parser.add_argument("--proxy-stream-body", default=None)
    parser.add_argument("--proxy-max-stream-bytes", type=int, default=None)
    parser.add_argument("--proxy-observation-body", default=None)
    parser.add_argument("--proxy-max-observation-body-bytes", type=int, default=None)
    parser.add_argument("--proxy-proof-verifier-public-key", default=None)
    parser.add_argument("--proxy-collector-public-key", default=None)
    parser.add_argument("--proxy-server-instance-id", default=None)
    parser.add_argument("--proxy-client-nonce", default=None)
    parser.add_argument("--proxy-client-request-digest", default=None)
    parser.add_argument("--proxy-request-digest", default=None)
    parser.add_argument("--proxy-operation-digest", default=None)
    parser.add_argument("--proxy-operation-context-digest", default=None)
    parser.add_argument("--proxy-tls-channel-binding", default=None)
    parser.add_argument("--proxy-proof-max-age-seconds", type=int, default=None)
    parser.add_argument("--p99-limit-ms", default=None)
    parser.add_argument("--out", default=None)
    parser.add_argument("--skip-current-host-check", action="store_true", help="Test-only bypass for synthetic fixture completion tests.")
    args = parser.parse_args()

    if args.verification_mode == "final":
        verify_manifest_v6_final(args)
        return

    load_readiness_dependencies()

    # Everything below this point is the legacy Docker /dev/nsm readiness
    # verifier. It cannot issue or validate Manifest v6 final completion.
    # Historical final-condition branches are permanently disabled behind
    # this local constant; the dispatch above is the sole final path.
    legacy_final_mode = False
    require(
        args.verification_mode == "readiness",
        "legacy verifier path is readiness-only",
    )
    require(
        args.final_result_phase == "finalize",
        "--final-result-phase prepare is only valid with --verification-mode final",
    )
    readiness_required_inputs = {
        "--release-provenance-trusted-public-key": (
            args.release_provenance_trusted_public_key
        ),
        "--sigstore-trusted-public-key": args.sigstore_trusted_public_key,
        "--rekor-trusted-public-key": args.rekor_trusted_public_key,
        "--external-checkpoint-provider": args.external_checkpoint_provider,
        "--external-checkpoint-trusted-public-key": (
            args.external_checkpoint_trusted_public_key
        ),
        "--policy-bundle": args.policy_bundle,
        "--policy-trusted-public-key": args.policy_trusted_public_key,
        "--policy-identity-verification": args.policy_identity_verification,
        "--policy-activation-verification": (
            args.policy_activation_verification
        ),
        "--policy-activation-signature": args.policy_activation_signature,
        "--policy-activation-trusted-public-key": (
            args.policy_activation_trusted_public_key
        ),
        "--reproducible-build-verification": (
            args.reproducible_build_verification
        ),
        "--reproducible-build-signature": args.reproducible_build_signature,
        "--reproducible-build-trusted-public-key": (
            args.reproducible_build_trusted_public_key
        ),
        "--out": args.out,
    }
    missing_readiness_inputs = [
        option
        for option, value in readiness_required_inputs.items()
        if not value
    ]
    require(
        not missing_readiness_inputs,
        "legacy readiness verification requires: "
        + ", ".join(missing_readiness_inputs),
    )

    require(
        bool(args.hardware_assurance) == bool(args.hardware_assurance_trusted_public_key),
        "hardware-backed completion requires both --hardware-assurance and --hardware-assurance-trusted-public-key",
    )
    supplied_hardware_challenges = sum(
        value is not None
        for value in (
            args.hardware_assurance_expected_challenge_nonce,
            args.hardware_assurance_expected_challenge_nonce_sha256,
        )
    )
    if args.hardware_assurance:
        require(
            supplied_hardware_challenges == 1,
            "hardware-backed completion requires exactly one --hardware-assurance-expected-challenge-nonce "
            "or --hardware-assurance-expected-challenge-nonce-sha256",
        )
    else:
        require(
            supplied_hardware_challenges == 0,
            "hardware assurance expected challenge options require --hardware-assurance",
        )
    bootstrap_receipt, bootstrap_receipt_fd = (
        run_production_readiness.load_sealed_bootstrap_receipt(required=False)
    )
    nonce_rollback_assurance = (
        run_production_readiness.validate_retained_nonce_rollback_assurance(
            retained_path=args.launcher_nonce_rollback_assurance_pins,
            expected_pins_sha256=(
                args.launcher_nonce_rollback_assurance_pins_sha256
            ),
            expected_contract_sha256=(
                args.launcher_nonce_rollback_assurance_contract_sha256
            ),
            bootstrap_receipt=bootstrap_receipt,
            required=bootstrap_receipt is not None,
        )
    )
    launch_manifest_v3 = (
        verify_launcher_nonce_rollback_manifest_v3(
            bootstrap_receipt,
            nonce_rollback_assurance,
        )
        if bootstrap_receipt is not None
        else {
            "apiVersion": "serverware.productionReadinessLaunch/v3",
            "purpose": "readiness-only",
            "verified": False,
        }
    )
    require(
        not any(
            (
                args.public_nitro_evidence_bundle,
                args.public_nitro_expectations,
                args.public_nitro_trust_roots,
                args.expected_public_nitro_trust_roots_sha256,
                args.public_nitro_trust_root_pin_id,
                args.promotion_acceptance_evidence,
                args.protected_client_state,
                args.protected_client_state_public_key,
                args.expected_protected_client_state_public_key_id,
                args.protected_client_state_checkpoint,
                args.protected_client_state_checkpoint_public_key,
                args.expected_protected_client_state_checkpoint_public_key_id,
                args.public_nitro_challenge,
                args.final_challenge_receipt,
                args.final_challenge_authority_public_key,
                args.final_challenge_authority_public_key_id,
                args.final_challenge_authority_provider,
                args.hardware_assurance_trusted_public_key_id,
                args.candidate_manifest_v6,
                args.source_input_manifest,
                args.source_git_inventory_public_key,
                args.source_untracked_approval_public_key,
                args.dependency_closure,
                args.build_watchdog_receipt,
                args.build_watchdog_public_key,
                args.promotion_receipt,
                args.promotion_public_key,
                args.builder_left_statement,
                args.builder_left_transcript,
                args.builder_left_public_key,
                args.builder_right_statement,
                args.builder_right_transcript,
                args.builder_right_public_key,
                args.manifest_v6_eif_build,
                args.manifest_v6_eif_builder_public_key,
                args.expected_final_v6_apparmor_profile_sha256,
                args.expected_final_v6_seccomp_profile_sha256,
                args.key_custody_evidence,
                args.key_custody_public_key,
                args.monotonic_witness,
                args.monotonic_witness_public_key,
                args.prior_witness_state,
                args.completion_proof_authentication,
                args.completion_authentication_public_key,
                args.completion_proof_checkpoint,
                args.completion_checkpoint_public_key,
            )
        ),
        "Manifest v6 final evidence options are not accepted by legacy readiness mode",
    )
    require(
        bool(args.control_plane_response_signing_public_key),
        "production completion requires --control-plane-response-signing-public-key",
    )
    require(
        bool(args.control_plane_response_signing_public_key_id),
        "production completion requires --control-plane-response-signing-public-key-id",
    )
    require(bool(args.proxy_response_proof), "production completion requires --proxy-response-proof")
    require(bool(args.proxy_proof_contract), "production completion requires --proxy-proof-contract")
    if args.proxy_proof_contract == "streaming-v1":
        require(bool(args.proxy_stream_body), "streaming-v1 completion requires --proxy-stream-body")
        require(
            isinstance(args.proxy_max_stream_bytes, int),
            "streaming-v1 completion requires --proxy-max-stream-bytes",
        )
        require(
            bool(args.proxy_operation_context_digest),
            "streaming-v1 completion requires --proxy-operation-context-digest",
        )
        require(
            1 <= args.proxy_max_stream_bytes <= MAX_PROXY_STREAM_BODY_BYTES,
            f"--proxy-max-stream-bytes must be between 1 and {MAX_PROXY_STREAM_BODY_BYTES}",
        )
        require(
            args.proxy_observation_body is None
            and args.proxy_max_observation_body_bytes is None,
            "streaming-v1 completion does not accept observation body settings",
        )
    elif args.proxy_proof_contract == "observation-v1":
        require(
            args.proxy_stream_body is None and args.proxy_max_stream_bytes is None,
            "observation-v1 completion does not accept streaming body settings",
        )
        require(
            args.proxy_operation_context_digest is None,
            "observation-v1 completion does not accept a streaming operation context digest",
        )
        require(
            bool(args.proxy_observation_body),
            "observation-v1 completion requires --proxy-observation-body",
        )
        require(
            isinstance(args.proxy_max_observation_body_bytes, int),
            "observation-v1 completion requires --proxy-max-observation-body-bytes",
        )
        require(
            1
            <= args.proxy_max_observation_body_bytes
            <= MAX_PROXY_OBSERVATION_BODY_BYTES,
            "--proxy-max-observation-body-bytes must be between 1 and "
            f"{MAX_PROXY_OBSERVATION_BODY_BYTES}",
        )
    else:
        require(
            args.proxy_stream_body is None and args.proxy_max_stream_bytes is None,
            "buffered-v3 completion does not accept streaming body settings",
        )
        require(
            args.proxy_operation_context_digest is None,
            "buffered-v3 completion does not accept a streaming operation context digest",
        )
        require(
            args.proxy_observation_body is None
            and args.proxy_max_observation_body_bytes is None,
            "buffered-v3 completion does not accept observation body settings",
        )
    require(
        bool(args.proxy_proof_verifier_public_key),
        "production completion requires --proxy-proof-verifier-public-key",
    )
    require(
        bool(args.proxy_collector_public_key),
        "production completion requires --proxy-collector-public-key",
    )
    require(bool(args.proxy_server_instance_id), "production completion requires --proxy-server-instance-id")
    require(bool(args.proxy_client_nonce), "production completion requires --proxy-client-nonce")
    require(
        bool(args.proxy_client_request_digest),
        "production completion requires --proxy-client-request-digest",
    )
    require(bool(args.proxy_request_digest), "production completion requires --proxy-request-digest")
    require(bool(args.proxy_operation_digest), "production completion requires --proxy-operation-digest")
    require(bool(args.proxy_tls_channel_binding), "production completion requires --proxy-tls-channel-binding")

    paths = {
        "production_readiness": Path(args.production_readiness),
        "production_readiness_config": Path(args.production_readiness_config),
        "production_readiness_env": Path(args.production_readiness_env),
        "production_host_preflight": Path(args.production_host_preflight),
        **(
            {
                "production_host_preflight_signing_public_key": Path(
                    args.production_host_preflight_signing_public_key
                )
            }
            if args.production_host_preflight_signing_public_key
            else {}
        ),
        "nitro_evidence": Path(args.nitro_evidence),
        "production_images_build": Path(args.production_images_build),
        "production_images_env": Path(args.production_images_env),
        "production_images_published": Path(args.production_images_published),
        "release_provenance_summary": Path(args.release_provenance_summary),
        "release_provenance": Path(args.release_provenance),
        "release_provenance_trusted_public_key": Path(args.release_provenance_trusted_public_key),
        "image_signatures_summary": Path(args.image_signatures_summary),
        "image_signatures": Path(args.image_signatures),
        "sigstore_trusted_public_key": Path(args.sigstore_trusted_public_key),
        "rekor_trusted_public_key": Path(args.rekor_trusted_public_key),
        "external_checkpoint_trusted_public_key": Path(args.external_checkpoint_trusted_public_key),
        "bench": Path(args.bench),
        "policy_bundle": Path(args.policy_bundle),
        "policy_trusted_public_key": Path(args.policy_trusted_public_key),
        "policy_identity_verification": Path(args.policy_identity_verification),
        "policy_activation_verification": Path(args.policy_activation_verification),
        "policy_activation_signature": Path(args.policy_activation_signature),
        "policy_activation_trusted_public_key": Path(args.policy_activation_trusted_public_key),
        "reproducible_build_verification": Path(args.reproducible_build_verification),
        "reproducible_build_signature": Path(args.reproducible_build_signature),
        "reproducible_build_trusted_public_key": Path(args.reproducible_build_trusted_public_key),
        "kms_materials": Path(args.kms_materials),
        "control_plane_response_signing_public_key": Path(
            args.control_plane_response_signing_public_key
        ),
        "proxy_response_proof": Path(args.proxy_response_proof),
        "proxy_proof_verifier_public_key": Path(args.proxy_proof_verifier_public_key),
        "proxy_collector_public_key": Path(args.proxy_collector_public_key),
        "compose_file": Path(args.compose_file),
    }
    if args.proxy_proof_contract == "streaming-v1":
        paths["proxy_stream_body"] = Path(args.proxy_stream_body)
    elif args.proxy_proof_contract == "observation-v1":
        paths["proxy_observation_body"] = Path(args.proxy_observation_body)
    if args.hardware_assurance:
        paths["hardware_assurance"] = Path(args.hardware_assurance)
        paths["hardware_assurance_trusted_public_key"] = Path(args.hardware_assurance_trusted_public_key)
    if legacy_final_mode:
        paths["final_challenge_receipt"] = Path(args.final_challenge_receipt)
        paths["final_challenge_authority_public_key"] = Path(args.final_challenge_authority_public_key)
        paths.update(
            {
                "candidate_manifest_v6": Path(args.candidate_manifest_v6),
                "source_input_manifest": Path(args.source_input_manifest),
                "source_git_inventory_public_key": Path(
                    args.source_git_inventory_public_key
                ),
                "source_untracked_approval_public_key": Path(
                    args.source_untracked_approval_public_key
                ),
                "dependency_closure": Path(args.dependency_closure),
                "build_watchdog_receipt": Path(args.build_watchdog_receipt),
                "build_watchdog_public_key": Path(args.build_watchdog_public_key),
                "promotion_receipt": Path(args.promotion_receipt),
                "promotion_public_key": Path(args.promotion_public_key),
                "builder_left_statement": Path(args.builder_left_statement),
                "builder_left_transcript": Path(args.builder_left_transcript),
                "builder_left_public_key": Path(args.builder_left_public_key),
                "builder_right_statement": Path(args.builder_right_statement),
                "builder_right_transcript": Path(args.builder_right_transcript),
                "builder_right_public_key": Path(args.builder_right_public_key),
                "manifest_v6_eif_build": Path(args.manifest_v6_eif_build),
                "manifest_v6_eif_builder_public_key": Path(
                    args.manifest_v6_eif_builder_public_key
                ),
                "key_custody_evidence": Path(args.key_custody_evidence),
                "key_custody_public_key": Path(args.key_custody_public_key),
                "monotonic_witness": Path(args.monotonic_witness),
                "monotonic_witness_public_key": Path(
                    args.monotonic_witness_public_key
                ),
                "prior_witness_state": Path(args.prior_witness_state),
                "completion_proof_authentication": Path(
                    args.completion_proof_authentication
                ),
                "completion_authentication_public_key": Path(
                    args.completion_authentication_public_key
                ),
                "completion_proof_checkpoint": Path(
                    args.completion_proof_checkpoint
                ),
                "completion_checkpoint_public_key": Path(
                    args.completion_checkpoint_public_key
                ),
            }
        )

    trust_root_keys = {
        "release_provenance_trusted_public_key",
        "sigstore_trusted_public_key",
        "rekor_trusted_public_key",
        "external_checkpoint_trusted_public_key",
        "policy_trusted_public_key",
        "policy_activation_trusted_public_key",
        "reproducible_build_trusted_public_key",
        "control_plane_response_signing_public_key",
        "proxy_proof_verifier_public_key",
        "proxy_collector_public_key",
        "hardware_assurance_trusted_public_key",
        "final_challenge_authority_public_key",
        "production_host_preflight_signing_public_key",
        "source_git_inventory_public_key",
        "source_untracked_approval_public_key",
        "build_watchdog_public_key",
        "promotion_public_key",
        "builder_left_public_key",
        "builder_right_public_key",
        "manifest_v6_eif_builder_public_key",
        "key_custody_public_key",
        "monotonic_witness_public_key",
        "completion_authentication_public_key",
        "completion_checkpoint_public_key",
    }
    input_limits: dict[str, tuple[str, int]] = {}
    for key in paths:
        if key in trust_root_keys:
            max_bytes = FINAL_TRUST_ROOT_MAX_BYTES
        elif key == "production_readiness_env" or key == "production_images_env":
            max_bytes = ENV_INPUT_MAX_BYTES
        elif key == "compose_file":
            max_bytes = COMPOSE_INPUT_MAX_BYTES
        elif key == "policy_bundle":
            max_bytes = POLICY_BUNDLE_MAX_BYTES
        elif key == "proxy_stream_body":
            max_bytes = args.proxy_max_stream_bytes
        elif key == "proxy_observation_body":
            max_bytes = args.proxy_max_observation_body_bytes
        else:
            max_bytes = COMPLETION_INPUT_MAX_BYTES
        input_limits[key] = (key.replace("_", " "), max_bytes)
    input_snapshots = InputSnapshots()
    final_file_snapshots = input_snapshots.capture_many(paths, input_limits)
    stable_input_directory, stable_paths = materialize_snapshots(
        final_file_snapshots,
        ("production_readiness_env", "compose_file"),
    )

    readiness = load_json_snapshot(final_file_snapshots["production_readiness"], "production readiness")
    production_readiness_config = load_json_snapshot(final_file_snapshots["production_readiness_config"], "production readiness config")
    production_host_preflight = load_production_host_preflight_json_snapshot(
        final_file_snapshots["production_host_preflight"],
        "production host preflight",
    )
    nitro_evidence = load_json_snapshot(final_file_snapshots["nitro_evidence"], "Nitro/KMS evidence")
    production_images_build = load_json_snapshot(final_file_snapshots["production_images_build"], "production images build")
    production_images_published = load_json_snapshot(final_file_snapshots["production_images_published"], "production images published")
    provenance_summary = load_json_snapshot(final_file_snapshots["release_provenance_summary"], "release provenance summary")
    provenance_document = load_json_snapshot(final_file_snapshots["release_provenance"], "release provenance")
    image_summary = load_json_snapshot(final_file_snapshots["image_signatures_summary"], "image signatures summary")
    image_document = load_json_snapshot(final_file_snapshots["image_signatures"], "image signatures")
    bench = load_benchmark_json_snapshot(
        final_file_snapshots["bench"],
        "decision-gate benchmark",
    )
    proxy_response_proof = load_json_snapshot(
        final_file_snapshots["proxy_response_proof"],
        "production proxy response proof",
    )
    trusted_control_plane_response_signing_public_key_pem = snapshot_text(
        final_file_snapshots[
            "control_plane_response_signing_public_key"
        ],
        "control-plane response signing trust root",
        encoding="ascii",
    )
    trusted_proxy_verifier_public_key_pem = snapshot_text(
        final_file_snapshots["proxy_proof_verifier_public_key"],
        "proxy proof vendor verifier trust root",
        encoding="ascii",
    )
    trusted_proxy_collector_public_key_pem = snapshot_text(
        final_file_snapshots["proxy_collector_public_key"],
        "proxy response collector trust root",
        encoding="ascii",
    )

    readiness_summary = verify_readiness(readiness)
    preflight_summary = verify_production_host_preflight(
        production_host_preflight,
        paths,
        input_snapshots,
        readiness_summary,
        verification_mode=args.verification_mode,
        preflight_signing_public_key=final_file_snapshots.get(
            "production_host_preflight_signing_public_key"
        ),
        preflight_signing_key_id=args.production_host_preflight_signing_key_id,
        preflight_max_age_seconds=args.production_host_preflight_max_age_seconds,
        expected_bootstrap_receipt=bootstrap_receipt,
        expected_nonce_rollback_assurance=nonce_rollback_assurance,
    )
    current_host_summary = verify_current_completion_host(
        preflight_summary,
        skip_current_host_check=args.skip_current_host_check,
    )
    production_config_summary = verify_production_config_result(production_readiness_config, preflight_summary)
    production_env_binding = verify_current_production_env_binding(
        paths,
        input_snapshots,
        readiness_summary,
        preflight_summary,
        production_config_summary,
        verification_mode=args.verification_mode,
        release_trust_inputs={
            RELEASE_PROVENANCE_TRUST_ROOT_ENV_KEY: args.release_provenance_trusted_public_key,
            SIGSTORE_TRUST_ROOT_ENV_KEY: args.sigstore_trusted_public_key,
            REKOR_TRUST_ROOT_ENV_KEY: args.rekor_trusted_public_key,
            EXTERNAL_CHECKPOINT_TRUST_ROOT_ENV_KEY: args.external_checkpoint_trusted_public_key,
            EXTERNAL_CHECKPOINT_PROVIDER_ENV_KEY: args.external_checkpoint_provider,
            CONTROL_PLANE_RESPONSE_SIGNING_KEY_ENV_KEY: (
                args.control_plane_response_signing_public_key
            ),
            CONTROL_PLANE_RESPONSE_SIGNING_KEY_ID_ENV_KEY: (
                args.control_plane_response_signing_public_key_id
            ),
            run_production_readiness.POLICY_TRUST_ROOT_ENV: (
                args.policy_trusted_public_key
            ),
            run_production_readiness.POLICY_TRUST_ROOT_ID_ENV: (
                args.policy_trusted_public_key_id
            ),
            run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ENV: (
                args.policy_activation_trusted_public_key
            ),
            run_production_readiness.POLICY_ACTIVATION_TRUST_ROOT_ID_ENV: (
                args.policy_activation_trusted_public_key_id
            ),
            run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ENV: (
                args.reproducible_build_trusted_public_key
            ),
            run_production_readiness.REPRODUCIBLE_BUILD_TRUST_ROOT_ID_ENV: (
                args.reproducible_build_trusted_public_key_id
            ),
        },
        final_inputs={
            FINAL_HARDWARE_ASSURANCE_ENV_KEY: args.hardware_assurance,
            FINAL_HARDWARE_TRUST_ROOT_ENV_KEY: args.hardware_assurance_trusted_public_key,
            FINAL_HARDWARE_TRUST_ROOT_ID_ENV_KEY: args.hardware_assurance_trusted_public_key_id,
            FINAL_HARDWARE_CHALLENGE_NONCE_ENV_KEY: args.hardware_assurance_expected_challenge_nonce,
            FINAL_HARDWARE_CHALLENGE_DIGEST_ENV_KEY: args.hardware_assurance_expected_challenge_nonce_sha256,
            FINAL_CHALLENGE_RECEIPT_ENV_KEY: args.final_challenge_receipt,
            FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ENV_KEY: args.final_challenge_authority_public_key,
            FINAL_CHALLENGE_AUTHORITY_TRUST_ROOT_ID_ENV_KEY: args.final_challenge_authority_public_key_id,
            FINAL_CHALLENGE_AUTHORITY_PROVIDER_ENV_KEY: args.final_challenge_authority_provider,
        },
        final_file_snapshots=final_file_snapshots,
        proxy_digest_inputs={
            attribute: getattr(args, attribute)
            for attribute in PROXY_EXPECTED_DIGEST_ENV_KEYS
        },
        launcher_trust_inputs={
            run_production_readiness.LAUNCHER_TRUSTED_ENV_PATH_INPUT: (
                args.launcher_trusted_production_env_path
            ),
            run_production_readiness.LAUNCHER_TRUSTED_ENV_SHA256_INPUT: (
                args.launcher_trusted_production_env_sha256
            ),
        },
        proxy_proof_max_age_seconds=args.proxy_proof_max_age_seconds,
        proxy_proof_contract=args.proxy_proof_contract,
        proxy_stream_body=args.proxy_stream_body,
        proxy_max_stream_bytes=args.proxy_max_stream_bytes,
        proxy_observation_body=args.proxy_observation_body,
        proxy_max_observation_body_bytes=args.proxy_max_observation_body_bytes,
        proxy_operation_context_digest=args.proxy_operation_context_digest,
        p99_limit_ms=args.p99_limit_ms,
        docker_executable=args.docker_executable,
        docker_compose_plugin_executable=args.docker_compose_plugin_executable,
        docker_unix_socket=args.docker_unix_socket,
        docker_daemon_id=args.docker_daemon_id,
        preflight_signing_public_key=args.production_host_preflight_signing_public_key,
        preflight_signing_key_id=args.production_host_preflight_signing_key_id,
        preflight_max_age_seconds=args.production_host_preflight_max_age_seconds,
        launcher_enforced=bootstrap_receipt is not None,
    )
    if bootstrap_receipt is not None:
        launcher_trust = production_env_binding.get("launcher_trust")
        require(
            isinstance(launcher_trust, dict),
            "launcher-enforced readiness is missing its production env trust binding",
        )
        launcher_trust["bootstrap_receipt"] = bootstrap_receipt
        launcher_trust["nonce_rollback_assurance"] = (
            nonce_rollback_assurance
        )
    production_env = load_production_env_snapshot(
        final_file_snapshots["production_readiness_env"]
    )
    args.proxy_proof_max_age_seconds = production_env_binding[
        "proxy_proof_max_age_seconds"
    ]
    args.docker_executable = production_env_binding["docker_executable"]
    args.docker_compose_plugin_executable = production_env_binding[
        "docker_compose_plugin_executable"
    ]
    args.docker_unix_socket = production_env_binding["docker_unix_socket"]
    args.docker_daemon_id = production_env_binding["docker_daemon_id"]
    if legacy_final_mode:
        production_env_binding["executing_interpreter"] = verify_current_interpreter_binding(
            production_env,
            production_env_binding["current_executable_digests"],
        )
        production_env_binding["executing_script"] = verify_current_script_binding(
            production_env
        )
    trusted_release_public_key_pem = snapshot_text(
        final_file_snapshots["release_provenance_trusted_public_key"],
        "release provenance trust root",
        encoding="ascii",
    )
    trusted_sigstore_public_key_pem = snapshot_text(
        final_file_snapshots["sigstore_trusted_public_key"],
        "Sigstore trust root",
        encoding="ascii",
    )
    trusted_rekor_public_key_pem = snapshot_text(
        final_file_snapshots["rekor_trusted_public_key"],
        "Rekor trust root",
        encoding="ascii",
    )
    trusted_external_public_key_pem = snapshot_text(
        final_file_snapshots["external_checkpoint_trusted_public_key"],
        "external checkpoint trust root",
        encoding="ascii",
    )
    trusted_external_log_id = release_public_key_id(trusted_external_public_key_pem)
    require(
        readiness_summary["external_transparency_provider"] == args.external_checkpoint_provider,
        "live readiness external transparency provider does not match the independently expected provider",
    )
    require(
        readiness_summary["external_transparency_log_id"] == trusted_external_log_id,
        "live readiness external transparency log does not match the independently trusted key",
    )
    require(
        hmac.compare_digest(
            ed25519_public_key_id(
                trusted_control_plane_response_signing_public_key_pem,
                "control-plane response signing trust root",
            ),
            production_env_binding[
                "control_plane_response_signing_public_key_id"
            ],
        ),
        "loaded control-plane response signing trust root identity differs from the hashed production readiness env binding",
    )
    for loaded_key_pem, binding_key, label in (
        (
            trusted_release_public_key_pem,
            "release_provenance_trusted_public_key_id",
            "release provenance trust root",
        ),
        (trusted_sigstore_public_key_pem, "sigstore_trusted_public_key_id", "Sigstore trust root"),
        (trusted_rekor_public_key_pem, "rekor_trusted_public_key_id", "Rekor trust root"),
        (
            trusted_external_public_key_pem,
            "external_checkpoint_trusted_public_key_id",
            "external checkpoint trust root",
        ),
    ):
        require(
            release_public_key_id(loaded_key_pem) == production_env_binding[binding_key],
            f"loaded {label} identity differs from the hashed production readiness env binding",
        )
    nitro_summary = verify_nitro_evidence(nitro_evidence, "standalone Nitro/KMS evidence")
    nitro_binding = verify_nitro_binding(readiness_summary, nitro_summary, preflight_summary)
    hardware_assurance_summary = None
    hardware_assurance_document = None
    trusted_hardware_verifier_public_key_pem = None
    trusted_final_challenge_authority_public_key_pem = None
    if args.hardware_assurance:
        hardware_assurance_document = load_json_snapshot(
            final_file_snapshots["hardware_assurance"],
            "hardware assurance",
        )
        trusted_hardware_verifier_public_key_pem = snapshot_text(
            final_file_snapshots["hardware_assurance_trusted_public_key"],
            "hardware assurance trust root",
            encoding="ascii",
        )
        if legacy_final_mode:
            require(
                hmac.compare_digest(
                    release_public_key_id(trusted_hardware_verifier_public_key_pem),
                    production_env_binding["hardware_assurance_trusted_public_key_id"],
                ),
                "loaded hardware assurance trust root identity differs from the hashed production readiness env binding",
            )
    if legacy_final_mode:
        trusted_final_challenge_authority_public_key_pem = snapshot_text(
            final_file_snapshots["final_challenge_authority_public_key"],
            "final challenge authority trust root",
            encoding="ascii",
        )
        require(
            hmac.compare_digest(
                release_public_key_id(trusted_final_challenge_authority_public_key_pem),
                production_env_binding["final_challenge_authority_public_key_id"],
            ),
            "loaded final challenge authority trust root identity differs from the hashed production readiness env binding",
        )
    provenance_summary_out = verify_release_provenance(
        provenance_summary,
        provenance_document,
        str(readiness_summary["external_transparency_provider"]),
        str(readiness_summary["external_transparency_log_id"]),
        trusted_release_public_key_pem,
        trusted_external_public_key_pem,
    )
    require(
        preflight_summary["production_compose_sha256"] == provenance_summary_out["compose_config_sha256"],
        "production host rendered Compose digest does not match signed release provenance",
    )
    provenance_summary_out["production_host_compose_bound"] = True
    current_source_tree_digest = build_production_images.source_tree_digest()
    require(
        provenance_summary_out["source_tree_digest"] == current_source_tree_digest,
        "release provenance source tree digest does not match current source tree",
    )
    provenance_summary_out["current_source_tree_digest"] = current_source_tree_digest
    provenance_summary_out["current_source_tree_bound"] = True
    production_images_build_summary = verify_production_image_build(
        production_images_build,
        str(provenance_summary_out["source_tree_digest"]),
    )
    require(
        production_images_build_summary["launch_authority"]
        == provenance_summary_out["launch_authority"],
        "production image build launch-authority binding does not match signed release provenance",
    )
    production_images_published_summary = verify_published_images(
        production_images_published,
        production_images_build_summary,
        list(readiness_summary["production_images"]),
    )
    build_config_ids = {
        item["service"]: item["image_id"]
        for item in production_images_build_summary["images"]
    }
    require(
        production_images_published_summary["config_ids"] == build_config_ids,
        "published production config IDs do not match the measured build config IDs",
    )
    require(
        provenance_summary_out["image_config_ids"] == build_config_ids,
        "signed release provenance config IDs do not match build and publish evidence",
    )
    running_containers = verify_running_production_containers(
        env_file=stable_paths["production_readiness_env"],
        compose_file=stable_paths["compose_file"],
        production_env=production_env,
        project_directory=paths["compose_file"].parent.resolve(),
        production_image_refs=list(readiness_summary["production_images"]),
        approved_image_config_ids=build_config_ids,
        source_tree_digest=current_source_tree_digest,
        runtime_model=preflight_summary["production_runtime_model"],
        artifact_expectations={
            "/run/serverware/release/release-provenance.json": {
                "sha256": final_file_snapshots["release_provenance"].sha256,
                "bytes": len(final_file_snapshots["release_provenance"].data),
            },
            "/run/serverware/release/image-signatures.json": {
                "sha256": final_file_snapshots["image_signatures"].sha256,
                "bytes": len(final_file_snapshots["image_signatures"].data),
            },
        },
        compose_project_name=production_env_binding[
            "docker_compose_project_name"
        ],
        skip_current_host_check=args.skip_current_host_check,
        docker_executable=args.docker_executable,
        docker_sha256=production_env_binding["current_executable_digests"][
            run_production_readiness.PRODUCTION_DOCKER_EXECUTABLE_ENV
        ],
        compose_plugin_executable=args.docker_compose_plugin_executable,
        compose_plugin_sha256=production_env_binding["docker_compose_plugin_sha256"],
        docker_unix_socket=args.docker_unix_socket,
        docker_daemon_id=args.docker_daemon_id,
        final_mode=legacy_final_mode,
    )
    image_summary_out = verify_image_signatures(
        image_summary,
        image_document,
        provenance_summary_out,
        list(readiness_summary["production_image_digests"]),
        list(readiness_summary["production_images"]),
        str(readiness_summary["sigstore_key_id"]),
        str(readiness_summary["rekor_log_id"]),
        str(readiness_summary["external_transparency_provider"]),
        str(readiness_summary["external_transparency_log_id"]),
        trusted_sigstore_public_key_pem,
        trusted_rekor_public_key_pem,
        trusted_external_public_key_pem,
    )
    benchmark_summary = verify_benchmark(
        bench,
        production_env_binding["p99_limit_ns"],
        str(production_env_binding["expected_data_plane_binary_digest"]),
    )
    production_gate_binary = next(
        (
            item.get("binary_digest")
            for item in production_images_build_summary["images"]
            if item.get("service") == "serverware-decision-gate"
        ),
        None,
    )
    require(
        production_gate_binary == benchmark_summary["data_plane_binary_digest"],
        "benchmark data-plane binary digest does not match the production image binary",
    )
    benchmark_summary["production_image_binary_bound"] = True
    require(
        args.proxy_server_instance_id == production_env_binding["expected_server_instance_id"],
        "proxy response expected server instance does not match the signed production environment",
    )
    attested_runtime = readiness_summary["nitro"]["attested_runtime"]
    require(
        attested_runtime["data_plane_binary_digest"] == production_gate_binary,
        "fresh Nitro-attested data-plane binary digest does not match the production image",
    )
    require(
        attested_runtime["provenance_digest"] == provenance_summary_out["provenance_digest"],
        "fresh Nitro-attested release digest does not match signed release provenance",
    )
    require(
        attested_runtime["source_tree_digest"] == provenance_summary_out["source_tree_digest"],
        "fresh Nitro-attested source tree digest does not match signed release provenance",
    )
    verified_release_identity = validate_release_identity(
        {
            "source_tree_digest": provenance_summary_out["source_tree_digest"],
            "provenance_digest": provenance_summary_out["provenance_digest"],
            "runtime_manifest_digest": attested_runtime["runtime_manifest_digest"],
            "data_plane_binary_digest": attested_runtime["data_plane_binary_digest"],
            "production_image_digests": readiness_summary["production_image_digests"],
            "production_image_refs": readiness_summary["production_images"],
            "production_images_build_sha256": final_file_snapshots["production_images_build"].sha256,
            "production_images_published_sha256": final_file_snapshots["production_images_published"].sha256,
            "image_signature_bundle_digest": image_summary_out["image_signature_bundle_digest"],
        },
        "independently verified release identity",
    )
    if bootstrap_receipt is not None:
        require(
            bootstrap_receipt.get("sourceTreeDigest")
            == provenance_summary_out["source_tree_digest"],
            "sealed launcher receipt source tree does not match signed release provenance",
        )
    if hardware_assurance_document is not None:
        require(
            trusted_hardware_verifier_public_key_pem is not None,
            "hardware assurance trusted verifier key was not loaded",
        )
        hardware_assurance_summary = verify_hardware_assurance(
            hardware_assurance_document,
            trusted_public_key_pem=trusted_hardware_verifier_public_key_pem,
            expected_trusted_public_key_id=(
                args.hardware_assurance_trusted_public_key_id
                if legacy_final_mode
                else None
            ),
            hardware_assurance_document_sha256=final_file_snapshots[
                "hardware_assurance"
            ].sha256,
            nitro_summary=nitro_summary,
            nitro_evidence_sha256=final_file_snapshots["nitro_evidence"].sha256,
            production_host_preflight_sha256=final_file_snapshots["production_host_preflight"].sha256,
            current_host=current_host_summary,
            expected_release_identity=verified_release_identity,
            expected_challenge_nonce=args.hardware_assurance_expected_challenge_nonce,
            expected_challenge_nonce_sha256=args.hardware_assurance_expected_challenge_nonce_sha256,
        )
    production_continuity: dict[str, Any] | None = None
    if legacy_final_mode:
        require(
            hardware_assurance_summary is not None,
            "final Manifest v6 continuity requires verified hardware assurance",
        )
        production_continuity = verify_production_continuity(
            snapshots=final_file_snapshots,
            expected_policy_hash=str(attested_runtime["policy_digest"]),
            expected_challenge_nonce_sha256=hardware_assurance_summary[
                "challenge_nonce_sha256"
            ],
        )
        require(
            production_continuity["eif"]["eif_file_sha384"]
            == hardware_assurance_summary["eif"]["image_sha384"]
            and production_continuity["eif"]["pcrs"]
            == hardware_assurance_summary["pcrs"],
            "Manifest v6 EIF identity or PCRs differ from hardware assurance",
        )
    release_security_summary = verify_release_security_evidence(
        snapshots=final_file_snapshots,
        production_build=production_images_build_summary,
        benchmark=benchmark_summary,
        attested_runtime=attested_runtime,
        preflight=preflight_summary,
        directly_verified_builders=(
            production_continuity["builders"]
            if production_continuity is not None
            else None
        ),
    )
    require(
        final_file_snapshots["reproducible_build_verification"].sha256
        == provenance_summary_out["reproducible_build_verification_sha256"],
        "release provenance does not bind the exact reproducible-build verification artifact",
    )
    require(
        (release_security_summary.get("reproducible_builds") or {}).get(
            "reportSha256"
        )
        == provenance_summary_out["reproducible_build_verification_sha256"],
        "verified reproducible-build report does not match signed release provenance",
    )
    verified_builders = (
        release_security_summary.get("reproducible_builds") or {}
    ).get("builders")
    require(
        verified_builders
        == provenance_summary_out["reproducible_build_builders"],
        "signed release provenance builder identities do not match the independently verified reproducible-build report",
    )
    if production_continuity is not None:
        raw_builder_key_ids = {
            production_continuity["builders"]["left"]["signing_key_id"],
            production_continuity["builders"]["right"]["signing_key_id"],
        }
        mediated_builder_key_ids = {
            item["key_id"] for item in verified_builders
        }
        require(
            raw_builder_key_ids == mediated_builder_key_ids,
            "raw builder statements do not match the independently configured reproducible-builder identities",
        )
    if bootstrap_receipt is not None:
        launcher_authorization = verify_bootstrap_launcher_authorization(
            bootstrap_receipt,
            signed_provenance_digest=provenance_summary_out[
                "production_launcher_binary_digest"
            ],
            independently_reproduced_digest=(
                release_security_summary.get("reproducible_builds") or {}
            ).get("productionLauncherBinaryDigest"),
        )
        launcher_authorization["launch_authorization"] = (
            verify_bootstrap_launch_authorization_bindings(
                bootstrap_receipt,
                signed_provenance_digest=provenance_summary_out[
                    "provenance_digest"
                ],
                signed_source_tree_digest=provenance_summary_out[
                    "source_tree_digest"
                ],
                release_provenance_sha256=final_file_snapshots[
                    "release_provenance"
                ].sha256,
                reproducible_build_verification_sha256=final_file_snapshots[
                    "reproducible_build_verification"
                ].sha256,
                current_host_identity_sha256=current_host_summary["identity"][
                    "identity_sha256"
                ],
                release_artifact_launch_authority=production_images_build_summary[
                    "launch_authority"
                ],
                nonce_rollback_assurance=nonce_rollback_assurance,
                launch_manifest_v3=launch_manifest_v3,
            )
        )
        provenance_summary_out["executed_production_launcher"] = launcher_authorization
        release_security_summary["reproducible_builds"][
            "executedProductionLauncherBound"
        ] = True
    policy_snapshot = verify_and_compile_policy_snapshot(
        final_file_snapshots["policy_bundle"],
        final_file_snapshots["policy_trusted_public_key"],
        expected_policy_digest=str(attested_runtime["policy_digest"]),
    )
    proxy_response_summary = verify_production_proxy_response_proof(
        proxy_response_proof,
        proof_contract=production_env_binding["proxy_proof_contract"],
        streamed_body_snapshot=final_file_snapshots.get("proxy_stream_body"),
        observation_body_snapshot=final_file_snapshots.get(
            "proxy_observation_body"
        ),
        expected_operation_context_digest=production_env_binding[
            "proxy_operation_context_digest"
        ],
        trusted_verifier_public_key_pem=trusted_proxy_verifier_public_key_pem,
        trusted_collector_public_key_pem=trusted_proxy_collector_public_key_pem,
        trusted_control_plane_response_signing_public_key_pem=(
            trusted_control_plane_response_signing_public_key_pem
        ),
        expected_control_plane_response_signing_public_key_id=(
            args.control_plane_response_signing_public_key_id
        ),
        policy_snapshot=policy_snapshot,
        expected_principal_id=production_env_binding[
            "expected_proxy_principal_id"
        ],
        expected_server_instance_id=str(args.proxy_server_instance_id),
        expected_client_nonce=str(args.proxy_client_nonce),
        expected_client_request_digest=str(args.proxy_client_request_digest),
        expected_request_digest=str(args.proxy_request_digest),
        expected_operation_digest=str(args.proxy_operation_digest),
        expected_tls_channel_binding=str(args.proxy_tls_channel_binding),
        expected_policy_digest=str(attested_runtime["policy_digest"]),
        expected_runtime_manifest_digest=str(attested_runtime["runtime_manifest_digest"]),
        expected_binary_digest=str(attested_runtime["data_plane_binary_digest"]),
        expected_release_digest=str(attested_runtime["provenance_digest"]),
        expected_image_signatures_digest=str(
            image_summary_out["image_signature_bundle_digest"]
        ),
        expected_source_tree_digest=str(attested_runtime["source_tree_digest"]),
        expected_response_signing_key_id=str(attested_runtime["response_signing_key_id"]),
        expected_tee_platform=str(nitro_summary["tee_platform"]),
        expected_quote_provider=str(nitro_summary["provider"]),
        max_age_seconds=args.proxy_proof_max_age_seconds,
    )
    if production_env_binding["proxy_proof_contract"] == "observation-v1":
        observation_body_snapshot = final_file_snapshots["proxy_observation_body"]
        proxy_response_summary["observed_body_artifact"] = {
            "path": str(observation_body_snapshot.path),
            "sha256": observation_body_snapshot.sha256,
            "bytes": len(observation_body_snapshot.data),
            "max_bytes": production_env_binding[
                "proxy_max_observation_body_bytes"
            ],
        }
        proxy_response_summary["observed_body_artifact_bound"] = True
    require(
        proxy_response_summary["collector_signing_key_id"]
        == production_env_binding["expected_proxy_collector_key_id"],
        "proxy response collector key does not match the signed production environment pin",
    )
    require(
        proxy_response_summary["trusted_verifier_key_id"]
        == production_env_binding["expected_proxy_verifier_key_id"],
        "proxy response vendor verifier key does not match the signed production environment pin",
    )
    candidate_assurance = completion_assurance(hardware_assurance_summary, current_host_summary)
    final_challenge_consumption: dict[str, Any] | None = None
    completion_identity: dict[str, Any] | None = None
    completion_identity_sha256: str | None = None
    if legacy_final_mode:
        require(
            candidate_assurance.get("final_completion") is True,
            "final verification mode did not satisfy hardware-backed final completion requirements",
        )
        require(hardware_assurance_summary is not None, "final verification mode is missing hardware assurance summary")
        require(
            isinstance(verified_builders, list) and len(verified_builders) == 2,
            "final verification mode is missing both independently verified builders",
        )
        require(
            production_continuity is not None,
            "final verification mode is missing Manifest v6 production continuity",
        )
        _, completion_authentication_key = load_ed25519_trust_root(
            final_file_snapshots["completion_authentication_public_key"],
            "completion proof authentication trust root",
        )
        _, completion_checkpoint_key = load_ed25519_trust_root(
            final_file_snapshots["completion_checkpoint_public_key"],
            "completion proof checkpoint trust root",
        )
        launch_authorization_identity = launcher_authorization[
            "launch_authorization"
        ]
        security_role_map = verify_launch_authority_key_role_separation(
            launch_authorization_identity["authority_key_id"],
            {
                "release_provenance_signer": provenance_summary_out[
                    "release_signing_key_id"
                ],
                "image_signature_signer": image_summary_out[
                    "image_signing_key_id"
                ],
                "rekor_transparency_log": production_env_binding[
                    "rekor_trusted_public_key_id"
                ],
                "external_checkpoint_log": production_env_binding[
                    "external_checkpoint_trusted_public_key_id"
                ],
                "control_plane_response_signer": proxy_response_summary[
                    "control_plane_response_signing_key_id"
                ],
                "policy_identity_signer": production_env_binding[
                    "policy_trusted_public_key_id"
                ],
                "policy_activation_signer": production_env_binding[
                    "policy_activation_trusted_public_key_id"
                ],
                "reproducible_build_report_signer": production_env_binding[
                    "reproducible_build_trusted_public_key_id"
                ],
                "reproducible_builder_left": verified_builders[0]["key_id"],
                "reproducible_builder_right": verified_builders[1]["key_id"],
                "production_host_preflight_signer": preflight_summary[
                    "authenticity"
                ]["key_id"],
                "proxy_proof_collector": proxy_response_summary[
                    "collector_signing_key_id"
                ],
                "proxy_response_statement_signer": proxy_response_summary[
                    "response_signing_key_id"
                ],
                "proxy_vendor_tee_verifier": proxy_response_summary[
                    "trusted_verifier_key_id"
                ],
                "hardware_assurance_verifier": hardware_assurance_summary[
                    "trusted_verifier_key_id"
                ],
                "final_challenge_authority": production_env_binding[
                    "final_challenge_authority_public_key_id"
                ],
                "source_git_inventory_authority": production_continuity[
                    "source"
                ]["git_inventory_key_id"],
                "source_untracked_approval_authority": production_continuity[
                    "source"
                ]["untracked_approval_key_id"],
                "build_watchdog_signer": production_continuity[
                    "buildWatchdog"
                ]["signing_key_id"],
                "promotion_receipt_signer": production_continuity[
                    "promotion"
                ]["signing_key_id"],
                "manifest_v6_eif_builder": production_continuity["eif"][
                    "signing_key_id"
                ],
                "key_custody_verifier": production_continuity["keyCustody"][
                    "signing_key_id"
                ],
                "monotonic_release_witness": production_continuity[
                    "monotonicWitness"
                ]["signing_key_id"],
                "completion_proof_authenticator": completion_authentication_key[
                    "spki_sha256"
                ],
                "completion_proof_checkpoint": completion_checkpoint_key[
                    "spki_sha256"
                ],
            },
        )
        provenance_summary_out["security_role_map"] = security_role_map
        completion_identity = final_completion_identity(
            hardware_assurance_summary,
            bootstrap_receipt=bootstrap_receipt,
            current_host_identity_sha256=current_host_summary["identity"]["identity_sha256"],
            key_custody_evidence_sha256=production_continuity["keyCustody"][
                "file_sha256"
            ],
            monotonic_witness_sha256=production_continuity[
                "monotonicWitness"
            ]["file_sha256"],
            production_continuity_sha256=production_continuity[
                "continuitySha256"
            ],
            production_release_identity_sha256=production_continuity[
                "productionReleaseIdentity"
            ]["productionReleaseIdentitySha256"],
            proxy_server_statement_sha256=proxy_response_summary["server_statement_sha256"],
            security_role_map_sha256=security_role_map["sha256"],
        )
        completion_identity_sha256 = sha256_prefixed_json(completion_identity)
        final_challenge_consumption = verify_final_challenge_receipt(
            load_json_snapshot(
                final_file_snapshots["final_challenge_receipt"],
                "final challenge receipt",
            ),
            trusted_public_key_pem=str(trusted_final_challenge_authority_public_key_pem),
            expected_trusted_public_key_id=str(
                args.final_challenge_authority_public_key_id
            ),
            final_challenge_receipt_sha256=final_file_snapshots[
                "final_challenge_receipt"
            ].sha256,
            expected_provider=str(args.final_challenge_authority_provider),
            expected_challenge_nonce_sha256=hardware_assurance_summary["challenge_nonce_sha256"],
            expected_completion_identity_sha256=completion_identity_sha256,
            expected_release_identity_sha256=hardware_assurance_summary["release_identity_sha256"],
            expected_hardware_verifier_key_id=hardware_assurance_summary["trusted_verifier_key_id"],
            expected_current_host_identity_sha256=current_host_summary["identity"]["identity_sha256"],
            expected_proxy_server_statement_sha256=proxy_response_summary["server_statement_sha256"],
            hardware_assurance_issued_at_unix=hardware_assurance_summary["issued_at_unix"],
        )
        require(
            final_challenge_consumption["authority_key_id"]
            == security_role_map["roles"]["final_challenge_authority"],
            "consumed final challenge authority differs from the approved security role map",
        )
        final_challenge_consumption["completion_identity"] = completion_identity
        assurance = candidate_assurance
    else:
        assurance = candidate_assurance

    proof_generated_at_unix = int(time.time())
    proof = {
        "apiVersion": COMPLETION_PROOF_API_VERSION,
        "kind": "ServerwarePreEnclaveReadiness",
        "verificationOk": True,
        "finalCompletionVerified": False,
        "actionAuthorization": None,
        "okForAction": False,
        "verification_passed": True,
        "verification_mode": "readiness",
        "result_scope": "readiness-only",
        "readiness_only": True,
        "readiness_ok": True,
        "completion_status": "pre-enclave-readiness",
        "release_completion": "not-final",
        "hardware_proof": False,
        "assurance_ceiling": assurance,
        "generated_at_unix": proof_generated_at_unix,
        "artifacts": {
            label: {
                "path": str(snapshot.path),
                "sha256": snapshot.sha256,
            }
            for label, snapshot in sorted(final_file_snapshots.items())
            if label
            not in {
                "completion_proof_authentication",
                "completion_authentication_public_key",
                "completion_proof_checkpoint",
                "completion_checkpoint_public_key",
            }
        },
        "production_readiness": readiness_summary,
        "production_readiness_config": production_config_summary,
        "current_completion_host": current_host_summary,
        "production_env_binding": production_env_binding,
        "running_production_containers": running_containers,
        "production_host_preflight": preflight_summary,
        "bootstrap_launcher": bootstrap_receipt
        if bootstrap_receipt is not None
        else {"required": False, "verified": False},
        "nonce_rollback_assurance": {
            **nonce_rollback_assurance,
            "launchManifest": launch_manifest_v3,
            "purpose": "readiness-only",
        },
        "nitro_kms_evidence": nitro_summary,
        "nitro_evidence_binding": nitro_binding,
        "hardware_assurance_evidence": hardware_assurance_summary
        if hardware_assurance_summary is not None
        else {"provided": False, "verified": False},
        "final_challenge_consumption": {
            "required": False,
            "consumed": False,
        },
        "production_images_build": production_images_build_summary,
        "production_images_published": production_images_published_summary,
        "release_provenance": provenance_summary_out,
        "image_signatures": image_summary_out,
        "benchmark": benchmark_summary,
        "release_security_evidence": release_security_summary,
        "production_proxy_response_proof": proxy_response_summary,
        "production_continuity": {
            "required": False,
            "verified": False,
            "pipeline": "readiness-only",
        },
    }
    proof_core_sha256 = sha256_prefixed_json(proof)
    proof["proof_core_sha256"] = proof_core_sha256
    proof["independently_authenticated"] = False
    proof["aggregate_authentication"] = {
        "required": False,
        "independently_authenticated": False,
        "scope": "readiness-only",
    }
    proof["proof_path"] = args.out
    generation = secrets.token_hex(16)
    proof_digest_path = completion_proof_digest_path(Path(args.out), generation)
    proof["integrity_metadata"] = {
        "generation": generation,
        "detached_sha256_path": str(proof_digest_path),
        "scope": "checksum-only",
        "independently_authenticated": False,
        "authenticity_requires_external_signature_or_checkpoint": True,
    }
    before_output_publication = None
    if bootstrap_receipt is not None:
        def revalidate_before_output_publication() -> None:
            (
                run_production_readiness
                .revalidate_bootstrap_launch_authorization_at_completion(
                    expected_receipt=bootstrap_receipt,
                    expected_descriptor=bootstrap_receipt_fd,
                    generated_at_unix=proof_generated_at_unix,
                )
            )

        before_output_publication = revalidate_before_output_publication

    write_output(
        Path(args.out),
        proof,
        before_output_publication=before_output_publication,
    )
    print(canonical_json(proof))
    stable_input_directory.cleanup()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(
            canonical_json(
                {
                    "apiVersion":
                    "serverware.releaseCompletionError/v1",
                    "error": str(exc),
                }
            ),
            file=sys.stderr,
        )
        raise SystemExit(1) from exc
