from __future__ import annotations

import base64
import binascii
import copy
import errno
import fcntl
import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import select
import shutil
import shlex
import signal
import socket
import sqlite3
import ssl
import stat
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtensionOID

from serverware import __version__, db
from serverware.config import (
    DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED,
    DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND,
    EXPECTED_DATA_PLANE_BINARY_DIGEST,
    IMAGE_SIGNATURES_PATH,
    KEY_RELEASE_ALLOW_DEBUG,
    KEY_RELEASE_REQUIRED,
    KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST,
    MASTER_KEY_UNSEAL_COMMAND,
    MITMPROXY_CONF_DIR,
    NITRO_NSM_UNSEAL_COMMAND_TEMPLATE,
    POLICY_MIN_ROLLBACK_EPOCH,
    POLICY_MIN_SEQUENCE,
    RELEASE_CHANNEL,
    RELEASE_PROVENANCE_PATH,
    SECRET_LEASE_TTL_SECONDS,
    TEE_PLATFORM,
    TEE_QUOTE_COMMAND,
    TEE_QUOTE_PROVIDER,
    TEE_QUOTE_SIGNING_KEY_PATH,
    TEE_QUOTE_VERIFY_COMMAND,
    WEB_TLS_CERT_FILE,
    ensure_data_dirs,
)
from serverware.policy_bundle import (
    get_policy_snapshot,
    policy_public_key_hash,
    policy_public_key_pem,
    strict_json_loads,
)
from serverware.response_identity import (
    response_public_key_info,
    sign_statement as sign_response_statement,
)


PRODUCTION_ATTESTATION_API_VERSION = "serverware.productionAttestation/v2"
PRODUCTION_ATTESTATION_CLAIMS_VERSION = "serverware.productionAttestationClaims/v2"
PRODUCTION_IDENTITY_VERSION = "serverware.productionAttestationIdentity/v2"
FINAL_COMPLETION_IDENTITY_VERSION = "serverware.finalCompletionIdentity/v3"
FINAL_COMPLETION_CORE_VERSIONS = {
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
FINAL_COMPLETION_CORE_FIELDS = frozenset(
    {*FINAL_COMPLETION_CORE_VERSIONS, "continuity"}
)
FINAL_COMPLETION_BINDING_FIELDS = frozenset(
    {
        "completionIdentity",
        "completionIdentitySha256",
        "completion_identity",
        "completion_identity_sha256",
    }
)
PRODUCTION_RUNTIME_STATE_VERSION = "serverware.productionAttestationRuntime/v2"
KEY_CUSTODY_VERSION = "serverware.enclaveKeyCustody/v3"
PROMOTED_MANIFEST_VERSION = "serverware.consolidatedTestArtifacts/v6"
PUBLIC_EVIDENCE_BUNDLE_VERSION = "serverware.publicAttestationBundle/v3"
PUBLIC_VERIFIER_INPUT_VERSION = "serverware.publicNitroVerificationBundle/v2"
PUBLIC_EVIDENCE_CHECKPOINT_VERSION = "serverware.publicEvidenceCheckpoint/v1"
PUBLIC_RELEASE_GRAPH_VERSION = "serverware.publicReleaseGraph/v1"
RELEASE_IDENTITY_VERSION = "serverware.releaseIdentity/v1"
LIVE_SESSION_PROOF_VERSION = "serverware.liveSessionProof/v1"
PUBLIC_ATTESTATION_DELIVERY_REBIND_VERSION = (
    "serverware.publicAttestationDeliveryRebind/v2"
)
SIGNED_PUBLIC_ATTESTATION_DELIVERY_REBIND_VERSION = (
    "serverware.signedPublicAttestationDeliveryRebind/v2"
)
PUBLIC_ATTESTATION_RECOVERY_JOURNAL_SEALED_ENTRY_VERSION = (
    "serverware.publicAttestationRecoveryJournalSealedEntry/v1"
)
PUBLIC_ATTESTATION_RECOVERY_MATERIAL_DOMAIN = (
    b"serverware.publicAttestationRecoveryMaterial/v1\x00"
)
LIVE_WITNESS_HEAD_VERSION = "serverware.liveWitnessHead/v1"
STABLE_RELEASE_STATEMENT_VERSION = (
    "serverware.stableReleaseStatement/v1"
)
PUBLIC_EVIDENCE_REQUEST_VERSION = (
    "serverware.publicAttestationRequest/v1"
)
PUBLIC_EVIDENCE_PRODUCER_DESCRIPTOR_VERSION = (
    "serverware.publicAttestationProducerDescriptor/v2"
)
PUBLIC_EVIDENCE_PRODUCER_REQUEST_VERSION = (
    "serverware.publicAttestationProducerRequest/v2"
)
PUBLIC_EVIDENCE_LIVE_REQUEST_VERSION = (
    "serverware.publicAttestationLiveRequest/v1"
)
PUBLIC_EVIDENCE_PRODUCER_BINDING_VERSION = (
    "serverware.publicAttestationProducerBinding/v3"
)
SIGNED_PUBLIC_EVIDENCE_PRODUCER_BINDING_VERSION = (
    "serverware.signedPublicAttestationProducerBinding/v1"
)
PUBLIC_EVIDENCE_SANDBOX_VERSION = (
    "serverware.publicAttestationExecutionSandbox/v2"
)
PUBLIC_EVIDENCE_CONFIG_VERSION = "serverware.publicAttestationConfig/v2"
PROTECTED_LIVE_WITNESS_STATE_VERSION = (
    "serverware.protectedLiveWitnessState/v2"
)
PUBLIC_EVIDENCE_NONCE_CONSUMPTION_VERSION = (
    "serverware.publicAttestationNonceConsumption/v1"
)
PUBLIC_EVIDENCE_VERIFIER_STATE_CLIENT_VERSION = (
    "serverware.attestationVerifierStateClient/v2"
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
SIGNED_NONCE_AUTHORITY_VERIFIER_STATE_VERSION = (
    "serverware.signedNonceAuthorityVerifierState/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_VERSION = (
    "serverware.nonceAuthorityVerifierState/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_VERSION = (
    "serverware.nonceAuthorityVerifierStatePreparedAuthorization/v3"
)
NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_VERSION = (
    "serverware.nonceAuthorityVerifierStateCommitReceipt/v3"
)
NONCE_AUTHORITY_VERIFIER_STATE_READ_REQUEST_VERSION = (
    "serverware.nonceAuthorityVerifierStateReadRequest/v2"
)
NONCE_AUTHORITY_VERIFIER_STATE_READ_RESPONSE_VERSION = (
    "serverware.nonceAuthorityVerifierStateReadResponse/v3"
)
NONCE_AUTHORITY_VERIFIER_STATE_ISSUE_CHALLENGE_REQUEST_VERSION = (
    "serverware.attestationVerifierStateIssueChallengeRequest/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_ISSUE_CHALLENGE_RESPONSE_VERSION = (
    "serverware.attestationVerifierStateIssueChallengeResponse/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_RECOVER_CHALLENGE_REQUEST_VERSION = (
    "serverware.attestationVerifierStateRecoverChallengeRequest/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_RECOVER_CHALLENGE_RESPONSE_VERSION = (
    "serverware.attestationVerifierStateRecoverChallengeResponse/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_PREPARE_REQUEST_VERSION = (
    "serverware.attestationVerifierStatePrepareRequest/v4"
)
NONCE_AUTHORITY_VERIFIER_STATE_PREPARE_RESPONSE_VERSION = (
    "serverware.attestationVerifierStatePrepareResponse/v4"
)
NONCE_AUTHORITY_VERIFIER_STATE_PREPARED_OPERATION_VERSION = (
    "serverware.attestationVerifierStatePreparedOperation/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_REQUEST_BINDING_VERSION = (
    "serverware.attestationVerifierStateRequestBinding/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_BINDING_VERSION = (
    "serverware.attestationVerifierStateRecoveryBinding/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_IDENTITY_VERSION = (
    "serverware.attestationVerifierStateRecoveryIdentity/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_SUCCESSOR_INTENT_VERSION = (
    "serverware.attestationVerifierStateSuccessorIntent/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_MARK_CONSUMPTION_REQUEST_VERSION = (
    "serverware.attestationVerifierStateMarkConsumptionRequest/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_MARK_CONSUMPTION_RESPONSE_VERSION = (
    "serverware.attestationVerifierStateMarkConsumptionResponse/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_ATTACH_NONCE_STATUS_REQUEST_VERSION = (
    "serverware.attestationVerifierStateAttachNonceStatusRequest/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_ATTACH_NONCE_STATUS_RESPONSE_VERSION = (
    "serverware.attestationVerifierStateAttachNonceStatusResponse/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_REQUEST_VERSION = (
    "serverware.attestationVerifierStateCommitRequest/v3"
)
NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_REQUEST_VERSION = (
    "serverware.attestationVerifierStateRecoveryRequest/v3"
)
NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_RESPONSE_VERSION = (
    "serverware.attestationVerifierStateRecoveryResponse/v3"
)
NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_LOOKUP_REQUEST_VERSION = (
    "serverware.attestationVerifierStateRecoveryLookupRequest/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_LOOKUP_RESPONSE_VERSION = (
    "serverware.attestationVerifierStateRecoveryLookupResponse/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_ABORT_REQUEST_VERSION = (
    "serverware.attestationVerifierStateAbortRequest/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_ABORT_RESPONSE_VERSION = (
    "serverware.attestationVerifierStateAbortResponse/v1"
)
NONCE_AUTHORITY_VERIFIER_STATE_TRANSITION_VERSION = (
    "serverware.nonceAuthorityVerifierStateTransition/v3"
)
SIGNED_VERIFIER_STATE_STORE_COMMIT_PROOF_VERSION = (
    "serverware.signedVerifierStateStoreCommitProof/v3"
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
VERIFIER_STATE_STORE_COMMIT_PROOF_VERSION = (
    "serverware.verifierStateStoreCommitProof/v3"
)
VERIFIER_STATE_STORE_COMMIT_CANDIDATE_VERSION = (
    "serverware.verifierStateStoreCommitCandidate/v2"
)
NONCE_TRANSACTION_STATUS_REQUEST_VERSION = (
    "serverware.attestationNonceTransactionStatusRequest/v1"
)
NONCE_TRANSACTION_STATUS_RESPONSE_VERSION = (
    "serverware.attestationNonceTransactionStatusResponse/v1"
)
SIGNED_NONCE_TRANSACTION_STATUS_EVIDENCE_VERSION = (
    "serverware.signedAttestationNonceTransactionStatusEvidence/v1"
)
NONCE_TRANSACTION_STATUS_EVIDENCE_VERSION = (
    "serverware.attestationNonceTransactionStatusEvidence/v1"
)
TRUSTED_TLS_SCOPE_VERSION = "serverware.enclaveTlsScope/v2"
TRUSTED_TLS_SCOPE_ENVELOPE_VERSION = "serverware.enclaveTlsScopeEnvelope/v2"
TRUSTED_TLS_SCOPE_EXTENSION = "serverware.enclave_tls_scope"
ATTESTATION_RESPONSE_STATEMENT_VERSION = "serverware.attestationResponse/v2"
PRODUCTION_PIPELINE = "manifest-v6-promoted-oci-nitro-eif"
RUNTIME_MANIFEST_DIGEST_VERSION = "serverware.runtimeManifestDigest/v2"
NITRO_USER_DATA_PREFIX = b"serverware:nitro-production-claims:v2:"
TLS_SCOPE_SIGNATURE_DOMAIN = (
    b"serverware.enclaveTlsScopeEnvelope/v2\x00Ed25519\x00"
)
KEY_GENERATION_SIGNATURE_DOMAIN = (
    b"serverware.enclaveKeyGeneration/v1\x00Ed25519\x00"
)
KEY_GENERATION_USER_DATA_PREFIX = b"serverware:key-generation:v1:"
NONCE_AUTHORITY_ASSURANCE_EVIDENCE_DOMAIN = (
    b"serverware.nonceAuthorityAssuranceEvidence/v1\x00Ed25519\x00"
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
NONCE_TRANSACTION_STATUS_EVIDENCE_DOMAIN = (
    b"serverware.attestationNonceTransactionStatusEvidence/v1\x00"
    b"Ed25519\x00"
)
NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_KEY_DOMAIN = (
    b"serverware.attestationVerifierStateRecoveryKey/v1\x00"
)
NONCE_AUTHORITY_VERIFIER_STATE_OPERATION_ID_DOMAIN = (
    b"serverware.attestationVerifierStateOperationId/v1\x00"
)
NONCE_AUTHORITY_VERIFIER_STATE_REQUEST_BINDING_DOMAIN = (
    b"serverware.attestationVerifierStateRequestBinding/v1\x00"
)
VERIFIER_STATE_STORE_COMMIT_PROOF_DOMAIN = (
    b"serverware.verifierStateStoreCommitProof/v3\x00Ed25519\x00"
)
VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_DOMAIN = (
    b"serverware.verifierStateStoreAssuranceEvidence/v1\x00Ed25519\x00"
)
VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_DOMAIN = (
    b"serverware.verifierStateRoleSeparationEvidence/v1\x00Ed25519\x00"
)
NONCE_AUTHORITY_VERIFIER_STATE_HEAD_DOMAIN = (
    b"serverware.nonceAuthorityVerifierStateHead/v1\x00"
)
PUBLIC_EVIDENCE_PRODUCER_BINDING_DOMAIN = (
    b"serverware.publicAttestationProducerBinding/v3\x00Ed25519\x00"
)

_SHA256_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SHA384_RE = re.compile(r"sha384:[0-9a-f]{96}\Z")
_IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@+-]{0,255}\Z")
_DEVELOPMENT_RELEASE_CHANNELS = {"dev", "development", "local", "test"}
_MAX_PRODUCTION_ARTIFACT_BYTES = 8 * 1024 * 1024
_MAX_PUBLIC_BUNDLE_BYTES = 4 * 1024 * 1024
_MAX_NITRO_TRUST_BUNDLE_BYTES = 512 * 1024
_CBPF_INSTRUCTION = struct.Struct("<HBBI")
_BPF_LD_W_ABS = 0x20
_BPF_JMP_JEQ_K = 0x15
_BPF_RET_K = 0x06
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_SECCOMP_RET_ALLOW = 0x7FFF0000
_X32_SYSCALL_BIT = 0x40000000
_AUDIT_ARCHITECTURES = {
    "x86_64": 0xC000003E,
    "aarch64": 0xC00000B7,
}
_PUBLIC_EVIDENCE_KERNEL_ABIS = {
    "x86_64": {
        "auditArchitecture": 0xC000003E,
        "syscallTableId": "linux-uapi-x86_64-serverware-v1",
        "syscallTableSha256":
            "sha256:2e3b41282fd357204e77d43bf1b9cd9fcf7bfc271c32513bb813052d099e8e0b",
        "syscalls": {
            "brk": 12,
            "clock_gettime": 228,
            "close": 3,
            "execveat": 322,
            "exit": 60,
            "exit_group": 231,
            "fstat": 5,
            "futex": 202,
            "getpid": 39,
            "getrandom": 318,
            "gettid": 186,
            "lseek": 8,
            "read": 0,
            "rt_sigreturn": 15,
            "seccomp": 317,
            "write": 1,
        },
    },
    "aarch64": {
        "auditArchitecture": 0xC00000B7,
        "syscallTableId": "linux-uapi-aarch64-serverware-v1",
        "syscallTableSha256":
            "sha256:2111fcbddd04d564b6d478b442b7cd543bf1075b13ce4eef7f9d42677070f21f",
        "syscalls": {
            "brk": 214,
            "clock_gettime": 113,
            "close": 57,
            "execveat": 281,
            "exit": 93,
            "exit_group": 94,
            "fstat": 80,
            "futex": 98,
            "getpid": 172,
            "getrandom": 278,
            "gettid": 178,
            "lseek": 62,
            "read": 63,
            "rt_sigreturn": 139,
            "seccomp": 277,
            "write": 64,
        },
    },
}
_PUBLIC_EVIDENCE_BOOTSTRAP_SYSCALLS = (
    "brk",
    "clock_gettime",
    "close",
    "execveat",
    "exit",
    "exit_group",
    "fstat",
    "futex",
    "getpid",
    "getrandom",
    "gettid",
    "lseek",
    "read",
    "rt_sigreturn",
    "seccomp",
    "write",
)
_PUBLIC_EVIDENCE_RUNTIME_SYSCALLS = tuple(
    name
    for name in _PUBLIC_EVIDENCE_BOOTSTRAP_SYSCALLS
    if name not in {"execveat", "seccomp"}
)
_PUBLIC_EVIDENCE_POST_EXEC_PREREQUISITE = (
    "measured-static-entry-stubs-plus-launcher-frame-broker-plus-"
    "read-only-cgroupns-v1"
)
_PUBLIC_EVIDENCE_FIXED_EXECUTABLE_FD = 126
_PUBLIC_EVIDENCE_SCM_CREDENTIALS_SIZE = struct.calcsize("3i")
PUBLIC_EVIDENCE_SOURCE_ONLY_NEGATIVE_FIXTURES = (
    "seccomp-allow-all",
    "seccomp-profile-byte-drift",
    "seccomp-unknown-syscall",
    "seccomp-recvmsg-recvmmsg",
    "seccomp-open-pidfd-getfd-or-scm-rights",
    "seccomp-memfd-module-bpf-io-uring-network",
    "seccomp-fork-namespace-ptrace-or-executable-memory",
    "producer-dynamic-elf",
    "launcher-dynamic-or-interpreted",
    "service-post-exec-filter-digest-unverifiable",
    "service-stream-instead-of-seqpacket",
    "service-missing-scm-credentials",
    "service-wrong-scm-credentials",
    "service-peer-pid-reuse",
    "service-seccomp-filter-count-drift",
    "service-scm-rights",
    "service-unknown-control-message",
    "service-anonymous-executable-map",
    "service-dynamic-shared-object-map",
    "service-cgroup-writable-ancestor",
    "service-cgroup-ancestor-acl",
    "service-cgroup-retained-fd-or-writable-mount",
    "service-cgroup-fd-under-alternate-path",
    "owner-liveness-not-seqpacket",
    "owner-liveness-eof",
    "owner-liveness-payload",
    "absolute-command-deadline",
    "producer-descendant-pid-reuse",
    "producer-descendant-pidfd-unavailable",
    "cleanup-reused-pgid-forbidden",
    "producer-fast-success-before-readiness-read",
    "guarded-service-exec-during-response",
    "quarantine-reap-without-next-request",
    "quarantine-cleanup-timeout",
    "hostile-host-proof-overclaim",
    "verifier-state-tls-version-downgrade",
    "verifier-state-server-spki-substitution",
    "verifier-state-client-spki-substitution",
    "verifier-state-authority-or-path-substitution",
    "verifier-state-redirect-or-proxy",
    "verifier-state-http-framing-ambiguity",
    "verifier-state-oversized-response",
    "verifier-state-stale-or-replayed-authorization",
    "verifier-state-prior-state-substitution",
    "verifier-state-successor-substitution",
    "verifier-state-challenge-substitution",
    "verifier-state-operation-substitution",
    "verifier-state-transaction-substitution",
    "verifier-state-consumption-substitution",
    "verifier-state-nonce-receipt-substitution",
    "verifier-state-assurance-substitution",
    "verifier-state-key-substitution",
    "verifier-state-store-substitution",
    "verifier-state-admin-domain-substitution",
    "verifier-state-malformed-signed-receipt",
    "verifier-state-unknown-outcome-replacement-operation",
    "verifier-state-unknown-outcome-recovery-request-drift",
    "verifier-state-uncommitted-recovery",
    "verifier-state-key-role-collision",
)


def _public_evidence_source_only_negative_fixture_contract() -> dict[str, Any]:
    if len(PUBLIC_EVIDENCE_SOURCE_ONLY_NEGATIVE_FIXTURES) != len(
        set(PUBLIC_EVIDENCE_SOURCE_ONLY_NEGATIVE_FIXTURES)
    ):
        raise AttestationContractError(
            "public evidence source-only negative fixture IDs are not unique"
        )
    return {
        "cases": PUBLIC_EVIDENCE_SOURCE_ONLY_NEGATIVE_FIXTURES,
        "expectedResult": "reject-before-production-ready-or-kill-and-prove-dead",
        "mustNotExecuteAtImport": True,
    }
_ALLOWED_NITRO_CERT_SIGNATURE_OIDS = {
    "1.2.840.10045.4.3.2",
    "1.2.840.10045.4.3.3",
    "1.2.840.113549.1.1.11",
    "1.2.840.113549.1.1.12",
}
_PUBLIC_ARTIFACT_NAMES = {
    "build-watchdog-receipt",
    "builder-statement-a",
    "builder-statement-b",
    "builder-transcript-a",
    "builder-transcript-b",
    "candidate-manifest-v6",
    "completion-authentication",
    "completion-checkpoint",
    "completion-proof",
    "key-custody",
    "production-identity",
    "promotion-receipt",
    "promoted-manifest-v6",
    "revocation-snapshot",
    "transparency-witness",
    "source-input-manifest",
}
_PUBLIC_V3_ARTIFACT_NAMES = {
    "nitro-trust-roots",
    "release-config",
    "stable-release-statement",
}
_PUBLIC_ROOT_ROLES = {
    "buildWatchdog",
    "builderA",
    "builderB",
    "completion-authenticator",
    "completion-checkpoint",
    "promotion",
    "revocation-authority",
    "sourceGitInventory",
    "sourceUntrackedApproval",
    "transparency-witness",
}
_PUBLIC_CHECKPOINT_ROLES = {
    "completion-checkpoint",
    "revocation-authority",
    "transparency-witness",
}
_COMPLETION_AUTHENTICATION_DOMAIN = (
    b"serverware.completionProofAuthentication/v1\x00Ed25519\x00"
)
_COMPLETION_CHECKPOINT_DOMAIN = (
    b"serverware.completionProofCheckpoint/v1\x00Ed25519\x00"
)
_BUILD_WATCHDOG_DOMAIN = (
    b"serverware.ociBuildWatchdogReceipt/v4\x00Ed25519\x00"
)
_PROMOTION_RECEIPT_DOMAIN = (
    b"serverware.verificationPromotionReceipt/v4\x00Ed25519\x00"
)
_RAW_BUILDER_STATEMENT_DOMAIN = (
    b"serverware.rawBuilderStatement/v1\x00Ed25519\x00"
)
_SOURCE_GIT_INVENTORY_DOMAIN = (
    b"serverware.gitSourceInventory/v3\x00Ed25519\x00"
)
_SOURCE_UNTRACKED_APPROVAL_DOMAIN = (
    b"serverware.untrackedSourceApproval/v2\x00Ed25519\x00"
)
_CUSTODY_MATERIALS = {
    "broker-kek",
    "ca",
    "credentials",
    "release",
    "response",
    "tls",
}
_KEY_GENERATION_FIELDS = {
    "brokerKek",
    "ca",
    "credentialRelease",
    "policy",
    "release",
    "response",
    "tls",
    "tlsScope",
}
_MANIFEST_LANE_ORDER = (
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
_MANIFEST_IMAGE_ORDER = tuple(
    f"lane-{name}" for name in _MANIFEST_LANE_ORDER
) + ("npm-publish-companion",)
_MANIFEST_BASE_ENVIRONMENT = {
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
_MANIFEST_PORTAL_DYNAMIC_ENVIRONMENT = [
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
_MANIFEST_SOURCE_CONTRACTS = {
    "approval-review": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_approval_review.py",
        ],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "browser-python-compatibility": {
        "exact": ["scripts/oci_lane_entrypoint.py"],
        "prefixes": [],
    },
    "chromium-compatibility": {
        "exact": ["scripts/oci_lane_entrypoint.py"],
        "prefixes": [],
    },
    "clean-room": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_agent_trust_clean_room.py",
            "scripts/verify_offline_artifact_manifest.py",
        ],
        "prefixes": ["serverware_agent_trust/"],
    },
    "credential-constraints": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_credential_constraints.py",
        ],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "credential-constraints-proxy": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_credential_constraints.py",
        ],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "host-python-compatibility": {
        "exact": ["scripts/oci_lane_entrypoint.py"],
        "prefixes": [],
    },
    "internal-service-auth": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_internal_service_auth.py",
        ],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
    "jit-transaction-sqlite-full": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_jit_transaction_state.py",
        ],
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
    "proxy-python-compatibility": {
        "exact": ["scripts/oci_lane_entrypoint.py"],
        "prefixes": [],
    },
    "rust-decision-gate-tests": {
        "exact": [],
        "prefixes": ["data-plane/decision-gate-rs/"],
    },
    "webauthn-attestation": {
        "exact": [
            "scripts/oci_lane_entrypoint.py",
            "scripts/test_webauthn_attestation.py",
        ],
        "prefixes": ["serverware/", "serverware_agent_trust/"],
    },
}
_MANIFEST_DEPENDENCY_CAPABILITIES = {
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


_TEE_HELPER_ENV_NAMES = (
    "PATH",
    "LANG",
    "LC_ALL",
    "TZ",
    "SERVERWARE_DATA_DIR",
    "SERVERWARE_EXTERNAL_TEE_FIXTURE_KEY",
    "SERVERWARE_NITRO_ALLOW_DEBUG",
    "SERVERWARE_NITRO_ALLOW_DEBUG_RELEASE",
    "SERVERWARE_NITRO_ALLOWED_MATERIALS",
    "SERVERWARE_NITRO_ATTESTATION_COMMAND",
    "SERVERWARE_NITRO_ATTESTATION_DOCUMENT",
    "SERVERWARE_NITRO_ATTESTATION_DOCUMENT_B64",
    "SERVERWARE_NITRO_CLOCK_SKEW_SECONDS",
    "SERVERWARE_NITRO_EXPECTED_PCRS",
    "SERVERWARE_NITRO_FIXTURE",
    "SERVERWARE_NITRO_FIXTURE_DEBUG",
    "SERVERWARE_NITRO_FIXTURE_DIR",
    "SERVERWARE_NITRO_FIXTURE_PCRS",
    "SERVERWARE_NITRO_KMS_FIXTURE_KEY",
    "SERVERWARE_NITRO_KMS_RELEASE_COMMAND",
    "SERVERWARE_NITRO_KMS_TIMEOUT_SECONDS",
    "SERVERWARE_NITRO_MAX_AGE_SECONDS",
    "SERVERWARE_NITRO_NSM_ATTEST_COMMAND_TEMPLATE",
    "SERVERWARE_NITRO_REQUIRE_KMS_COMMAND",
    "SERVERWARE_NITRO_NSM_MAX_DOCUMENT_BYTES",
    "SERVERWARE_NITRO_NSM_OUTPUT_FORMAT",
    "SERVERWARE_NITRO_NSM_TIMEOUT_SECONDS",
    "SERVERWARE_NITRO_ROOT_CERT",
    "SERVERWARE_NITRO_ROOT_CERT_PEM",
    "SERVERWARE_NITRO_ROOT_SHA256",
    "SERVERWARE_NITRO_KEY_CUSTODY_PATH",
    "SERVERWARE_NITRO_PRODUCTION_IDENTITY_PATH",
    "SERVERWARE_NITRO_PROMOTED_MANIFEST_PATH",
    "SERVERWARE_NITRO_RUNTIME_STATE_PATH",
)


class AttestationContractError(ValueError):
    """A non-secret-bearing failure in the public attestation contract."""


class _PublicEvidenceNonceChannelTransportError(
    AttestationContractError
):
    """The exact nonce request may have committed despite channel failure."""


@dataclass(frozen=True, slots=True)
class NitroVerificationTrust:
    bundle_sha256: str
    roots: tuple[x509.Certificate, ...]
    crls: tuple[x509.CertificateRevocationList, ...]
    allowed_leaf_extended_key_usage_oids: tuple[str, ...]
    expected_module_id: str
    expected_eif_sha384: str
    expected_pcrs: tuple[str, str, str]
    max_attestation_age_seconds: int
    max_future_skew_seconds: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.bundle_sha256, str)
            or _SHA256_RE.fullmatch(self.bundle_sha256) is None
            or not isinstance(self.roots, tuple)
            or not self.roots
            or not isinstance(self.crls, tuple)
            or not self.crls
            or any(
                not isinstance(item, x509.Certificate)
                for item in self.roots
            )
            or any(
                not isinstance(item, x509.CertificateRevocationList)
                for item in self.crls
            )
            or not isinstance(
                self.allowed_leaf_extended_key_usage_oids, tuple
            )
            or any(
                not isinstance(item, str)
                or re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", item) is None
                for item in self.allowed_leaf_extended_key_usage_oids
            )
            or self.allowed_leaf_extended_key_usage_oids
            != tuple(sorted(set(self.allowed_leaf_extended_key_usage_oids)))
            or not isinstance(self.expected_module_id, str)
            or not 1 <= len(self.expected_module_id.encode("utf-8")) <= 256
            or "\x00" in self.expected_module_id
            or not isinstance(self.expected_eif_sha384, str)
            or _SHA384_RE.fullmatch(self.expected_eif_sha384) is None
            or not isinstance(self.expected_pcrs, tuple)
            or len(self.expected_pcrs) != 3
            or any(
                not isinstance(item, str)
                or _SHA384_RE.fullmatch(item) is None
                for item in self.expected_pcrs
            )
            or self.expected_pcrs[0] != self.expected_eif_sha384
            or type(self.max_attestation_age_seconds) is not int
            or not 1 <= self.max_attestation_age_seconds <= 900
            or type(self.max_future_skew_seconds) is not int
            or not 0 <= self.max_future_skew_seconds <= 60
        ):
            raise AttestationContractError(
                "Nitro verification trust is incomplete or inconsistent"
            )


@dataclass(frozen=True, slots=True)
class AttestationChallenge:
    challenge_id: str
    value: str
    value_sha256: str
    tls_binding_sha256: str
    connection_id: str
    peer_spki_sha256: str
    issued_at_unix: int
    expires_at_unix: int

    def public_document(self) -> dict[str, Any]:
        return {
            "apiVersion": "serverware.attestationChallenge/v2",
            "challengeId": self.challenge_id,
            "value": self.value,
            "valueSha256": self.value_sha256,
            "tlsBindingSha256": self.tls_binding_sha256,
            "connectionId": self.connection_id,
            "peerSpkiSha256": self.peer_spki_sha256,
            "issuedAtUnix": self.issued_at_unix,
            "expiresAtUnix": self.expires_at_unix,
            "channelBound": True,
            "oneUse": True,
        }


@dataclass(slots=True)
class _StoredChallenge:
    value_sha256: str
    tls_binding_sha256: str
    connection_id: str
    peer_spki_sha256: str
    issued_at_unix: int
    expires_at_unix: int
    state: str = "issued"
    reservation_id: str | None = None
    reservation_expires_at_unix: int | None = None


@dataclass(frozen=True, slots=True)
class AttestationChallengeReservation:
    reservation_id: str
    challenge: AttestationChallenge


@dataclass(frozen=True, slots=True)
class ProductionAttestationHttpResponse:
    body: bytes
    status_code: int
    raw_headers: tuple[tuple[bytes, bytes], ...]
    statement: dict[str, Any]
    signature: str


@dataclass(frozen=True, slots=True)
class PublicEvidenceHttpResponse:
    body: bytes
    status_code: int
    raw_headers: tuple[tuple[bytes, bytes], ...]
    body_sha256: str


@dataclass(frozen=True, slots=True)
class PublicEvidenceProducerDescriptor:
    descriptor_sha256: str
    executable_path: Path
    executable_sha256: str
    immutable_config_bytes: bytes
    immutable_config_sha256: str
    minimum_rollback_continuity_commitment_sha256: str
    release_identity: dict[str, Any]
    release_identity_sha256: str
    tls_scope_signing_public_key_spki_der_base64url: str
    sandbox_launcher_path: Path
    sandbox_launcher_sha256: str
    sandbox_descriptor_bytes: bytes
    sandbox_descriptor_sha256: str
    stable_statement_sha256: str
    sandbox_cgroup_path: Path
    sandbox_root_path: Path
    sandbox_seccomp_profile_path: Path
    sandbox_seccomp_profile_sha256: str
    sandbox_seccomp_profile_id: str
    sandbox_mount_sources: tuple[tuple[str, Path], ...]
    sandbox_sealed_files: tuple[
        tuple[str, Path, str | None, int], ...
    ]
    sandbox_measurement_copies: tuple[tuple[str, str], ...]
    sandbox_producer_streams: tuple[tuple[str, int], ...]
    sandbox_fixture_mode: bool
    nonce_store_identity_sha256: str
    nonce_store_key_spki_sha256: str
    nonce_store_signing_public_key_spki_der_base64url: str
    nonce_service_request_fd: int
    nonce_service_response_fd: int
    nonce_service_expected_peer_uid: int
    nonce_service_expected_peer_gid: int
    nonce_service_expected_peer_executable_sha256: str
    nonce_service_expected_peer_executable_map_closure_sha256: str
    nonce_service_expected_peer_cgroup_ancestor_closure_sha256: str
    nonce_service_expected_peer_post_exec_profile_sha256: str
    nonce_service_expected_peer_cgroup_path: str
    nonce_service_max_response_bytes: int
    nonce_service_timeout_milliseconds: int
    verifier_state_service_authority: str
    verifier_state_service_host: str
    verifier_state_service_port: int
    verifier_state_service_read_path: str
    verifier_state_service_issue_challenge_path: str
    verifier_state_service_recover_challenge_path: str
    verifier_state_service_prepare_path: str
    verifier_state_service_recovery_lookup_path: str
    verifier_state_service_mark_consumption_path: str
    verifier_state_service_attach_nonce_status_path: str
    verifier_state_service_abort_path: str
    verifier_state_service_commit_path: str
    verifier_state_service_recover_path: str
    verifier_state_service_tls_context: ssl.SSLContext
    verifier_state_service_tls_material_snapshot_sha256: str
    verifier_state_service_client_certificate_spki_sha256: str
    verifier_state_service_server_leaf_spki_sha256: str
    verifier_state_service_configuration_sha256: str
    verifier_state_service_max_response_bytes: int
    verifier_state_service_timeout_milliseconds: int
    verifier_state_service_concurrency_limit: int
    global_role_key_spki_sha256s: tuple[str, ...]
    nonce_authority_assurance: dict[str, Any]
    nonce_authority_assurance_sha256: str
    nonce_authority_assurance_evidence: dict[str, Any] | None
    nonce_authority_assurance_evidence_key_spki_sha256: str
    nonce_authority_assurance_evidence_signing_public_key_spki_der_base64url: str
    nonce_authority_verifier_state_key_spki_sha256: str
    nonce_authority_verifier_state_signing_public_key_spki_der_base64url: str
    nonce_authority_verifier_state_store_identity_sha256: str
    nonce_authority_verifier_state_store_administrative_domain_sha256: str
    nonce_authority_verifier_state_store_attestation_key_spki_sha256: str
    nonce_authority_verifier_state_store_attestation_public_key_spki_der_base64url: str
    nonce_authority_verifier_state_store_assurance_evidence: dict[str, Any]
    nonce_authority_verifier_state_store_assurance_evidence_sha256: str
    nonce_authority_verifier_state_store_assurance_evidence_signing_public_key_spki_der_base64url: str
    nonce_authority_verifier_state_store_assurance_issuer_administrative_domain_sha256: str
    nonce_authority_verifier_state_store_assurance_issuer_credential_identity_sha256: str
    nonce_authority_verifier_state_store_assurance_issuer_identity_sha256: str
    nonce_authority_verifier_state_store_configuration_sha256: str
    nonce_authority_verifier_state_store_credential_identity_sha256: str
    nonce_authority_verifier_state_store_minimum_commit_index: int
    nonce_authority_verifier_state_store_minimum_generation: int
    nonce_authority_verifier_state_store_rollback_mechanism: str
    nonce_authority_verifier_state_role_separation_evidence: dict[str, Any]
    nonce_authority_verifier_state_role_separation_evidence_sha256: str
    nonce_authority_verifier_state_role_separation_evidence_signing_public_key_spki_der_base64url: str
    nonce_authority_verifier_state_role_separation_evidence_issuer: dict[str, Any]
    producer_request_schema_sha256: str
    witness_store_identity_sha256: str
    witness_store_key_spki_sha256: str
    witness_store_signing_public_key_spki_der_base64url: str
    trust_roots_sha256: str
    max_input_bytes: int
    max_output_bytes: int
    timeout_milliseconds: int
    concurrency_limit: int


@dataclass(frozen=True, slots=True)
class PublicEvidenceNonceReservation:
    consumed_at_unix: int
    nonce_sha256: str
    one_use_sequence: int
    store_identity_sha256: str
    tls_binding_sha256: str
    request_body_sha256: str
    expires_at_unix: int


@dataclass(slots=True)
class _QuarantinedPublicEvidenceTree:
    process: subprocess.Popen[bytes]
    process_pidfd: int | None
    cgroup_descriptor: int
    semaphore: threading.BoundedSemaphore


class PublicEvidenceNonceStore:
    """Restart-durable atomic nonce consumption backed by a private SQLite file.

    The unique nonce digest and committed sequence are authoritative across
    workers and restarts. Records are tombstones and are never deleted or
    reopened; capacity exhaustion fails closed. Production deployments that
    need host-independent rollback resistance must replace this reference
    boundary with the separately authenticated external CAS service.
    """

    def __init__(
        self,
        *,
        database_path: Path,
        store_identity_sha256: str,
        capacity: int = 4096,
        clock: Any = time.time,
    ) -> None:
        if type(capacity) is not int or not 16 <= capacity <= 1_000_000:
            raise AttestationContractError(
                "public evidence nonce capacity must be between 16 and 1000000"
            )
        _require_digest(
            store_identity_sha256,
            "public evidence nonce-store identity",
        )
        if (
            not isinstance(database_path, Path)
            or not database_path.is_absolute()
            or not database_path.name
            or ".." in database_path.parts
            or "." in database_path.parts
            or os.path.normpath(os.fspath(database_path))
            != os.fspath(database_path)
        ):
            raise AttestationContractError(
                "public evidence nonce-store path is invalid"
            )
        self._capacity = capacity
        self._clock = clock
        self._database_path = database_path
        self._store_identity_sha256 = store_identity_sha256
        self._initialize()

    def _now(self) -> int:
        try:
            value = int(self._clock())
        except Exception as exc:
            raise AttestationContractError(
                "public evidence nonce clock is unavailable"
            ) from exc
        if value < 1:
            raise AttestationContractError(
                "public evidence nonce clock returned an invalid value"
            )
        return value

    def _connect(self) -> sqlite3.Connection:
        try:
            connection = sqlite3.connect(
                os.fspath(self._database_path),
                timeout=5.0,
                isolation_level=None,
            )
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            return connection
        except sqlite3.Error as exc:
            raise AttestationContractError(
                "public evidence nonce store is unavailable"
            ) from exc

    def _initialize(self) -> None:
        parent = self._database_path.parent
        try:
            parent_stat = parent.stat(follow_symlinks=False)
        except OSError as exc:
            raise AttestationContractError(
                "public evidence nonce-store directory is unavailable"
            ) from exc
        if (
            not stat.S_ISDIR(parent_stat.st_mode)
            or parent_stat.st_uid != os.geteuid()
            or stat.S_IMODE(parent_stat.st_mode) & 0o077
        ):
            raise AttestationContractError(
                "public evidence nonce-store directory must be private and owned by the service uid"
            )
        try:
            database_stat = self._database_path.stat(
                follow_symlinks=False
            )
        except FileNotFoundError:
            flags = (
                os.O_RDWR
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = os.open(
                self._database_path,
                flags,
                0o600,
            )
            os.close(descriptor)
            database_stat = self._database_path.stat(
                follow_symlinks=False
            )
        except OSError as exc:
            raise AttestationContractError(
                "public evidence nonce-store file is unavailable"
            ) from exc
        if (
            not stat.S_ISREG(database_stat.st_mode)
            or database_stat.st_uid != os.geteuid()
            or stat.S_IMODE(database_stat.st_mode) != 0o600
            or database_stat.st_nlink != 1
        ):
            raise AttestationContractError(
                "public evidence nonce-store file is not private and regular"
            )
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS nonce_store_metadata (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    store_identity_sha256 TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS consumed_public_nonces (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    nonce_sha256 TEXT NOT NULL UNIQUE,
                    store_identity_sha256 TEXT NOT NULL,
                    tls_binding_sha256 TEXT NOT NULL,
                    request_body_sha256 TEXT NOT NULL,
                    consumed_at_unix INTEGER NOT NULL,
                    expires_at_unix INTEGER NOT NULL,
                    one_use INTEGER NOT NULL CHECK (one_use = 1)
                )
                """
            )
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT store_identity_sha256
                FROM nonce_store_metadata
                WHERE singleton = 1
                """
            ).fetchone()
            if row is None:
                connection.execute(
                    """
                    INSERT INTO nonce_store_metadata (
                        singleton,
                        store_identity_sha256
                    ) VALUES (1, ?)
                    """,
                    (self._store_identity_sha256,),
                )
            elif row != (self._store_identity_sha256,):
                raise AttestationContractError(
                    "public evidence nonce store crossed its pinned identity"
                )
            connection.execute("COMMIT")
        except AttestationContractError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise AttestationContractError(
                "public evidence nonce store could not be initialized"
            ) from exc
        finally:
            connection.close()

    def reserve(
        self,
        *,
        nonce_sha256: str,
        tls_binding_sha256: str,
        request_body_sha256: str,
        expires_at_unix: int,
    ) -> PublicEvidenceNonceReservation:
        _require_digest(nonce_sha256, "public evidence caller nonce")
        _require_digest(tls_binding_sha256, "public evidence TLS binding")
        _require_digest(request_body_sha256, "public evidence request body")
        now = self._now()
        if (
            type(expires_at_unix) is not int
            or not now < expires_at_unix <= now + 60
        ):
            raise AttestationContractError(
                "public evidence nonce expiry is invalid"
            )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            count = connection.execute(
                "SELECT COUNT(*) FROM consumed_public_nonces"
            ).fetchone()
            if (
                count is None
                or type(count[0]) is not int
                or count[0] >= self._capacity
            ):
                raise AttestationContractError(
                    "public evidence nonce store is at capacity"
                )
            cursor = connection.execute(
                """
                INSERT INTO consumed_public_nonces (
                    nonce_sha256,
                    store_identity_sha256,
                    tls_binding_sha256,
                    request_body_sha256,
                    consumed_at_unix,
                    expires_at_unix,
                    one_use
                ) VALUES (?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    nonce_sha256,
                    self._store_identity_sha256,
                    tls_binding_sha256,
                    request_body_sha256,
                    now,
                    expires_at_unix,
                ),
            )
            sequence = cursor.lastrowid
            if type(sequence) is not int or sequence < 1:
                raise AttestationContractError(
                    "public evidence nonce store returned an invalid sequence"
                )
            connection.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise AttestationContractError(
                "public evidence caller nonce was already consumed"
            ) from exc
        except AttestationContractError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise AttestationContractError(
                "public evidence nonce consumption failed"
            ) from exc
        finally:
            connection.close()
        return PublicEvidenceNonceReservation(
            consumed_at_unix=now,
            nonce_sha256=nonce_sha256,
            one_use_sequence=sequence,
            store_identity_sha256=self._store_identity_sha256,
            tls_binding_sha256=tls_binding_sha256,
            request_body_sha256=request_body_sha256,
            expires_at_unix=expires_at_unix,
        )

    def finalize(self, reservation: PublicEvidenceNonceReservation) -> None:
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT
                    sequence,
                    store_identity_sha256,
                    tls_binding_sha256,
                    request_body_sha256,
                    consumed_at_unix,
                    expires_at_unix,
                    one_use
                FROM consumed_public_nonces
                WHERE nonce_sha256 = ?
                """,
                (reservation.nonce_sha256,),
            ).fetchone()
        except sqlite3.Error as exc:
            raise AttestationContractError(
                "public evidence nonce consumption could not be rechecked"
            ) from exc
        finally:
            connection.close()
        if row != (
            reservation.one_use_sequence,
            reservation.store_identity_sha256,
            reservation.tls_binding_sha256,
            reservation.request_body_sha256,
            reservation.consumed_at_unix,
            reservation.expires_at_unix,
            1,
        ):
            raise AttestationContractError(
                "public evidence durable nonce consumption is invalid"
            )

    def release(self, reservation: PublicEvidenceNonceReservation) -> None:
        self.finalize(reservation)
        raise AttestationContractError(
            "consumed public evidence nonces cannot be released or reopened"
        )


class ProductionAttestationChallengeStore:
    """Bounded in-process one-use challenges.

    Production rollback resistance still requires the off-host witness. This
    store only prevents concurrent and same-process replay of the online
    attestation request.
    """

    def __init__(
        self,
        *,
        capacity: int = 1024,
        ttl_seconds: int = 60,
        reservation_ttl_seconds: int = 15,
        per_peer_capacity: int = 8,
        clock: Any = time.time,
    ) -> None:
        if type(capacity) is not int or not 16 <= capacity <= 65536:
            raise AttestationContractError(
                "attestation challenge capacity must be between 16 and 65536"
            )
        if type(ttl_seconds) is not int or not 15 <= ttl_seconds <= 300:
            raise AttestationContractError(
                "attestation challenge TTL must be between 15 and 300 seconds"
            )
        if (
            type(reservation_ttl_seconds) is not int
            or not 5 <= reservation_ttl_seconds <= 60
        ):
            raise AttestationContractError(
                "attestation reservation TTL must be between 5 and 60 seconds"
            )
        if (
            type(per_peer_capacity) is not int
            or not 1 <= per_peer_capacity <= 64
        ):
            raise AttestationContractError(
                "attestation per-peer capacity must be between 1 and 64"
            )
        self._capacity = capacity
        self._ttl_seconds = ttl_seconds
        self._reservation_ttl_seconds = reservation_ttl_seconds
        self._per_peer_capacity = per_peer_capacity
        self._clock = clock
        self._records: dict[str, _StoredChallenge] = {}
        self._lock = threading.Lock()

    def _now(self) -> int:
        try:
            value = int(self._clock())
        except Exception as exc:
            raise AttestationContractError(
                "attestation challenge clock is unavailable"
            ) from exc
        if value < 1:
            raise AttestationContractError(
                "attestation challenge clock returned an invalid value"
            )
        return value

    def _discard_expired_locked(self, now: int) -> None:
        for record in self._records.values():
            if (
                record.state == "reserved"
                and record.reservation_expires_at_unix is not None
                and record.reservation_expires_at_unix <= now
            ):
                record.state = "issued"
                record.reservation_id = None
                record.reservation_expires_at_unix = None
        expired = [
            challenge_id
            for challenge_id, record in self._records.items()
            if record.expires_at_unix <= now
        ]
        for challenge_id in expired:
            self._records.pop(challenge_id, None)

    def issue(
        self,
        *,
        tls_binding_sha256: str,
        connection_id: str,
        peer_spki_sha256: str,
        bound_expires_at_unix: int,
    ) -> AttestationChallenge:
        _require_digest(tls_binding_sha256, "attestation challenge TLS binding")
        _require_digest(peer_spki_sha256, "attestation challenge peer SPKI")
        if (
            not isinstance(connection_id, str)
            or _IDENTIFIER_RE.fullmatch(connection_id) is None
        ):
            raise AttestationContractError(
                "attestation challenge connection ID is invalid"
            )
        now = self._now()
        if (
            type(bound_expires_at_unix) is not int
            or bound_expires_at_unix - now < 15
        ):
            raise AttestationContractError(
                "attestation TLS scope has insufficient remaining lifetime"
            )
        raw_value = secrets.token_bytes(32)
        value = b64e(raw_value)
        challenge_id = str(uuid.uuid4())
        value_sha256 = sha256_prefixed(raw_value)
        expires_at = min(
            now + self._ttl_seconds, bound_expires_at_unix
        )
        with self._lock:
            self._discard_expired_locked(now)
            if len(self._records) >= self._capacity:
                raise AttestationContractError(
                    "attestation challenge store is at capacity"
                )
            peer_count = sum(
                1
                for record in self._records.values()
                if record.peer_spki_sha256 == peer_spki_sha256
            )
            if peer_count >= self._per_peer_capacity:
                raise AttestationContractError(
                    "attestation challenge peer is at capacity"
                )
            if challenge_id in self._records:
                raise AttestationContractError(
                    "attestation challenge identifier collision"
                )
            self._records[challenge_id] = _StoredChallenge(
                value_sha256=value_sha256,
                tls_binding_sha256=tls_binding_sha256,
                connection_id=connection_id,
                peer_spki_sha256=peer_spki_sha256,
                issued_at_unix=now,
                expires_at_unix=expires_at,
            )
        return AttestationChallenge(
            challenge_id=challenge_id,
            value=value,
            value_sha256=value_sha256,
            tls_binding_sha256=tls_binding_sha256,
            connection_id=connection_id,
            peer_spki_sha256=peer_spki_sha256,
            issued_at_unix=now,
            expires_at_unix=expires_at,
        )

    def reserve(
        self,
        challenge_id: str,
        value: str,
        tls_binding_sha256: str,
        connection_id: str,
        peer_spki_sha256: str,
    ) -> AttestationChallengeReservation:
        _require_digest(tls_binding_sha256, "attestation challenge TLS binding")
        _require_digest(peer_spki_sha256, "attestation challenge peer SPKI")
        if not isinstance(challenge_id, str):
            raise AttestationContractError("attestation challenge ID is invalid")
        try:
            parsed_id = str(uuid.UUID(challenge_id))
        except ValueError as exc:
            raise AttestationContractError(
                "attestation challenge ID is invalid"
            ) from exc
        if parsed_id != challenge_id:
            raise AttestationContractError(
                "attestation challenge ID is not canonical"
            )
        if not isinstance(value, str) or len(value) != 43:
            raise AttestationContractError("attestation challenge value is invalid")
        try:
            raw_value = b64d(value)
        except Exception as exc:
            raise AttestationContractError(
                "attestation challenge value is invalid"
            ) from exc
        if len(raw_value) != 32 or b64e(raw_value) != value:
            raise AttestationContractError(
                "attestation challenge value is not canonical"
            )
        now = self._now()
        actual_digest = sha256_prefixed(raw_value)
        with self._lock:
            self._discard_expired_locked(now)
            record = self._records.get(challenge_id)
            if record is None:
                raise AttestationContractError(
                    "attestation challenge is unavailable, expired, or already used"
                )
            if (
                record.state != "issued"
                or record.expires_at_unix <= now
                or not hmac.compare_digest(record.value_sha256, actual_digest)
                or not hmac.compare_digest(
                    record.tls_binding_sha256, tls_binding_sha256
                )
                or record.connection_id != connection_id
                or not hmac.compare_digest(
                    record.peer_spki_sha256, peer_spki_sha256
                )
            ):
                raise AttestationContractError(
                    "attestation challenge is invalid, reserved, or expired"
                )
            reservation_id = str(uuid.uuid4())
            record.state = "reserved"
            record.reservation_id = reservation_id
            record.reservation_expires_at_unix = min(
                record.expires_at_unix,
                now + self._reservation_ttl_seconds,
            )
        challenge = AttestationChallenge(
            challenge_id=challenge_id,
            value=value,
            value_sha256=actual_digest,
            tls_binding_sha256=record.tls_binding_sha256,
            connection_id=record.connection_id,
            peer_spki_sha256=record.peer_spki_sha256,
            issued_at_unix=record.issued_at_unix,
            expires_at_unix=record.expires_at_unix,
        )
        return AttestationChallengeReservation(
            reservation_id=reservation_id,
            challenge=challenge,
        )

    def finalize(self, reservation: AttestationChallengeReservation) -> None:
        now = self._now()
        challenge_id = reservation.challenge.challenge_id
        with self._lock:
            self._discard_expired_locked(now)
            record = self._records.get(challenge_id)
            if (
                record is None
                or record.state != "reserved"
                or record.reservation_id != reservation.reservation_id
                or record.reservation_expires_at_unix is None
                or record.reservation_expires_at_unix <= now
            ):
                raise AttestationContractError(
                    "attestation reservation is unavailable or expired"
                )
            self._records.pop(challenge_id)

    def release(self, reservation: AttestationChallengeReservation) -> None:
        now = self._now()
        challenge_id = reservation.challenge.challenge_id
        with self._lock:
            self._discard_expired_locked(now)
            record = self._records.get(challenge_id)
            if record is None:
                return
            if record.state == "issued" and record.reservation_id is None:
                return
            if (
                record.state != "reserved"
                or record.reservation_id != reservation.reservation_id
            ):
                raise AttestationContractError(
                    "attestation reservation release token is invalid"
                )
            record.state = "issued"
            record.reservation_id = None
            record.reservation_expires_at_unix = None


@dataclass(frozen=True, slots=True)
class TrustedTlsScope:
    """Authenticated facts signed by the enclave-owned TLS stack."""

    api_version: str
    provider: str
    exporter: bytes
    exporter_label: str
    connection_id: str
    connection_nonce: bytes
    issued_at_unix: int
    expires_at_unix: int
    leaf_certificate_sha256: str
    leaf_spki_sha256: str
    peer_certificate_sha256: str
    peer_spki_sha256: str
    peer_identity: str
    tls_stack_measurement_sha256: str
    enclave_instance_id: str
    enclave_boot_id: str
    tls_key_generation: int
    tls_scope_key_generation: int
    tls_scope_key_spki_sha256: str
    envelope_sha256: str

    def __post_init__(self) -> None:
        if self.api_version != TRUSTED_TLS_SCOPE_VERSION:
            raise AttestationContractError("trusted TLS scope version is invalid")
        if (
            not isinstance(self.provider, str)
            or not self.provider.startswith("enclave-")
            or len(self.provider) > 128
        ):
            raise AttestationContractError(
                "trusted TLS scope provider is not enclave-owned"
            )
        if type(self.exporter) is not bytes or not 32 <= len(self.exporter) <= 64:
            raise AttestationContractError(
                "trusted TLS exporter must contain 32 to 64 bytes"
            )
        if self.exporter_label != "EXPORTER-Serverware-Attestation-v1":
            raise AttestationContractError("trusted TLS exporter label is invalid")
        if (
            type(self.connection_nonce) is not bytes
            or len(self.connection_nonce) != 32
        ):
            raise AttestationContractError(
                "trusted TLS connection nonce must contain 32 bytes"
            )
        for value, label in (
            (self.leaf_certificate_sha256, "TLS leaf certificate"),
            (self.leaf_spki_sha256, "TLS leaf SPKI"),
            (self.peer_certificate_sha256, "TLS peer certificate"),
            (self.peer_spki_sha256, "TLS peer SPKI"),
            (self.tls_stack_measurement_sha256, "TLS stack measurement"),
            (self.tls_scope_key_spki_sha256, "TLS scope signing key"),
            (self.envelope_sha256, "TLS scope envelope"),
        ):
            _require_digest(value, label)
        for value, label in (
            (self.peer_identity, "TLS peer identity"),
            (self.connection_id, "TLS connection ID"),
            (self.enclave_instance_id, "enclave instance ID"),
            (self.enclave_boot_id, "enclave boot ID"),
        ):
            if not isinstance(value, str) or _IDENTIFIER_RE.fullmatch(value) is None:
                raise AttestationContractError(f"{label} is invalid")
        if (
            type(self.tls_key_generation) is not int
            or self.tls_key_generation < 1
            or type(self.tls_scope_key_generation) is not int
            or self.tls_scope_key_generation < 1
        ):
            raise AttestationContractError(
                "TLS or TLS-scope key generation is invalid"
            )
        if (
            type(self.issued_at_unix) is not int
            or type(self.expires_at_unix) is not int
            or self.issued_at_unix < 1
            or self.expires_at_unix <= self.issued_at_unix
            or self.expires_at_unix - self.issued_at_unix > 60
        ):
            raise AttestationContractError(
                "trusted TLS scope validity is invalid"
            )

    @property
    def exporter_sha256(self) -> str:
        return sha256_prefixed(self.exporter)

    def binding_document(self) -> dict[str, Any]:
        document = {
            "apiVersion": TRUSTED_TLS_SCOPE_VERSION,
            "provider": self.provider,
            "connectionId": self.connection_id,
            "connectionNonceSha256": sha256_prefixed(
                self.connection_nonce
            ),
            "issuedAtUnix": self.issued_at_unix,
            "expiresAtUnix": self.expires_at_unix,
            "exporterLabel": self.exporter_label,
            "exporterSha256": self.exporter_sha256,
            "leafCertificateSha256": self.leaf_certificate_sha256,
            "leafSpkiSha256": self.leaf_spki_sha256,
            "peerCertificateSha256": self.peer_certificate_sha256,
            "peerSpkiSha256": self.peer_spki_sha256,
            "peerIdentity": self.peer_identity,
            "tlsStackMeasurementSha256": self.tls_stack_measurement_sha256,
            "enclaveInstanceId": self.enclave_instance_id,
            "enclaveBootId": self.enclave_boot_id,
            "tlsKeyGeneration": self.tls_key_generation,
            "tlsScopeEnvelopeSha256": self.envelope_sha256,
            "tlsScopeKeyGeneration": self.tls_scope_key_generation,
            "tlsScopeKeySpkiSha256": self.tls_scope_key_spki_sha256,
        }
        return {
            **document,
            "bindingSha256": sha256_prefixed(
                canonical_json(document).encode("ascii")
            ),
        }


def _load_ed25519_spki_der(
    encoded: Any, *, label: str
) -> tuple[Ed25519PublicKey, str]:
    if not isinstance(encoded, str) or not 1 <= len(encoded) <= 256:
        raise AttestationContractError(f"{label} is invalid")
    try:
        der = b64d(encoded)
    except Exception as exc:
        raise AttestationContractError(f"{label} is invalid") from exc
    if b64e(der) != encoded or len(der) != 44:
        raise AttestationContractError(f"{label} is not canonical Ed25519 SPKI")
    try:
        key = serialization.load_der_public_key(der)
    except (TypeError, ValueError) as exc:
        raise AttestationContractError(f"{label} is invalid") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise AttestationContractError(f"{label} must be Ed25519")
    return key, sha256_prefixed(der)


def _verified_tls_scope_envelope(
    raw: bytes,
    *,
    production_state: Mapping[str, Any],
    now: int,
) -> TrustedTlsScope:
    if not 1 <= len(raw) <= 64 * 1024:
        raise AttestationContractError(
            "the enclave TLS scope envelope exceeds its bound"
        )
    envelope = _strict_json_document(raw, label="enclave TLS scope envelope")
    if raw != canonical_json(envelope).encode("ascii"):
        raise AttestationContractError(
            "the enclave TLS scope envelope is not canonical JSON"
        )
    envelope = _require_exact_fields(
        envelope,
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "signature",
            "signingKeyId",
        },
        "enclave TLS scope envelope",
    )
    if envelope.get("apiVersion") != TRUSTED_TLS_SCOPE_ENVELOPE_VERSION:
        raise AttestationContractError(
            "the enclave TLS scope envelope version is invalid"
        )
    payload = _require_exact_fields(
        envelope.get("payload"),
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
        "enclave TLS scope payload",
    )
    payload_sha256 = sha256_prefixed(
        canonical_json(payload).encode("ascii")
    )
    if not hmac.compare_digest(
        payload_sha256,
        _require_digest(envelope.get("payloadSha256"), "TLS scope payload"),
    ):
        raise AttestationContractError("the TLS scope payload digest is invalid")
    custody = production_state.get("custody")
    runtime = production_state.get("runtime")
    if not isinstance(custody, Mapping) or not isinstance(runtime, Mapping):
        raise AttestationContractError(
            "remeasured TLS scope state is unavailable"
        )
    tls_material = _material_by_name(custody, "tls")
    tls_scope_material = tls_material.get("scopeSigningKey")
    if not isinstance(tls_scope_material, Mapping):
        raise AttestationContractError(
            "TLS scope-signing custody evidence is missing"
        )
    scope_key = tls_material.get("scopeSigningKey")
    if not isinstance(scope_key, Mapping):
        raise AttestationContractError(
            "TLS custody omits the scope signing key"
        )
    key, key_id = _load_ed25519_spki_der(
        scope_key.get("publicKeySpkiDerBase64url"),
        label="TLS scope signing public key",
    )
    expected_generation = _require_positive_generation(
        scope_key.get("keyGeneration"),
        "TLS scope signing key generation",
    )
    payload_tls_generation = _require_positive_generation(
        payload.get("tlsKeyGeneration"),
        "TLS key generation",
    )
    payload_scope_generation = _require_positive_generation(
        payload.get("tlsScopeKeyGeneration"),
        "TLS scope key generation",
    )
    if (
        envelope.get("signingKeyId") != key_id
        or scope_key.get("publicKeySpkiSha256") != key_id
        or payload_scope_generation != expected_generation
    ):
        raise AttestationContractError(
            "the TLS scope signer does not match remeasured custody"
        )
    signature = envelope.get("signature")
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise AttestationContractError(
            "the TLS scope envelope signature is invalid"
        )
    try:
        signature_bytes = b64d(signature.split(":", 1)[1])
        if (
            len(signature_bytes) != 64
            or b64e(signature_bytes) != signature.split(":", 1)[1]
        ):
            raise ValueError("noncanonical signature")
        key.verify(
            signature_bytes,
            TLS_SCOPE_SIGNATURE_DOMAIN
            + canonical_json(
                {"payload": payload, "payloadSha256": payload_sha256}
            ).encode("ascii"),
        )
    except (InvalidSignature, ValueError) as exc:
        raise AttestationContractError(
            "the TLS scope envelope signature verification failed"
        ) from exc
    issued_at = payload.get("issuedAtUnix")
    expires_at = payload.get("expiresAtUnix")
    if (
        type(issued_at) is not int
        or type(expires_at) is not int
        or issued_at > now + 5
        or not issued_at <= now < expires_at
        or not 1 <= expires_at - issued_at <= 60
    ):
        raise AttestationContractError(
            "the TLS scope envelope is stale or overlong"
        )
    try:
        exporter = b64d(str(payload.get("exporter")))
        connection_nonce = b64d(str(payload.get("connectionNonce")))
    except Exception as exc:
        raise AttestationContractError(
            "the TLS scope binary fields are invalid"
        ) from exc
    if (
        b64e(exporter) != payload.get("exporter")
        or b64e(connection_nonce) != payload.get("connectionNonce")
    ):
        raise AttestationContractError(
            "the TLS scope binary fields are not canonical"
        )
    active = _require_exact_fields(
        runtime.get("activeTlsConnection"),
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
        "remeasured active TLS connection",
    )
    envelope_sha256 = sha256_prefixed(raw)
    expected_active = {
        "connectionId": payload.get("connectionId"),
        "connectionNonceSha256": sha256_prefixed(connection_nonce),
        "envelopeSha256": envelope_sha256,
        "expiresAtUnix": expires_at,
        "exporterSha256": sha256_prefixed(exporter),
        "issuedAtUnix": issued_at,
        "leafCertificateSha256": payload.get("leafCertificateSha256"),
        "leafSpkiSha256": payload.get("leafSpkiSha256"),
        "peerCertificateSha256": payload.get("peerCertificateSha256"),
        "peerIdentity": payload.get("peerIdentity"),
        "peerSpkiSha256": payload.get("peerSpkiSha256"),
        "tlsStackMeasurementSha256": payload.get(
            "tlsStackMeasurementSha256"
        ),
    }
    if dict(active) != expected_active:
        raise AttestationContractError(
            "the signed TLS scope differs from remeasured connection state"
        )
    if (
        payload.get("apiVersion") != TRUSTED_TLS_SCOPE_VERSION
        or payload.get("provider") != "enclave-nitro-tls"
        or payload.get("exporterLabel")
        != "EXPORTER-Serverware-Attestation-v1"
        or payload.get("enclaveInstanceId") != runtime.get("enclaveInstanceId")
        or payload.get("enclaveBootId") != runtime.get("enclaveBootId")
        or payload.get("leafSpkiSha256")
        != tls_material.get("identitySpkiSha256")
        or payload_tls_generation
        != _require_positive_generation(
            tls_material.get("keyGeneration"),
            "remeasured TLS key generation",
        )
        or payload_scope_generation
        != _require_positive_generation(
            runtime.get("keyGenerations", {}).get("tlsScope"),
            "remeasured TLS scope key generation",
        )
        or runtime.get("tlsScopeSigningKeySpkiSha256") != key_id
    ):
        raise AttestationContractError(
            "the signed TLS scope is not bound to production custody"
        )
    return TrustedTlsScope(
        api_version=TRUSTED_TLS_SCOPE_VERSION,
        provider=str(payload["provider"]),
        exporter=exporter,
        exporter_label=str(payload["exporterLabel"]),
        connection_id=str(payload["connectionId"]),
        connection_nonce=connection_nonce,
        issued_at_unix=issued_at,
        expires_at_unix=expires_at,
        leaf_certificate_sha256=str(payload["leafCertificateSha256"]),
        leaf_spki_sha256=str(payload["leafSpkiSha256"]),
        peer_certificate_sha256=str(payload["peerCertificateSha256"]),
        peer_spki_sha256=str(payload["peerSpkiSha256"]),
        peer_identity=str(payload["peerIdentity"]),
        tls_stack_measurement_sha256=str(
            payload["tlsStackMeasurementSha256"]
        ),
        enclave_instance_id=str(payload["enclaveInstanceId"]),
        enclave_boot_id=str(payload["enclaveBootId"]),
        tls_key_generation=payload_tls_generation,
        tls_scope_key_generation=payload_scope_generation,
        tls_scope_key_spki_sha256=key_id,
        envelope_sha256=envelope_sha256,
    )


def trusted_tls_scope_from_asgi(
    scope: Mapping[str, Any],
    *,
    production_state: Mapping[str, Any],
) -> TrustedTlsScope:
    extensions = scope.get("extensions")
    if not isinstance(extensions, Mapping):
        raise AttestationContractError(
            "the enclave TLS extension is unavailable"
        )
    trusted = extensions.get(TRUSTED_TLS_SCOPE_EXTENSION)
    if type(trusted) is not bytes:
        raise AttestationContractError(
            "ordinary host TLS cannot satisfy production attestation"
        )
    return _verified_tls_scope_envelope(
        trusted,
        production_state=production_state,
        now=int(time.time()),
    )


def trusted_public_tls_scope_from_asgi(
    scope: Mapping[str, Any],
    *,
    descriptor: PublicEvidenceProducerDescriptor,
) -> TrustedTlsScope:
    extensions = scope.get("extensions")
    if not isinstance(extensions, Mapping):
        raise AttestationContractError(
            "the enclave TLS extension is unavailable"
        )
    trusted = extensions.get(TRUSTED_TLS_SCOPE_EXTENSION)
    if type(trusted) is not bytes:
        raise AttestationContractError(
            "ordinary host TLS cannot satisfy production attestation"
        )
    envelope = _require_exact_fields(
        _strict_json_document(
            trusted,
            label="public evidence enclave TLS scope envelope",
        ),
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "signature",
            "signingKeyId",
        },
        "public evidence enclave TLS scope envelope",
    )
    payload = _require_exact_fields(
        envelope.get("payload"),
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
        "public evidence enclave TLS scope payload",
    )
    try:
        connection_nonce = b64d(str(payload.get("connectionNonce")))
        exporter = b64d(str(payload.get("exporter")))
    except Exception as exc:
        raise AttestationContractError(
            "public evidence TLS scope binary fields are invalid"
        ) from exc
    tls_key_generation = _require_positive_generation(
        payload.get("tlsKeyGeneration"),
        "public evidence TLS key generation",
    )
    tls_scope_key_generation = _require_positive_generation(
        payload.get("tlsScopeKeyGeneration"),
        "public evidence TLS scope key generation",
    )
    tls_scope_key_encoded = (
        descriptor.tls_scope_signing_public_key_spki_der_base64url
    )
    _, tls_scope_key_id = _load_ed25519_spki_der(
        tls_scope_key_encoded,
        label="pinned public evidence TLS scope signing key",
    )
    synthetic_state = {
        "custody": {
            "materials": [
                {
                    "identitySpkiSha256": payload.get("leafSpkiSha256"),
                    "keyGeneration": tls_key_generation,
                    "name": "tls",
                    "scopeSigningKey": {
                        "keyGeneration": tls_scope_key_generation,
                        "publicKeySpkiDerBase64url":
                        tls_scope_key_encoded,
                        "publicKeySpkiSha256": tls_scope_key_id,
                    },
                }
            ]
        },
        "runtime": {
            "activeTlsConnection": {
                "connectionId": payload.get("connectionId"),
                "connectionNonceSha256":
                sha256_prefixed(connection_nonce),
                "envelopeSha256": sha256_prefixed(trusted),
                "expiresAtUnix": payload.get("expiresAtUnix"),
                "exporterSha256": sha256_prefixed(exporter),
                "issuedAtUnix": payload.get("issuedAtUnix"),
                "leafCertificateSha256":
                payload.get("leafCertificateSha256"),
                "leafSpkiSha256": payload.get("leafSpkiSha256"),
                "peerCertificateSha256":
                payload.get("peerCertificateSha256"),
                "peerIdentity": payload.get("peerIdentity"),
                "peerSpkiSha256": payload.get("peerSpkiSha256"),
                "tlsStackMeasurementSha256":
                payload.get("tlsStackMeasurementSha256"),
            },
            "enclaveBootId": payload.get("enclaveBootId"),
            "enclaveInstanceId": payload.get("enclaveInstanceId"),
            "keyGenerations": {
                "tlsScope": tls_scope_key_generation,
            },
            "tlsScopeSigningKeySpkiSha256": tls_scope_key_id,
        },
    }
    verified = _verified_tls_scope_envelope(
        trusted,
        production_state=synthetic_state,
        now=int(time.time()),
    )
    if (
        verified.tls_scope_key_spki_sha256
        != descriptor.release_identity["configuration"][
            "tlsScopeSigningKeySpkiSha256"
        ]
    ):
        raise AttestationContractError(
            "authenticated public TLS scope crossed the stable release identity"
        )
    return verified


def _production_release() -> bool:
    return RELEASE_CHANNEL.strip().lower() not in _DEVELOPMENT_RELEASE_CHANNELS


def _environment_positive_int(
    name: str, default: int, minimum: int, maximum: int
) -> int:
    raw = os.getenv(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise AttestationContractError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise AttestationContractError(
            f"{name} must be between {minimum} and {maximum}"
        )
    return value


_ATTESTATION_CHALLENGES = ProductionAttestationChallengeStore(
    capacity=_environment_positive_int(
        "SERVERWARE_ATTESTATION_CHALLENGE_CAPACITY", 1024, 16, 65536
    ),
    ttl_seconds=_environment_positive_int(
        "SERVERWARE_ATTESTATION_CHALLENGE_TTL_SECONDS", 60, 15, 300
    ),
    reservation_ttl_seconds=_environment_positive_int(
        "SERVERWARE_ATTESTATION_RESERVATION_TTL_SECONDS", 60, 5, 60
    ),
    per_peer_capacity=_environment_positive_int(
        "SERVERWARE_ATTESTATION_PER_PEER_CAPACITY", 8, 1, 64
    ),
)
_PUBLIC_EVIDENCE_NONCE_CHANNEL_LOCKS: dict[
    tuple[int, int, str], threading.Lock
] = {}
_PUBLIC_EVIDENCE_NONCE_CHANNEL_LOCKS_LOCK = threading.Lock()
_PUBLIC_EVIDENCE_VERIFIER_STATE_SEMAPHORES: dict[
    tuple[str, str, str], threading.BoundedSemaphore
] = {}
_PUBLIC_EVIDENCE_VERIFIER_STATE_SEMAPHORES_LOCK = threading.Lock()
_PUBLIC_EVIDENCE_PRODUCER_SEMAPHORES: dict[
    str, threading.BoundedSemaphore
] = {}
_PUBLIC_EVIDENCE_PRODUCER_SEMAPHORES_LOCK = threading.Lock()
_PUBLIC_EVIDENCE_QUARANTINED_TREES: list[
    _QuarantinedPublicEvidenceTree
] = []
_PUBLIC_EVIDENCE_QUARANTINE_LOCK = threading.Lock()
_PUBLIC_EVIDENCE_QUARANTINE_EVENT = threading.Event()
_PUBLIC_EVIDENCE_QUARANTINE_THREAD_LOCK = threading.Lock()
_PUBLIC_EVIDENCE_QUARANTINE_THREAD: threading.Thread | None = None


def _require_legacy_challenge_deployment() -> None:
    if not _production_release():
        return
    raise AttestationContractError(
        "the process-local legacy challenge protocol is disabled in production; use the durable public-evidence nonce protocol"
    )


def issue_attestation_challenge(
    tls_scope: TrustedTlsScope,
) -> dict[str, Any]:
    _require_legacy_challenge_deployment()
    binding_sha256 = tls_scope.binding_document()["bindingSha256"]
    return _ATTESTATION_CHALLENGES.issue(
        tls_binding_sha256=binding_sha256,
        connection_id=tls_scope.connection_id,
        peer_spki_sha256=tls_scope.peer_spki_sha256,
        bound_expires_at_unix=tls_scope.expires_at_unix,
    ).public_document()


def reserve_attestation_challenge(
    challenge_id: str,
    value: str,
    tls_scope: TrustedTlsScope,
) -> AttestationChallengeReservation:
    _require_legacy_challenge_deployment()
    binding_sha256 = tls_scope.binding_document()["bindingSha256"]
    return _ATTESTATION_CHALLENGES.reserve(
        challenge_id,
        value,
        binding_sha256,
        tls_scope.connection_id,
        tls_scope.peer_spki_sha256,
    )


def finalize_attestation_challenge(
    reservation: AttestationChallengeReservation,
) -> None:
    _ATTESTATION_CHALLENGES.finalize(reservation)


def release_attestation_challenge(
    reservation: AttestationChallengeReservation,
) -> None:
    _ATTESTATION_CHALLENGES.release(reservation)


def canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def sha256_prefixed(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def b64e(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64d(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _require_exact_fields(
    value: Any, expected: set[str], label: str
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != expected:
        raise AttestationContractError(
            f"{label} fields do not match the closed contract"
        )
    return value


def _require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise AttestationContractError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return value


def _require_sha384(value: Any, label: str) -> str:
    if not isinstance(value, str) or _SHA384_RE.fullmatch(value) is None:
        raise AttestationContractError(
            f"{label} must be a lowercase SHA-384 digest"
        )
    return value


def _require_positive_generation(value: Any, label: str) -> int:
    if type(value) is not int or not 1 <= value <= (1 << 64) - 1:
        raise AttestationContractError(f"{label} must be a positive integer")
    return value


def _require_normalized_absolute_path_text(
    value: Any,
    label: str,
) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 4096
        or not value.startswith("/")
        or value == "/"
        or "\x00" in value
        or "//" in value
        or any(component in {".", ".."} for component in value.split("/"))
        or os.path.normpath(value) != value
    ):
        raise AttestationContractError(
            f"{label} path must be normalized and absolute with no dot components"
        )
    return value


def _require_canonical_role_paths(
    value: Any,
    *,
    label: str,
    maximum: int,
) -> tuple[tuple[str, Path], ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise AttestationContractError(f"{label} exceeds its bound")
    result: list[tuple[str, Path]] = []
    for index, item in enumerate(value):
        entry = _require_exact_fields(
            item,
            {"path", "role"},
            f"{label} entry {index}",
        )
        role = entry.get("role")
        if (
            not isinstance(role, str)
            or _IDENTIFIER_RE.fullmatch(role) is None
        ):
            raise AttestationContractError(
                f"{label} entry {index} role is invalid"
            )
        path = Path(
            _require_normalized_absolute_path_text(
                entry.get("path"),
                f"{label} entry {index}",
            )
        )
        result.append((role, path))
    roles = [role for role, _ in result]
    if roles != sorted(set(roles)):
        raise AttestationContractError(
            f"{label} roles must be unique and canonically ordered"
        )
    return tuple(result)


def _require_canonical_roles(
    value: Any,
    *,
    label: str,
    maximum: int,
) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > maximum:
        raise AttestationContractError(f"{label} exceeds its bound")
    result: list[str] = []
    for index, item in enumerate(value):
        entry = _require_exact_fields(
            item,
            {"role"},
            f"{label} entry {index}",
        )
        role = entry.get("role")
        if (
            not isinstance(role, str)
            or _IDENTIFIER_RE.fullmatch(role) is None
        ):
            raise AttestationContractError(
                f"{label} entry {index} is invalid"
            )
        result.append(role)
    if result != sorted(set(result)):
        raise AttestationContractError(
            f"{label} roles must be unique and canonically ordered"
        )
    return tuple(result)


def _retained_public_evidence_stream_fds(
    roles: tuple[str, ...],
) -> tuple[tuple[str, int], ...]:
    raw_value = os.environ.get(
        "SERVERWARE_PUBLIC_ATTESTATION_RETAINED_STREAM_FDS"
    )
    if not roles:
        if raw_value not in {None, ""}:
            raise AttestationContractError(
                "public evidence retained streams were configured without signed roles"
            )
        return ()
    if (
        not isinstance(raw_value, str)
        or not 2 <= len(raw_value) <= 4096
        or not raw_value.isascii()
    ):
        raise AttestationContractError(
            "public evidence retained stream FD map is unavailable"
        )
    raw = raw_value.encode("ascii")
    document = _strict_json_document(
        raw,
        label="public evidence retained stream FD map",
    )
    if (
        raw != canonical_json(document).encode("ascii")
        or set(document) != set(roles)
    ):
        raise AttestationContractError(
            "public evidence retained stream FD map differs from signed roles"
        )
    result: list[tuple[str, int]] = []
    for role in roles:
        descriptor = document[role]
        if (
            type(descriptor) is not int
            or not 3 <= descriptor <= 1_048_575
        ):
            raise AttestationContractError(
                f"public evidence retained stream {role} FD is invalid"
            )
        result.append((role, descriptor))
    if len({descriptor for _, descriptor in result}) != len(result):
        raise AttestationContractError(
            "public evidence retained stream FDs are not unique"
        )
    return tuple(result)


def _retained_public_evidence_verifier_state_tls_fds(
    roles: tuple[str, ...],
) -> tuple[tuple[str, int], ...]:
    raw_value = os.environ.get(
        "SERVERWARE_PUBLIC_ATTESTATION_VERIFIER_STATE_TLS_FDS"
    )
    if (
        not isinstance(raw_value, str)
        or not 2 <= len(raw_value) <= 4096
        or not raw_value.isascii()
    ):
        raise AttestationContractError(
            "public evidence retained verifier-state TLS FD map is unavailable"
        )
    raw = raw_value.encode("ascii")
    document = _strict_json_document(
        raw,
        label="public evidence retained verifier-state TLS FD map",
    )
    if (
        raw != canonical_json(document).encode("ascii")
        or set(document) != set(roles)
    ):
        raise AttestationContractError(
            "public evidence retained verifier-state TLS FD map differs from signed roles"
        )
    result: list[tuple[str, int]] = []
    for role in roles:
        source_fd = document[role]
        if type(source_fd) is not int or not 3 <= source_fd <= 1_048_575:
            raise AttestationContractError(
                f"public evidence retained verifier-state TLS {role} FD is invalid"
            )
        try:
            retained_fd = os.dup(source_fd)
            flags = fcntl.fcntl(retained_fd, fcntl.F_GETFD)
            fcntl.fcntl(
                retained_fd,
                fcntl.F_SETFD,
                flags | fcntl.FD_CLOEXEC,
            )
        except OSError as exc:
            raise AttestationContractError(
                f"public evidence retained verifier-state TLS {role} FD is unavailable"
            ) from exc
        result.append((role, retained_fd))
    if len({descriptor for _, descriptor in result}) != len(result):
        for _, descriptor in result:
            os.close(descriptor)
        raise AttestationContractError(
            "public evidence retained verifier-state TLS FDs are not unique"
        )
    return tuple(result)


def _snapshot_public_evidence_tls_material_fd(
    fd: int,
    *,
    label: str,
    maximum: int,
    read_content: bool = True,
) -> tuple[bytes, tuple[int, ...]]:
    try:
        before = os.fstat(fd)
        access_mode = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != 0
            or mode not in {0o400, 0o440, 0o444}
            or access_mode != os.O_RDONLY
            or not 1 <= before.st_size <= maximum
        ):
            raise AttestationContractError(
                f"{label} retained FD is not a root-owned read-only single-link file"
            )
        raw = bytearray()
        if read_content:
            offset = 0
            while len(raw) <= maximum:
                chunk = os.pread(
                    fd,
                    min(64 * 1024, maximum + 1 - len(raw)),
                    offset,
                )
                if not chunk:
                    break
                raw.extend(chunk)
                offset += len(chunk)
        after = os.fstat(fd)
    except AttestationContractError:
        raise
    except OSError as exc:
        raise AttestationContractError(
            f"{label} retained FD could not be snapshotted"
        ) from exc
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_nlink,
        item.st_uid,
        item.st_gid,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    before_identity = identity(before)
    if (
        before_identity != identity(after)
        or (read_content and len(raw) != before.st_size)
        or len(raw) > maximum
    ):
        raise AttestationContractError(
            f"{label} changed while its retained FD was snapshotted"
        )
    return bytes(raw), before_identity


def _preload_public_evidence_verifier_state_tls_context(
    *,
    ca_fd: int,
    client_certificate_fd: int,
    client_key_fd: int,
    expected_client_certificate_spki_sha256: str,
) -> tuple[ssl.SSLContext, str]:
    ca_raw, ca_identity = _snapshot_public_evidence_tls_material_fd(
        ca_fd,
        label="public evidence verifier-state CA",
        maximum=1024 * 1024,
    )
    certificate_raw, certificate_identity = (
        _snapshot_public_evidence_tls_material_fd(
            client_certificate_fd,
            label="public evidence verifier-state client certificate",
            maximum=256 * 1024,
        )
    )
    key_raw, key_identity = _snapshot_public_evidence_tls_material_fd(
        client_key_fd,
        label="public evidence verifier-state client key",
        maximum=256 * 1024,
        read_content=False,
    )
    if (
        _public_evidence_certificate_spki_sha256(
            certificate_raw,
            label="public evidence verifier-state client certificate",
        )
        != expected_client_certificate_spki_sha256
    ):
        raise AttestationContractError(
            "public evidence verifier-state client certificate crossed its SPKI pin"
        )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.set_alpn_protocols(["http/1.1"])
    try:
        context.load_verify_locations(
            cadata=(
                ca_raw.decode("ascii")
                if ca_raw.startswith(b"-----BEGIN ")
                else ca_raw
            )
        )
        context.load_cert_chain(
            certfile=f"/proc/self/fd/{client_certificate_fd}",
            keyfile=f"/proc/self/fd/{client_key_fd}",
        )
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise AttestationContractError(
            "public evidence retained verifier-state TLS material could not be preloaded"
        ) from exc
    for fd, expected, label in (
        (ca_fd, ca_identity, "CA"),
        (
            client_certificate_fd,
            certificate_identity,
            "client certificate",
        ),
        (client_key_fd, key_identity, "client key"),
    ):
        try:
            if expected != (
                lambda item: (
                    item.st_dev,
                    item.st_ino,
                    item.st_mode,
                    item.st_nlink,
                    item.st_uid,
                    item.st_gid,
                    item.st_size,
                    item.st_mtime_ns,
                    item.st_ctime_ns,
                )
            )(os.fstat(fd)):
                raise AttestationContractError(
                    f"public evidence verifier-state {label} changed during TLS preload"
                )
        except OSError as exc:
            raise AttestationContractError(
                f"public evidence verifier-state {label} identity was lost during TLS preload"
            ) from exc
    snapshot = {
        "caSha256": sha256_prefixed(ca_raw),
        "clientCertificateSha256":
        sha256_prefixed(certificate_raw),
        "clientCertificateSpkiSha256":
        expected_client_certificate_spki_sha256,
        "clientKeyIdentitySha256": sha256_prefixed(
            canonical_json(list(key_identity)).encode("ascii")
        ),
    }
    del key_raw
    return (
        context,
        sha256_prefixed(canonical_json(snapshot).encode("ascii")),
    )


def _read_stable_root_owned_file(
    path: Path, *, label: str, maximum: int
) -> bytes:
    if (
        not path.is_absolute()
        or not path.name
        or "." in path.parts
        or ".." in path.parts
        or os.path.normpath(os.fspath(path)) != os.fspath(path)
    ):
        raise AttestationContractError(
            f"{label} path must be normalized and absolute"
        )
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        raise AttestationContractError(
            f"{label} requires no-follow file operations"
        )
    directory_flags = (
        os.O_RDONLY
        | directory
        | no_follow
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open("/", directory_flags)
    file_descriptor: int | None = None
    try:
        for component in path.parent.parts[1:]:
            next_descriptor = os.open(
                component, directory_flags, dir_fd=descriptor
            )
            directory_stat = os.fstat(next_descriptor)
            if (
                not stat.S_ISDIR(directory_stat.st_mode)
                or directory_stat.st_uid != 0
                or stat.S_IMODE(directory_stat.st_mode) & 0o022
            ):
                os.close(next_descriptor)
                raise AttestationContractError(
                    f"{label} path must use root-owned, non-writable directories"
                )
            os.close(descriptor)
            descriptor = next_descriptor
        file_descriptor = os.open(
            path.name,
            os.O_RDONLY
            | no_follow
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=descriptor,
        )
        before = os.fstat(file_descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != 0
            or mode not in {0o400, 0o440, 0o444}
            or not 1 <= before.st_size <= maximum
        ):
            raise AttestationContractError(
                f"{label} must be a root-owned, read-only, single-link regular file"
            )
        payload = bytearray()
        while len(payload) <= maximum:
            chunk = os.read(file_descriptor, maximum + 1 - len(payload))
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(file_descriptor)
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_uid,
            item.st_gid,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if (
            identity(before) != identity(after)
            or len(payload) != before.st_size
            or len(payload) > maximum
        ):
            raise AttestationContractError(
                f"{label} changed or exceeded its bound while being read"
            )
        return bytes(payload)
    except AttestationContractError:
        raise
    except OSError as exc:
        raise AttestationContractError(
            f"{label} is unavailable through a safe path"
        ) from exc
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        os.close(descriptor)


def _strict_json_document(raw: bytes, *, label: str) -> dict[str, Any]:
    if not raw or raw.startswith(b"\xef\xbb\xbf"):
        raise AttestationContractError(f"{label} is not canonical JSON")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise AttestationContractError(
                    f"{label} contains duplicate JSON keys"
                )
            result[key] = value
        return result

    try:
        value = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=pairs,
            parse_float=lambda _: (_ for _ in ()).throw(
                AttestationContractError(
                    f"{label} must not contain floating-point values"
                )
            ),
            parse_constant=lambda _: (_ for _ in ()).throw(
                AttestationContractError(
                    f"{label} must not contain non-finite values"
                )
            ),
        )
    except AttestationContractError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise AttestationContractError(f"{label} is invalid JSON") from exc
    if not isinstance(value, dict):
        raise AttestationContractError(f"{label} must be a JSON object")
    _validate_public_json_grammar(value, label=label)
    if len(canonical_json(value).encode("ascii")) > len(raw) + 4096:
        raise AttestationContractError(f"{label} exceeds canonical bounds")
    return value


def _configured_production_path(environment_name: str, label: str) -> Path:
    raw = os.getenv(environment_name, "")
    if not raw or raw != raw.strip():
        raise AttestationContractError(f"{label} path is not configured")
    return Path(raw)


def _validate_pcrs(value: Any, label: str) -> dict[str, str]:
    pcrs = _require_exact_fields(value, {"PCR0", "PCR1", "PCR2"}, label)
    return {
        name: _require_sha384(pcrs.get(name), f"{label} {name}")
        for name in ("PCR0", "PCR1", "PCR2")
    }


def _validate_key_generations(value: Any) -> dict[str, int]:
    generations = _require_exact_fields(
        value, _KEY_GENERATION_FIELDS, "production key generations"
    )
    return {
        name: _require_positive_generation(
            generations.get(name), f"{name} key generation"
        )
        for name in sorted(_KEY_GENERATION_FIELDS)
    }


def _validate_completion_identity(value: Any) -> dict[str, Any]:
    identity = _require_exact_fields(
        value,
        {
            "apiVersion",
            "challengeNonceSha256",
            "coreDigests",
            "pipeline",
            "releaseGeneration",
            "rollbackEpoch",
        },
        "final completion identity",
    )
    if identity.get("apiVersion") != FINAL_COMPLETION_IDENTITY_VERSION:
        raise AttestationContractError(
            "final completion identity version is invalid"
        )
    if identity.get("pipeline") != PRODUCTION_PIPELINE:
        raise AttestationContractError(
            "final completion identity pipeline is invalid"
        )
    _require_digest(
        identity.get("challengeNonceSha256"),
        "final completion challenge nonce",
    )
    core_digests = _require_exact_fields(
        identity.get("coreDigests"),
        FINAL_COMPLETION_CORE_FIELDS,
        "final completion core digests",
    )
    for name, digest in core_digests.items():
        _require_digest(digest, f"final completion {name} core")
    if (
        type(identity.get("releaseGeneration")) is not int
        or identity["releaseGeneration"] < 1
        or type(identity.get("rollbackEpoch")) is not int
        or identity["rollbackEpoch"] < 0
    ):
        raise AttestationContractError(
            "final completion release generation or rollback epoch is invalid"
        )
    return dict(identity)


def _without_completion_bindings(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {
            str(key): _without_completion_bindings(item)
            for key, item in value.items()
            if key not in FINAL_COMPLETION_BINDING_FIELDS
        }
    if isinstance(value, list):
        return [_without_completion_bindings(item) for item in value]
    return value


def _completion_core(name: str, payload: Mapping[str, Any]) -> dict[str, Any]:
    if name not in FINAL_COMPLETION_CORE_VERSIONS:
        raise AttestationContractError(f"unknown completion core {name}")
    core = {
        "apiVersion": FINAL_COMPLETION_CORE_VERSIONS[name],
        "pipeline": PRODUCTION_PIPELINE,
        "payload": dict(payload),
    }
    stack: list[Any] = [core]
    while stack:
        current = stack.pop()
        if isinstance(current, Mapping):
            forbidden = FINAL_COMPLETION_BINDING_FIELDS.intersection(current)
            if forbidden:
                raise AttestationContractError(
                    f"{name} completion core contains a completion binding"
                )
            stack.extend(current.values())
        elif isinstance(current, list):
            stack.extend(current)
    return core


def _builder_transcript_core_payload(
    transcript: Mapping[str, Any],
) -> dict[str, Any]:
    outer_events = transcript.get("events")
    if not isinstance(outer_events, list):
        raise AttestationContractError(
            "builder transcript core requires an event list"
        )
    previous_core_event_sha256 = sha256_prefixed(b"")
    core_events: list[dict[str, Any]] = []
    for sequence, outer_record in enumerate(outer_events, start=1):
        if (
            not isinstance(outer_record, Mapping)
            or outer_record.get("sequence") != sequence
            or not isinstance(outer_record.get("event"), Mapping)
        ):
            raise AttestationContractError(
                "builder transcript core event is malformed"
            )
        core_event_payload = {
            "event": _without_completion_bindings(outer_record["event"]),
            "previousEventSha256": previous_core_event_sha256,
            "sequence": sequence,
        }
        core_event_sha256 = sha256_prefixed(
            canonical_json(core_event_payload).encode("ascii")
        )
        core_events.append(
            {
                **core_event_payload,
                "eventSha256": core_event_sha256,
            }
        )
        previous_core_event_sha256 = core_event_sha256
    core_payload = {
        str(key): _without_completion_bindings(value)
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
    return core_payload


def _validate_completion_identity_binding(
    value: Any, digest: Any, *, label: str
) -> dict[str, Any]:
    identity = _validate_completion_identity(value)
    expected = sha256_prefixed(canonical_json(identity).encode("ascii"))
    if not isinstance(digest, str) or not hmac.compare_digest(digest, expected):
        raise AttestationContractError(
            f"{label} completion identity digest is invalid"
        )
    return identity


def _validate_production_identity(value: dict[str, Any]) -> dict[str, Any]:
    identity = _require_exact_fields(
        value,
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
    if (
        identity.get("apiVersion") != PRODUCTION_IDENTITY_VERSION
        or identity.get("pipeline") != PRODUCTION_PIPELINE
    ):
        raise AttestationContractError(
            "production identity is not the Manifest v6 Nitro pipeline"
        )
    for field in (
        "buildWatchdogReceiptSha256",
        "candidateManifestFileSha256",
        "candidateManifestPayloadSha256",
        "completionIdentitySha256",
        "dependencyClosureSha256",
        "importedImageMappingsSha256",
        "monotonicWitnessSha256",
        "promotedManifestSha256",
        "promotionReceiptSha256",
        "productionContinuitySha256",
        "productionReleaseIdentitySha256",
        "sourceClosureSha256",
        "sourceInputApprovalSha256",
        "sourceInputManifestFileSha256",
        "sourceInputManifestPayloadSha256",
    ):
        _require_digest(identity.get(field), f"production identity {field}")
    _validate_completion_identity_binding(
        identity.get("completionIdentity"),
        identity.get("completionIdentitySha256"),
        label="production identity",
    )
    builder_digests = identity.get("builderStatementSha256s")
    if (
        not isinstance(builder_digests, list)
        or len(builder_digests) != 2
        or builder_digests != sorted(builder_digests)
        or len(set(builder_digests)) != 2
    ):
        raise AttestationContractError(
            "production identity must bind exactly two ordered independent builders"
        )
    for digest in builder_digests:
        _require_digest(digest, "builder statement")
    image_sha384 = _require_sha384(
        identity.get("eifImageSha384"), "production EIF image"
    )
    pcrs = _validate_pcrs(identity.get("pcrs"), "production EIF PCRs")
    if not hmac.compare_digest(pcrs["PCR0"], image_sha384):
        raise AttestationContractError(
            "production EIF image digest does not match PCR0"
        )
    _require_positive_generation(
        identity.get("releaseGeneration"), "production release generation"
    )
    return dict(identity)


def _manifest_dependency_role(name: str) -> str:
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


def _manifest_expected_process(name: str) -> dict[str, Any]:
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
            list(_MANIFEST_PORTAL_DYNAMIC_ENVIRONMENT)
            if name == "portal-browser-oauth"
            else []
        ),
        "entrypoint": entrypoint,
        "environment": dict(_MANIFEST_BASE_ENVIRONMENT),
        "gid": 65532,
        "uid": 65532,
    }


def _validate_manifest_isolation(value: Any, *, name: str) -> None:
    isolation = _require_exact_fields(
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
    fixed = {
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
    for field, expected in fixed.items():
        if isolation.get(field) != expected:
            raise AttestationContractError(
                f"{name} isolation {field} is not the fixed v6 contract"
            )
    _require_digest(
        isolation.get("apparmorProfileSha256"),
        f"{name} AppArmor profile",
    )
    _require_digest(
        isolation.get("seccompProfileSha256"),
        f"{name} seccomp profile",
    )


def _validate_manifest_network(value: Any, *, name: str) -> None:
    network = _require_exact_fields(
        value, {"egress", "mode", "namespace", "role"}, f"{name} network"
    )
    if name == "portal-browser-oauth":
        expected = {
            "egress": "none",
            "mode": "internal",
            "namespace": "private-anchor",
            "role": "portal-npm-private",
        }
    elif name == "npm-publish-companion":
        expected = {
            "egress": "none",
            "mode": "join",
            "namespace": "lane:portal-browser-oauth",
            "role": "portal-npm-private",
        }
    else:
        expected = {
            "egress": "none",
            "mode": "none",
            "namespace": "private",
            "role": None,
        }
    if dict(network) != expected:
        raise AttestationContractError(
            f"{name} network is not the fixed v6 contract"
        )


def _validate_manifest_runtime(
    value: Any,
    *,
    name: str,
    image: Mapping[str, Any],
) -> None:
    runtime = _require_exact_fields(
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
    role = _manifest_dependency_role(name)
    expected_semantic = (
        image.get("semanticContract", {}).get("contractSha256")
        if name == "clean-room"
        and isinstance(image.get("semanticContract"), Mapping)
        else None
    )
    if (
        runtime.get("dependencyRole") != role
        or runtime.get("dependencyCapabilities")
        != _MANIFEST_DEPENDENCY_CAPABILITIES[role]
        or runtime.get("dependencyCapabilityCatalogSha256")
        != image.get("capabilityCatalogSha256")
        or runtime.get("dependencyClosureSha256")
        != image.get("dependencyClosureSha256")
        or runtime.get("dependencyFileManifestSha256")
        != image.get("dependencyFileManifestSha256")
        or runtime.get("semanticContractSha256") != expected_semantic
    ):
        raise AttestationContractError(
            f"{name} runtime does not match its imported image"
        )
    for field in (
        "dependencyCapabilityCatalogSha256",
        "dependencyClosureSha256",
        "dependencyFileManifestSha256",
    ):
        _require_digest(runtime.get(field), f"{name} runtime {field}")


def _validate_manifest_image(value: Any, *, role: str) -> dict[str, Any]:
    image = _require_exact_fields(
        value,
        {
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
        },
        f"{role} imported image",
    )
    lane_name = role.removeprefix("lane-")
    if (
        image.get("role") != role
        or image.get("platform") != {"architecture": "amd64", "os": "linux"}
        or image.get("containerdImageId") != image.get("manifestDigest")
        or image.get("dependencyRole")
        != _manifest_dependency_role(lane_name)
    ):
        raise AttestationContractError(
            f"{role} imported image identity is invalid"
        )
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
        _require_digest(image.get(field), f"{role} image {field}")
    catalog = image.get("capabilityCatalog")
    if not isinstance(catalog, Mapping):
        raise AttestationContractError(
            f"{role} dependency capability catalog is missing"
        )
    catalog_payload = dict(catalog)
    catalog_digest = catalog_payload.pop("catalogSha256", None)
    if (
        catalog.get("apiVersion")
        != "serverware.dependencyCapabilityCatalog/v2"
        or catalog_digest != image["capabilityCatalogSha256"]
        or catalog_digest
        != sha256_prefixed(
            canonical_json(catalog_payload).encode("ascii")
        )
    ):
        raise AttestationContractError(
            f"{role} dependency capability catalog is invalid"
        )
    capability_attestation = _require_exact_fields(
        image.get("capabilityAttestation"),
        {"apiVersion", "payload", "payloadSha256", "signature"},
        f"{role} dependency capability attestation",
    )
    capability_payload = capability_attestation.get("payload")
    if (
        capability_attestation.get("apiVersion")
        != "serverware.dependencyCapabilityAttestation/v1"
        or not isinstance(capability_payload, Mapping)
        or capability_attestation.get("payloadSha256")
        != sha256_prefixed(
            canonical_json(capability_payload).encode("ascii")
        )
        or not isinstance(capability_attestation.get("signature"), Mapping)
    ):
        raise AttestationContractError(
            f"{role} dependency capability attestation is invalid"
        )
    signature = _require_exact_fields(
        capability_attestation["signature"],
        {
            "algorithm",
            "domain",
            "keyFileSha256",
            "rawKeySha256",
            "value",
        },
        f"{role} dependency capability signature",
    )
    if (
        signature.get("algorithm") != "Ed25519"
        or signature.get("domain")
        != "serverware.dependencyCapabilityAttestation/v1\x00Ed25519"
        or not isinstance(signature.get("value"), str)
    ):
        raise AttestationContractError(
            f"{role} dependency capability signature metadata is invalid"
        )
    for field in ("keyFileSha256", "rawKeySha256"):
        _require_digest(signature.get(field), f"{role} capability {field}")
    try:
        capability_signature = base64.b64decode(
            str(signature.get("value")), validate=True
        )
    except Exception as exc:
        raise AttestationContractError(
            f"{role} dependency capability signature is invalid"
        ) from exc
    if len(capability_signature) != 64:
        raise AttestationContractError(
            f"{role} dependency capability signature is invalid"
        )
    diff_ids = image.get("rootfsDiffIds")
    if (
        not isinstance(diff_ids, list)
        or not diff_ids
        or diff_ids != list(dict.fromkeys(diff_ids))
    ):
        raise AttestationContractError(f"{role} rootfs layers are invalid")
    for digest in diff_ids:
        _require_digest(digest, f"{role} rootfs layer")
    if role == "npm-publish-companion":
        tools = _require_exact_fields(
            image.get("fixedToolIdentities"),
            {"node", "npmEntrypoint", "npmPackageManifest"},
            "npm fixed tool identities",
        )
        for name, tool_value in tools.items():
            tool = _require_exact_fields(
                tool_value, {"path", "sha256", "size"}, f"npm {name}"
            )
            if (
                not isinstance(tool.get("path"), str)
                or not tool["path"].startswith("/")
                or type(tool.get("size")) is not int
                or tool["size"] < 1
            ):
                raise AttestationContractError(
                    f"npm {name} identity is invalid"
                )
            _require_digest(tool.get("sha256"), f"npm {name}")
    elif image.get("fixedToolIdentities") is not None:
        raise AttestationContractError(
            f"{role} has unauthorized fixed tool identities"
        )
    return dict(image)


def _validate_promoted_manifest(value: dict[str, Any]) -> dict[str, Any]:
    manifest = _require_exact_fields(
        value,
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
    if (
        manifest.get("apiVersion") != PROMOTED_MANIFEST_VERSION
        or manifest.get("platform")
        != {"architecture": "amd64", "os": "linux"}
    ):
        raise AttestationContractError(
            "promoted manifest is not Manifest v6"
        )
    payload = dict(manifest)
    manifest_sha256 = _require_digest(
        payload.pop("manifestSha256", None), "promoted Manifest v6 payload"
    )
    if not hmac.compare_digest(
        manifest_sha256,
        sha256_prefixed(canonical_json(payload).encode("ascii")),
    ):
        raise AttestationContractError(
            "promoted Manifest v6 payload digest is invalid"
        )
    candidate = _require_exact_fields(
        manifest.get("candidate"),
        {
            "fileSha256",
            "indexSha256",
            "payloadSha256",
            "promotionContractSha256",
        },
        "Manifest v6 candidate",
    )
    for field in candidate:
        _require_digest(candidate.get(field), f"candidate {field}")
    source = _require_exact_fields(
        manifest.get("sourceSnapshot"),
        {
            "sourceClosureSha256",
            "sourceEvidence",
            "sourceEvidenceSha256",
            "sourceFileInventorySha256",
            "sourceGitInventoryKeyRawSha256",
            "sourceGitInventoryKeySpkiSha256",
            "sourceGitInventoryPayloadSha256",
            "sourceManifestFileSha256",
            "sourceManifestPayloadSha256",
            "sourcePathListSha256",
            "sourceRootBindingSha256",
            "sourceSelectionManifestFileSha256",
            "sourceSelectionManifestPayloadSha256",
            "sourceSelectionModel",
            "sourceUntrackedApprovalKeyRawSha256",
            "sourceUntrackedApprovalKeySpkiSha256",
            "sourceUntrackedApprovalPayloadSha256",
            "snapshotRootBindingSha256",
        },
        "Manifest v6 source snapshot",
    )
    if (
        source.get("sourceSelectionModel")
        != "signed-raw-git-index-tree-worktree-status-plus-approved-untracked/v3"
        or not isinstance(source.get("sourceEvidence"), Mapping)
    ):
        raise AttestationContractError(
            "Manifest v6 source selection contract is invalid"
        )
    source_evidence = _require_exact_fields(
        source.get("sourceEvidence"),
        {
            "apiVersion",
            "gitInventory",
            "identitySha256",
            "untrackedApproval",
        },
        "Manifest v6 source evidence",
    )
    git_inventory = _require_exact_fields(
        source_evidence.get("gitInventory"),
        {
            "envelopeSha256",
            "headTree",
            "indexEntriesSha256",
            "indexRawSha256",
            "indexTree",
            "keyRawSha256",
            "keySpkiSha256",
            "payloadSha256",
            "signatureSha256",
            "statusRawSha256",
            "treeEntriesSha256",
            "treeRawSha256",
            "worktreeEntriesSha256",
        },
        "Manifest v6 Git source evidence",
    )
    untracked = _require_exact_fields(
        source_evidence.get("untrackedApproval"),
        {
            "challengeSha256",
            "envelopeSha256",
            "keyRawSha256",
            "keySpkiSha256",
            "pathListSha256",
            "payloadSha256",
            "signatureSha256",
        },
        "Manifest v6 untracked-source approval",
    )
    if (
        source_evidence.get("apiVersion")
        != "serverware.sourceEvidenceIdentity/v1"
        or git_inventory.get("indexTree") != git_inventory.get("headTree")
        or source_evidence.get("identitySha256")
        != sha256_prefixed(
            canonical_json(
                {
                    "apiVersion": source_evidence["apiVersion"],
                    "gitInventory": git_inventory,
                    "untrackedApproval": untracked,
                }
            ).encode("ascii")
        )
        or source.get("sourceEvidenceSha256")
        != source_evidence.get("identitySha256")
        or source.get("sourceGitInventoryKeyRawSha256")
        != git_inventory.get("keyRawSha256")
        or source.get("sourceGitInventoryKeySpkiSha256")
        != git_inventory.get("keySpkiSha256")
        or source.get("sourceGitInventoryPayloadSha256")
        != git_inventory.get("payloadSha256")
        or source.get("sourceUntrackedApprovalKeyRawSha256")
        != untracked.get("keyRawSha256")
        or source.get("sourceUntrackedApprovalKeySpkiSha256")
        != untracked.get("keySpkiSha256")
        or source.get("sourceUntrackedApprovalPayloadSha256")
        != untracked.get("payloadSha256")
    ):
        raise AttestationContractError(
            "Manifest v6 source evidence bindings are invalid"
        )
    for record, label in (
        (git_inventory, "Git source evidence"),
        (untracked, "untracked-source approval"),
    ):
        for field, item in record.items():
            if field in {"headTree", "indexTree"}:
                if not isinstance(item, str) or re.fullmatch(
                    r"(?:sha1:[0-9a-f]{40}|sha256:[0-9a-f]{64})", item
                ) is None:
                    raise AttestationContractError(
                        f"{label} tree identity is invalid"
                    )
            else:
                _require_digest(item, f"{label} {field}")
    for field, item in source.items():
        if field in {"sourceEvidence", "sourceSelectionModel"}:
            continue
        _require_digest(item, f"source snapshot {field}")
    lane_order = manifest.get("laneOrder")
    lanes = manifest.get("lanes")
    images = manifest.get("images")
    mappings = manifest.get("imageMappings")
    if (
        lane_order != list(_MANIFEST_LANE_ORDER)
        or not isinstance(lanes, dict)
        or list(lanes) != list(_MANIFEST_LANE_ORDER)
        or not isinstance(images, dict)
        or list(images) != list(_MANIFEST_IMAGE_ORDER)
        or not isinstance(mappings, dict)
        or list(mappings) != list(_MANIFEST_IMAGE_ORDER)
    ):
        raise AttestationContractError(
            "Manifest v6 lane and image order is invalid"
        )
    validated_images = {
        role: _validate_manifest_image(images[role], role=role)
        for role in _MANIFEST_IMAGE_ORDER
    }
    for role in _MANIFEST_IMAGE_ORDER:
        mapping = _require_exact_fields(
            mappings[role],
            {"candidate", "imported", "mappingSha256", "role"},
            f"{role} image mapping",
        )
        candidate_image = _require_exact_fields(
            mapping.get("candidate"),
            {
                "archiveSha256",
                "archiveSize",
                "capabilityAttestation",
                "capabilityCatalog",
                "capabilityCatalogSha256",
                "configDigest",
                "dependencyClosureSha256",
                "dependencyFileManifestSha256",
                "dependencyPackageInventorySha256",
                "dependencyRole",
                "executableInventorySha256",
                "fileManifestSha256",
                "fixedToolIdentities",
                "indexDigest",
                "layerDigests",
                "manifestDigest",
                "rootfsDiffIds",
                "rootfsDigest",
                "sbomSha256",
                "semanticContract",
            },
            f"{role} candidate image",
        )
        if (
            mapping.get("role") != role
            or mapping.get("imported") != validated_images[role]
            or type(candidate_image.get("archiveSize")) is not int
            or candidate_image["archiveSize"] < 1
        ):
            raise AttestationContractError(
                f"{role} candidate/imported image mapping is invalid"
            )
        for candidate_field, imported_field in (
            ("capabilityAttestation", "capabilityAttestation"),
            ("capabilityCatalog", "capabilityCatalog"),
            ("capabilityCatalogSha256", "capabilityCatalogSha256"),
            ("configDigest", "configDigest"),
            ("dependencyClosureSha256", "dependencyClosureSha256"),
            ("dependencyFileManifestSha256", "dependencyFileManifestSha256"),
            (
                "dependencyPackageInventorySha256",
                "dependencyPackageInventorySha256",
            ),
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
            if (
                candidate_image.get(candidate_field)
                != validated_images[role].get(imported_field)
            ):
                raise AttestationContractError(
                    f"{role} candidate/imported {candidate_field} differs"
                )
        for field in (
            "archiveSha256",
            "capabilityCatalogSha256",
            "configDigest",
            "dependencyClosureSha256",
            "dependencyFileManifestSha256",
            "dependencyPackageInventorySha256",
            "executableInventorySha256",
            "fileManifestSha256",
            "indexDigest",
            "manifestDigest",
            "rootfsDigest",
            "sbomSha256",
        ):
            _require_digest(candidate_image.get(field), f"{role} {field}")
        for field in ("layerDigests", "rootfsDiffIds"):
            if (
                not isinstance(candidate_image.get(field), list)
                or not candidate_image[field]
            ):
                raise AttestationContractError(
                    f"{role} candidate {field} is invalid"
                )
            for digest in candidate_image[field]:
                _require_digest(digest, f"{role} candidate {field}")
        expected_mapping_digest = sha256_prefixed(
            canonical_json(
                {
                    "candidate": candidate_image,
                    "imported": validated_images[role],
                    "role": role,
                }
            ).encode("ascii")
        )
        if mapping.get("mappingSha256") != expected_mapping_digest:
            raise AttestationContractError(
                f"{role} image mapping digest is invalid"
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
    for name in _MANIFEST_LANE_ORDER:
        lane = _require_exact_fields(
            lanes[name],
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
            f"{name} lane",
        )
        if (
            lane.get("name") != name
            or lane.get("imageRole") != f"lane-{name}"
            or lane.get("capabilityProbes") != expected_probes.get(name, [])
            or lane.get("process") != _manifest_expected_process(name)
            or lane.get("sourceSet") != _MANIFEST_SOURCE_CONTRACTS[name]
        ):
            raise AttestationContractError(
                f"{name} lane identity is not the fixed v6 contract"
            )
        _validate_manifest_isolation(lane.get("isolation"), name=name)
        _validate_manifest_network(lane.get("network"), name=name)
        _validate_manifest_runtime(
            lane.get("runtime"),
            name=name,
            image=validated_images[f"lane-{name}"],
        )
    companions = _require_exact_fields(
        manifest.get("companions"), {"npmPublish"}, "Manifest v6 companions"
    )
    npm = _require_exact_fields(
        companions.get("npmPublish"),
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
    if (
        npm.get("imageRole") != "npm-publish-companion"
        or npm.get("npmVersion") != "11.8.0"
        or npm.get("operation") != "npm.publish.fixture"
        or npm.get("operationCount") != 2
        or npm.get("inputProtocol")
        != "one-canonical-json-frame-on-stdin-no-generic-command"
        or npm.get("retryEquality")
        != {
            "canonicalHttpRequestBytes": "identical",
            "operationInputBytes": "identical",
            "rawHttpRequestBytes": "different-only-by-npm-session",
            "requestBodyBytes": "identical",
        }
        or npm.get("process")
        != _manifest_expected_process("npm-publish-companion")
        or npm.get("sourceSet")
        != {"exact": ["scripts/npm_publish_companion.js"], "prefixes": []}
    ):
        raise AttestationContractError(
            "npm publish companion is not the fixed v6 contract"
        )
    _validate_manifest_isolation(
        npm.get("isolation"), name="npm-publish-companion"
    )
    _validate_manifest_network(
        npm.get("network"), name="npm-publish-companion"
    )
    _validate_manifest_runtime(
        npm.get("runtime"),
        name="npm-publish-companion",
        image=validated_images["npm-publish-companion"],
    )
    promotion = _require_exact_fields(
        manifest.get("promotion"),
        {
            "acceptanceSha256",
            "apiVersion",
            "candidatePromotionContractSha256",
        },
        "Manifest v6 promotion",
    )
    if promotion.get("apiVersion") != "serverware.verificationPromotionAcceptance/v2":
        raise AttestationContractError("Manifest v6 promotion version is invalid")
    _require_digest(
        promotion.get("candidatePromotionContractSha256"),
        "candidate promotion contract",
    )
    promotion_payload = dict(promotion)
    supplied_acceptance = promotion_payload.pop("acceptanceSha256", None)
    if supplied_acceptance != sha256_prefixed(
        canonical_json(promotion_payload).encode("ascii")
    ):
        raise AttestationContractError(
            "Manifest v6 promotion acceptance digest is invalid"
        )
    watchdog = _require_exact_fields(
        manifest.get("watchdog"),
        {
            "bootCleanupContractSha256",
            "protocolVersion",
            "resourceLabelNames",
            "selectionMode",
        },
        "Manifest v6 watchdog",
    )
    if (
        watchdog.get("protocolVersion")
        != "serverware.ociVerificationWatchdog/v4"
        or watchdog.get("selectionMode")
        != "exact-kind-id-pairs-and-complete-label-set"
        or watchdog.get("resourceLabelNames")
        != [
            "org.serverware.attempt",
            "org.serverware.kind",
            "org.serverware.lane",
            "org.serverware.lane-sequence",
            "org.serverware.lease",
            "org.serverware.manifest",
            "org.serverware.promotion-receipt",
            "org.serverware.role",
        ]
    ):
        raise AttestationContractError(
            "Manifest v6 watchdog contract is invalid"
        )
    _require_digest(
        watchdog.get("bootCleanupContractSha256"),
        "watchdog boot cleanup contract",
    )
    return dict(manifest)


class _CborReader:
    def __init__(self, raw: bytes, *, maximum_items: int = 8192) -> None:
        self.raw = raw
        self.offset = 0
        self.items = 0
        self.maximum_items = maximum_items

    def _take(self, count: int) -> bytes:
        if count < 0 or self.offset + count > len(self.raw):
            raise AttestationContractError("Nitro CBOR is truncated")
        result = self.raw[self.offset : self.offset + count]
        self.offset += count
        return result

    def _length(self, additional: int) -> int:
        if additional < 24:
            return additional
        widths = {24: 1, 25: 2, 26: 4, 27: 8}
        width = widths.get(additional)
        if width is None:
            raise AttestationContractError(
                "Nitro CBOR indefinite or reserved lengths are forbidden"
            )
        value = int.from_bytes(self._take(width), "big")
        minimum = {1: 24, 2: 256, 4: 65536, 8: 1 << 32}[width]
        if value < minimum:
            raise AttestationContractError(
                "Nitro CBOR uses a noncanonical integer length"
            )
        return value

    def read(self, depth: int = 0) -> Any:
        if depth > 24 or self.items >= self.maximum_items:
            raise AttestationContractError("Nitro CBOR exceeds structural bounds")
        self.items += 1
        initial = self._take(1)[0]
        major = initial >> 5
        additional = initial & 31
        if major in {0, 1}:
            value = self._length(additional)
            return value if major == 0 else -1 - value
        if major in {2, 3}:
            length = self._length(additional)
            if length > 1024 * 1024:
                raise AttestationContractError("Nitro CBOR string is oversized")
            raw = self._take(length)
            if major == 2:
                return raw
            try:
                return raw.decode("utf-8", errors="strict")
            except UnicodeDecodeError as exc:
                raise AttestationContractError(
                    "Nitro CBOR text is invalid UTF-8"
                ) from exc
        if major == 4:
            length = self._length(additional)
            if length > 4096:
                raise AttestationContractError("Nitro CBOR array is oversized")
            return [self.read(depth + 1) for _ in range(length)]
        if major == 5:
            length = self._length(additional)
            if length > 4096:
                raise AttestationContractError("Nitro CBOR map is oversized")
            result: dict[Any, Any] = {}
            previous_key_order: tuple[int, bytes] | None = None
            for _ in range(length):
                key_start = self.offset
                key = self.read(depth + 1)
                encoded_key = self.raw[key_start : self.offset]
                key_order = (len(encoded_key), encoded_key)
                if not isinstance(key, (int, str)) or key in result:
                    raise AttestationContractError(
                        "Nitro CBOR map key is invalid or duplicated"
                    )
                if (
                    previous_key_order is not None
                    and key_order <= previous_key_order
                ):
                    raise AttestationContractError(
                        "Nitro CBOR map keys are not in canonical order"
                    )
                previous_key_order = key_order
                result[key] = self.read(depth + 1)
            return result
        if major == 6:
            tag = self._length(additional)
            return ("tag", tag, self.read(depth + 1))
        if major == 7 and additional in {20, 21, 22}:
            return {20: False, 21: True, 22: None}[additional]
        raise AttestationContractError(
            "Nitro CBOR contains an unsupported value"
        )


def _parse_nitro_attestation_document(raw: bytes) -> dict[str, Any]:
    if not 512 <= len(raw) <= 1024 * 1024:
        raise AttestationContractError(
            "raw Nitro attestation document is outside its size bound"
        )
    outer_reader = _CborReader(raw)
    cose = outer_reader.read()
    if outer_reader.offset != len(raw):
        raise AttestationContractError("raw Nitro COSE has trailing bytes")
    if (
        isinstance(cose, tuple)
        and len(cose) == 3
        and cose[0] == "tag"
        and cose[1] == 18
    ):
        cose = cose[2]
    if (
        not isinstance(cose, list)
        or len(cose) != 4
        or not isinstance(cose[0], bytes)
        or not isinstance(cose[1], dict)
        or not isinstance(cose[2], bytes)
        or not isinstance(cose[3], bytes)
        or len(cose[3]) < 64
    ):
        raise AttestationContractError("raw Nitro document is not COSE_Sign1")
    payload_reader = _CborReader(cose[2])
    payload = payload_reader.read()
    if payload_reader.offset != len(cose[2]) or not isinstance(payload, dict):
        raise AttestationContractError(
            "raw Nitro COSE payload is invalid"
        )
    required = {
        "module_id",
        "digest",
        "timestamp",
        "pcrs",
        "certificate",
        "cabundle",
        "public_key",
        "user_data",
        "nonce",
    }
    if set(payload) != required:
        raise AttestationContractError(
            "raw Nitro payload fields do not match the closed contract"
        )
    if (
        not isinstance(payload["module_id"], str)
        or not 1 <= len(payload["module_id"]) <= 256
        or payload["digest"] != "SHA384"
        or type(payload["timestamp"]) is not int
        or payload["timestamp"] < 1
        or not isinstance(payload["certificate"], bytes)
        or not 1 <= len(payload["certificate"]) <= 16 * 1024
        or not isinstance(payload["cabundle"], list)
        or not 1 <= len(payload["cabundle"]) <= 16
        or any(
            not isinstance(item, bytes) or not 1 <= len(item) <= 16 * 1024
            for item in payload["cabundle"]
        )
        or not isinstance(payload["public_key"], (bytes, type(None)))
        or not isinstance(payload["user_data"], bytes)
        or not isinstance(payload["nonce"], bytes)
    ):
        raise AttestationContractError(
            "raw Nitro payload value types are invalid"
        )
    pcrs = payload["pcrs"]
    if (
        not isinstance(pcrs, dict)
        or set(pcrs) != {0, 1, 2}
        or any(
            not isinstance(pcrs[index], bytes) or len(pcrs[index]) != 48
            for index in (0, 1, 2)
        )
    ):
        raise AttestationContractError(
            "raw Nitro PCR0-2 are missing or invalid"
        )
    parsed_pcrs = {
        f"PCR{index}": "sha384:" + pcrs[index].hex()
        for index in (0, 1, 2)
    }
    return {
        "moduleId": payload["module_id"],
        "timestamp": payload["timestamp"],
        "pcrs": parsed_pcrs,
        "nonce": payload["nonce"],
        "userData": payload["user_data"],
        "publicKey": payload["public_key"],
        "debug": all(
            hmac.compare_digest(pcrs[index], b"\x00" * 48)
            for index in (0, 1, 2)
        ),
        "payloadSha256": sha256_prefixed(cose[2]),
    }


def load_nitro_verification_trust(
    raw: bytes, *, expected_sha256: str
) -> NitroVerificationTrust:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= _MAX_NITRO_TRUST_BUNDLE_BYTES
    ):
        raise AttestationContractError(
            "setup Nitro trust bundle is outside its size bound"
        )
    measured_sha256 = sha256_prefixed(raw)
    if (
        not isinstance(expected_sha256, str)
        or _SHA256_RE.fullmatch(expected_sha256) is None
        or not hmac.compare_digest(measured_sha256, expected_sha256)
    ):
        raise AttestationContractError(
            "setup Nitro trust bundle differs from its independent pin"
        )
    document = _strict_json_document(raw, label="setup Nitro trust bundle")
    if raw != canonical_json(document).encode("ascii") + b"\n":
        raise AttestationContractError(
            "setup Nitro trust bundle is not canonical versioned JSON"
        )
    document = _require_exact_fields(
        document,
        {
            "apiVersion",
            "awsNitroCrlsDerBase64url",
            "awsNitroRootCertificatesPem",
            "nitroCertificateProfile",
        },
        "setup Nitro trust bundle",
    )
    if document.get("apiVersion") != "serverware.setupNitroTrustBundle/v1":
        raise AttestationContractError(
            "setup Nitro trust bundle version is invalid"
        )
    root_values = document.get("awsNitroRootCertificatesPem")
    crl_values = document.get("awsNitroCrlsDerBase64url")
    if (
        not isinstance(root_values, list)
        or not 1 <= len(root_values) <= 8
        or not isinstance(crl_values, list)
        or not 1 <= len(crl_values) <= 32
    ):
        raise AttestationContractError(
            "setup Nitro trust roots or CRLs are absent"
        )
    roots: list[x509.Certificate] = []
    for item in root_values:
        if (
            not isinstance(item, str)
            or item.count("-----BEGIN CERTIFICATE-----") != 1
            or item.count("-----END CERTIFICATE-----") != 1
        ):
            raise AttestationContractError(
                "setup Nitro root certificate PEM is invalid"
            )
        try:
            encoded_pem = item.encode("ascii")
            certificate = x509.load_pem_x509_certificate(encoded_pem)
        except (UnicodeEncodeError, ValueError) as exc:
            raise AttestationContractError(
                "setup Nitro root certificate PEM is invalid"
            ) from exc
        if certificate.public_bytes(serialization.Encoding.PEM) != encoded_pem:
            raise AttestationContractError(
                "setup Nitro root certificate PEM is not canonical"
            )
        roots.append(certificate)
    crls: list[x509.CertificateRevocationList] = []
    for item in crl_values:
        if not isinstance(item, str):
            raise AttestationContractError(
                "setup Nitro CRL encoding is invalid"
            )
        try:
            encoded = b64d(item)
            crl = x509.load_der_x509_crl(encoded)
        except (TypeError, ValueError, binascii.Error) as exc:
            raise AttestationContractError(
                "setup Nitro CRL encoding is invalid"
            ) from exc
        if b64e(encoded) != item:
            raise AttestationContractError(
                "setup Nitro CRL is not canonical base64url"
            )
        crls.append(crl)
    root_ders = [
        item.public_bytes(serialization.Encoding.DER) for item in roots
    ]
    crl_ders = [
        item.public_bytes(serialization.Encoding.DER) for item in crls
    ]
    if len(set(root_ders)) != len(root_ders) or len(set(crl_ders)) != len(
        crl_ders
    ):
        raise AttestationContractError(
            "setup Nitro trust roots or CRLs are duplicated"
        )
    profile = _require_exact_fields(
        document.get("nitroCertificateProfile"),
        {
            "allowedLeafExtendedKeyUsageOids",
            "expectedEifSha384",
            "expectedModuleId",
            "expectedPcrs",
            "maxAttestationAgeSeconds",
            "maxFutureSkewSeconds",
        },
        "setup Nitro certificate profile",
    )
    eku_oids = profile.get("allowedLeafExtendedKeyUsageOids")
    max_age = profile.get("maxAttestationAgeSeconds")
    future_skew = profile.get("maxFutureSkewSeconds")
    expected_module_id = profile.get("expectedModuleId")
    expected_eif = _require_sha384(
        profile.get("expectedEifSha384"),
        "setup Nitro expected EIF",
    )
    expected_pcrs = _validate_pcrs(
        profile.get("expectedPcrs"), "setup Nitro expected PCRs"
    )
    if (
        not isinstance(eku_oids, list)
        or len(eku_oids) > 16
        or any(
            not isinstance(item, str)
            or re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", item) is None
            for item in eku_oids
        )
        or eku_oids != sorted(set(eku_oids))
        or type(max_age) is not int
        or not 1 <= max_age <= 900
        or type(future_skew) is not int
        or not 0 <= future_skew <= 60
        or not isinstance(expected_module_id, str)
        or not 1 <= len(expected_module_id.encode("utf-8")) <= 256
        or "\x00" in expected_module_id
    ):
        raise AttestationContractError(
            "setup Nitro certificate profile is invalid"
        )
    if expected_pcrs["PCR0"] != expected_eif:
        raise AttestationContractError(
            "setup Nitro expected EIF does not match expected PCR0"
        )
    return NitroVerificationTrust(
        bundle_sha256=measured_sha256,
        roots=tuple(roots),
        crls=tuple(crls),
        allowed_leaf_extended_key_usage_oids=tuple(eku_oids),
        expected_module_id=expected_module_id,
        expected_eif_sha384=expected_eif,
        expected_pcrs=tuple(
            expected_pcrs[name] for name in ("PCR0", "PCR1", "PCR2")
        ),
        max_attestation_age_seconds=max_age,
        max_future_skew_seconds=future_skew,
    )


def _nitro_certificate_time(
    certificate: x509.Certificate, field: str
) -> datetime:
    preferred = getattr(certificate, f"{field}_utc", None)
    if preferred is not None:
        return preferred
    return getattr(certificate, field).replace(tzinfo=timezone.utc)


def _verify_nitro_signed_object(
    issuer: x509.Certificate,
    child: x509.Certificate | x509.CertificateRevocationList,
) -> None:
    if child.issuer != issuer.subject:
        raise AttestationContractError(
            "Nitro certificate or CRL issuer is invalid"
        )
    if (
        child.signature_algorithm_oid.dotted_string
        not in _ALLOWED_NITRO_CERT_SIGNATURE_OIDS
    ):
        raise AttestationContractError(
            "Nitro certificate or CRL signature algorithm is not allowed"
        )
    key = issuer.public_key()
    signed_bytes = (
        child.tbs_certificate_bytes
        if isinstance(child, x509.Certificate)
        else child.tbs_certlist_bytes
    )
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(
                child.signature,
                signed_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm,
            )
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(
                child.signature,
                signed_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        else:
            raise AttestationContractError(
                "Nitro issuer public key type is unsupported"
            )
    except InvalidSignature as exc:
        raise AttestationContractError(
            "Nitro certificate or CRL signature is invalid"
        ) from exc


def _nitro_basic_constraints(
    certificate: x509.Certificate, *, label: str
) -> x509.BasicConstraints:
    try:
        return certificate.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
    except x509.ExtensionNotFound as exc:
        raise AttestationContractError(
            f"{label} lacks BasicConstraints"
        ) from exc


def _verify_nitro_certificate_chain(
    *,
    leaf_der: bytes,
    bundle_der: list[bytes],
    trust: NitroVerificationTrust,
    issued_at: datetime,
    verified_at: datetime,
) -> tuple[x509.Certificate, x509.Certificate]:
    if not 1 <= len(bundle_der) <= 16:
        raise AttestationContractError(
            "Nitro certificate bundle size is invalid"
        )
    try:
        leaf = x509.load_der_x509_certificate(leaf_der)
        supplied = [
            x509.load_der_x509_certificate(item) for item in bundle_der
        ]
    except ValueError as exc:
        raise AttestationContractError(
            "Nitro certificate chain contains invalid DER"
        ) from exc
    roots_by_der = {
        item.public_bytes(serialization.Encoding.DER): item
        for item in trust.roots
    }
    if not roots_by_der or len(roots_by_der) != len(trust.roots):
        raise AttestationContractError(
            "Nitro trust roots are empty or duplicated"
        )
    candidates = [leaf, *supplied]
    if len(
        {
            item.public_bytes(serialization.Encoding.DER)
            for item in candidates
        }
    ) != len(candidates):
        raise AttestationContractError(
            "Nitro certificate chain contains duplicates"
        )
    chain = [leaf]
    unused = list(supplied)
    trusted_root: x509.Certificate | None = None
    while len(chain) <= 16:
        current = chain[-1]
        current_der = current.public_bytes(serialization.Encoding.DER)
        if current_der in roots_by_der:
            trusted_root = roots_by_der[current_der]
            break
        issuers = [
            candidate
            for candidate in unused
            if candidate.subject == current.issuer
        ]
        issuer_ders = {
            item.public_bytes(serialization.Encoding.DER)
            for item in issuers
        }
        issuers.extend(
            root
            for root in trust.roots
            if root.subject == current.issuer
            and root.public_bytes(serialization.Encoding.DER)
            not in issuer_ders
        )
        if len(issuers) != 1:
            raise AttestationContractError(
                "Nitro certificate chain is missing or ambiguous"
            )
        issuer = issuers[0]
        _verify_nitro_signed_object(issuer, current)
        chain.append(issuer)
        if issuer in unused:
            unused.remove(issuer)
    if trusted_root is None or unused:
        raise AttestationContractError(
            "Nitro chain does not terminate at one pinned root"
        )
    _verify_nitro_signed_object(trusted_root, trusted_root)
    for index, certificate in enumerate(chain):
        if not (
            _nitro_certificate_time(certificate, "not_valid_before")
            <= issued_at
            <= _nitro_certificate_time(certificate, "not_valid_after")
            and _nitro_certificate_time(certificate, "not_valid_before")
            <= verified_at
            <= _nitro_certificate_time(certificate, "not_valid_after")
        ):
            raise AttestationContractError(
                "Nitro certificate is not valid at issuance and verification time"
            )
        constraints = _nitro_basic_constraints(
            certificate, label=f"Nitro certificate {index}"
        )
        if constraints.ca != (index != 0):
            raise AttestationContractError(
                "Nitro leaf or CA BasicConstraints role is invalid"
            )
        if (
            constraints.path_length is not None
            and constraints.path_length < max(0, index - 1)
        ):
            raise AttestationContractError(
                "Nitro CA path-length constraint is exceeded"
            )
        try:
            usage = certificate.extensions.get_extension_for_oid(
                ExtensionOID.KEY_USAGE
            ).value
        except x509.ExtensionNotFound as exc:
            raise AttestationContractError(
                "Nitro certificate lacks KeyUsage"
            ) from exc
        if index == 0:
            if (
                not usage.digital_signature
                or usage.key_cert_sign
                or usage.crl_sign
            ):
                raise AttestationContractError(
                    "Nitro leaf KeyUsage is invalid"
                )
            try:
                eku = certificate.extensions.get_extension_for_oid(
                    ExtensionOID.EXTENDED_KEY_USAGE
                ).value
                observed_eku = tuple(
                    sorted(item.dotted_string for item in eku)
                )
            except x509.ExtensionNotFound:
                observed_eku = ()
            if (
                observed_eku
                != trust.allowed_leaf_extended_key_usage_oids
            ):
                raise AttestationContractError(
                    "Nitro leaf ExtendedKeyUsage differs from its pin"
                )
        elif not usage.key_cert_sign or not usage.crl_sign:
            raise AttestationContractError(
                "Nitro CA KeyUsage is invalid"
            )
    for index, certificate in enumerate(chain[:-1]):
        issuer = chain[index + 1]
        matching_crls = [
            crl for crl in trust.crls if crl.issuer == issuer.subject
        ]
        if len(matching_crls) != 1:
            raise AttestationContractError(
                "Nitro certificate lacks one current issuer CRL"
            )
        crl = matching_crls[0]
        _verify_nitro_signed_object(issuer, crl)
        last_update = getattr(crl, "last_update_utc", None)
        if last_update is None:
            last_update = crl.last_update.replace(tzinfo=timezone.utc)
        next_update = getattr(crl, "next_update_utc", None)
        if next_update is None and crl.next_update is not None:
            next_update = crl.next_update.replace(tzinfo=timezone.utc)
        if (
            next_update is None
            or not last_update <= issued_at <= next_update
            or not last_update <= verified_at <= next_update
        ):
            raise AttestationContractError(
                "Nitro CRL is stale at issuance or verification time"
            )
        if (
            crl.get_revoked_certificate_by_serial_number(
                certificate.serial_number
            )
            is not None
        ):
            raise AttestationContractError(
                "Nitro certificate is revoked"
            )
    leaf_key = leaf.public_key()
    if (
        not isinstance(leaf_key, ec.EllipticCurvePublicKey)
        or leaf_key.curve.name != "secp384r1"
    ):
        raise AttestationContractError(
            "Nitro leaf key must be ECDSA P-384"
        )
    return leaf, trusted_root


def _canonical_cbor(value: Any) -> bytes:
    def head(major: int, size: int) -> bytes:
        if size < 24:
            return bytes([(major << 5) | size])
        if size < 256:
            return bytes([(major << 5) | 24, size])
        if size < 65536:
            return bytes([(major << 5) | 25]) + size.to_bytes(2, "big")
        if size < 1 << 32:
            return bytes([(major << 5) | 26]) + size.to_bytes(4, "big")
        return bytes([(major << 5) | 27]) + size.to_bytes(8, "big")

    if isinstance(value, int):
        return (
            head(0, value)
            if value >= 0
            else head(1, -1 - value)
        )
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return head(3, len(encoded)) + encoded
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(
            _canonical_cbor(item) for item in value
        )
    if isinstance(value, dict):
        entries = [
            (_canonical_cbor(key), _canonical_cbor(item))
            for key, item in value.items()
        ]
        entries.sort(key=lambda item: (len(item[0]), item[0]))
        return head(5, len(entries)) + b"".join(
            key + item for key, item in entries
        )
    raise AttestationContractError(
        "unsupported value in Nitro COSE signature structure"
    )


def verify_nitro_attestation_document(
    raw: bytes,
    *,
    trust: NitroVerificationTrust,
    expected_module_id: str,
    expected_nonce: bytes,
    expected_user_data: bytes,
    expected_pcrs: Mapping[str, str],
    expected_eif_sha384: str,
    now_unix: int,
) -> dict[str, Any]:
    if (
        type(raw) is not bytes
        or not 512 <= len(raw) <= 1024 * 1024
        or type(expected_nonce) is not bytes
        or not 32 <= len(expected_nonce) <= 64
        or type(expected_user_data) is not bytes
        or not 1 <= len(expected_user_data) <= 1024 * 1024
        or type(now_unix) is not int
        or now_unix < 1
    ):
        raise AttestationContractError(
            "Nitro verification input is outside its bound"
        )
    if (
        not isinstance(expected_module_id, str)
        or not 1 <= len(expected_module_id) <= 256
        or "\x00" in expected_module_id
    ):
        raise AttestationContractError(
            "expected Nitro module identity is invalid"
        )
    normalized_pcrs = _validate_pcrs(
        expected_pcrs, "independently expected Nitro PCRs"
    )
    expected_eif = _require_sha384(
        expected_eif_sha384, "independently expected EIF"
    )
    if normalized_pcrs["PCR0"] != expected_eif:
        raise AttestationContractError(
            "independently expected EIF does not map exactly to PCR0"
        )
    reader = _CborReader(raw)
    tagged = reader.read()
    if reader.offset != len(raw):
        raise AttestationContractError(
            "Nitro COSE has trailing bytes"
        )
    if (
        not isinstance(tagged, tuple)
        or tagged[:2] != ("tag", 18)
        or not isinstance(tagged[2], list)
        or len(tagged[2]) != 4
    ):
        raise AttestationContractError(
            "production Nitro evidence must be tagged COSE_Sign1"
        )
    protected, unprotected, payload_raw, signature = tagged[2]
    if (
        not isinstance(protected, bytes)
        or not protected
        or unprotected != {}
        or not isinstance(payload_raw, bytes)
        or not isinstance(signature, bytes)
        or len(signature) != 96
    ):
        raise AttestationContractError(
            "Nitro COSE_Sign1 fields are invalid"
        )
    protected_reader = _CborReader(protected)
    protected_map = protected_reader.read()
    if (
        protected_reader.offset != len(protected)
        or protected_map != {1: -35}
    ):
        raise AttestationContractError(
            "Nitro protected header must contain only ES384"
        )
    payload_reader = _CborReader(payload_raw)
    payload = payload_reader.read()
    if (
        payload_reader.offset != len(payload_raw)
        or not isinstance(payload, dict)
        or set(payload)
        != {
            "cabundle",
            "certificate",
            "digest",
            "module_id",
            "nonce",
            "pcrs",
            "public_key",
            "timestamp",
            "user_data",
        }
    ):
        raise AttestationContractError(
            "Nitro attestation payload is not the closed schema"
        )
    timestamp_ms = payload.get("timestamp")
    issued_at_unix = (
        timestamp_ms // 1000 if type(timestamp_ms) is int else -1
    )
    if (
        payload.get("digest") != "SHA384"
        or payload.get("module_id") != expected_module_id
        or issued_at_unix < 1
        or issued_at_unix
        > now_unix + trust.max_future_skew_seconds
        or now_unix - issued_at_unix
        > trust.max_attestation_age_seconds
        or payload.get("nonce") != expected_nonce
        or payload.get("user_data") != expected_user_data
    ):
        raise AttestationContractError(
            "Nitro module, time, nonce, or user_data binding is invalid"
        )
    pcrs = payload.get("pcrs")
    if (
        not isinstance(pcrs, dict)
        or set(pcrs) != {0, 1, 2}
        or any(
            not isinstance(pcrs[index], bytes)
            or len(pcrs[index]) != 48
            or pcrs[index] == b"\x00" * 48
            for index in (0, 1, 2)
        )
    ):
        raise AttestationContractError(
            "Nitro PCR0-2 are invalid or debug measurements"
        )
    observed_pcrs = {
        f"PCR{index}": "sha384:" + pcrs[index].hex()
        for index in (0, 1, 2)
    }
    if observed_pcrs != normalized_pcrs:
        raise AttestationContractError(
            "Nitro PCR0-2 differ from independent expectations"
        )
    leaf_der = payload.get("certificate")
    cabundle = payload.get("cabundle")
    if (
        not isinstance(leaf_der, bytes)
        or not 1 <= len(leaf_der) <= 16 * 1024
        or not isinstance(cabundle, list)
        or any(
            not isinstance(item, bytes) or not 1 <= len(item) <= 16 * 1024
            for item in cabundle
        )
    ):
        raise AttestationContractError(
            "Nitro certificate material is invalid"
        )
    leaf, root = _verify_nitro_certificate_chain(
        leaf_der=leaf_der,
        bundle_der=list(cabundle),
        trust=trust,
        issued_at=datetime.fromtimestamp(
            timestamp_ms / 1000, tz=timezone.utc
        ),
        verified_at=datetime.fromtimestamp(now_unix, tz=timezone.utc),
    )
    r = int.from_bytes(signature[:48], "big")
    s = int.from_bytes(signature[48:], "big")
    if r == 0 or s == 0:
        raise AttestationContractError(
            "Nitro COSE signature scalar is zero"
        )
    sig_structure = _canonical_cbor(
        ["Signature1", protected, b"", payload_raw]
    )
    try:
        leaf.public_key().verify(
            encode_dss_signature(r, s),
            sig_structure,
            ec.ECDSA(hashes.SHA384()),
        )
    except InvalidSignature as exc:
        raise AttestationContractError(
            "Nitro COSE ES384 signature is invalid"
        ) from exc
    recipient_der = payload.get("public_key")
    if not isinstance(recipient_der, bytes) or not 1 <= len(
        recipient_der
    ) <= 4096:
        raise AttestationContractError(
            "Nitro recipient public key is absent"
        )
    try:
        recipient = serialization.load_der_public_key(recipient_der)
    except (TypeError, ValueError) as exc:
        raise AttestationContractError(
            "Nitro recipient public key is invalid DER"
        ) from exc
    if (
        not isinstance(recipient, rsa.RSAPublicKey)
        or not 2048 <= recipient.key_size <= 4096
        or recipient.public_numbers().e != 65537
    ):
        raise AttestationContractError(
            "Nitro recipient key must be RSA 2048-4096/e=65537"
        )
    return {
        "apiVersion": "serverware.verifiedNitroHardwareIdentity/v1",
        "attestationDocumentSha256": sha256_prefixed(raw),
        "issuedAtUnix": issued_at_unix,
        "moduleId": expected_module_id,
        "pcrs": observed_pcrs,
        "eifImageSha384": expected_eif,
        "leafCertificateSha256": sha256_prefixed(
            leaf.public_bytes(serialization.Encoding.DER)
        ),
        "rootCertificateSha256": sha256_prefixed(
            root.public_bytes(serialization.Encoding.DER)
        ),
        "recipientPublicKeySha256": sha256_prefixed(recipient_der),
        "trustBundleSha256": trust.bundle_sha256,
        "hardwareIdentityVerified": True,
        "keyCustodyVerified": False,
    }


def _verify_generation_statement(
    value: Any,
    *,
    role: str,
    identity_spki_sha256: str,
    key_generation: int,
    recipient_spki_sha256: str,
    generation_key: Ed25519PublicKey,
    generation_key_id: str,
    expected_pcrs: Mapping[str, str],
    expected_policy_hash: str,
    expected_rollback_epoch: int,
    expected_release_generation: int,
) -> tuple[str, str]:
    envelope = _require_exact_fields(
        value,
        {
            "apiVersion",
            "nitroDocumentBase64url",
            "nitroDocumentSha256",
            "payload",
            "payloadSha256",
            "signature",
            "signingKeyId",
        },
        f"{role} enclave-generation statement",
    )
    if envelope.get("apiVersion") != "serverware.enclaveKeyGeneration/v1":
        raise AttestationContractError(
            f"{role} enclave-generation statement version is invalid"
        )
    payload = _require_exact_fields(
        envelope.get("payload"),
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
        f"{role} enclave-generation payload",
    )
    payload_sha256 = sha256_prefixed(
        canonical_json(payload).encode("ascii")
    )
    if (
        envelope.get("payloadSha256") != payload_sha256
        or envelope.get("signingKeyId") != generation_key_id
        or payload.get("role") != role
        or payload.get("identitySpkiSha256") != identity_spki_sha256
        or payload.get("keyGeneration") != key_generation
        or payload.get("recipientSpkiSha256") != recipient_spki_sha256
        or payload.get("pcrs") != expected_pcrs
        or payload.get("policyHash") != expected_policy_hash
        or payload.get("rollbackEpoch") != expected_rollback_epoch
        or payload.get("releaseGeneration") != expected_release_generation
    ):
        raise AttestationContractError(
            f"{role} enclave-generation bindings are invalid"
        )
    signature = envelope.get("signature")
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise AttestationContractError(
            f"{role} enclave-generation signature is invalid"
        )
    try:
        signature_bytes = b64d(signature.split(":", 1)[1])
        if len(signature_bytes) != 64:
            raise ValueError("invalid signature length")
        generation_key.verify(
            signature_bytes,
            KEY_GENERATION_SIGNATURE_DOMAIN
            + canonical_json(
                {"payload": payload, "payloadSha256": payload_sha256}
            ).encode("ascii"),
        )
    except (InvalidSignature, ValueError) as exc:
        raise AttestationContractError(
            f"{role} enclave-generation signature failed"
        ) from exc
    try:
        challenge_nonce = b64d(str(payload.get("challengeNonce")))
        nitro_raw = b64d(str(envelope.get("nitroDocumentBase64url")))
    except Exception as exc:
        raise AttestationContractError(
            f"{role} generation evidence encoding is invalid"
        ) from exc
    if (
        len(challenge_nonce) != 32
        or b64e(challenge_nonce) != payload.get("challengeNonce")
        or b64e(nitro_raw) != envelope.get("nitroDocumentBase64url")
        or envelope.get("nitroDocumentSha256") != sha256_prefixed(nitro_raw)
    ):
        raise AttestationContractError(
            f"{role} generation evidence encoding is not canonical"
        )
    parsed = _parse_nitro_attestation_document(nitro_raw)
    expected_user_data = KEY_GENERATION_USER_DATA_PREFIX + bytes.fromhex(
        payload_sha256.split(":", 1)[1]
    )
    if (
        parsed["nonce"] != challenge_nonce
        or parsed["userData"] != expected_user_data
        or parsed["pcrs"] != expected_pcrs
        or parsed["debug"] is not False
    ):
        raise AttestationContractError(
            f"{role} raw Nitro generation evidence is not bound"
        )
    return sha256_prefixed(nitro_raw), payload_sha256


def _validate_custody(value: dict[str, Any]) -> dict[str, Any]:
    custody = _require_exact_fields(
        value,
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
        "enclave key-custody evidence",
    )
    if (
        custody.get("apiVersion") != KEY_CUSTODY_VERSION
        or custody.get("pipeline") != PRODUCTION_PIPELINE
    ):
        raise AttestationContractError(
            "key-custody evidence is not for the production Nitro pipeline"
    )
    _require_digest(
        custody.get("completionIdentitySha256"),
        "key-custody completion identity",
    )
    _validate_completion_identity_binding(
        custody.get("completionIdentity"),
        custody.get("completionIdentitySha256"),
        label="key custody",
    )
    custody_core_payload = {
        key: item
        for key, item in custody.items()
        if key not in {"completionIdentity", "completionIdentitySha256"}
    }
    custody_core_sha256 = sha256_prefixed(
        canonical_json(
            _completion_core("custody", custody_core_payload)
        ).encode("ascii")
    )
    if custody["completionIdentity"]["coreDigests"]["custody"] != custody_core_sha256:
        raise AttestationContractError(
            "completion identity does not bind the canonical key-custody core"
        )
    policy_hash = _require_digest(
        custody.get("policyHash"), "custody policy hash"
    )
    image_sha384 = _require_sha384(
        custody.get("eifImageSha384"), "custody EIF image"
    )
    pcrs = _validate_pcrs(custody.get("pcrs"), "custody PCRs")
    if not hmac.compare_digest(image_sha384, pcrs["PCR0"]):
        raise AttestationContractError(
            "custody EIF image digest does not match PCR0"
        )
    rollback_epoch = custody.get("rollbackEpoch")
    if type(rollback_epoch) is not int or rollback_epoch < 0:
        raise AttestationContractError("custody rollback epoch is invalid")
    release_generation = _require_positive_generation(
        custody.get("releaseGeneration"), "custody release generation"
    )
    recipient_encoded = custody.get("recipientPublicKeySpkiDerBase64url")
    if not isinstance(recipient_encoded, str) or not 1 <= len(recipient_encoded) <= 4096:
        raise AttestationContractError("custody recipient public key is invalid")
    try:
        recipient_der = b64d(recipient_encoded)
        serialization.load_der_public_key(recipient_der)
    except (TypeError, ValueError) as exc:
        raise AttestationContractError(
            "custody recipient public key is invalid"
        ) from exc
    recipient_key_id = sha256_prefixed(recipient_der)
    if (
        b64e(recipient_der) != recipient_encoded
        or custody.get("recipientPublicKeySpkiSha256") != recipient_key_id
    ):
        raise AttestationContractError(
            "custody recipient public key identity is invalid"
        )
    generation_key, generation_key_id = _load_ed25519_spki_der(
        custody.get("generationSignerPublicKeySpkiDerBase64url"),
        label="custody generation signer",
    )
    if (
        custody.get("generationSignerPublicKeySpkiSha256")
        != generation_key_id
    ):
        raise AttestationContractError(
            "custody generation signer identity is invalid"
        )
    materials = custody.get("materials")
    if not isinstance(materials, list) or len(materials) != len(_CUSTODY_MATERIALS):
        raise AttestationContractError(
            "custody evidence must bind every required key material"
        )
    observed_names: set[str] = set()
    for material in materials:
        item = _require_exact_fields(
            material,
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
            "key-custody material",
        )
        name = item.get("name")
        if name not in _CUSTODY_MATERIALS or name in observed_names:
            raise AttestationContractError(
                "key-custody material inventory is invalid"
            )
        observed_names.add(str(name))
        identity_encoded = item.get("identityPublicKeySpkiDerBase64url")
        if not isinstance(identity_encoded, str) or not 1 <= len(identity_encoded) <= 4096:
            raise AttestationContractError(f"{name} raw public key is invalid")
        try:
            identity_der = b64d(identity_encoded)
            serialization.load_der_public_key(identity_der)
        except (TypeError, ValueError) as exc:
            raise AttestationContractError(
                f"{name} raw public key is invalid"
            ) from exc
        identity_key_id = sha256_prefixed(identity_der)
        if (
            b64e(identity_der) != identity_encoded
            or item.get("identitySpkiSha256") != identity_key_id
        ):
            raise AttestationContractError(
                f"{name} public-key identity is invalid"
            )
        key_generation = _require_positive_generation(
            item.get("keyGeneration"), f"{name} key generation"
        )
        generation_nitro_sha256, _ = _verify_generation_statement(
            item.get("generationStatement"),
            role=str(name),
            identity_spki_sha256=identity_key_id,
            key_generation=key_generation,
            recipient_spki_sha256=recipient_key_id,
            generation_key=generation_key,
            generation_key_id=generation_key_id,
            expected_pcrs=pcrs,
            expected_policy_hash=policy_hash,
            expected_rollback_epoch=rollback_epoch,
            expected_release_generation=release_generation,
        )
        release = _require_exact_fields(
            item.get("kmsRecipientRelease"),
            {
                "conditions",
                "encryptionContext",
                "encryptionContextSha256",
                "generationNitroDocumentSha256",
                "kmsKeyIdSha256",
                "rawResponseBase64url",
                "rawResponseSha256",
            },
            f"{name} KMS recipient release",
        )
        conditions = _require_exact_fields(
            release.get("conditions"),
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
        expected_conditions = {
            "eifImageSha384": image_sha384,
            "identitySpkiSha256": identity_key_id,
            "keyGeneration": key_generation,
            "pcrs": pcrs,
            "pipeline": PRODUCTION_PIPELINE,
            "policyHash": policy_hash,
            "recipientSpkiSha256": recipient_key_id,
            "releaseGeneration": release_generation,
            "role": name,
            "rollbackEpoch": rollback_epoch,
        }
        if (
            dict(conditions) != expected_conditions
            or release.get("generationNitroDocumentSha256")
            != generation_nitro_sha256
        ):
            raise AttestationContractError(
                f"{name} KMS release conditions are not bound"
            )
        context = _require_exact_fields(
            release.get("encryptionContext"),
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
        expected_context = {
            key: expected_conditions[key]
            for key in (
                "identitySpkiSha256",
                "pipeline",
                "policyHash",
                "recipientSpkiSha256",
                "releaseGeneration",
                "role",
                "rollbackEpoch",
            )
        }
        context_sha256 = sha256_prefixed(
            canonical_json(context).encode("ascii")
        )
        if (
            dict(context) != expected_context
            or release.get("encryptionContextSha256") != context_sha256
            or item.get("kmsEncryptionContextSha256") != context_sha256
        ):
            raise AttestationContractError(
                f"{name} KMS encryption context is invalid"
            )
        try:
            raw_response = b64d(str(release.get("rawResponseBase64url")))
        except Exception as exc:
            raise AttestationContractError(
                f"{name} raw KMS response encoding is invalid"
            ) from exc
        if (
            not 1 <= len(raw_response) <= 1024 * 1024
            or b64e(raw_response) != release.get("rawResponseBase64url")
            or release.get("rawResponseSha256")
            != sha256_prefixed(raw_response)
        ):
            raise AttestationContractError(
                f"{name} raw KMS response is invalid"
            )
        response_document = _require_exact_fields(
            _strict_json_document(
                raw_response, label=f"{name} raw KMS response"
            ),
            {"CiphertextForRecipient", "KeyId"},
            f"{name} raw KMS response",
        )
        ciphertext = response_document.get("CiphertextForRecipient")
        key_id_value = response_document.get("KeyId")
        if (
            not isinstance(ciphertext, str)
            or not isinstance(key_id_value, str)
            or not 1 <= len(key_id_value) <= 2048
        ):
            raise AttestationContractError(
                f"{name} raw KMS response fields are invalid"
            )
        try:
            ciphertext_bytes = base64.b64decode(ciphertext, validate=True)
        except Exception as exc:
            raise AttestationContractError(
                f"{name} KMS ciphertext is invalid"
            ) from exc
        if (
            not 1 <= len(ciphertext_bytes) <= 1024 * 1024
            or release.get("kmsKeyIdSha256")
            != sha256_prefixed(key_id_value.encode("utf-8"))
        ):
            raise AttestationContractError(
                f"{name} KMS response key or ciphertext is invalid"
            )
        scope_key = item.get("scopeSigningKey")
        if name == "tls":
            scope = _require_exact_fields(
                scope_key,
                {
                    "keyGeneration",
                    "publicKeySpkiDerBase64url",
                    "publicKeySpkiSha256",
                },
                "TLS scope signing key",
            )
            _, scope_key_id = _load_ed25519_spki_der(
                scope.get("publicKeySpkiDerBase64url"),
                label="TLS scope signing public key",
            )
            if scope.get("publicKeySpkiSha256") != scope_key_id:
                raise AttestationContractError(
                    "TLS scope signing key custody is invalid"
                )
            _require_positive_generation(
                scope.get("keyGeneration"),
                "TLS scope signing key generation",
            )
        elif scope_key is not None:
            raise AttestationContractError(
                f"{name} has an unauthorized TLS scope signing key"
            )
    if observed_names != _CUSTODY_MATERIALS:
        raise AttestationContractError(
            "key-custody material inventory is incomplete"
        )
    return dict(custody)


def _validate_runtime_state(value: dict[str, Any]) -> dict[str, Any]:
    runtime = _require_exact_fields(
        value,
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
        "production attestation runtime state",
    )
    if (
        runtime.get("apiVersion") != PRODUCTION_RUNTIME_STATE_VERSION
        or runtime.get("pipeline") != PRODUCTION_PIPELINE
    ):
        raise AttestationContractError(
            "runtime state is not the Manifest v6 Nitro pipeline"
        )
    for field in (
        "caSpkiSha256",
        "completionIdentitySha256",
        "custodyEvidenceSha256",
        "policyHash",
        "productionIdentitySha256",
        "promotedManifestSha256",
        "tlsScopeSigningKeySpkiSha256",
    ):
        _require_digest(runtime.get(field), f"runtime {field}")
    _validate_completion_identity_binding(
        runtime.get("completionIdentity"),
        runtime.get("completionIdentitySha256"),
        label="runtime",
    )
    for field in ("enclaveBootId", "enclaveInstanceId"):
        value_field = runtime.get(field)
        if (
            not isinstance(value_field, str)
            or _IDENTIFIER_RE.fullmatch(value_field) is None
        ):
            raise AttestationContractError(f"runtime {field} is invalid")
    if type(runtime.get("policySequence")) is not int or runtime["policySequence"] < 1:
        raise AttestationContractError("runtime policy sequence is invalid")
    if type(runtime.get("rollbackEpoch")) is not int or runtime["rollbackEpoch"] < 0:
        raise AttestationContractError("runtime rollback epoch is invalid")
    _require_positive_generation(
        runtime.get("releaseGeneration"), "runtime release generation"
    )
    _validate_key_generations(runtime.get("keyGenerations"))
    active = _require_exact_fields(
        runtime.get("activeTlsConnection"),
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
        _require_digest(active.get(field), f"active TLS {field}")
    for field in ("connectionId", "peerIdentity"):
        item = active.get(field)
        if (
            not isinstance(item, str)
            or _IDENTIFIER_RE.fullmatch(item) is None
        ):
            raise AttestationContractError(
                f"active TLS {field} is invalid"
            )
    if (
        type(active.get("issuedAtUnix")) is not int
        or type(active.get("expiresAtUnix")) is not int
        or not 1
        <= active["expiresAtUnix"] - active["issuedAtUnix"]
        <= 60
    ):
        raise AttestationContractError(
            "active TLS connection lifetime is invalid"
        )
    return dict(runtime)


def production_attestation_state(
    *,
    require_completion_runtime_cores: bool = True,
) -> dict[str, Any]:
    if type(require_completion_runtime_cores) is not bool:
        raise AttestationContractError(
            "production attestation state validation mode is invalid"
        )
    paths = {
        "productionIdentity": _configured_production_path(
            "SERVERWARE_NITRO_PRODUCTION_IDENTITY_PATH",
            "production identity",
        ),
        "promotedManifest": _configured_production_path(
            "SERVERWARE_NITRO_PROMOTED_MANIFEST_PATH",
            "promoted Manifest v6",
        ),
        "runtimeState": _configured_production_path(
            "SERVERWARE_NITRO_RUNTIME_STATE_PATH",
            "production runtime state",
        ),
        "keyCustody": _configured_production_path(
            "SERVERWARE_NITRO_KEY_CUSTODY_PATH",
            "key-custody evidence",
        ),
    }
    raw_documents = {
        name: _read_stable_root_owned_file(
            path,
            label=name,
            maximum=_MAX_PRODUCTION_ARTIFACT_BYTES,
        )
        for name, path in paths.items()
    }
    parsed_documents = {
        name: _strict_json_document(raw, label=name)
        for name, raw in raw_documents.items()
    }
    for name, raw in raw_documents.items():
        if raw != canonical_json(parsed_documents[name]).encode("ascii") + b"\n":
            raise AttestationContractError(
                f"{name} must use canonical versioned JSON encoding"
            )
    identity = _validate_production_identity(
        parsed_documents["productionIdentity"]
    )
    manifest = _validate_promoted_manifest(
        parsed_documents["promotedManifest"]
    )
    runtime = _validate_runtime_state(
        parsed_documents["runtimeState"]
    )
    custody = _validate_custody(
        parsed_documents["keyCustody"]
    )
    digests = {
        name: sha256_prefixed(raw)
        for name, raw in raw_documents.items()
    }
    expected_bindings = (
        (
            runtime["productionIdentitySha256"],
            digests["productionIdentity"],
            "runtime production identity",
        ),
        (
            runtime["completionIdentity"],
            identity["completionIdentity"],
            "runtime completion identity",
        ),
        (
            runtime["completionIdentitySha256"],
            identity["completionIdentitySha256"],
            "runtime completion identity digest",
        ),
        (
            runtime["promotedManifestSha256"],
            digests["promotedManifest"],
            "runtime promoted manifest",
        ),
        (
            runtime["custodyEvidenceSha256"],
            digests["keyCustody"],
            "runtime custody evidence",
        ),
        (
            runtime["releaseGeneration"],
            identity["releaseGeneration"],
            "release generation",
        ),
        (
            runtime["releaseGeneration"],
            custody["releaseGeneration"],
            "custody release generation",
        ),
        (
            custody["completionIdentity"],
            identity["completionIdentity"],
            "custody completion identity",
        ),
        (
            custody["completionIdentitySha256"],
            identity["completionIdentitySha256"],
            "custody completion identity digest",
        ),
        (runtime["policyHash"], custody["policyHash"], "custody policy"),
        (runtime["rollbackEpoch"], custody["rollbackEpoch"], "custody rollback epoch"),
        (identity["eifImageSha384"], custody["eifImageSha384"], "custody EIF"),
        (identity["pcrs"], custody["pcrs"], "custody PCRs"),
        (
            identity["candidateManifestFileSha256"],
            manifest["candidate"]["fileSha256"],
            "candidate Manifest file",
        ),
        (
            identity["candidateManifestPayloadSha256"],
            manifest["candidate"]["payloadSha256"],
            "candidate Manifest payload",
        ),
        (
            identity["sourceClosureSha256"],
            manifest["sourceSnapshot"]["sourceClosureSha256"],
            "source closure",
        ),
        (
            identity["sourceInputManifestFileSha256"],
            manifest["sourceSnapshot"]["sourceManifestFileSha256"],
            "source input Manifest file",
        ),
        (
            identity["sourceInputManifestPayloadSha256"],
            manifest["sourceSnapshot"]["sourceManifestPayloadSha256"],
            "source input Manifest payload",
        ),
        (
            identity["importedImageMappingsSha256"],
            sha256_prefixed(
                canonical_json(manifest["imageMappings"]).encode("ascii")
            ),
            "imported image mappings",
        ),
    )
    for actual, expected, label in expected_bindings:
        if actual != expected:
            raise AttestationContractError(
                f"{label} binding does not match remeasured evidence"
            )
    if not hmac.compare_digest(
        identity["promotedManifestSha256"], digests["promotedManifest"]
    ):
        raise AttestationContractError(
            "production identity does not bind the promoted Manifest v6"
        )
    custody_core_payload = {
        key: value
        for key, value in custody.items()
        if key not in FINAL_COMPLETION_BINDING_FIELDS
    }
    custody_core_sha256 = sha256_prefixed(
        canonical_json(
            _completion_core("custody", custody_core_payload)
        ).encode("ascii")
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
        (
            identity["completionIdentity"]["coreDigests"]["builderA"],
            identity["completionIdentity"]["coreDigests"]["builderB"],
        )
    )
    release_core_payload["eifCoreSha256"] = identity[
        "completionIdentity"
    ]["coreDigests"]["eif"]
    release_core_sha256 = sha256_prefixed(
        canonical_json(
            _completion_core("release", release_core_payload)
        ).encode("ascii")
    )
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
    runtime_core_payload["releaseCoreSha256"] = release_core_sha256
    runtime_core_sha256 = sha256_prefixed(
        canonical_json(
            _completion_core("runtime", runtime_core_payload)
        ).encode("ascii")
    )
    hardware_core_sha256 = sha256_prefixed(
        canonical_json(
            _completion_core(
                "hardware",
                {
                    "eifSha384": identity["eifImageSha384"],
                    "moduleId": runtime["enclaveInstanceId"],
                    "pcrs": identity["pcrs"],
                    "recipientPublicKeySha256": custody[
                        "recipientPublicKeySpkiSha256"
                    ],
                },
            )
        ).encode("ascii")
    )
    actual_state_cores = {
        "custody": custody_core_sha256,
        "hardware": hardware_core_sha256,
        "release": release_core_sha256,
        "runtime": runtime_core_sha256,
    }
    required_state_cores = (
        actual_state_cores
        if require_completion_runtime_cores
        else {
            name: actual_state_cores[name]
            for name in ("custody", "release")
        }
    )
    for name, digest in required_state_cores.items():
        if identity["completionIdentity"]["coreDigests"][name] != digest:
            raise AttestationContractError(
                f"completion identity {name} core was not reconstructed from remeasured state"
            )
    tls_material = _material_by_name(custody, "tls")
    tls_scope_key = tls_material.get("scopeSigningKey")
    if not isinstance(tls_scope_key, Mapping):
        raise AttestationContractError(
            "TLS scope-signing custody evidence is missing"
        )
    if (
        runtime["caSpkiSha256"]
        != _material_by_name(custody, "ca")["identitySpkiSha256"]
        or runtime["keyGenerations"]["tls"] != tls_material["keyGeneration"]
        or runtime["keyGenerations"]["tlsScope"]
        != tls_scope_key.get("keyGeneration")
        or runtime["tlsScopeSigningKeySpkiSha256"]
        != tls_scope_key.get("publicKeySpkiSha256")
        or runtime["activeTlsConnection"]["leafSpkiSha256"]
        != tls_material["identitySpkiSha256"]
    ):
        raise AttestationContractError(
            "runtime TLS identities do not match enclave custody"
        )
    return {
        "identity": identity,
        "promotedManifest": manifest,
        "runtime": runtime,
        "custody": custody,
        "digests": digests,
        "stableCoreDigests": {
            "custody": custody_core_sha256,
            "eif": identity["completionIdentity"]["coreDigests"]["eif"],
            "release": release_core_sha256,
            "runtime": runtime_core_sha256,
        },
    }


def _external_counter_field(name: str, value: Any) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", name.lower())
    return (
        normalized == "ordinal"
        or normalized.endswith("generation")
        or normalized.endswith("epoch")
        or normalized.endswith("sequence")
        or normalized.endswith("treesize")
        or normalized.endswith("index")
    )


def _validate_public_json_grammar(
    value: Any,
    *,
    label: str,
    depth: int = 0,
    field_name: str | None = None,
) -> None:
    if depth > 32:
        raise AttestationContractError(f"{label} exceeds nesting bounds")
    if (
        field_name is not None
        and _external_counter_field(field_name, value)
        and (type(value) is not int or value < 0)
    ):
        raise AttestationContractError(
            f"{label} {field_name} must be an unsigned integer"
        )
    if value is None or type(value) in {bool, int}:
        return
    if isinstance(value, str):
        if len(value.encode("utf-8")) > 1024 * 1024 or "\x00" in value:
            raise AttestationContractError(
                f"{label} contains an invalid string"
            )
        return
    if isinstance(value, list):
        if len(value) > 100_000:
            raise AttestationContractError(f"{label} list is oversized")
        for item in value:
            _validate_public_json_grammar(
                item, label=label, depth=depth + 1
            )
        return
    if isinstance(value, Mapping):
        if len(value) > 4096:
            raise AttestationContractError(f"{label} object is oversized")
        for key, item in value.items():
            if (
                not isinstance(key, str)
                or not 1 <= len(key) <= 128
                or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,127}", key)
                is None
            ):
                raise AttestationContractError(
                    f"{label} contains an invalid field name"
                )
            _validate_public_json_grammar(
                item,
                label=label,
                depth=depth + 1,
                field_name=key,
            )
        return
    raise AttestationContractError(
        f"{label} contains a value outside the public JSON grammar"
    )


def _load_public_key_from_root(root: Mapping[str, Any]) -> Ed25519PublicKey:
    pem = root.get("publicKeyPem")
    if not isinstance(pem, str) or not 1 <= len(pem.encode("ascii")) <= 16384:
        raise AttestationContractError("public evidence trust root is invalid")
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (TypeError, ValueError) as exc:
        raise AttestationContractError(
            "public evidence trust root is not a public key"
        ) from exc
    if not isinstance(key, Ed25519PublicKey):
        raise AttestationContractError(
            "public evidence trust root must be Ed25519"
        )
    der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if not hmac.compare_digest(
        sha256_prefixed(der),
        _require_digest(root.get("keyId"), "public evidence trust-root key ID"),
    ):
        raise AttestationContractError(
            "public evidence trust-root key ID does not match its SPKI"
        )
    return key


def _required_public_pin(name: str, label: str) -> str:
    value = os.getenv(name, "")
    if not value:
        if _production_release():
            raise AttestationContractError(
                f"{label} external pin is required in production"
            )
        raise AttestationContractError(f"{label} external pin is unavailable")
    return _require_digest(value, label)


def _pinned_public_root_ids() -> dict[str, str]:
    raw = os.getenv("SERVERWARE_PUBLIC_ATTESTATION_ROOT_KEY_IDS", "")
    if not raw:
        raise AttestationContractError(
            "public evidence root-key pins are required"
        )
    document = _strict_json_document(
        raw.encode("utf-8"), label="public evidence root-key pins"
    )
    roots = _require_exact_fields(
        document, _PUBLIC_ROOT_ROLES, "public evidence root-key pins"
    )
    return {
        role: _require_digest(roots.get(role), f"{role} root-key pin")
        for role in sorted(_PUBLIC_ROOT_ROLES)
    }


def _verify_domain_completion_envelope(
    document: Mapping[str, Any],
    *,
    api_version: str,
    domain: bytes,
    key: Ed25519PublicKey,
    key_file_sha256: str,
    raw_key_sha256: str,
    label: str,
) -> tuple[dict[str, Any], str]:
    envelope = _require_exact_fields(
        document,
        {"apiVersion", "payload", "payloadSha256", "signature"},
        label,
    )
    payload = envelope.get("payload")
    if envelope.get("apiVersion") != api_version or not isinstance(
        payload, dict
    ):
        raise AttestationContractError(f"{label} version or payload is invalid")
    payload_sha256 = sha256_prefixed(
        canonical_json(payload).encode("ascii")
    )
    if envelope.get("payloadSha256") != payload_sha256:
        raise AttestationContractError(f"{label} payload digest is invalid")
    signature = _require_exact_fields(
        envelope.get("signature"),
        {
            "algorithm",
            "domain",
            "keyFileSha256",
            "rawKeySha256",
            "value",
        },
        f"{label} signature",
    )
    if (
        signature.get("algorithm") != "Ed25519"
        or signature.get("domain") != domain[:-1].decode("ascii")
        or signature.get("keyFileSha256") != key_file_sha256
        or signature.get("rawKeySha256") != raw_key_sha256
        or not isinstance(signature.get("value"), str)
    ):
        raise AttestationContractError(f"{label} signature metadata is invalid")
    _require_digest(key_file_sha256, f"{label} key file")
    _require_digest(raw_key_sha256, f"{label} raw key")
    key_der = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if (
        len(key_der) != 44
        or signature.get("rawKeySha256")
        != sha256_prefixed(key_der[-32:])
    ):
        raise AttestationContractError(
            f"{label} raw signing-key identity is invalid"
        )
    try:
        signature_bytes = base64.b64decode(
            signature["value"], validate=True
        )
        if len(signature_bytes) != 64:
            raise ValueError("invalid Ed25519 signature length")
        key.verify(
            signature_bytes,
            domain
            + canonical_json(
                {"payload": payload, "payloadSha256": payload_sha256}
            ).encode("ascii"),
        )
    except (InvalidSignature, ValueError) as exc:
        raise AttestationContractError(
            f"{label} signature verification failed"
        ) from exc
    return dict(payload), payload_sha256


def _validate_public_source_path(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value.encode("utf-8")) > 4096
        or value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise AttestationContractError(f"{label} is not path-safe")
    return value


def _validate_public_source_and_candidate(
    *,
    source: Mapping[str, Any],
    candidate: Mapping[str, Any],
    source_file_sha256: str,
    candidate_file_sha256: str,
    identity: Mapping[str, Any],
    keys: Mapping[str, Ed25519PublicKey],
    key_file_sha256s: Mapping[str, str],
    raw_key_sha256s: Mapping[str, str],
) -> dict[str, Any]:
    source = _require_exact_fields(
        source,
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
            "sourceEvidence",
            "sourceEvidenceSha256",
            "symlinkCount",
            "trackedInventorySha256",
            "trackedPaths",
            "untrackedApproval",
            "untrackedApprovalPayloadSha256",
        },
        "public source-input manifest",
    )
    source_payload = dict(source)
    source_payload_sha256 = _require_digest(
        source_payload.pop("payloadSha256", None),
        "public source-input payload",
    )
    if (
        source.get("apiVersion") != "serverware.sourceInputManifest/v3"
        or source.get("selectionModel")
        != "signed-raw-git-index-tree-worktree-status-plus-approved-untracked/v3"
        or source_payload_sha256
        != sha256_prefixed(canonical_json(source_payload).encode("ascii"))
        or source_file_sha256 != identity["sourceInputManifestFileSha256"]
        or source_payload_sha256
        != identity["sourceInputManifestPayloadSha256"]
        or source.get("untrackedApprovalPayloadSha256")
        != identity["sourceInputApprovalSha256"]
    ):
        raise AttestationContractError(
            "public source-input artifact does not match production identity"
        )
    for field in (
        "gitInventoryPayloadSha256",
        "pathListSha256",
        "requiredUntrackedInventorySha256",
        "sourceEvidenceSha256",
        "trackedInventorySha256",
        "untrackedApprovalPayloadSha256",
    ):
        _require_digest(source.get(field), f"public source-input {field}")
    git_payload, _ = _verify_domain_completion_envelope(
        source["gitInventory"],
        api_version="serverware.gitSourceInventory/v3",
        domain=_SOURCE_GIT_INVENTORY_DOMAIN,
        key=keys["sourceGitInventory"],
        key_file_sha256=key_file_sha256s["sourceGitInventory"],
        raw_key_sha256=raw_key_sha256s["sourceGitInventory"],
        label="public signed Git inventory",
    )
    approval_payload, _ = _verify_domain_completion_envelope(
        source["untrackedApproval"],
        api_version="serverware.untrackedSourceApproval/v2",
        domain=_SOURCE_UNTRACKED_APPROVAL_DOMAIN,
        key=keys["sourceUntrackedApproval"],
        key_file_sha256=key_file_sha256s["sourceUntrackedApproval"],
        raw_key_sha256=raw_key_sha256s["sourceUntrackedApproval"],
        label="public signed untracked-source approval",
    )
    git_payload = _require_exact_fields(
        git_payload,
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
        "public signed Git inventory payload",
    )
    approval_payload = _require_exact_fields(
        approval_payload,
        {
            "challengeSha256",
            "decision",
            "entries",
            "gitInventoryPayloadSha256",
            "pathListSha256",
        },
        "public signed untracked-source approval payload",
    )
    if (
        source["gitInventoryPayloadSha256"]
        != source["gitInventory"]["payloadSha256"]
        or source["untrackedApprovalPayloadSha256"]
        != source["untrackedApproval"]["payloadSha256"]
        or git_payload.get("indexTree") != git_payload.get("headTree")
        or git_payload.get("objectFormat") not in {"sha1", "sha256"}
        or approval_payload.get("decision")
        != "approve-exact-required-untracked-for-source-freeze"
        or approval_payload.get("gitInventoryPayloadSha256")
        != source["gitInventoryPayloadSha256"]
    ):
        raise AttestationContractError(
            "public source signatures crossed their source-input manifest"
        )
    for field in (
        "indexEntriesSha256",
        "indexInventoryRawSha256",
        "repositoryIdSha256",
        "treeEntriesSha256",
        "worktreeEntriesSha256",
    ):
        _require_digest(
            git_payload.get(field), f"public Git inventory {field}"
        )
    _require_digest(
        approval_payload.get("challengeSha256"),
        "public untracked approval challenge",
    )
    raw_commands = {
        "index": ["git", "ls-files", "--stage", "-z"],
        "status": [
            "git",
            "status",
            "--porcelain=v1",
            "-z",
            "--ignored=matching",
            "--untracked-files=all",
        ],
        "tree": ["git", "ls-tree", "-rz", "--full-tree", "HEAD"],
    }
    raw_evidence = _require_exact_fields(
        git_payload.get("rawEvidence"),
        {"index", "status", "tree"},
        "public raw Git evidence",
    )
    raw_evidence_digests: dict[str, str] = {}
    for name in ("index", "status", "tree"):
        record = _require_exact_fields(
            raw_evidence.get(name),
            {"bytesBase64", "command", "sha256"},
            f"public raw Git {name} evidence",
        )
        encoded = record.get("bytesBase64")
        if (
            record.get("command") != raw_commands[name]
            or not isinstance(encoded, str)
            or len(encoded) > _MAX_PUBLIC_BUNDLE_BYTES * 2
        ):
            raise AttestationContractError(
                f"public raw Git {name} evidence is invalid"
            )
        try:
            raw_bytes = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise AttestationContractError(
                f"public raw Git {name} evidence is not canonical base64"
            ) from exc
        if (
            len(raw_bytes) > _MAX_PUBLIC_BUNDLE_BYTES
            or record.get("sha256") != sha256_prefixed(raw_bytes)
        ):
            raise AttestationContractError(
                f"public raw Git {name} evidence digest is invalid"
            )
        raw_evidence_digests[name] = str(record["sha256"])
    if (
        git_payload.get("indexInventoryRawSha256")
        != raw_evidence_digests["index"]
    ):
        raise AttestationContractError(
            "public raw Git index crossed its signed inventory"
        )
    tracked = source.get("trackedPaths")
    untracked = source.get("requiredUntrackedPaths")
    if (
        not isinstance(tracked, list)
        or tracked != sorted(set(tracked))
        or not isinstance(untracked, list)
        or untracked != sorted(set(untracked))
        or set(tracked) & set(untracked)
    ):
        raise AttestationContractError(
            "public source path inventories are invalid"
        )
    for path in [*tracked, *untracked]:
        _validate_public_source_path(path, "public source path")
    if (
        source["trackedInventorySha256"]
        != sha256_prefixed(canonical_json(tracked).encode("ascii"))
        or source["requiredUntrackedInventorySha256"]
        != sha256_prefixed(canonical_json(untracked).encode("ascii"))
        or source["pathListSha256"]
        != sha256_prefixed(
            canonical_json(sorted([*tracked, *untracked])).encode("ascii")
        )
        or approval_payload.get("pathListSha256")
        != sha256_prefixed(canonical_json(untracked).encode("ascii"))
    ):
        raise AttestationContractError(
            "public source path inventory digests are invalid"
        )
    source_entries = source.get("entries")
    if (
        not isinstance(source_entries, list)
        or len(source_entries) != source.get("entryCount")
        or [item.get("path") for item in source_entries if isinstance(item, Mapping)]
        != sorted([*tracked, *untracked])
    ):
        raise AttestationContractError(
            "public source entries do not equal the selected path inventory"
        )
    for entry_value in source_entries:
        if not isinstance(entry_value, Mapping):
            raise AttestationContractError("public source entry is invalid")
        common = {
            "classification",
            "mode",
            "path",
            "provenance",
            "type",
        }
        fields = (
            common | {"sha256", "size"}
            if entry_value.get("type") == "file"
            else common | {"target"}
            if entry_value.get("type") == "symlink"
            else set()
        )
        entry = _require_exact_fields(
            entry_value, fields, "public source entry"
        )
        path = _validate_public_source_path(
            entry.get("path"), "public source entry path"
        )
        expected_provenance = (
            "tracked" if path in set(tracked) else "required-untracked"
        )
        if (
            entry.get("classification") not in {"source", "build-input"}
            or entry.get("provenance") != expected_provenance
            or (
                entry.get("type") == "file"
                and (
                    entry.get("mode") not in {0o400, 0o500}
                    or type(entry.get("size")) is not int
                    or entry["size"] < 0
                )
            )
            or (
                entry.get("type") == "symlink"
                and (
                    entry.get("mode") != 0o777
                    or not isinstance(entry.get("target"), str)
                    or "\x00" in entry["target"]
                )
            )
        ):
            raise AttestationContractError(
                "public source entry metadata is invalid"
            )
        if entry.get("type") == "file":
            _require_digest(
                entry.get("sha256"), "public source file entry"
            )
    approval_entries = approval_payload.get("entries")
    expected_approval_entries = [
        dict(entry)
        for entry in source_entries
        if entry.get("provenance") == "required-untracked"
    ]
    if (
        not isinstance(approval_entries, list)
        or approval_entries != expected_approval_entries
    ):
        raise AttestationContractError(
            "public untracked-source approval is not exact"
        )
    status = _require_exact_fields(
        git_payload.get("status"),
        {
            "ignoredPaths",
            "ignoredPathsSha256",
            "policy",
            "trackedChanges",
            "trackedChangesSha256",
            "untrackedPaths",
            "untrackedPathsSha256",
        },
        "public Git status inventory",
    )
    if status.get("policy") != (
        "git-status-v1-z-complete-with-ignored-separate/v2"
    ):
        raise AttestationContractError(
            "public Git status policy is invalid"
        )
    for field, digest_field in (
        ("ignoredPaths", "ignoredPathsSha256"),
        ("trackedChanges", "trackedChangesSha256"),
        ("untrackedPaths", "untrackedPathsSha256"),
    ):
        values = status.get(field)
        if (
            not isinstance(values, list)
            or status.get(digest_field)
            != sha256_prefixed(canonical_json(values).encode("ascii"))
        ):
            raise AttestationContractError(
                f"public Git status {field} is invalid"
            )
    index_entries = git_payload.get("indexEntries")
    tree_entries = git_payload.get("treeEntries")
    worktree_entries = git_payload.get("worktreeEntries")
    if (
        not isinstance(index_entries, list)
        or not isinstance(tree_entries, list)
        or not isinstance(worktree_entries, list)
        or git_payload["indexEntriesSha256"]
        != sha256_prefixed(canonical_json(index_entries).encode("ascii"))
        or git_payload["treeEntriesSha256"]
        != sha256_prefixed(canonical_json(tree_entries).encode("ascii"))
        or git_payload["worktreeEntriesSha256"]
        != sha256_prefixed(canonical_json(worktree_entries).encode("ascii"))
    ):
        raise AttestationContractError(
            "public Git structured inventories are invalid"
        )
    for item_value in index_entries:
        item = _require_exact_fields(
            item_value,
            {"gitMode", "objectId", "path", "stage"},
            "public Git index entry",
        )
        _validate_public_source_path(
            item.get("path"), "public Git index path"
        )
        if (
            item.get("gitMode") not in {"100644", "100755", "120000"}
            or item.get("stage") != 0
        ):
            raise AttestationContractError(
                "public Git index mode or stage is invalid"
            )
    for item_value in tree_entries:
        item = _require_exact_fields(
            item_value,
            {"gitMode", "objectId", "objectType", "path"},
            "public Git tree entry",
        )
        _validate_public_source_path(
            item.get("path"), "public Git tree path"
        )
        if (
            item.get("gitMode") not in {"100644", "100755", "120000"}
            or item.get("objectType") != "blob"
        ):
            raise AttestationContractError(
                "public Git tree entry is invalid"
            )
    for item_value in worktree_entries:
        if not isinstance(item_value, Mapping):
            raise AttestationContractError(
                "public Git worktree entry is invalid"
            )
        common = {
            "classification",
            "gitMode",
            "indexObjectId",
            "mode",
            "path",
            "type",
            "worktreeObjectId",
        }
        fields = (
            common | {"sha256", "size"}
            if item_value.get("type") == "file"
            else common | {"target"}
            if item_value.get("type") == "symlink"
            else set()
        )
        item = _require_exact_fields(
            item_value, fields, "public Git worktree entry"
        )
        _validate_public_source_path(
            item.get("path"), "public Git worktree path"
        )
    tracked_changes = status["trackedChanges"]
    for change_value in tracked_changes:
        change = _require_exact_fields(
            change_value,
            {"path", "status"},
            "public Git tracked change",
        )
        _validate_public_source_path(
            change.get("path"), "public Git changed path"
        )
        if (
            not isinstance(change.get("status"), str)
            or re.fullmatch(r"[ MADU?!]{2}", change["status"]) is None
            or "R" in change["status"]
            or "C" in change["status"]
        ):
            raise AttestationContractError(
                "public Git tracked status is invalid"
            )
    source_evidence = _require_exact_fields(
        source.get("sourceEvidence"),
        {"apiVersion", "gitInventory", "identitySha256", "untrackedApproval"},
        "public source evidence identity",
    )
    source_evidence_payload = dict(source_evidence)
    source_evidence_sha256 = _require_digest(
        source_evidence_payload.pop("identitySha256", None),
        "public source evidence identity",
    )
    try:
        git_signature = base64.b64decode(
            source["gitInventory"]["signature"]["value"], validate=True
        )
        approval_signature = base64.b64decode(
            source["untrackedApproval"]["signature"]["value"], validate=True
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise AttestationContractError(
            "public source evidence signature encoding is invalid"
        ) from exc
    expected_source_evidence_payload = {
        "apiVersion": "serverware.sourceEvidenceIdentity/v1",
        "gitInventory": {
            "envelopeSha256": sha256_prefixed(
                canonical_json(source["gitInventory"]).encode("ascii")
            ),
            "headTree": git_payload["headTree"],
            "indexEntriesSha256": git_payload["indexEntriesSha256"],
            "indexRawSha256": git_payload["indexInventoryRawSha256"],
            "indexTree": git_payload["indexTree"],
            "keyRawSha256": raw_key_sha256s["sourceGitInventory"],
            "keySpkiSha256": sha256_prefixed(
                keys["sourceGitInventory"].public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ),
            "payloadSha256": source["gitInventoryPayloadSha256"],
            "signatureSha256": sha256_prefixed(git_signature),
            "statusRawSha256": raw_evidence_digests["status"],
            "treeEntriesSha256": git_payload["treeEntriesSha256"],
            "treeRawSha256": raw_evidence_digests["tree"],
            "worktreeEntriesSha256": git_payload[
                "worktreeEntriesSha256"
            ],
        },
        "untrackedApproval": {
            "challengeSha256": approval_payload["challengeSha256"],
            "envelopeSha256": sha256_prefixed(
                canonical_json(source["untrackedApproval"]).encode("ascii")
            ),
            "keyRawSha256":
            raw_key_sha256s["sourceUntrackedApproval"],
            "keySpkiSha256": sha256_prefixed(
                keys["sourceUntrackedApproval"].public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ),
            "pathListSha256": approval_payload["pathListSha256"],
            "payloadSha256": source[
                "untrackedApprovalPayloadSha256"
            ],
            "signatureSha256": sha256_prefixed(approval_signature),
        },
    }
    if (
        source_evidence.get("apiVersion")
        != "serverware.sourceEvidenceIdentity/v1"
        or source_evidence_payload != expected_source_evidence_payload
        or source_evidence_sha256
        != sha256_prefixed(
            canonical_json(source_evidence_payload).encode("ascii")
        )
        or source_evidence_sha256 != source["sourceEvidenceSha256"]
    ):
        raise AttestationContractError(
            "public source evidence identity is invalid"
        )

    candidate = _require_exact_fields(
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
        "public Candidate Manifest v6",
    )
    candidate_payload = dict(candidate)
    candidate_payload_sha256 = _require_digest(
        candidate_payload.pop("candidateManifestPayloadSha256", None),
        "public Candidate Manifest payload",
    )
    if (
        candidate.get("apiVersion")
        != "serverware.consolidatedCandidateArtifacts/v6"
        or candidate_payload_sha256
        != sha256_prefixed(canonical_json(candidate_payload).encode("ascii"))
        or candidate_file_sha256 != identity["candidateManifestFileSha256"]
        or candidate_payload_sha256
        != identity["candidateManifestPayloadSha256"]
        or candidate.get("laneOrder") != list(_MANIFEST_LANE_ORDER)
        or not isinstance(candidate.get("lanes"), Mapping)
        or list(candidate["lanes"]) != list(_MANIFEST_LANE_ORDER)
        or not isinstance(candidate.get("images"), Mapping)
        or list(candidate["images"]) != list(_MANIFEST_IMAGE_ORDER)
    ):
        raise AttestationContractError(
            "public Candidate Manifest v6 identity or ordered inventory is invalid"
        )
    source_snapshot = candidate.get("sourceSnapshot")
    if (
        not isinstance(source_snapshot, Mapping)
        or source_snapshot.get("sourceSelectionManifestFileSha256")
        != source_file_sha256
        or source_snapshot.get("sourceSelectionManifestPayloadSha256")
        != source_payload_sha256
        or source_snapshot.get("sourceClosureSha256")
        != identity["sourceClosureSha256"]
    ):
        raise AttestationContractError(
            "public Candidate Manifest crossed its source-input evidence"
        )
    continuity = _require_exact_fields(
        candidate.get("buildContinuity"),
        {
            "buildBundle",
            "buildPlan",
            "buildWatchdogReceipt",
            "dependencyBundle",
            "sourceSnapshot",
        },
        "public Candidate build continuity",
    )
    if continuity.get("sourceSnapshot") != source_snapshot:
        raise AttestationContractError(
            "public Candidate source continuity is invalid"
        )
    dependency = continuity.get("dependencyBundle")
    if not isinstance(dependency, Mapping):
        raise AttestationContractError(
            "public Candidate dependency bundle is missing"
        )
    dependency_payload = dict(dependency)
    dependency_payload_sha256 = _require_digest(
        dependency_payload.pop("manifestSha256", None),
        "public Candidate dependency payload",
    )
    if (
        dependency.get("apiVersion")
        != "serverware.ociDependencyBundle/v5"
        or dependency_payload_sha256
        != sha256_prefixed(canonical_json(dependency_payload).encode("ascii"))
        or sha256_prefixed(canonical_json(dependency).encode("ascii"))
        != identity["dependencyClosureSha256"]
    ):
        raise AttestationContractError(
            "public Candidate dependency closure is invalid"
        )
    promotion_contract = candidate.get("promotionContract")
    if not isinstance(promotion_contract, Mapping):
        raise AttestationContractError(
            "public Candidate promotion contract is missing"
        )
    contract_payload = dict(promotion_contract)
    contract_sha256 = _require_digest(
        contract_payload.pop("contractSha256", None),
        "public Candidate promotion contract",
    )
    if contract_sha256 != sha256_prefixed(
        canonical_json(contract_payload).encode("ascii")
    ):
        raise AttestationContractError(
            "public Candidate promotion contract digest is invalid"
        )

    image_identities: dict[str, dict[str, Any]] = {}
    for role in _MANIFEST_IMAGE_ORDER:
        image = _require_exact_fields(
            candidate["images"][role],
            {
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
            },
            f"public {role} Candidate image",
        )
        archive = _require_exact_fields(
            image.get("archive"),
            {"path", "sha256", "size"},
            f"public {role} Candidate archive",
        )
        file_manifest = _require_exact_fields(
            image.get("fileManifest"),
            {"path", "sha256"},
            f"public {role} Candidate file manifest",
        )
        sbom = _require_exact_fields(
            image.get("sbom"),
            {"path", "sha256"},
            f"public {role} Candidate SBOM",
        )
        if (
            image.get("role") != role
            or image.get("platform")
            != {"architecture": "amd64", "os": "linux"}
            or type(archive.get("size")) is not int
            or archive["size"] < 1
        ):
            raise AttestationContractError(
                f"public {role} Candidate image identity is invalid"
            )
        for digest in (
            archive.get("sha256"),
            file_manifest.get("sha256"),
            image.get("configDigest"),
            image.get("indexDigest"),
            image.get("manifestDigest"),
            image.get("rootfsDigest"),
            sbom.get("sha256"),
        ):
            _require_digest(digest, f"public {role} Candidate image")
        image_identities[role] = {
            "archiveSha256": archive["sha256"],
            "archiveSize": archive["size"],
            "configDigest": image["configDigest"],
            "fileManifestSha256": file_manifest["sha256"],
            "indexDigest": image["indexDigest"],
            "layerDigests": image["layerDigests"],
            "manifestDigest": image["manifestDigest"],
            "rootfsDiffIds": image["rootfsDiffIds"],
            "rootfsDigest": image["rootfsDigest"],
            "sbomSha256": sbom["sha256"],
        }
    return {
        "buildBundle": continuity["buildBundle"],
        "buildPlan": continuity["buildPlan"],
        "candidateImagesSha256": sha256_prefixed(
            canonical_json(image_identities).encode("ascii")
        ),
        "dependencyFileSha256": sha256_prefixed(
            canonical_json(dependency).encode("ascii") + b"\n"
        ),
        "dependencyPayloadSha256": dependency_payload_sha256,
        "imageIdentities": image_identities,
        "promotionContractSha256": contract_sha256,
        "source": dict(source),
        "watchdogBinding": continuity["buildWatchdogReceipt"],
    }


def _verify_public_builder_evidence(
    *,
    role: str,
    statement_document: Mapping[str, Any],
    transcript_document: Mapping[str, Any],
    statement_file_sha256: str,
    transcript_file_sha256: str,
    identity: Mapping[str, Any],
    candidate: Mapping[str, Any],
    source: Mapping[str, Any],
    key: Ed25519PublicKey,
    key_file_sha256: str,
    raw_key_sha256: str,
) -> dict[str, Any]:
    payload, _ = _verify_domain_completion_envelope(
        statement_document,
        api_version="serverware.rawBuilderStatement/v1",
        domain=_RAW_BUILDER_STATEMENT_DOMAIN,
        key=key,
        key_file_sha256=key_file_sha256,
        raw_key_sha256=raw_key_sha256,
        label=f"public {role} builder statement",
    )
    payload = _require_exact_fields(
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
            "sourceClosureSha256",
            "sourceInputManifestFileSha256",
            "sourceInputManifestPayloadSha256",
            "toolchainSha256",
            "transcriptFileSha256",
            "transcriptPayloadSha256",
        },
        f"public {role} builder payload",
    )
    transcript = _require_exact_fields(
        transcript_document,
        {
            "apiVersion",
            "builderId",
            "candidate",
            "completedAtUnix",
            "completionIdentity",
            "completionIdentitySha256",
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
        f"public {role} builder transcript",
    )
    for field in ("builderId", "invocationId", "operatorId"):
        if (
            not isinstance(payload.get(field), str)
            or _IDENTIFIER_RE.fullmatch(str(payload[field])) is None
        ):
            raise AttestationContractError(
                f"public {role} builder identity is invalid"
            )
    issued_at = payload.get("issuedAtUnix")
    expires_at = payload.get("expiresAtUnix")
    started_at = transcript.get("startedAtUnix")
    completed_at = transcript.get("completedAtUnix")
    now = int(time.time())
    if (
        type(issued_at) is not int
        or type(expires_at) is not int
        or type(started_at) is not int
        or type(completed_at) is not int
        or not started_at <= completed_at <= issued_at <= now < expires_at
        or expires_at - issued_at > 900
        or payload.get("pipeline") != PRODUCTION_PIPELINE
        or transcript.get("pipeline") != PRODUCTION_PIPELINE
        or transcript.get("apiVersion")
        != "serverware.rawBuilderTranscript/v1"
        or transcript.get("kind") != "HermeticBuilderTranscript"
        or transcript.get("builderId") != payload["builderId"]
        or transcript.get("invocationId") != payload["invocationId"]
        or transcript.get("network")
        != {"mode": "none", "observedEndpoints": []}
    ):
        raise AttestationContractError(
            f"public {role} builder timing, identity, pipeline, or network is invalid"
        )
    builder_completion_identity = _validate_completion_identity_binding(
        payload.get("completionIdentity"),
        payload.get("completionIdentitySha256"),
        label=f"public {role} builder",
    )
    transcript_completion_identity = _validate_completion_identity_binding(
        transcript.get("completionIdentity"),
        transcript.get("completionIdentitySha256"),
        label=f"public {role} transcript",
    )
    if (
        builder_completion_identity != identity["completionIdentity"]
        or transcript_completion_identity != builder_completion_identity
    ):
        raise AttestationContractError(
            f"public {role} builder crossed the final completion identity"
        )
    statement_bindings = {
        "candidateManifestFileSha256":
        identity["candidateManifestFileSha256"],
        "candidateManifestPayloadSha256":
        identity["candidateManifestPayloadSha256"],
        "completionIdentitySha256": identity["completionIdentitySha256"],
        "dependencyManifestFileSha256":
        candidate["dependencyFileSha256"],
        "dependencyManifestPayloadSha256":
        candidate["dependencyPayloadSha256"],
        "imageOutputsSha256": candidate["candidateImagesSha256"],
        "sourceClosureSha256": identity["sourceClosureSha256"],
        "sourceInputManifestFileSha256":
        identity["sourceInputManifestFileSha256"],
        "sourceInputManifestPayloadSha256":
        identity["sourceInputManifestPayloadSha256"],
        "transcriptFileSha256": transcript_file_sha256,
    }
    if any(
        payload.get(field) != expected
        for field, expected in statement_bindings.items()
    ):
        raise AttestationContractError(
            f"public {role} builder statement crossed release evidence"
        )
    for field in ("environmentSha256", "toolchainSha256"):
        _require_digest(payload.get(field), f"public {role} {field}")
    sandbox = _require_exact_fields(
        transcript.get("sandbox"),
        {
            "environmentSha256",
            "filesystemInputSha256",
            "kind",
            "profileSha256",
            "toolchainSha256",
        },
        f"public {role} builder sandbox",
    )
    if (
        sandbox.get("kind") != "independently-measured-hermetic-builder"
        or sandbox.get("environmentSha256") != payload["environmentSha256"]
        or sandbox.get("toolchainSha256") != payload["toolchainSha256"]
    ):
        raise AttestationContractError(
            f"public {role} builder sandbox binding is invalid"
        )
    for field in (
        "environmentSha256",
        "filesystemInputSha256",
        "profileSha256",
        "toolchainSha256",
    ):
        _require_digest(sandbox.get(field), f"public {role} sandbox {field}")
    expected_source = {
        "gitInventoryPayloadSha256": source[
            "gitInventoryPayloadSha256"
        ],
        "sourceClosureSha256": identity["sourceClosureSha256"],
        "sourceInputManifestFileSha256":
        identity["sourceInputManifestFileSha256"],
        "sourceInputManifestPayloadSha256":
        identity["sourceInputManifestPayloadSha256"],
        "untrackedApprovalPayloadSha256": source[
            "untrackedApprovalPayloadSha256"
        ],
    }
    expected_candidate = {
        "candidateImagesSha256": candidate["candidateImagesSha256"],
        "candidateManifestFileSha256":
        identity["candidateManifestFileSha256"],
        "candidateManifestPayloadSha256":
        identity["candidateManifestPayloadSha256"],
        "promotionContractSha256": candidate[
            "promotionContractSha256"
        ],
    }
    dependencies = transcript.get("dependencies")
    if (
        transcript.get("source") != expected_source
        or transcript.get("candidate") != expected_candidate
        or not isinstance(dependencies, Mapping)
        or dependencies.get("dependencyManifestFileSha256")
        != candidate["dependencyFileSha256"]
        or dependencies.get("dependencyManifestPayloadSha256")
        != candidate["dependencyPayloadSha256"]
        or transcript.get("imageOutputs") != candidate["imageIdentities"]
    ):
        raise AttestationContractError(
            f"public {role} builder transcript crossed source, dependency, or image evidence"
        )
    transcript_payload = dict(transcript)
    transcript_payload_sha256 = _require_digest(
        transcript_payload.pop("transcriptSha256", None),
        f"public {role} transcript payload",
    )
    if (
        transcript_payload_sha256
        != sha256_prefixed(canonical_json(transcript_payload).encode("ascii"))
        or payload.get("transcriptPayloadSha256")
        != transcript_payload_sha256
    ):
        raise AttestationContractError(
            f"public {role} builder transcript digest is invalid"
        )
    events = transcript.get("events")
    if not isinstance(events, list) or not 3 <= len(events) <= 100_000:
        raise AttestationContractError(
            f"public {role} builder event chain is invalid"
        )
    previous = sha256_prefixed(b"")
    event_types: list[Any] = []
    for sequence, event_value in enumerate(events, start=1):
        event = _require_exact_fields(
            event_value,
            {"event", "eventSha256", "previousEventSha256", "sequence"},
            f"public {role} builder event",
        )
        if (
            event.get("sequence") != sequence
            or event.get("previousEventSha256") != previous
            or not isinstance(event.get("event"), Mapping)
        ):
            raise AttestationContractError(
                f"public {role} builder event chain is invalid"
            )
        event_payload = {
            "event": event["event"],
            "previousEventSha256": previous,
            "sequence": sequence,
        }
        previous = sha256_prefixed(
            canonical_json(event_payload).encode("ascii")
        )
        if event.get("eventSha256") != previous:
            raise AttestationContractError(
                f"public {role} builder event digest is invalid"
            )
        event_types.append(event["event"].get("type"))
    if (
        transcript.get("eventHeadSha256") != previous
        or event_types[0] != "build-started"
        or event_types[-1] != "build-completed"
    ):
        raise AttestationContractError(
            f"public {role} builder event boundaries are invalid"
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
    transcript_core_payload = _builder_transcript_core_payload(transcript)
    builder_core = _completion_core(
        role,
        {
            "signingKeyId": sha256_prefixed(
                key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            ),
            "statement": statement_core_payload,
            "transcript": transcript_core_payload,
        },
    )
    builder_core_sha256 = sha256_prefixed(
        canonical_json(builder_core).encode("ascii")
    )
    if (
        builder_completion_identity["coreDigests"][role]
        != builder_core_sha256
    ):
        raise AttestationContractError(
            f"public {role} completion core digest is not reconstructible"
        )
    return {
        "builderId": payload["builderId"],
        "completionIdentity": builder_completion_identity,
        "completionIdentitySha256": payload["completionIdentitySha256"],
        "invocationId": payload["invocationId"],
        "operatorId": payload["operatorId"],
        "outputsSha256": payload["imageOutputsSha256"],
        "statementFileSha256": statement_file_sha256,
        "coreSha256": builder_core_sha256,
    }


def _completion_proof_core(document: Mapping[str, Any]) -> dict[str, Any]:
    excluded = {
        "aggregate_authentication",
        "authentication_artifacts",
        "independently_authenticated",
        "integrity_metadata",
        "proof_core_sha256",
        "proof_path",
    }
    return {
        key: value for key, value in document.items() if key not in excluded
    }


def _verify_merkle_inclusion(
    leaf: str, proof: Any, root: str
) -> bool:
    try:
        current = bytes.fromhex(_require_digest(leaf, "Merkle leaf")[7:])
        expected_root = bytes.fromhex(
            _require_digest(root, "Merkle root")[7:]
        )
    except ValueError:
        return False
    if not isinstance(proof, list) or len(proof) > 64:
        return False
    for item in proof:
        if (
            not isinstance(item, Mapping)
            or set(item) != {"hash", "side"}
            or item.get("side") not in {"left", "right"}
        ):
            return False
        try:
            sibling = bytes.fromhex(
                _require_digest(item.get("hash"), "Merkle sibling")[7:]
            )
        except (AttestationContractError, ValueError):
            return False
        material = (
            b"\x01" + sibling + current
            if item["side"] == "left"
            else b"\x01" + current + sibling
        )
        current = hashlib.sha256(material).digest()
    return hmac.compare_digest(current, expected_root)


def _terminal_journal_canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _terminal_journal_value_bytes(value: Any) -> bytes:
    if isinstance(value, str):
        return value.encode("ascii")
    return _terminal_journal_canonical_bytes(value)


def _terminal_journal_identity_key(
    recovery_identity: Mapping[str, Any],
) -> str:
    return hashlib.sha256(
        _terminal_journal_canonical_bytes(dict(recovery_identity))
    ).hexdigest()


def _terminal_journal_path(
    directory: str,
    recovery_identity: Mapping[str, Any],
) -> str:
    return os.path.join(
        directory,
        f"{_terminal_journal_identity_key(recovery_identity)}.terminal.json",
    )


def _public_evidence_prepared_journal_path(
    directory: str,
    recovery_identity: Mapping[str, Any],
) -> str:
    recovery_key_sha256 = sha256_prefixed(
        NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_KEY_DOMAIN
        + canonical_json(dict(recovery_identity)).encode("ascii")
    )
    return os.path.join(
        directory,
        recovery_key_sha256[7:] + ".json",
    )


def _terminal_journal_open_directory(
    directory: str,
) -> tuple[int, os.stat_result]:
    os.makedirs(directory, mode=0o700, exist_ok=True)
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(directory, flags)
    try:
        metadata = os.fstat(descriptor)
        path_metadata = os.stat(directory, follow_symlinks=False)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_uid != os.geteuid()
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise AttestationContractError(
                "terminal journal directory must be a stable, owned "
                "mode-0700 directory"
            )
        return descriptor, metadata
    except Exception:
        os.close(descriptor)
        raise


def _terminal_journal_validate_locked_file(
    *,
    directory_fd: int,
    name: str,
    descriptor: int,
    directory_owner: int,
    label: str,
) -> os.stat_result:
    metadata = os.fstat(descriptor)
    path_metadata = os.stat(
        name,
        dir_fd=directory_fd,
        follow_symlinks=False,
    )
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != directory_owner
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or (metadata.st_dev, metadata.st_ino)
        != (path_metadata.st_dev, path_metadata.st_ino)
    ):
        raise AttestationContractError(
            f"{label} must be a stable, owned, single-link mode-0600 "
            "regular file"
        )
    return metadata


def _terminal_journal_open_lock_file(
    *,
    directory_fd: int,
    directory_owner: int,
    lock_name: str,
    label: str,
) -> int:
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    lock_fd = os.open(
        lock_name,
        flags,
        0o600,
        dir_fd=directory_fd,
    )
    try:
        _terminal_journal_validate_locked_file(
            directory_fd=directory_fd,
            name=lock_name,
            descriptor=lock_fd,
            directory_owner=directory_owner,
            label=label,
        )
        os.fsync(lock_fd)
        os.fsync(directory_fd)
        return lock_fd
    except Exception:
        os.close(lock_fd)
        raise


@contextmanager
def _terminal_journal_directory_lock(
    directory: str,
) -> Any:
    directory_fd, directory_metadata = _terminal_journal_open_directory(
        directory
    )
    lock_name = ".terminal.inventory.lock"
    lock_fd = -1
    try:
        lock_fd = _terminal_journal_open_lock_file(
            directory_fd=directory_fd,
            directory_owner=directory_metadata.st_uid,
            lock_name=lock_name,
            label="terminal journal inventory lock",
        )
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        _terminal_journal_validate_locked_file(
            directory_fd=directory_fd,
            name=lock_name,
            descriptor=lock_fd,
            directory_owner=directory_metadata.st_uid,
            label="terminal journal inventory lock",
        )
        current_directory = os.stat(directory, follow_symlinks=False)
        if (
            current_directory.st_dev,
            current_directory.st_ino,
            current_directory.st_uid,
            stat.S_IMODE(current_directory.st_mode),
        ) != (
            directory_metadata.st_dev,
            directory_metadata.st_ino,
            directory_metadata.st_uid,
            0o700,
        ):
            raise AttestationContractError(
                "terminal journal directory changed while acquiring its "
                "inventory lock"
            )
        yield directory_fd, directory_metadata
    finally:
        if lock_fd >= 0:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        os.close(directory_fd)


@contextmanager
def _terminal_journal_identity_lock_locked(
    *,
    directory_fd: int,
    directory_owner: int,
    recovery_identity: Mapping[str, Any],
) -> Any:
    lock_name = (
        f"{_terminal_journal_identity_key(recovery_identity)}.terminal.lock"
    )
    lock_fd = _terminal_journal_open_lock_file(
        directory_fd=directory_fd,
        directory_owner=directory_owner,
        lock_name=lock_name,
        label="terminal journal identity lock",
    )
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        _terminal_journal_validate_locked_file(
            directory_fd=directory_fd,
            name=lock_name,
            descriptor=lock_fd,
            directory_owner=directory_owner,
            label="terminal journal identity lock",
        )
        yield
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)


@contextmanager
def _terminal_journal_lock(
    directory: str,
    recovery_identity: Mapping[str, Any],
) -> Any:
    # All journal operations acquire global inventory/capacity ownership
    # before an identity lock; callers must not invert this order.
    with _terminal_journal_directory_lock(
        directory
    ) as (directory_fd, directory_metadata):
        with _terminal_journal_identity_lock_locked(
            directory_fd=directory_fd,
            directory_owner=directory_metadata.st_uid,
            recovery_identity=recovery_identity,
        ):
            yield directory_fd, directory_metadata


def _terminal_journal_publish_no_replace(
    *,
    directory_fd: int,
    target_name: str,
    payload: bytes,
) -> bool:
    temporary_name = (
        f".{target_name}.tmp.{os.getpid()}.{secrets.token_hex(16)}"
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(
        temporary_name,
        flags,
        0o600,
        dir_fd=directory_fd,
    )
    write_error: Exception | None = None
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise AttestationContractError(
                    "terminal journal write made no progress"
                )
            offset += written
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        path_metadata = os.stat(
            temporary_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size != len(payload)
            or (metadata.st_dev, metadata.st_ino)
            != (path_metadata.st_dev, path_metadata.st_ino)
        ):
            raise AttestationContractError(
                "terminal journal temporary publication file is unsafe"
            )
    except Exception as exc:
        write_error = exc
    finally:
        os.close(descriptor)
    if write_error is not None:
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            raise write_error
    try:
        try:
            os.link(
                temporary_name,
                target_name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except FileExistsError:
            return False
        os.fsync(directory_fd)
        return True
    finally:
        removed_temporary = False
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
            removed_temporary = True
        except FileNotFoundError:
            pass
        if removed_temporary:
            os.fsync(directory_fd)


def _terminal_journal_remove_prepared_locked(
    *,
    directory_fd: int,
    directory_owner: int,
    prepared_path: str,
) -> None:
    prepared_name = os.path.basename(prepared_path)
    try:
        metadata = os.stat(
            prepared_name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != directory_owner
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise AttestationContractError(
            "prepared recovery journal must be an owned, single-link "
            "mode-0600 regular file"
        )
    os.unlink(prepared_name, dir_fd=directory_fd)
    os.fsync(directory_fd)


def _terminal_journal_seal(
    *,
    key: bytes,
    recovery_identity: Mapping[str, Any],
    document: Mapping[str, Any],
) -> bytes:
    if len(key) != 32:
        raise AttestationContractError(
            "terminal journal retained sealing key must be 32 bytes"
        )
    nonce = secrets.token_bytes(12)
    aad = _terminal_journal_canonical_bytes(
        {
            "apiVersion": "serverware.publicAttestationTerminalJournal/v1",
            "recoveryIdentity": dict(recovery_identity),
        }
    )
    ciphertext = AESGCM(key).encrypt(
        nonce,
        _terminal_journal_canonical_bytes(dict(document)),
        aad,
    )
    envelope = {
        "apiVersion": "serverware.publicAttestationTerminalJournal/v1",
        "encoding": "aes-256-gcm",
        "recoveryIdentity": dict(recovery_identity),
        "nonceBase64url": base64.urlsafe_b64encode(nonce).rstrip(b"=").decode(
            "ascii"
        ),
        "ciphertextBase64url": base64.urlsafe_b64encode(ciphertext)
        .rstrip(b"=")
        .decode("ascii"),
    }
    return _terminal_journal_canonical_bytes(envelope) + b"\n"


def _terminal_journal_decode_base64url(value: Any, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise AttestationContractError(
            f"terminal journal {field} must be non-empty base64url"
        )
    try:
        return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))
    except Exception as exc:
        raise AttestationContractError(
            f"terminal journal {field} is invalid"
        ) from exc


def _terminal_journal_unseal(
    *,
    key: bytes,
    recovery_identity: Mapping[str, Any],
    payload: bytes,
) -> dict[str, Any]:
    if len(payload) > 4 * 1024 * 1024:
        raise AttestationContractError(
            "terminal journal entry exceeds the bounded size"
        )
    try:
        envelope = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AttestationContractError(
            "terminal journal envelope is invalid JSON"
        ) from exc
    if not isinstance(envelope, Mapping) or set(envelope) != {
        "apiVersion",
        "encoding",
        "recoveryIdentity",
        "nonceBase64url",
        "ciphertextBase64url",
    }:
        raise AttestationContractError(
            "terminal journal envelope fields are not exact"
        )
    if (
        envelope["apiVersion"]
        != "serverware.publicAttestationTerminalJournal/v1"
        or envelope["encoding"] != "aes-256-gcm"
        or envelope["recoveryIdentity"] != dict(recovery_identity)
    ):
        raise AttestationContractError(
            "terminal journal envelope binding is invalid"
        )
    aad = _terminal_journal_canonical_bytes(
        {
            "apiVersion": "serverware.publicAttestationTerminalJournal/v1",
            "recoveryIdentity": dict(recovery_identity),
        }
    )
    try:
        plaintext = AESGCM(key).decrypt(
            _terminal_journal_decode_base64url(
                envelope["nonceBase64url"],
                "nonceBase64url",
            ),
            _terminal_journal_decode_base64url(
                envelope["ciphertextBase64url"],
                "ciphertextBase64url",
            ),
            aad,
        )
        document = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise AttestationContractError(
            "terminal journal authentication failed"
        ) from exc
    if not isinstance(document, Mapping):
        raise AttestationContractError(
            "terminal journal plaintext must be an object"
        )
    return dict(document)


def _public_evidence_terminal_journal_store(
    *,
    directory: str,
    retained_sealing_key: bytes,
    recovery_identity: Mapping[str, Any],
    historical_tls_binding: Mapping[str, Any],
    response_body: bytes,
    live_session_proof: Mapping[str, Any],
    live_session_signature: Any,
    terminal_at_unix: int,
    prepared_journal_path: str | None = None,
    maximum_entries: int | None = None,
    verify_terminal_authority_evidence: Any | None = None,
    terminal_authority_evidence_for: Any | None = None,
    now_unix: int | None = None,
) -> dict[str, Any]:
    body_sha256 = sha256_prefixed(response_body)
    proof = dict(live_session_proof)
    signature = (
        dict(live_session_signature)
        if isinstance(live_session_signature, Mapping)
        else live_session_signature
    )
    core = {
        "apiVersion": "serverware.publicAttestationTerminalResult/v1",
        "status": "responsePending",
        "recoveryIdentity": dict(recovery_identity),
        "recoveryIdentitySha256": sha256_prefixed(
            _terminal_journal_canonical_bytes(dict(recovery_identity))
        ),
        "recoveryKeySha256": "sha256:"
        + _terminal_journal_identity_key(recovery_identity),
        "historicalTlsBinding": dict(historical_tls_binding),
        "historicalTlsBindingSha256": sha256_prefixed(
            _terminal_journal_canonical_bytes(dict(historical_tls_binding))
        ),
        "responseBodyBase64url": base64.urlsafe_b64encode(response_body)
        .rstrip(b"=")
        .decode("ascii"),
        "responseBodySha256": body_sha256,
        "liveSessionProof": proof,
        "liveSessionProofSha256": sha256_prefixed(
            _terminal_journal_canonical_bytes(proof)
        ),
        "liveSessionSignature": signature,
        "liveSessionSignatureSha256": sha256_prefixed(
            _terminal_journal_value_bytes(signature)
        ),
        "terminalAtUnix": terminal_at_unix,
        "terminalAuthorityEvidence": None,
    }
    immutable_core = {
        key: value
        for key, value in core.items()
        if key not in {"status", "terminalAuthorityEvidence"}
    }
    document = {
        **core,
        "terminalResultSha256": sha256_prefixed(
            _terminal_journal_canonical_bytes(immutable_core)
        ),
    }
    prepared_path = (
        os.path.join(
            directory,
            f"{_terminal_journal_identity_key(recovery_identity)}.json",
        )
        if prepared_journal_path is None
        else prepared_journal_path
    )
    if (
        os.path.dirname(prepared_path) != directory
        or not os.path.basename(prepared_path).endswith(".json")
        or os.path.basename(prepared_path).endswith(
            ".terminal.json"
        )
    ):
        raise AttestationContractError(
            "prepared recovery journal path is invalid"
        )
    document_bytes = _terminal_journal_canonical_bytes(document)
    target_name = os.path.basename(
        _terminal_journal_path(directory, recovery_identity)
    )
    if maximum_entries is not None:
        if (
            type(maximum_entries) is not int
            or maximum_entries < 1
            or type(now_unix) is not int
            or not callable(verify_terminal_authority_evidence)
            or not callable(terminal_authority_evidence_for)
        ):
            raise AttestationContractError(
                "terminal journal publication capacity policy is invalid"
            )
    with _terminal_journal_directory_lock(
        directory
    ) as (directory_fd, directory_metadata):
        directory_owner = directory_metadata.st_uid
        with _terminal_journal_identity_lock_locked(
            directory_fd=directory_fd,
            directory_owner=directory_owner,
            recovery_identity=recovery_identity,
        ):
            try:
                existing = _public_evidence_terminal_journal_load_locked(
                    directory_fd=directory_fd,
                    directory_owner=directory_owner,
                    retained_sealing_key=retained_sealing_key,
                    recovery_identity=recovery_identity,
                )
            except FileNotFoundError:
                existing = None
            if existing is not None:
                if not hmac.compare_digest(
                    _terminal_journal_canonical_bytes(existing),
                    document_bytes,
                ):
                    raise AttestationContractError(
                        "terminal journal recovery identity conflicts with "
                        "different terminal bytes"
                    )
                _terminal_journal_remove_prepared_locked(
                    directory_fd=directory_fd,
                    directory_owner=directory_owner,
                    prepared_path=prepared_path,
                )
                return existing

        if maximum_entries is not None:
            retained_identities = (
                _public_evidence_terminal_journal_recovery_identities_locked(
                    directory_fd=directory_fd,
                    directory_owner=directory_owner,
                    maximum_entries=maximum_entries + 1,
                )
            )
            _public_evidence_terminal_journal_prune_locked(
                directory_fd=directory_fd,
                directory_owner=directory_owner,
                retained_sealing_key=retained_sealing_key,
                recovery_identities=retained_identities,
                maximum_entries=maximum_entries,
                verify_terminal_authority_evidence=(
                    verify_terminal_authority_evidence
                ),
                now_unix=now_unix,
                terminal_authority_evidence_for=(
                    terminal_authority_evidence_for
                ),
            )
            retained_identities = (
                _public_evidence_terminal_journal_recovery_identities_locked(
                    directory_fd=directory_fd,
                    directory_owner=directory_owner,
                    maximum_entries=maximum_entries + 1,
                )
            )
            if len(retained_identities) >= maximum_entries:
                raise AttestationContractError(
                    "terminal journal capacity is occupied by unexpired "
                    "response-pending results"
                )

        with _terminal_journal_identity_lock_locked(
            directory_fd=directory_fd,
            directory_owner=directory_owner,
            recovery_identity=recovery_identity,
        ):
            try:
                existing = _public_evidence_terminal_journal_load_locked(
                    directory_fd=directory_fd,
                    directory_owner=directory_owner,
                    retained_sealing_key=retained_sealing_key,
                    recovery_identity=recovery_identity,
                )
            except FileNotFoundError:
                existing = None
            if existing is not None:
                if not hmac.compare_digest(
                    _terminal_journal_canonical_bytes(existing),
                    document_bytes,
                ):
                    raise AttestationContractError(
                        "terminal journal recovery identity conflicts with "
                        "different terminal bytes"
                    )
                retained = existing
            else:
                published = _terminal_journal_publish_no_replace(
                    directory_fd=directory_fd,
                    target_name=target_name,
                    payload=_terminal_journal_seal(
                        key=retained_sealing_key,
                        recovery_identity=recovery_identity,
                        document=document,
                    ),
                )
                if not published:
                    existing = (
                        _public_evidence_terminal_journal_load_locked(
                            directory_fd=directory_fd,
                            directory_owner=directory_owner,
                            retained_sealing_key=retained_sealing_key,
                            recovery_identity=recovery_identity,
                        )
                    )
                    if not hmac.compare_digest(
                        _terminal_journal_canonical_bytes(existing),
                        document_bytes,
                    ):
                        raise AttestationContractError(
                            "terminal journal recovery identity conflicts "
                            "with different terminal bytes"
                        )
                    retained = existing
                else:
                    retained = document
            _terminal_journal_remove_prepared_locked(
                directory_fd=directory_fd,
                directory_owner=directory_owner,
                prepared_path=prepared_path,
            )
            return retained


def _public_evidence_terminal_journal_load_locked(
    *,
    directory_fd: int,
    directory_owner: int,
    retained_sealing_key: bytes,
    recovery_identity: Mapping[str, Any],
) -> dict[str, Any]:
    target_name = (
        f"{_terminal_journal_identity_key(recovery_identity)}.terminal.json"
    )
    flags = os.O_RDONLY
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(target_name, flags, dir_fd=directory_fd)
    try:
        before = _terminal_journal_validate_locked_file(
            directory_fd=directory_fd,
            name=target_name,
            descriptor=descriptor,
            directory_owner=directory_owner,
            label="terminal journal entry",
        )
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > 4 * 1024 * 1024:
                raise AttestationContractError(
                    "terminal journal entry exceeds the bounded size"
                )
            chunks.append(chunk)
        after = _terminal_journal_validate_locked_file(
            directory_fd=directory_fd,
            name=target_name,
            descriptor=descriptor,
            directory_owner=directory_owner,
            label="terminal journal entry",
        )
        stable_fields = (
            "st_dev",
            "st_ino",
            "st_mode",
            "st_nlink",
            "st_uid",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if any(
            getattr(before, field) != getattr(after, field)
            for field in stable_fields
        ):
            raise AttestationContractError(
                "terminal journal entry changed while it was read"
            )
    finally:
        os.close(descriptor)
    document = _terminal_journal_unseal(
        key=retained_sealing_key,
        recovery_identity=recovery_identity,
        payload=b"".join(chunks),
    )
    expected_fields = {
        "apiVersion",
        "status",
        "recoveryIdentity",
        "recoveryIdentitySha256",
        "recoveryKeySha256",
        "historicalTlsBinding",
        "historicalTlsBindingSha256",
        "responseBodyBase64url",
        "responseBodySha256",
        "liveSessionProof",
        "liveSessionProofSha256",
        "liveSessionSignature",
        "liveSessionSignatureSha256",
        "terminalAtUnix",
        "terminalAuthorityEvidence",
        "terminalResultSha256",
    }
    if set(document) != expected_fields:
        raise AttestationContractError(
            "terminal journal result fields are not exact"
        )
    if (
        document["apiVersion"]
        != "serverware.publicAttestationTerminalResult/v1"
        or document["recoveryIdentity"] != dict(recovery_identity)
        or document["recoveryIdentitySha256"]
        != sha256_prefixed(
            _terminal_journal_canonical_bytes(dict(recovery_identity))
        )
        or document["recoveryKeySha256"]
        != "sha256:" + _terminal_journal_identity_key(recovery_identity)
        or document["status"] != "responsePending"
    ):
        raise AttestationContractError(
            "terminal journal recovery identity is invalid"
        )
    body = _terminal_journal_decode_base64url(
        document["responseBodyBase64url"],
        "responseBodyBase64url",
    )
    if sha256_prefixed(body) != document["responseBodySha256"]:
        raise AttestationContractError(
            "terminal journal response body digest is invalid"
        )
    for field, digest_field in (
        ("historicalTlsBinding", "historicalTlsBindingSha256"),
        ("liveSessionProof", "liveSessionProofSha256"),
        ("liveSessionSignature", "liveSessionSignatureSha256"),
    ):
        value_bytes = (
            _terminal_journal_value_bytes(document[field])
            if field == "liveSessionSignature"
            else _terminal_journal_canonical_bytes(document[field])
        )
        if sha256_prefixed(value_bytes) != document[digest_field]:
            raise AttestationContractError(
                f"terminal journal {field} digest is invalid"
            )
    immutable_core = {
        key: document[key]
        for key in expected_fields
        if key
        not in {
            "status",
            "terminalAuthorityEvidence",
            "terminalResultSha256",
        }
    }
    if sha256_prefixed(
        _terminal_journal_canonical_bytes(immutable_core)
    ) != document["terminalResultSha256"]:
        raise AttestationContractError(
            "terminal journal result digest is invalid"
        )
    evidence = document["terminalAuthorityEvidence"]
    if evidence is not None:
        raise AttestationContractError(
            "response-pending terminal result carries retirement evidence"
        )
    return document


def _public_evidence_terminal_journal_load(
    *,
    directory: str,
    retained_sealing_key: bytes,
    recovery_identity: Mapping[str, Any],
) -> dict[str, Any]:
    with _terminal_journal_lock(
        directory,
        recovery_identity,
    ) as (directory_fd, directory_metadata):
        return _public_evidence_terminal_journal_load_locked(
            directory_fd=directory_fd,
            directory_owner=directory_metadata.st_uid,
            retained_sealing_key=retained_sealing_key,
            recovery_identity=recovery_identity,
        )


def _public_evidence_terminal_journal_retire_locked(
    *,
    directory_fd: int,
    directory_owner: int,
    retained_sealing_key: bytes,
    recovery_identity: Mapping[str, Any],
    terminal_authority_evidence: Mapping[str, Any],
    verify_terminal_authority_evidence: Any,
) -> None:
    evidence = dict(terminal_authority_evidence)
    if set(evidence) != {
        "apiVersion",
        "status",
        "recoveryIdentity",
        "terminalResultSha256",
        "evidenceAtUnix",
        "issuer",
        "signature",
    }:
        raise AttestationContractError(
            "terminal authority evidence fields are not exact"
        )
    if (
        evidence["apiVersion"]
        != "serverware.publicAttestationTerminalAuthorityEvidence/v1"
        or evidence["status"] not in {"aborted", "expired"}
        or evidence["recoveryIdentity"] != dict(recovery_identity)
    ):
        raise AttestationContractError(
            "terminal authority evidence binding is invalid"
        )
    document = _public_evidence_terminal_journal_load_locked(
        directory_fd=directory_fd,
        directory_owner=directory_owner,
        retained_sealing_key=retained_sealing_key,
        recovery_identity=recovery_identity,
    )
    if (
        evidence["terminalResultSha256"]
        != document["terminalResultSha256"]
    ):
        raise AttestationContractError(
            "terminal authority evidence binding is invalid"
        )
    if verify_terminal_authority_evidence(evidence) is not True:
        raise AttestationContractError(
            "terminal authority evidence authentication failed"
        )
    os.unlink(
        (
            f"{_terminal_journal_identity_key(recovery_identity)}"
            ".terminal.json"
        ),
        dir_fd=directory_fd,
    )
    os.fsync(directory_fd)


def _public_evidence_terminal_journal_retire(
    *,
    directory: str,
    retained_sealing_key: bytes,
    recovery_identity: Mapping[str, Any],
    terminal_authority_evidence: Mapping[str, Any],
    verify_terminal_authority_evidence: Any,
) -> None:
    with _terminal_journal_lock(
        directory,
        recovery_identity,
    ) as (directory_fd, directory_metadata):
        _public_evidence_terminal_journal_retire_locked(
            directory_fd=directory_fd,
            directory_owner=directory_metadata.st_uid,
            retained_sealing_key=retained_sealing_key,
            recovery_identity=recovery_identity,
            terminal_authority_evidence=terminal_authority_evidence,
            verify_terminal_authority_evidence=(
                verify_terminal_authority_evidence
            ),
        )


def _public_evidence_terminal_journal_recover_delivery(
    *,
    directory: str,
    retained_sealing_key: bytes,
    recovery_identity: Mapping[str, Any],
    current_tls_binding: Mapping[str, Any],
    rebind_issued_at_unix: int,
    response_signing_key_id: str,
    sign_delivery_rebind: Any,
) -> dict[str, Any]:
    terminal = _public_evidence_terminal_journal_load(
        directory=directory,
        retained_sealing_key=retained_sealing_key,
        recovery_identity=recovery_identity,
    )
    if terminal["status"] != "responsePending":
        raise AttestationContractError(
            "only a response-pending terminal result may be recovered"
        )
    historical_result = {
        "evidenceBodySha256": terminal["responseBodySha256"],
        "liveSessionProofSha256": terminal["liveSessionProofSha256"],
        "liveSessionSignatureSha256": terminal[
            "liveSessionSignatureSha256"
        ],
    }
    rebind_payload = {
        "apiVersion": PUBLIC_ATTESTATION_DELIVERY_REBIND_VERSION,
        "recoveryIdentity": dict(recovery_identity),
        "recoveryIdentitySha256": terminal[
            "recoveryIdentitySha256"
        ],
        "historicalTlsBindingSha256": terminal[
            "historicalTlsBindingSha256"
        ],
        "historicalResult": historical_result,
        "historicalResultSha256": sha256_prefixed(
            _terminal_journal_canonical_bytes(historical_result)
        ),
        "currentTlsBinding": dict(current_tls_binding),
        "currentTlsBindingSha256": sha256_prefixed(
            _terminal_journal_canonical_bytes(dict(current_tls_binding))
        ),
        "rebindIssuedAtUnix": rebind_issued_at_unix,
        "expiresAtUnix": min(
            int(current_tls_binding["expiresAtUnix"]),
            rebind_issued_at_unix + 30,
        ),
        "responseSigningKeyId": response_signing_key_id,
    }
    rebind_core = {
        "apiVersion":
        SIGNED_PUBLIC_ATTESTATION_DELIVERY_REBIND_VERSION,
        "payload": rebind_payload,
        "payloadSha256": sha256_prefixed(
            _terminal_journal_canonical_bytes(rebind_payload)
        ),
        "responseSigningKeyId": response_signing_key_id,
        "signatureAlgorithm": "Ed25519",
    }
    signature = sign_delivery_rebind(rebind_core)
    if not isinstance(signature, str):
        raise AttestationContractError(
            "delivery rebind signer must return an Ed25519 signature"
        )
    return {
        "apiVersion": "serverware.publicAttestationRecoveredResponse/v1",
        "recoveryIdentity": dict(recovery_identity),
        "terminalResultSha256": terminal["terminalResultSha256"],
        "responseBody": _terminal_journal_decode_base64url(
            terminal["responseBodyBase64url"],
            "responseBodyBase64url",
        ),
        "liveSessionProof": terminal["liveSessionProof"],
        "liveSessionSignature": terminal["liveSessionSignature"],
        "deliveryRebind": {
            **rebind_core,
            "signature": signature,
        },
    }


def _public_evidence_terminal_journal_prune_locked(
    *,
    directory_fd: int,
    directory_owner: int,
    retained_sealing_key: bytes,
    recovery_identities: Sequence[Mapping[str, Any]],
    maximum_entries: int,
    verify_terminal_authority_evidence: Any,
    now_unix: int | None = None,
    terminal_authority_evidence_for: Any | None = None,
) -> int:
    if maximum_entries < 1:
        raise AttestationContractError(
            "terminal journal maximum_entries must be positive"
        )
    loaded: list[tuple[int, str, dict[str, Any]]] = []
    removed = 0
    ordered_identities = sorted(
        (dict(identity) for identity in recovery_identities),
        key=_terminal_journal_identity_key,
    )
    for identity in ordered_identities:
        with _terminal_journal_identity_lock_locked(
            directory_fd=directory_fd,
            directory_owner=directory_owner,
            recovery_identity=identity,
        ):
            try:
                document = _public_evidence_terminal_journal_load_locked(
                    directory_fd=directory_fd,
                    directory_owner=directory_owner,
                    retained_sealing_key=retained_sealing_key,
                    recovery_identity=identity,
                )
            except FileNotFoundError:
                continue
            proof = document["liveSessionProof"]
            expires_at = (
                proof.get("expiresAtUnix")
                if isinstance(proof, Mapping)
                else None
            )
            if (
                now_unix is not None
                and terminal_authority_evidence_for is not None
                and document["status"] == "responsePending"
                and type(expires_at) is int
                and expires_at <= now_unix
            ):
                evidence = terminal_authority_evidence_for(
                    document,
                    "expired",
                    now_unix,
                )
                _public_evidence_terminal_journal_retire_locked(
                    directory_fd=directory_fd,
                    directory_owner=directory_owner,
                    retained_sealing_key=retained_sealing_key,
                    recovery_identity=identity,
                    terminal_authority_evidence=evidence,
                    verify_terminal_authority_evidence=(
                        verify_terminal_authority_evidence
                    ),
                )
                removed += 1
                continue
            loaded.append(
                (
                    int(document["terminalAtUnix"]),
                    document["recoveryKeySha256"],
                    document,
                )
            )
    loaded.sort(key=lambda item: (item[0], item[1]))
    if len(loaded) > maximum_entries:
        raise AttestationContractError(
            "terminal journal capacity is occupied by authoritative "
            "response-pending results"
        )
    return removed


def _public_evidence_terminal_journal_prune(
    *,
    directory: str,
    retained_sealing_key: bytes,
    recovery_identities: Sequence[Mapping[str, Any]],
    maximum_entries: int,
    verify_terminal_authority_evidence: Any,
    now_unix: int | None = None,
    terminal_authority_evidence_for: Any | None = None,
) -> int:
    # Caller-provided inventory is advisory only. Capacity decisions use one
    # fresh inventory while holding the directory-global lock.
    del recovery_identities
    with _terminal_journal_directory_lock(
        directory
    ) as (directory_fd, directory_metadata):
        locked_identities = (
            _public_evidence_terminal_journal_recovery_identities_locked(
                directory_fd=directory_fd,
                directory_owner=directory_metadata.st_uid,
                maximum_entries=maximum_entries + 1,
            )
        )
        return _public_evidence_terminal_journal_prune_locked(
            directory_fd=directory_fd,
            directory_owner=directory_metadata.st_uid,
            retained_sealing_key=retained_sealing_key,
            recovery_identities=locked_identities,
            maximum_entries=maximum_entries,
            verify_terminal_authority_evidence=(
                verify_terminal_authority_evidence
            ),
            now_unix=now_unix,
            terminal_authority_evidence_for=(
                terminal_authority_evidence_for
            ),
        )


def _public_v3_artifacts(
    artifacts: Any,
) -> tuple[dict[str, dict[str, Any]], dict[str, bytes], dict[str, str]]:
    if (
        not isinstance(artifacts, list)
        or len(artifacts) != len(_PUBLIC_V3_ARTIFACT_NAMES)
    ):
        raise AttestationContractError(
            "public v3 evidence artifact inventory is incomplete"
        )
    documents: dict[str, dict[str, Any]] = {}
    raw_documents: dict[str, bytes] = {}
    digests: dict[str, str] = {}
    observed_names: list[str] = []
    for artifact_value in artifacts:
        artifact = _require_exact_fields(
            artifact_value,
            {"contentBase64url", "mediaType", "name", "sha256"},
            "public v3 evidence artifact",
        )
        name = artifact.get("name")
        if name not in _PUBLIC_V3_ARTIFACT_NAMES or name in documents:
            raise AttestationContractError(
                "public v3 evidence artifact inventory is invalid"
            )
        observed_names.append(str(name))
        if artifact.get("mediaType") != "application/json":
            raise AttestationContractError(
                "public v3 evidence artifacts must be JSON"
            )
        encoded = artifact.get("contentBase64url")
        if not isinstance(encoded, str):
            raise AttestationContractError(
                "public v3 evidence artifact encoding is invalid"
            )
        try:
            raw = b64d(encoded)
        except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
            raise AttestationContractError(
                "public v3 evidence artifact is not base64url"
            ) from exc
        if (
            not raw
            or len(raw) > _MAX_PUBLIC_BUNDLE_BYTES
            or b64e(raw) != encoded
        ):
            raise AttestationContractError(
                "public v3 evidence artifact encoding is noncanonical or overlong"
            )
        digest = _require_digest(
            artifact.get("sha256"),
            f"public v3 {name} artifact",
        )
        if not hmac.compare_digest(digest, sha256_prefixed(raw)):
            raise AttestationContractError(
                f"public v3 {name} artifact digest is invalid"
            )
        decoded = _strict_json_document(
            raw, label=f"public v3 {name} artifact"
        )
        if raw != canonical_json(decoded).encode("ascii") + b"\n":
            raise AttestationContractError(
                f"public v3 {name} artifact is not canonical JSON plus LF"
            )
        _validate_public_json_grammar(
            decoded, label=f"public v3 {name} artifact"
        )
        documents[str(name)] = decoded
        raw_documents[str(name)] = raw
        digests[str(name)] = digest
    if set(documents) != _PUBLIC_V3_ARTIFACT_NAMES:
        raise AttestationContractError(
            "public v3 evidence artifact inventory is incomplete"
        )
    if observed_names != sorted(_PUBLIC_V3_ARTIFACT_NAMES):
        raise AttestationContractError(
            "public v3 evidence artifacts are not in canonical name order"
        )
    return documents, raw_documents, digests


def _release_identity_from_descriptor(
    descriptor: PublicEvidenceProducerDescriptor,
) -> dict[str, Any]:
    try:
        from scripts import verify_nitro_tee as public_verifier

        return public_verifier.validate_release_identity(
            descriptor.release_identity,
            label="pinned stable release identity",
        )
    except (
        ImportError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AttestationContractError(
            "pinned stable release identity is invalid"
        ) from exc


def _validate_public_evidence_nonce_authority_assurance(
    value: Any,
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    assurance = dict(
        _require_exact_fields(
            value,
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
            "public evidence nonce-authority assurance",
        )
    )
    rollback = _require_exact_fields(
        assurance.get("rollbackProtection"),
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
        "public evidence nonce-authority rollback protection",
    )
    for field in (
        "administrativeDomainSha256",
        "authorityIdentitySha256",
    ):
        _require_digest(
            assurance.get(field),
            f"public evidence nonce-authority {field}",
        )
    _require_positive_generation(
        assurance.get("authorityEpoch"),
        "public evidence nonce-authority epoch",
    )
    _require_positive_generation(
        assurance.get("authorityGeneration"),
        "public evidence nonce-authority generation",
    )
    if (
        assurance.get("apiVersion")
        != NONCE_AUTHORITY_ASSURANCE_VERSION
        or sha256_prefixed(
            canonical_json(assurance).encode("ascii")
        )
        != expected_sha256
        or rollback.get("exactSuccessorRequired") is not True
        or rollback.get("freshVerifierChallengeRequired") is not True
    ):
        raise AttestationContractError(
            "public evidence nonce-authority assurance crossed its immutable identity"
        )
    profile = (
        assurance.get("backendClass"),
        rollback.get("mechanism"),
        rollback.get("keyProtection"),
        rollback.get("stateCommitment"),
        rollback.get("verifierStateStoreClass"),
        assurance.get("assuranceEvidenceType"),
    )
    production_profiles = {
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
    if assurance.get("productionEligible") is True:
        _require_digest(
            assurance.get("assuranceEvidenceSha256"),
            "public evidence nonce-authority assurance evidence",
        )
        if (
            assurance.get("assuranceLevel")
            != "productionRollbackProtected"
            or rollback.get("administrativeRollbackResistance")
            is not True
            or rollback.get("backendAttestationRequired") is not True
            or profile not in production_profiles
        ):
            raise AttestationContractError(
                "public evidence production nonce-authority assurance is not closed"
            )
    elif (
        assurance.get("productionEligible") is not False
        or assurance.get("assuranceLevel")
        not in {
            "nonProductionFixture",
            "nonProductionDurableReference",
        }
        or assurance.get("assuranceEvidenceSha256") is not None
        or rollback.get("administrativeRollbackResistance") is not False
        or rollback.get("backendAttestationRequired") is not False
        or profile
        != (
            "nonProductionSqlite",
            "none",
            "retainedFdReference",
            "localHashChain",
            "nonProductionCallerFile",
            "none",
        )
    ):
        raise AttestationContractError(
            "public evidence non-production nonce-authority assurance is not closed"
        )
    return assurance


def _verify_public_evidence_standard_envelope(
    value: Any,
    *,
    api_version: str,
    domain: bytes,
    signing_key: Ed25519PublicKey,
    signing_key_id: str,
    label: str,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    envelope = dict(
        _require_exact_fields(
            value,
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
    )
    payload = envelope.get("payload")
    if not isinstance(payload, Mapping):
        raise AttestationContractError(f"{label} payload is not an object")
    payload = dict(payload)
    payload_sha256 = sha256_prefixed(
        canonical_json(payload).encode("ascii")
    )
    if (
        envelope.get("apiVersion") != api_version
        or envelope.get("payloadSha256") != payload_sha256
        or envelope.get("signatureAlgorithm") != "Ed25519"
        or envelope.get("signingKeyId") != signing_key_id
        or envelope.get("signingKeySpkiSha256") != signing_key_id
    ):
        raise AttestationContractError(
            f"{label} crossed its version, digest, or signing key"
        )
    try:
        signature = b64d(str(envelope.get("signatureBase64url")))
        if len(signature) != 64:
            raise ValueError("signature length is invalid")
        signing_key.verify(
            signature,
            domain
            + canonical_json(
                {
                    "payload": payload,
                    "payloadSha256": payload_sha256,
                }
            ).encode("ascii"),
        )
    except (
        InvalidSignature,
        binascii.Error,
        UnicodeEncodeError,
        ValueError,
    ) as exc:
        raise AttestationContractError(
            f"{label} signature is invalid"
        ) from exc
    return (
        envelope,
        payload,
        sha256_prefixed(canonical_json(envelope).encode("ascii")),
    )


def _validate_public_evidence_assurance_evidence(
    value: Any,
    *,
    assurance: Mapping[str, Any],
    signing_key: Ed25519PublicKey,
    signing_key_id: str,
    nonce_store_key_id: str,
    verifier_state_key_id: str,
    verifier_state_store_identity_sha256: str,
    verifier_state_store_administrative_domain_sha256: str,
    now: int,
) -> dict[str, Any] | None:
    if assurance.get("productionEligible") is not True:
        if value is not None:
            raise AttestationContractError(
                "non-production nonce-authority assurance must not carry assurance evidence"
            )
        return None
    envelope, payload, envelope_sha256 = (
        _verify_public_evidence_standard_envelope(
            value,
            api_version=(
                SIGNED_NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION
            ),
            domain=NONCE_AUTHORITY_ASSURANCE_EVIDENCE_DOMAIN,
            signing_key=signing_key,
            signing_key_id=signing_key_id,
            label="public evidence nonce-authority assurance evidence",
        )
    )
    payload = dict(
        _require_exact_fields(
            payload,
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
            "public evidence nonce-authority assurance-evidence payload",
        )
    )
    issued = _require_positive_generation(
        payload.get("issuedAtUnix"),
        "public evidence assurance-evidence issue time",
    )
    expires = _require_positive_generation(
        payload.get("expiresAtUnix"),
        "public evidence assurance-evidence expiry",
    )
    rollback = assurance["rollbackProtection"]
    if (
        envelope_sha256 != assurance.get("assuranceEvidenceSha256")
        or payload.get("apiVersion")
        != NONCE_AUTHORITY_ASSURANCE_EVIDENCE_VERSION
        or payload.get("administrativeDomainSha256")
        != assurance.get("administrativeDomainSha256")
        or payload.get("assuranceEvidenceType")
        != assurance.get("assuranceEvidenceType")
        or payload.get("authorityEpoch")
        != assurance.get("authorityEpoch")
        or payload.get("authorityGeneration")
        != assurance.get("authorityGeneration")
        or payload.get("authorityIdentitySha256")
        != assurance.get("authorityIdentitySha256")
        or payload.get("backendClass")
        != assurance.get("backendClass")
        or payload.get("nonceAuthorityStateSigningKeySpkiSha256")
        != nonce_store_key_id
        or payload.get("rollbackMechanism")
        != rollback.get("mechanism")
        or payload.get("stateCommitment")
        != rollback.get("stateCommitment")
        or payload.get("verifierStateStoreClass")
        != rollback.get("verifierStateStoreClass")
        or payload.get("verifierStateStoreIdentitySha256")
        != verifier_state_store_identity_sha256
        or payload.get(
            "verifierStateStoreAdministrativeDomainSha256"
        )
        != verifier_state_store_administrative_domain_sha256
        or payload.get("verifierStateStoreSigningKeySpkiSha256")
        != verifier_state_key_id
        or verifier_state_store_administrative_domain_sha256
        == assurance.get("administrativeDomainSha256")
        or not issued <= now < expires
        or expires - issued > 900
    ):
        raise AttestationContractError(
            "public evidence nonce-authority assurance evidence is stale or crossed"
        )
    return envelope


def _validate_global_attestation_key_role_separation(
    role_key_ids: Mapping[str, Any],
    *,
    expected_roles: Sequence[str] | None = None,
) -> dict[str, str]:
    expected = tuple(expected_roles or role_key_ids)
    if not expected or set(role_key_ids) != set(expected):
        missing = sorted(set(expected) - set(role_key_ids))
        extra = sorted(set(role_key_ids) - set(expected))
        raise AttestationContractError(
            "global public attestation key roles are not exact: "
            f"missing={missing!r} extra={extra!r}"
        )
    normalized: dict[str, str] = {}
    collisions: dict[str, list[str]] = {}
    for name in expected:
        key_id = _require_digest(
            role_key_ids[name],
            f"global public attestation role {name}",
        )
        normalized[name] = key_id
        collisions.setdefault(key_id, []).append(name)
    duplicate_roles = sorted(
        sorted(names)
        for names in collisions.values()
        if len(names) > 1
    )
    if duplicate_roles:
        raise AttestationContractError(
            "global public attestation key roles must be pairwise distinct: "
            f"{duplicate_roles!r}"
        )
    return normalized


def _validate_public_evidence_store_and_role_assurance(
    config: Mapping[str, Any],
    *,
    assurance: Mapping[str, Any],
    nonce_store_key_id: str,
    verifier_state_key_id: str,
    store_attestation_key_id: str,
    service: Mapping[str, Any],
    now: int,
) -> dict[str, Any]:
    (
        store_evidence_key,
        store_evidence_key_id,
    ) = _load_ed25519_spki_der(
        config.get(
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
        ),
        label="public evidence store-assurance issuer key",
    )
    store_envelope, store_payload, store_evidence_sha256 = (
        _verify_public_evidence_standard_envelope(
            config.get(
                "nonceAuthorityVerifierStateStoreAssuranceEvidence"
            ),
            api_version=(
                SIGNED_VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION
            ),
            domain=VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_DOMAIN,
            signing_key=store_evidence_key,
            signing_key_id=store_evidence_key_id,
            label="public evidence verifier-state store assurance",
        )
    )
    store_payload = dict(
        _require_exact_fields(
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
            "public evidence store assurance payload",
        )
    )
    store_issued = _require_positive_generation(
        store_payload.get("evidenceIssuedAtUnix"),
        "public evidence store-assurance issue time",
    )
    store_expires = _require_positive_generation(
        store_payload.get("evidenceExpiresAtUnix"),
        "public evidence store-assurance expiry",
    )
    minimum_generation = _require_positive_generation(
        store_payload.get("minimumStoreGeneration"),
        "public evidence store-assurance minimum generation",
    )
    minimum_commit_index = _require_positive_generation(
        store_payload.get("minimumStoreCommitIndex"),
        "public evidence store-assurance minimum commit index",
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
        _require_digest(
            store_payload.get(field),
            f"public evidence store assurance {field}",
        )
    if (
        store_evidence_sha256
        != config.get(
            "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
        )
        or store_payload.get("apiVersion")
        != VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_VERSION
        or store_payload.get("productionEligible") is not True
        or store_payload.get("generationSemantics")
        != "strictlyMonotonicU64"
        or store_payload.get("commitIndexSemantics")
        != "equalToVerifierStateGeneration"
        or store_payload.get("rollbackMechanism")
        != config.get(
            "nonceAuthorityVerifierStateStoreRollbackMechanism"
        )
        or store_payload.get("storeIdentitySha256")
        != config.get(
            "nonceAuthorityVerifierStateStoreIdentitySha256"
        )
        or store_payload.get("storeAdministrativeDomainSha256")
        != config.get(
            "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
        )
        or store_payload.get("storeCredentialIdentitySha256")
        != config.get(
            "nonceAuthorityVerifierStateStoreCredentialIdentitySha256"
        )
        or store_payload.get("storeAttestationKeySpkiSha256")
        != store_attestation_key_id
        or store_payload.get("storeConfigurationSha256")
        != config.get(
            "nonceAuthorityVerifierStateStoreConfigurationSha256"
        )
        or store_payload.get("issuerAdministrativeDomainSha256")
        != config.get(
            "nonceAuthorityVerifierStateStoreAssuranceIssuerAdministrativeDomainSha256"
        )
        or store_payload.get("issuerCredentialIdentitySha256")
        != config.get(
            "nonceAuthorityVerifierStateStoreAssuranceIssuerCredentialIdentitySha256"
        )
        or store_payload.get("issuerIdentitySha256")
        != config.get(
            "nonceAuthorityVerifierStateStoreAssuranceIssuerIdentitySha256"
        )
        or minimum_generation
        != config.get(
            "nonceAuthorityVerifierStateStoreMinimumGeneration"
        )
        or minimum_commit_index
        != config.get(
            "nonceAuthorityVerifierStateStoreMinimumCommitIndex"
        )
        or not store_issued <= now < store_expires
        or store_expires - store_issued > 86400
        or store_payload["issuerAdministrativeDomainSha256"]
        == store_payload["storeAdministrativeDomainSha256"]
        or store_payload["issuerCredentialIdentitySha256"]
        == store_payload["storeCredentialIdentitySha256"]
        or store_payload["issuerIdentitySha256"]
        == store_payload["storeIdentitySha256"]
        or store_evidence_key_id == store_attestation_key_id
    ):
        raise AttestationContractError(
            "public evidence store assurance is stale, substituted, or self-attested"
        )
    role_evidence_key, role_evidence_key_id = _load_ed25519_spki_der(
        config.get(
            "nonceAuthorityVerifierStateRoleSeparationEvidenceSigningPublicKeySpkiDerBase64url"
        ),
        label="public evidence role-separation issuer key",
    )
    role_envelope, role_payload, role_evidence_sha256 = (
        _verify_public_evidence_standard_envelope(
            config.get(
                "nonceAuthorityVerifierStateRoleSeparationEvidence"
            ),
            api_version=(
                SIGNED_VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_VERSION
            ),
            domain=VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_DOMAIN,
            signing_key=role_evidence_key,
            signing_key_id=role_evidence_key_id,
            label="public evidence verifier-state role separation",
        )
    )
    role_payload = dict(
        _require_exact_fields(
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
            "public evidence role-separation payload",
        )
    )

    def role(value: Any, label: str) -> dict[str, Any]:
        result = dict(
            _require_exact_fields(
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
        )
        for field in result:
            _require_digest(result[field], f"{label} {field}")
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
        config.get(
            "nonceAuthorityVerifierStateRoleSeparationEvidenceIssuer"
        ),
        "pinned role-separation issuer",
    )
    role_issued = _require_positive_generation(
        role_payload.get("evidenceIssuedAtUnix"),
        "public evidence role-separation issue time",
    )
    role_expires = _require_positive_generation(
        role_payload.get("evidenceExpiresAtUnix"),
        "public evidence role-separation expiry",
    )
    if (
        role_payload.get("apiVersion")
        != VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_VERSION
        or role_payload.get("assuranceSha256")
        != config.get("nonceAuthorityAssuranceSha256")
        or role_payload.get("productionEligible") is not True
        or not role_issued <= now < role_expires
        or role_expires - role_issued > 86400
        or roles["roleSeparationEvidenceIssuer"] != pinned_issuer
        or roles["roleSeparationEvidenceIssuer"]["keySpkiSha256"]
        != role_evidence_key_id
        or roles["nonceAuthority"]["keySpkiSha256"]
        != nonce_store_key_id
        or roles["nonceAuthority"]["administrativeDomainSha256"]
        != assurance.get("administrativeDomainSha256")
        or roles["nonceAuthority"]["roleIdentitySha256"]
        != assurance.get("authorityIdentitySha256")
        or roles["nonceAuthority"]["assuranceEvidenceSha256"]
        != assurance.get("assuranceEvidenceSha256")
        or roles["nonceAuthorityAssuranceEvidenceIssuer"][
            "keySpkiSha256"
        ]
        != assurance_evidence_key_id
        or roles["verifierStateSigner"]["keySpkiSha256"]
        != verifier_state_key_id
        or roles["verifierStateStore"]["keySpkiSha256"]
        != store_attestation_key_id
        or roles["verifierStateStore"]["roleIdentitySha256"]
        != store_payload["storeIdentitySha256"]
        or roles["verifierStateStore"]["administrativeDomainSha256"]
        != store_payload["storeAdministrativeDomainSha256"]
        or roles["verifierStateStore"]["credentialIdentitySha256"]
        != store_payload["storeCredentialIdentitySha256"]
        or roles["verifierStateStore"]["assuranceEvidenceSha256"]
        != store_evidence_sha256
        or roles["storeAssuranceEvidenceIssuer"]["keySpkiSha256"]
        != store_evidence_key_id
        or roles["storeAssuranceEvidenceIssuer"][
            "administrativeDomainSha256"
        ]
        != store_payload["issuerAdministrativeDomainSha256"]
        or roles["storeAssuranceEvidenceIssuer"][
            "credentialIdentitySha256"
        ]
        != store_payload["issuerCredentialIdentitySha256"]
        or roles["storeAssuranceEvidenceIssuer"]["roleIdentitySha256"]
        != store_payload["issuerIdentitySha256"]
        or roles["publicAttestationClientTls"]["keySpkiSha256"]
        != service.get("clientCertificateSpkiSha256")
        or roles["verifierStateServiceListenerTls"][
            "keySpkiSha256"
        ]
        != service.get("serverLeafSpkiSha256")
    ):
        raise AttestationContractError(
            "public evidence role separation is stale or crossed"
        )
    for field in (
        "administrativeDomainSha256",
        "credentialIdentitySha256",
        "endpointIdentitySha256",
        "keySpkiSha256",
        "roleIdentitySha256",
    ):
        if len({roles[name][field] for name in role_names}) != len(
            role_names
        ):
            raise AttestationContractError(
                f"public evidence roles collide on {field}"
            )
    return {
        "roleEvidence": role_envelope,
        "roleEvidenceSha256": role_evidence_sha256,
        "roleEvidenceKeyId": role_evidence_key_id,
        "roleKeyIdsByRole": {
            name: roles[name]["keySpkiSha256"]
            for name in role_names
        },
        "roleKeyIds": tuple(
            roles[name]["keySpkiSha256"]
            for name in role_names
        ),
        "storeEvidence": store_envelope,
        "storeEvidenceSha256": store_evidence_sha256,
        "storeEvidenceKeyId": store_evidence_key_id,
    }


def _public_evidence_certificate_spki_sha256(
    raw: bytes,
    *,
    label: str,
) -> str:
    try:
        try:
            certificate = x509.load_pem_x509_certificate(raw)
        except ValueError:
            certificate = x509.load_der_x509_certificate(raw)
        spki_der = certificate.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except (TypeError, ValueError) as exc:
        raise AttestationContractError(f"{label} is invalid") from exc
    return sha256_prefixed(spki_der)


def _validate_public_release_graph(
    value: Any,
    *,
    verified_release: Mapping[str, Any],
    release_config_sha256: str,
    stable_statement_sha256: str,
    trust_root_bundle_sha256: str,
    public_verifier: Any,
) -> dict[str, Any]:
    graph = _require_exact_fields(
        value,
        {
            "apiVersion",
            "releaseIdentity",
            "releaseIdentitySha256",
            "releaseConfigSha256",
            "stableReleaseStatementSha256",
            "trustRootBundleSha256",
        },
        "public v3 stable release graph",
    )
    if graph.get("apiVersion") != PUBLIC_RELEASE_GRAPH_VERSION:
        raise AttestationContractError(
            "public v3 stable release graph version is invalid"
        )
    try:
        release_identity = public_verifier.validate_release_identity(
            graph.get("releaseIdentity"),
            label="public v3 graph stable release identity",
        )
        release_identity_sha256 = public_verifier.require_sha256(
            graph.get("releaseIdentitySha256"),
            "public v3 graph stable release identity",
        )
        graph_release_config_sha256 = public_verifier.require_sha256(
            graph.get("releaseConfigSha256"),
            "public v3 graph release config",
        )
        statement_sha256 = public_verifier.require_sha256(
            graph.get("stableReleaseStatementSha256"),
            "public v3 graph stable release statement",
        )
        graph_trust_roots = public_verifier.require_sha256(
            graph.get("trustRootBundleSha256"),
            "public v3 graph trust-root bundle",
        )
        public_verifier.require(
            release_identity == verified_release["releaseIdentity"]
            and release_identity_sha256
            == verified_release["releaseIdentitySha256"]
            == public_verifier.sha256_json(release_identity)
            and graph_release_config_sha256 == release_config_sha256
            and statement_sha256 == stable_statement_sha256
            and graph_trust_roots == trust_root_bundle_sha256,
            "public v3 release graph differs from the authenticated stable release",
        )
    except (
        KeyError,
        TypeError,
        public_verifier.VerificationError,
    ) as exc:
        raise AttestationContractError(
            "public v3 stable release graph reconstruction failed"
        ) from exc
    return dict(graph)


def _load_public_evidence_producer_descriptor(
) -> PublicEvidenceProducerDescriptor:
    descriptor_path = _configured_production_path(
        "SERVERWARE_PUBLIC_ATTESTATION_PRODUCER_DESCRIPTOR_PATH",
        "public evidence producer descriptor",
    )
    raw = _read_stable_root_owned_file(
        descriptor_path,
        label="public evidence producer descriptor",
        maximum=64 * 1024,
    )
    descriptor_sha256 = sha256_prefixed(raw)
    expected_descriptor_sha256 = _required_public_pin(
        "SERVERWARE_PUBLIC_ATTESTATION_PRODUCER_DESCRIPTOR_SHA256",
        "public evidence producer descriptor",
    )
    if not hmac.compare_digest(
        descriptor_sha256, expected_descriptor_sha256
    ):
        raise AttestationContractError(
            "public evidence producer descriptor differs from its external pin"
        )
    document = _strict_json_document(
        raw, label="public evidence producer descriptor"
    )
    if raw != canonical_json(document).encode("ascii") + b"\n":
        raise AttestationContractError(
            "public evidence producer descriptor is not canonical JSON plus LF"
        )
    _validate_public_json_grammar(
        document, label="public evidence producer descriptor"
    )
    descriptor = _require_exact_fields(
        document,
        {
            "apiVersion",
            "concurrencyLimit",
            "executablePath",
            "executableSha256",
            "immutableConfigPath",
            "maxInputBytes",
            "maxOutputBytes",
            "nonceService",
            "nonceStoreIdentitySha256",
            "nonceStoreKeySpkiSha256",
            "producerRequestSchemaSha256",
            "sandboxResources",
            "sandboxDescriptorPath",
            "sandboxDescriptorSha256",
            "sandboxLauncherPath",
            "sandboxLauncherSha256",
            "timeoutMilliseconds",
            "trustRootsSha256",
            "verifierStateService",
            "witnessStoreIdentitySha256",
            "witnessStoreKeySpkiSha256",
        },
        "public evidence producer descriptor",
    )
    if (
        descriptor.get("apiVersion")
        != PUBLIC_EVIDENCE_PRODUCER_DESCRIPTOR_VERSION
    ):
        raise AttestationContractError(
            "public evidence producer descriptor version is invalid"
        )
    executable_sha256 = _require_digest(
        descriptor.get("executableSha256"),
        "public evidence producer executable",
    )
    immutable_config_sha256 = _required_public_pin(
        "SERVERWARE_PUBLIC_ATTESTATION_CONFIG_SHA256",
        "public evidence immutable configuration",
    )
    stable_statement_sha256 = _required_public_pin(
        "SERVERWARE_PUBLIC_ATTESTATION_STABLE_STATEMENT_SHA256",
        "public evidence stable release statement",
    )
    sandbox_launcher_sha256 = _require_digest(
        descriptor.get("sandboxLauncherSha256"),
        "public evidence sandbox launcher",
    )
    sandbox_descriptor_sha256 = _require_digest(
        descriptor.get("sandboxDescriptorSha256"),
        "public evidence sandbox descriptor",
    )
    trust_roots_sha256 = _require_digest(
        descriptor.get("trustRootsSha256"),
        "public Nitro trust roots",
    )
    producer_request_schema_sha256 = _require_digest(
        descriptor.get("producerRequestSchemaSha256"),
        "public evidence producer-request schema",
    )
    nonce_store_identity_sha256 = _require_digest(
        descriptor.get("nonceStoreIdentitySha256"),
        "public evidence nonce-store identity",
    )
    nonce_store_key_spki_sha256 = _require_digest(
        descriptor.get("nonceStoreKeySpkiSha256"),
        "public evidence nonce-store key",
    )
    witness_store_identity_sha256 = _require_digest(
        descriptor.get("witnessStoreIdentitySha256"),
        "public evidence witness-store identity",
    )
    witness_store_key_spki_sha256 = _require_digest(
        descriptor.get("witnessStoreKeySpkiSha256"),
        "public evidence witness-store key",
    )
    static_pin_pairs = (
        (
            executable_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_PRODUCER_EXECUTABLE_SHA256",
                "public evidence producer executable",
            ),
            "producer executable",
        ),
        (
            sandbox_launcher_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_SANDBOX_LAUNCHER_SHA256",
                "public evidence sandbox launcher",
            ),
            "sandbox launcher",
        ),
        (
            sandbox_descriptor_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_SANDBOX_DESCRIPTOR_SHA256",
                "public evidence sandbox descriptor",
            ),
            "sandbox descriptor",
        ),
        (
            trust_roots_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_NITRO_TRUST_ROOTS_SHA256",
                "public Nitro trust roots",
            ),
            "Nitro trust roots",
        ),
        (
            producer_request_schema_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_PRODUCER_REQUEST_SCHEMA_SHA256",
                "public evidence producer-request schema",
            ),
            "producer-request schema",
        ),
        (
            nonce_store_identity_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_NONCE_STORE_IDENTITY_SHA256",
                "public evidence nonce-store identity",
            ),
            "nonce-store identity",
        ),
        (
            nonce_store_key_spki_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_NONCE_STORE_KEY_SPKI_SHA256",
                "public evidence nonce-store key",
            ),
            "nonce-store key",
        ),
        (
            witness_store_identity_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_WITNESS_STORE_IDENTITY_SHA256",
                "public evidence witness-store identity",
            ),
            "witness-store identity",
        ),
        (
            witness_store_key_spki_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_WITNESS_STORE_KEY_SPKI_SHA256",
                "public evidence witness-store key",
            ),
            "witness-store key",
        ),
    )
    for actual, expected, label in static_pin_pairs:
        if not hmac.compare_digest(actual, expected):
            raise AttestationContractError(
                f"public evidence {label} differs from its external pin"
            )
    executable_path_value = _require_normalized_absolute_path_text(
        descriptor.get("executablePath"),
        "public evidence producer executable",
    )
    immutable_config_path_value = _require_normalized_absolute_path_text(
        descriptor.get("immutableConfigPath"),
        "public evidence immutable configuration",
    )
    sandbox_launcher_path_value = _require_normalized_absolute_path_text(
        descriptor.get("sandboxLauncherPath"),
        "public evidence sandbox launcher",
    )
    sandbox_descriptor_path_value = (
        _require_normalized_absolute_path_text(
            descriptor.get("sandboxDescriptorPath"),
            "public evidence sandbox descriptor",
        )
    )
    nonce_service = _require_exact_fields(
        descriptor.get("nonceService"),
        {
            "apiVersion",
            "expectedPeerCgroupPath",
            "expectedPeerExecutableSha256",
            "expectedPeerGid",
            "expectedPeerUid",
            "maxResponseBytes",
            "requestRole",
            "responseRole",
            "socketType",
            "timeoutMilliseconds",
        },
        "public evidence nonce service",
    )
    nonce_request_role = nonce_service.get("requestRole")
    nonce_response_role = nonce_service.get("responseRole")
    nonce_expected_peer_uid = nonce_service.get("expectedPeerUid")
    nonce_expected_peer_gid = nonce_service.get("expectedPeerGid")
    if (
        nonce_service.get("apiVersion")
        != "serverware.attestationNonceConsumeOnceRequest/v3"
        or nonce_service.get("socketType")
        != "AF_UNIX/SOCK_SEQPACKET"
        or not isinstance(nonce_request_role, str)
        or _IDENTIFIER_RE.fullmatch(nonce_request_role) is None
        or not isinstance(nonce_response_role, str)
        or _IDENTIFIER_RE.fullmatch(nonce_response_role) is None
        or nonce_request_role == nonce_response_role
        or nonce_request_role != "nonceRequest"
        or nonce_response_role != "nonceResponse"
        or type(nonce_expected_peer_uid) is not int
        or not 1 <= nonce_expected_peer_uid <= (1 << 31) - 1
        or type(nonce_expected_peer_gid) is not int
        or not 1 <= nonce_expected_peer_gid <= (1 << 31) - 1
    ):
        raise AttestationContractError(
            "public evidence nonce service contract is invalid"
        )
    nonce_expected_peer_executable_sha256 = _require_digest(
        nonce_service.get("expectedPeerExecutableSha256"),
        "public evidence nonce-service executable",
    )
    nonce_expected_peer_cgroup_path = (
        _require_normalized_absolute_path_text(
            nonce_service.get("expectedPeerCgroupPath"),
            "public evidence nonce-service cgroup",
        )
    )
    nonce_service_max_response_bytes = (
        _require_positive_generation(
            nonce_service.get("maxResponseBytes"),
            "public evidence nonce-service response bound",
        )
    )
    nonce_service_timeout_milliseconds = (
        _require_positive_generation(
            nonce_service.get("timeoutMilliseconds"),
            "public evidence nonce-service timeout",
        )
    )
    if (
        not 512
        <= nonce_service_max_response_bytes
        <= 1024 * 1024
        or not 100
        <= nonce_service_timeout_milliseconds
        <= 30_000
    ):
        raise AttestationContractError(
            "public evidence nonce service bounds are invalid"
        )
    verifier_state_service = _require_exact_fields(
        descriptor.get("verifierStateService"),
        {
            "abortPath",
            "apiVersion",
            "attachNonceStatusPath",
            "caFdRole",
            "clientCertificateFdRole",
            "clientCertificateSpkiSha256",
            "clientKeyFdRole",
            "commitPath",
            "concurrencyLimit",
            "endpoint",
            "markConsumptionPath",
            "maxResponseBytes",
            "issueChallengePath",
            "preparePath",
            "readPath",
            "recoverPath",
            "recoverChallengePath",
            "recoveryLookupPath",
            "serverLeafSpkiSha256",
            "serviceConfigurationSha256",
            "timeoutMilliseconds",
        },
        "public evidence verifier-state service",
    )
    endpoint = verifier_state_service.get("endpoint")
    try:
        parsed_endpoint = urllib.parse.urlsplit(str(endpoint))
        verifier_state_service_port = parsed_endpoint.port
    except ValueError as exc:
        raise AttestationContractError(
            "public evidence verifier-state endpoint is invalid"
        ) from exc
    verifier_state_service_host = parsed_endpoint.hostname
    try:
        verifier_state_service_packed_address = socket.inet_pton(
            socket.AF_INET,
            str(verifier_state_service_host),
        )
    except OSError as exc:
        raise AttestationContractError(
            "public evidence verifier-state endpoint must use a literal IPv4 address"
        ) from exc
    if (
        verifier_state_service.get("apiVersion")
        != PUBLIC_EVIDENCE_VERIFIER_STATE_CLIENT_VERSION
        or not isinstance(endpoint, str)
        or parsed_endpoint.scheme != "https"
        or parsed_endpoint.path != ""
        or parsed_endpoint.query
        or parsed_endpoint.fragment
        or parsed_endpoint.username is not None
        or parsed_endpoint.password is not None
        or not isinstance(verifier_state_service_host, str)
        or not verifier_state_service_host
        or socket.inet_ntop(
            socket.AF_INET,
            verifier_state_service_packed_address,
        )
        != verifier_state_service_host
        or verifier_state_service_port is None
        or not 1 <= verifier_state_service_port <= 65535
        or parsed_endpoint.netloc
        != endpoint.removeprefix("https://")
        or verifier_state_service.get("readPath")
        != "/v1/state/read"
        or verifier_state_service.get("issueChallengePath")
        != "/v1/state/issue-challenge"
        or verifier_state_service.get("recoverChallengePath")
        != "/v1/state/recover-challenge"
        or verifier_state_service.get("preparePath")
        != "/v1/state/prepare"
        or verifier_state_service.get("recoveryLookupPath")
        != "/v1/state/recovery-lookup"
        or verifier_state_service.get("markConsumptionPath")
        != "/v1/state/mark-consumption"
        or verifier_state_service.get("attachNonceStatusPath")
        != "/v1/state/attach-nonce-status"
        or verifier_state_service.get("abortPath")
        != "/v1/state/abort"
        or verifier_state_service.get("commitPath")
        != "/v1/state/commit"
        or verifier_state_service.get("recoverPath")
        != "/v1/state/recover"
        or verifier_state_service.get("caFdRole")
        != "verifierStateCa"
        or verifier_state_service.get("clientCertificateFdRole")
        != "verifierStateClientCertificate"
        or verifier_state_service.get("clientKeyFdRole")
        != "verifierStateClientKey"
    ):
        raise AttestationContractError(
            "public evidence verifier-state endpoint authority or paths are not exact"
        )
    verifier_state_service_server_leaf_spki_sha256 = _require_digest(
        verifier_state_service.get("serverLeafSpkiSha256"),
        "public evidence verifier-state server leaf SPKI",
    )
    verifier_state_service_client_certificate_spki_sha256 = (
        _require_digest(
            verifier_state_service.get(
                "clientCertificateSpkiSha256"
            ),
            "public evidence verifier-state client certificate SPKI",
        )
    )
    verifier_state_service_configuration_sha256 = _require_digest(
        verifier_state_service.get("serviceConfigurationSha256"),
        "public evidence verifier-state service configuration",
    )
    verifier_state_service_max_response_bytes = (
        _require_positive_generation(
            verifier_state_service.get("maxResponseBytes"),
            "public evidence verifier-state response bound",
        )
    )
    verifier_state_service_timeout_milliseconds = (
        _require_positive_generation(
            verifier_state_service.get("timeoutMilliseconds"),
            "public evidence verifier-state timeout",
        )
    )
    verifier_state_service_concurrency_limit = (
        _require_positive_generation(
            verifier_state_service.get("concurrencyLimit"),
            "public evidence verifier-state concurrency",
        )
    )
    if (
        not 1024
        <= verifier_state_service_max_response_bytes
        <= 256 * 1024
        or not 100
        <= verifier_state_service_timeout_milliseconds
        <= 10_000
        or verifier_state_service_concurrency_limit != 1
    ):
        raise AttestationContractError(
            "public evidence verifier-state service bounds are invalid"
        )
    verifier_state_tls_roles = (
        "verifierStateCa",
        "verifierStateClientCertificate",
        "verifierStateClientKey",
    )
    verifier_state_tls_fds = dict(
        _retained_public_evidence_verifier_state_tls_fds(
            verifier_state_tls_roles
        )
    )
    try:
        (
            verifier_state_service_tls_context,
            verifier_state_service_tls_material_snapshot_sha256,
        ) = _preload_public_evidence_verifier_state_tls_context(
            ca_fd=verifier_state_tls_fds["verifierStateCa"],
            client_certificate_fd=verifier_state_tls_fds[
                "verifierStateClientCertificate"
            ],
            client_key_fd=verifier_state_tls_fds[
                "verifierStateClientKey"
            ],
            expected_client_certificate_spki_sha256=(
                verifier_state_service_client_certificate_spki_sha256
            ),
        )
    finally:
        for retained_fd in verifier_state_tls_fds.values():
            os.close(retained_fd)
    immutable_config_path = Path(immutable_config_path_value)
    immutable_config = _read_stable_root_owned_file(
        immutable_config_path,
        label="public evidence immutable configuration",
        maximum=1024 * 1024,
    )
    if not hmac.compare_digest(
        sha256_prefixed(immutable_config), immutable_config_sha256
    ):
        raise AttestationContractError(
            "public evidence immutable configuration digest is invalid"
        )
    immutable_config_document = _strict_json_document(
        immutable_config,
        label="public evidence immutable configuration",
    )
    if (
        immutable_config
        != canonical_json(immutable_config_document).encode("ascii") + b"\n"
    ):
        raise AttestationContractError(
            "public evidence immutable configuration is not canonical JSON plus LF"
        )
    immutable_config_document = _require_exact_fields(
        immutable_config_document,
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
        "public evidence immutable configuration",
    )
    if (
        immutable_config_document.get("apiVersion")
        != PUBLIC_EVIDENCE_CONFIG_VERSION
    ):
        raise AttestationContractError(
            "public evidence immutable configuration version is invalid"
        )
    minimum_rollback_continuity_commitment_sha256 = _require_digest(
        immutable_config_document.get(
            "minimumRollbackContinuityCommitmentSha256"
        ),
        "public evidence minimum rollback continuity commitment",
    )
    nonce_authority_assurance_sha256 = _require_digest(
        immutable_config_document.get(
            "nonceAuthorityAssuranceSha256"
        ),
        "public evidence nonce-authority assurance",
    )
    nonce_authority_assurance = (
        _validate_public_evidence_nonce_authority_assurance(
            immutable_config_document.get(
                "nonceAuthorityAssurance"
            ),
            expected_sha256=nonce_authority_assurance_sha256,
        )
    )
    if (
        nonce_authority_assurance.get("authorityIdentitySha256")
        != nonce_store_identity_sha256
    ):
        raise AttestationContractError(
            "public evidence nonce-authority assurance crossed the nonce-store identity"
        )
    verifier_state_key_encoded = immutable_config_document.get(
        "nonceAuthorityVerifierStateSigningPublicKeySpkiDerBase64url"
    )
    (
        _verifier_state_signing_key,
        nonce_authority_verifier_state_key_spki_sha256,
    ) = _load_ed25519_spki_der(
        verifier_state_key_encoded,
        label="public evidence nonce-authority verifier-state signing key",
    )
    assurance_evidence_key_encoded = immutable_config_document.get(
        "nonceAuthorityAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
    )
    (
        assurance_evidence_signing_key,
        nonce_authority_assurance_evidence_key_spki_sha256,
    ) = _load_ed25519_spki_der(
        assurance_evidence_key_encoded,
        label="public evidence nonce-authority assurance-evidence signing key",
    )
    nonce_authority_verifier_state_store_identity_sha256 = (
        _require_digest(
            immutable_config_document.get(
                "nonceAuthorityVerifierStateStoreIdentitySha256"
            ),
            "public evidence nonce-authority verifier-state store identity",
        )
    )
    nonce_authority_verifier_state_store_administrative_domain_sha256 = (
        _require_digest(
            immutable_config_document.get(
                "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256"
            ),
            "public evidence nonce-authority verifier-state administrative domain",
        )
    )
    verifier_state_store_attestation_key_encoded = (
        immutable_config_document.get(
            "nonceAuthorityVerifierStateStoreAttestationPublicKeySpkiDerBase64url"
        )
    )
    (
        _verifier_state_store_attestation_key,
        nonce_authority_verifier_state_store_attestation_key_spki_sha256,
    ) = _load_ed25519_spki_der(
        verifier_state_store_attestation_key_encoded,
        label="public evidence verifier-state store attestation key",
    )
    nonce_authority_verifier_state_store_assurance_evidence_sha256 = (
        _require_digest(
            immutable_config_document.get(
                "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256"
            ),
            "public evidence verifier-state store assurance evidence",
        )
    )
    if (
        nonce_authority_assurance.get("productionEligible") is not True
    ):
        raise AttestationContractError(
            "public evidence production requires complete production assurance"
        )
    nonce_authority_verifier_state_store_configuration_sha256 = (
        _require_digest(
            immutable_config_document.get(
                "nonceAuthorityVerifierStateStoreConfigurationSha256"
            ),
            "public evidence verifier-state store configuration",
        )
    )
    nonce_authority_verifier_state_store_credential_identity_sha256 = (
        _require_digest(
            immutable_config_document.get(
                "nonceAuthorityVerifierStateStoreCredentialIdentitySha256"
            ),
            "public evidence verifier-state store credential identity",
        )
    )
    nonce_authority_verifier_state_store_minimum_generation = (
        _require_positive_generation(
            immutable_config_document.get(
                "nonceAuthorityVerifierStateStoreMinimumGeneration"
            ),
            "public evidence verifier-state store minimum generation",
        )
    )
    nonce_authority_verifier_state_store_minimum_commit_index = (
        _require_positive_generation(
            immutable_config_document.get(
                "nonceAuthorityVerifierStateStoreMinimumCommitIndex"
            ),
            "public evidence verifier-state store minimum commit index",
        )
    )
    nonce_authority_verifier_state_store_rollback_mechanism = (
        immutable_config_document.get(
            "nonceAuthorityVerifierStateStoreRollbackMechanism"
        )
    )
    if (
        not isinstance(
            nonce_authority_verifier_state_store_rollback_mechanism,
            str,
        )
        or not 1
        <= len(
            nonce_authority_verifier_state_store_rollback_mechanism
        )
        <= 256
    ):
        raise AttestationContractError(
            "public evidence verifier-state store rollback mechanism is invalid"
        )
    for field in (
        "nonceAuthorityVerifierStateStoreAssuranceIssuerAdministrativeDomainSha256",
        "nonceAuthorityVerifierStateStoreAssuranceIssuerCredentialIdentitySha256",
        "nonceAuthorityVerifierStateStoreAssuranceIssuerIdentitySha256",
    ):
        _require_digest(
            immutable_config_document.get(field),
            f"public evidence {field}",
        )
    if (
        nonce_authority_verifier_state_store_identity_sha256
        == nonce_authority_assurance.get("authorityIdentitySha256")
        or nonce_authority_verifier_state_store_administrative_domain_sha256
        == nonce_authority_assurance.get(
            "administrativeDomainSha256"
        )
    ):
        raise AttestationContractError(
            "public evidence verifier-state store is not independent from the nonce authority"
        )
    config_verifier_state_service = _require_exact_fields(
        immutable_config_document.get(
            "nonceAuthorityVerifierStateService"
        ),
        {
            "abortPath",
            "apiVersion",
            "attachNonceStatusPath",
            "clientCertificateSpkiSha256",
            "commitPath",
            "concurrencyLimit",
            "endpoint",
            "markConsumptionPath",
            "maxResponseBytes",
            "issueChallengePath",
            "preparePath",
            "readPath",
            "recoverPath",
            "recoverChallengePath",
            "recoveryLookupPath",
            "serverLeafSpkiSha256",
            "serviceConfigurationSha256",
            "timeoutMilliseconds",
        },
        "public evidence immutable verifier-state service",
    )
    expected_config_verifier_state_service = {
        "abortPath": "/v1/state/abort",
        "apiVersion": PUBLIC_EVIDENCE_VERIFIER_STATE_CLIENT_VERSION,
        "attachNonceStatusPath": "/v1/state/attach-nonce-status",
        "clientCertificateSpkiSha256":
        verifier_state_service_client_certificate_spki_sha256,
        "commitPath": "/v1/state/commit",
        "concurrencyLimit":
        verifier_state_service_concurrency_limit,
        "endpoint": endpoint,
        "maxResponseBytes":
        verifier_state_service_max_response_bytes,
        "issueChallengePath": "/v1/state/issue-challenge",
        "markConsumptionPath": "/v1/state/mark-consumption",
        "preparePath": "/v1/state/prepare",
        "readPath": "/v1/state/read",
        "recoverPath": "/v1/state/recover",
        "recoverChallengePath": "/v1/state/recover-challenge",
        "recoveryLookupPath": "/v1/state/recovery-lookup",
        "serverLeafSpkiSha256":
        verifier_state_service_server_leaf_spki_sha256,
        "serviceConfigurationSha256":
        verifier_state_service_configuration_sha256,
        "timeoutMilliseconds":
        verifier_state_service_timeout_milliseconds,
    }
    if dict(config_verifier_state_service) != (
        expected_config_verifier_state_service
    ):
        raise AttestationContractError(
            "public evidence verifier-state service crossed the immutable configuration"
        )
    nonce_authority_assurance_evidence = (
        _validate_public_evidence_assurance_evidence(
            immutable_config_document.get(
                "nonceAuthorityAssuranceEvidence"
            ),
            assurance=nonce_authority_assurance,
            signing_key=assurance_evidence_signing_key,
            signing_key_id=(
                nonce_authority_assurance_evidence_key_spki_sha256
            ),
            nonce_store_key_id=nonce_store_key_spki_sha256,
            verifier_state_key_id=(
                nonce_authority_verifier_state_key_spki_sha256
            ),
            verifier_state_store_identity_sha256=(
                nonce_authority_verifier_state_store_identity_sha256
            ),
            verifier_state_store_administrative_domain_sha256=(
                nonce_authority_verifier_state_store_administrative_domain_sha256
            ),
            now=int(time.time()),
        )
    )
    store_and_role_assurance = (
        _validate_public_evidence_store_and_role_assurance(
            immutable_config_document,
            assurance=nonce_authority_assurance,
            nonce_store_key_id=nonce_store_key_spki_sha256,
            verifier_state_key_id=(
                nonce_authority_verifier_state_key_spki_sha256
            ),
            store_attestation_key_id=(
                nonce_authority_verifier_state_store_attestation_key_spki_sha256
            ),
            service=config_verifier_state_service,
            now=int(time.time()),
        )
    )
    verifier_state_external_pins = (
        (
            nonce_authority_assurance_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_NONCE_AUTHORITY_ASSURANCE_SHA256",
                "public evidence nonce-authority assurance",
            ),
            "nonce-authority assurance",
        ),
        (
            nonce_authority_assurance_evidence_key_spki_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_NONCE_ASSURANCE_EVIDENCE_KEY_SPKI_SHA256",
                "public evidence nonce assurance-evidence key",
            ),
            "nonce assurance-evidence key",
        ),
        (
            nonce_authority_verifier_state_key_spki_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_VERIFIER_STATE_KEY_SPKI_SHA256",
                "public evidence verifier-state signing key",
            ),
            "verifier-state signing key",
        ),
        (
            nonce_authority_verifier_state_store_identity_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_VERIFIER_STATE_STORE_IDENTITY_SHA256",
                "public evidence verifier-state store identity",
            ),
            "verifier-state store identity",
        ),
        (
            nonce_authority_verifier_state_store_administrative_domain_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_VERIFIER_STATE_ADMIN_DOMAIN_SHA256",
                "public evidence verifier-state administrative domain",
            ),
            "verifier-state administrative domain",
        ),
        (
            nonce_authority_verifier_state_store_attestation_key_spki_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_VERIFIER_STATE_STORE_ATTESTATION_KEY_SPKI_SHA256",
                "public evidence verifier-state store attestation key",
            ),
            "verifier-state store attestation key",
        ),
        (
            nonce_authority_verifier_state_store_configuration_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_VERIFIER_STATE_STORE_CONFIG_SHA256",
                "public evidence verifier-state store configuration",
            ),
            "verifier-state store configuration",
        ),
        (
            store_and_role_assurance["storeEvidenceKeyId"],
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_VERIFIER_STATE_STORE_ASSURANCE_ISSUER_KEY_SPKI_SHA256",
                "public evidence store-assurance issuer key",
            ),
            "store-assurance issuer key",
        ),
        (
            store_and_role_assurance["roleEvidenceSha256"],
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_VERIFIER_STATE_ROLE_SEPARATION_EVIDENCE_SHA256",
                "public evidence role-separation evidence",
            ),
            "role-separation evidence",
        ),
        (
            store_and_role_assurance["roleEvidenceKeyId"],
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_VERIFIER_STATE_ROLE_SEPARATION_ISSUER_KEY_SPKI_SHA256",
                "public evidence role-separation issuer key",
            ),
            "role-separation issuer key",
        ),
        (
            verifier_state_service_configuration_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_VERIFIER_STATE_SERVICE_CONFIG_SHA256",
                "public evidence verifier-state service configuration",
            ),
            "verifier-state service configuration",
        ),
        (
            verifier_state_service_server_leaf_spki_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_VERIFIER_STATE_SERVER_SPKI_SHA256",
                "public evidence verifier-state server SPKI",
            ),
            "verifier-state server SPKI",
        ),
        (
            verifier_state_service_client_certificate_spki_sha256,
            _required_public_pin(
                "SERVERWARE_PUBLIC_ATTESTATION_VERIFIER_STATE_CLIENT_SPKI_SHA256",
                "public evidence verifier-state client SPKI",
            ),
            "verifier-state client SPKI",
        ),
    )
    for actual, expected, label in verifier_state_external_pins:
        if not hmac.compare_digest(actual, expected):
            raise AttestationContractError(
                f"public evidence {label} differs from its external pin"
            )
    expected_store_assurance_evidence_sha256 = _required_public_pin(
        "SERVERWARE_PUBLIC_ATTESTATION_VERIFIER_STATE_STORE_ASSURANCE_EVIDENCE_SHA256",
        "public evidence verifier-state store assurance evidence",
    )
    if not hmac.compare_digest(
        nonce_authority_verifier_state_store_assurance_evidence_sha256,
        expected_store_assurance_evidence_sha256,
    ):
        raise AttestationContractError(
            "public evidence verifier-state store assurance evidence differs from its external pin"
        )
    try:
        from scripts import verify_nitro_tee as public_verifier

        release_identity = public_verifier.validate_release_identity(
            immutable_config_document.get("releaseIdentity"),
            label="pinned public release identity",
        )
        release_identity_sha256 = public_verifier.sha256_json(
            release_identity
        )
    except (
        ImportError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AttestationContractError(
            "public evidence immutable release identity is invalid"
        ) from exc
    if (
        immutable_config_document.get("releaseIdentitySha256")
        != release_identity_sha256
        or immutable_config_document.get(
            "sandboxDescriptorSha256"
        )
        != sandbox_descriptor_sha256
        or release_identity["configuration"]["trustRootBundleSha256"]
        != trust_roots_sha256
    ):
        raise AttestationContractError(
            "public evidence immutable release identity crossed its configured roots"
        )
    producer_policy = _require_exact_fields(
        immutable_config_document.get("producerPolicy"),
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
        },
        "public evidence immutable producer policy",
    )
    expected_producer_policy = {
        "nonceStoreIdentitySha256": nonce_store_identity_sha256,
        "nonceStoreKeySpkiSha256": nonce_store_key_spki_sha256,
        "producerDescriptorSha256": descriptor_sha256,
        "producerExecutableSha256": executable_sha256,
        "producerRequestSchemaSha256":
        producer_request_schema_sha256,
        "sandboxDescriptorSha256": sandbox_descriptor_sha256,
        "sandboxLauncherSha256": sandbox_launcher_sha256,
        "witnessStoreIdentitySha256":
        witness_store_identity_sha256,
        "witnessStoreKeySpkiSha256":
        witness_store_key_spki_sha256,
    }
    if (
        dict(producer_policy) != expected_producer_policy
        or release_identity["configuration"]["publicAttestation"]
        != expected_producer_policy
    ):
        raise AttestationContractError(
            "public evidence producer policy crossed the stable release identity"
        )
    tls_scope_key_encoded = immutable_config_document.get(
        "tlsScopeSigningPublicKeySpkiDerBase64url"
    )
    _, tls_scope_key_id = _load_ed25519_spki_der(
        tls_scope_key_encoded,
        label="public evidence TLS scope signing key",
    )
    if (
        tls_scope_key_id
        != release_identity["configuration"][
            "tlsScopeSigningKeySpkiSha256"
        ]
    ):
        raise AttestationContractError(
            "public evidence TLS scope signing key crossed the stable release identity"
        )
    witness_store_key_encoded = immutable_config_document.get(
        "witnessStoreSigningPublicKeySpkiDerBase64url"
    )
    _, witness_store_key_id = _load_ed25519_spki_der(
        witness_store_key_encoded,
        label="public evidence witness-store signing key",
    )
    if witness_store_key_id != witness_store_key_spki_sha256:
        raise AttestationContractError(
            "public evidence witness-store key crossed the stable release identity"
        )
    nonce_store_key_encoded = immutable_config_document.get(
        "nonceStoreSigningPublicKeySpkiDerBase64url"
    )
    _, nonce_store_key_id = _load_ed25519_spki_der(
        nonce_store_key_encoded,
        label="public evidence nonce-store signing key",
    )
    if nonce_store_key_id != nonce_store_key_spki_sha256:
        raise AttestationContractError(
            "public evidence nonce-store key crossed the stable release identity"
        )
    role_resources = _require_exact_fields(
        descriptor.get("sandboxResources"),
        {
            "measurementCopies",
            "mountSources",
            "producerStreams",
            "rootPath",
            "sealedFiles",
            "seccompProfilePath",
        },
        "public evidence sandbox resources for role validation",
    )
    role_sealed_files = dict(
        _require_canonical_role_paths(
            role_resources.get("sealedFiles"),
            label="public evidence role-validation sealed files",
            maximum=16,
        )
    )
    trust_roots_path_value = role_sealed_files.get("trustRoots")
    if trust_roots_path_value is None:
        raise AttestationContractError(
            "public evidence trust roots are absent from the sealed role resources"
        )
    trust_roots_role_bytes = _read_stable_root_owned_file(
        Path(trust_roots_path_value),
        label="public evidence trust-root role registry",
        maximum=256 * 1024,
    )
    if not hmac.compare_digest(
        sha256_prefixed(trust_roots_role_bytes),
        trust_roots_sha256,
    ):
        raise AttestationContractError(
            "public evidence trust-root role registry crossed its descriptor pin"
        )
    trust_roots_role_document = _strict_json_document(
        trust_roots_role_bytes,
        label="public evidence trust-root role registry",
    )
    if (
        trust_roots_role_bytes
        != canonical_json(trust_roots_role_document).encode("ascii")
        + b"\n"
    ):
        raise AttestationContractError(
            "public evidence trust-root role registry is not canonical JSON plus LF"
        )
    try:
        from scripts import verify_nitro_tee as public_verifier

        trust_root_role_ids = public_verifier.load_trust_roots(
            trust_roots_role_document,
            trust_roots_role_bytes,
            independently_expected_sha256=trust_roots_sha256,
        )["keyIds"]
    except (
        ImportError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AttestationContractError(
            "public evidence trust-root role registry is invalid"
        ) from exc
    global_role_key_spki_sha256s = {
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
            f"trustRoot:{name}": trust_root_role_ids[name]
            for name in sorted(trust_root_role_ids)
            if name not in {"completion", "witness"}
        },
    }
    _validate_global_attestation_key_role_separation(
        global_role_key_spki_sha256s
    )
    sandbox_descriptor_path = Path(sandbox_descriptor_path_value)
    sandbox_descriptor_bytes = _read_stable_root_owned_file(
        sandbox_descriptor_path,
        label="public evidence sandbox descriptor",
        maximum=64 * 1024,
    )
    if not hmac.compare_digest(
        sha256_prefixed(sandbox_descriptor_bytes),
        sandbox_descriptor_sha256,
    ):
        raise AttestationContractError(
            "public evidence sandbox descriptor digest is invalid"
        )
    sandbox_document = _strict_json_document(
        sandbox_descriptor_bytes,
        label="public evidence sandbox descriptor",
    )
    if (
        sandbox_descriptor_bytes
        != canonical_json(sandbox_document).encode("ascii") + b"\n"
    ):
        raise AttestationContractError(
            "public evidence sandbox descriptor is not canonical JSON plus LF"
        )
    sandbox = _require_exact_fields(
        sandbox_document,
        {
            "apiVersion",
            "capabilities",
            "cgroup",
            "executionMode",
            "executable",
            "fdPolicy",
            "identity",
            "monitoring",
            "namespaces",
            "network",
            "noNewPrivileges",
            "process",
            "productionClaim",
            "rootFilesystem",
            "seccomp",
            "trustBoundary",
        },
        "public evidence sandbox descriptor",
    )
    cgroup = _require_exact_fields(
        sandbox.get("cgroup"),
        {
            "disposable",
            "fdRole",
            "identity",
            "killMode",
            "limits",
            "ancestorProtection",
            "membershipPath",
            "migrationProtection",
            "path",
            "requireEmptyBeforeLaunch",
            "requireEmptyOnExit",
            "requiredControllers",
        },
        "public evidence sandbox cgroup",
    )
    network = _require_exact_fields(
        sandbox.get("network"),
        {
            "allowedAddressFamilies",
            "denyNewNetworkSockets",
            "loopback",
            "mode",
        },
        "public evidence sandbox network policy",
    )
    capabilities = _require_exact_fields(
        sandbox.get("capabilities"),
        {
            "ambient",
            "bounding",
            "effective",
            "inheritable",
            "permitted",
        },
        "public evidence sandbox capabilities",
    )
    root_filesystem = _require_exact_fields(
        sandbox.get("rootFilesystem"),
        {
            "bindMounts",
            "emptyTmpfs",
            "maxBytes",
            "nodev",
            "noexec",
            "nosuid",
            "path",
            "readOnlyAfterSetup",
            "rootDirectoryFdRole",
            "rootDirectoryIdentity",
        },
        "public evidence sandbox root filesystem",
    )
    seccomp = _require_exact_fields(
        sandbox.get("seccomp"),
        {
            "architecture",
            "auditArchitecture",
            "bootstrapProfile",
            "contract",
            "defaultAction",
            "format",
            "kernelAbi",
            "runtimeProfile",
            "transition",
            "unknownSyscallAction",
        },
        "public evidence sandbox seccomp policy",
    )
    sandbox_process = _require_exact_fields(
        sandbox.get("process"),
        {
            "absoluteCommandDeadline",
            "launcherIsSessionLeader",
            "namespaceInitIsProducer",
            "ownerLivenessFdRole",
            "ownerLivenessTransport",
            "parentDeathSignal",
            "parentDeathSignalScope",
            "producerIsProcessGroupLeader",
            "producerStartsNewSession",
            "reapEntireTreeBeforeExit",
        },
        "public evidence sandbox process policy",
    )
    sandbox_monitoring = _require_exact_fields(
        sandbox.get("monitoring"),
        {
            "commandDeadlineMilliseconds",
            "killAndReapTimeoutMilliseconds",
            "limitMutationWatch",
            "membershipPollMilliseconds",
            "startupTimeoutMilliseconds",
        },
        "public evidence sandbox monitoring policy",
    )
    trust_boundary = _require_exact_fields(
        sandbox.get("trustBoundary"),
        {
            "claim",
            "hostKernelTrusted",
            "hostRootTrusted",
            "hostileHostProof",
            "launcherStaticElfRequired",
        },
        "public evidence sandbox trust boundary",
    )
    fd_policy = _require_exact_fields(
        sandbox.get("fdPolicy"),
        {
            "closeAllOthers",
            "immutableConfig",
            "namedProducerFds",
            "stderr",
            "stdin",
            "stdout",
        },
        "public evidence sandbox FD policy",
    )
    sandbox_executable = _require_exact_fields(
        sandbox.get("executable"),
        {
            "architecture",
            "command",
            "executionSource",
            "executableSha256",
            "format",
            "postExecEnforcement",
            "requireSealed",
            "sourceFdRole",
            "static",
        },
        "public evidence sandbox executable policy",
    )
    post_exec_enforcement = _require_exact_fields(
        sandbox_executable.get("postExecEnforcement"),
        {
            "entryStubSha256",
            "entryStubMeasured",
            "mechanism",
            "requiredBeforeApplicationCode",
            "runtimeProfileSha256",
        },
        "public evidence producer post-exec enforcement",
    )
    architecture = seccomp.get("architecture")
    if architecture not in _PUBLIC_EVIDENCE_KERNEL_ABIS:
        raise AttestationContractError(
            "public evidence seccomp architecture is unsupported"
        )
    kernel_abi_contract = _PUBLIC_EVIDENCE_KERNEL_ABIS[str(architecture)]
    kernel_abi = _require_exact_fields(
        seccomp.get("kernelAbi"),
        {
            "endianness",
            "syscallTableId",
            "syscallTableSha256",
            "wordBits",
        },
        "public evidence seccomp kernel ABI",
    )
    bootstrap_profile = _require_exact_fields(
        seccomp.get("bootstrapProfile"),
        {
            "allowedSyscalls",
            "instructionCount",
            "profileFdRole",
            "profileId",
            "profileSha256",
        },
        "public evidence bootstrap seccomp profile",
    )
    runtime_profile = _require_exact_fields(
        seccomp.get("runtimeProfile"),
        {
            "allowedSyscalls",
            "embeddedInStaticProducer",
            "profileId",
            "profileSha256",
        },
        "public evidence runtime seccomp profile",
    )
    transition = _require_exact_fields(
        seccomp.get("transition"),
        {
            "execFlags",
            "execSyscall",
            "executableFd",
            "externalEnforcementPrerequisite",
            "method",
            "requiredSeccompFilterCount",
        },
        "public evidence seccomp transition",
    )
    sandbox_seccomp_profile_id = bootstrap_profile.get("profileId")
    entry_stub_sha256 = _require_digest(
        post_exec_enforcement.get("entryStubSha256"),
        "public evidence producer entry stub",
    )
    runtime_profile_sha256 = _require_digest(
        runtime_profile.get("profileSha256"),
        "public evidence runtime seccomp profile",
    )
    if runtime_profile_sha256 != sha256_prefixed(
        _public_evidence_closed_seccomp_profile_bytes(
            str(architecture),
            syscall_names=_PUBLIC_EVIDENCE_RUNTIME_SYSCALLS,
        )
    ):
        raise AttestationContractError(
            "public evidence runtime seccomp digest is not the fixed profile"
        )
    if (
        seccomp.get("contract") != "serverware.closedSeccompProfile/v1"
        or seccomp.get("format") != "linux-cbpf-sock-filter-le-v1"
        or seccomp.get("auditArchitecture")
        != kernel_abi_contract["auditArchitecture"]
        or seccomp.get("defaultAction") != "kill-process"
        or seccomp.get("unknownSyscallAction") != "kill-process"
        or kernel_abi
        != {
            "endianness": "little",
            "syscallTableId": kernel_abi_contract["syscallTableId"],
            "syscallTableSha256": kernel_abi_contract[
                "syscallTableSha256"
            ],
            "wordBits": 64,
        }
        or sandbox_seccomp_profile_id
        != f"serverware-producer-bootstrap-{architecture}-v1"
        or bootstrap_profile.get("profileFdRole") != "seccompProfile"
        or bootstrap_profile.get("allowedSyscalls")
        != list(_PUBLIC_EVIDENCE_BOOTSTRAP_SYSCALLS)
        or runtime_profile.get("profileId")
        != f"serverware-producer-runtime-{architecture}-v1"
        or runtime_profile.get("allowedSyscalls")
        != list(_PUBLIC_EVIDENCE_RUNTIME_SYSCALLS)
        or runtime_profile.get("embeddedInStaticProducer") is not True
        or transition
        != {
            "execFlags": ["AT_EMPTY_PATH"],
            "execSyscall": "execveat",
            "executableFd": _PUBLIC_EVIDENCE_FIXED_EXECUTABLE_FD,
            "externalEnforcementPrerequisite":
            _PUBLIC_EVIDENCE_POST_EXEC_PREREQUISITE,
            "method": "measured-static-entrypoint-additive-filter",
            "requiredSeccompFilterCount": 2,
        }
        or post_exec_enforcement
        != {
            "entryStubSha256": entry_stub_sha256,
            "entryStubMeasured": True,
            "mechanism": "measured-static-entry-stub-additive-seccomp",
            "requiredBeforeApplicationCode": True,
            "runtimeProfileSha256": runtime_profile_sha256,
        }
    ):
        raise AttestationContractError(
            "public evidence seccomp contract is not the fixed kernel-ABI profile"
        )
    resources = _require_exact_fields(
        descriptor.get("sandboxResources"),
        {
            "measurementCopies",
            "mountSources",
            "producerStreams",
            "rootPath",
            "sealedFiles",
            "seccompProfilePath",
        },
        "public evidence sandbox resources",
    )
    sandbox_root_path = Path(
        _require_normalized_absolute_path_text(
            resources.get("rootPath"),
            "public evidence sandbox root",
        )
    )
    sandbox_seccomp_profile_path = Path(
        _require_normalized_absolute_path_text(
            resources.get("seccompProfilePath"),
            "public evidence sandbox seccomp profile",
        )
    )
    sandbox_mount_sources = _require_canonical_role_paths(
        resources.get("mountSources"),
        label="public evidence sandbox mount sources",
        maximum=32,
    )
    sandbox_sealed_files = _require_canonical_role_paths(
        resources.get("sealedFiles"),
        label="public evidence sandbox sealed files",
        maximum=16,
    )
    raw_measurement_copies = resources.get("measurementCopies")
    if (
        not isinstance(raw_measurement_copies, list)
        or len(raw_measurement_copies) > 2
    ):
        raise AttestationContractError(
            "public evidence sandbox measurement-copy resources exceed their bound"
        )
    measurement_copies: list[tuple[str, str]] = []
    for index, item in enumerate(raw_measurement_copies):
        entry = _require_exact_fields(
            item,
            {"measurementOf", "role"},
            f"public evidence sandbox measurement copy {index}",
        )
        role = entry.get("role")
        measurement_of = entry.get("measurementOf")
        if (
            not isinstance(role, str)
            or _IDENTIFIER_RE.fullmatch(role) is None
            or measurement_of
            not in {"producerExecutable", "sandboxDescriptor"}
        ):
            raise AttestationContractError(
                "public evidence sandbox measurement-copy resource is invalid"
            )
        measurement_copies.append((role, str(measurement_of)))
    if (
        [role for role, _ in measurement_copies]
        != sorted({role for role, _ in measurement_copies})
        or len({source for _, source in measurement_copies})
        != len(measurement_copies)
    ):
        raise AttestationContractError(
            "public evidence sandbox measurement-copy resources are not canonical and unique"
        )
    sandbox_measurement_copies = tuple(measurement_copies)
    sandbox_producer_stream_roles = _require_canonical_roles(
        resources.get("producerStreams"),
        label="public evidence sandbox producer streams",
        maximum=16,
    )
    if (
        nonce_request_role not in sandbox_producer_stream_roles
        or nonce_response_role not in sandbox_producer_stream_roles
    ):
        raise AttestationContractError(
            "public evidence producer omits the signed nonce-service channels"
        )
    retained_stream_roles = sandbox_producer_stream_roles
    retained_stream_fds = dict(
        _retained_public_evidence_stream_fds(
            retained_stream_roles
        )
    )
    sandbox_producer_streams = tuple(
        (role, retained_stream_fds[role])
        for role in sandbox_producer_stream_roles
    )
    nonce_service_request_fd = retained_stream_fds[
        nonce_request_role
    ]
    nonce_service_response_fd = retained_stream_fds[
        nonce_response_role
    ]
    bind_mounts = root_filesystem.get("bindMounts")
    named_producer_fds = fd_policy.get("namedProducerFds")
    if not isinstance(bind_mounts, list) or not isinstance(
        named_producer_fds, list
    ):
        raise AttestationContractError(
            "public evidence sandbox FD and mount allowlists are invalid"
        )
    expected_mount_roles = [
        item.get("sourceFdRole")
        for item in bind_mounts
        if isinstance(item, dict)
    ]
    expected_sealed_roles = [
        item.get("role")
        for item in named_producer_fds
        if isinstance(item, dict)
        and item.get("kind")
        in {
            "sealed-regular-file",
            "sealed-release-bound-file",
        }
    ]
    expected_stream_roles = [
        item.get("role")
        for item in named_producer_fds
        if isinstance(item, dict)
        and item.get("kind") == "connected-unix-service"
    ]
    expected_measurement_copies = {
        item.get("role"): item.get("measurementOf")
        for item in named_producer_fds
        if isinstance(item, dict)
        and item.get("kind") == "sealed-measurement-copy"
    }
    sandbox_seccomp_profile_sha256 = _require_digest(
        bootstrap_profile.get("profileSha256"),
        "public evidence sandbox seccomp profile",
    )
    if sandbox_seccomp_profile_sha256 != sha256_prefixed(
        _public_evidence_closed_seccomp_profile_bytes(
            str(architecture),
            syscall_names=_PUBLIC_EVIDENCE_BOOTSTRAP_SYSCALLS,
        )
    ):
        raise AttestationContractError(
            "public evidence bootstrap seccomp digest is not the fixed profile"
        )
    sealed_rule_details: dict[str, tuple[str | None, int]] = {}
    for index, item in enumerate(named_producer_fds):
        if (
            not isinstance(item, dict)
            or item.get("kind")
            not in {
                "sealed-regular-file",
                "sealed-release-bound-file",
            }
        ):
            continue
        role = item.get("role")
        expected_sha256 = (
            _require_digest(
                item.get("expectedSha256"),
                f"public evidence sealed producer FD {index}",
            )
            if item.get("kind") == "sealed-regular-file"
            else None
        )
        maximum = _require_positive_generation(
            item.get("maxBytes"),
            f"public evidence sealed producer FD {index} bound",
        )
        if (
            not isinstance(role, str)
            or _IDENTIFIER_RE.fullmatch(role) is None
            or maximum > _MAX_PUBLIC_BUNDLE_BYTES
            or role in sealed_rule_details
        ):
            raise AttestationContractError(
                "public evidence sealed producer FD policy is invalid"
            )
        sealed_rule_details[role] = (expected_sha256, maximum)
    if {role for role, _ in sandbox_sealed_files} != set(
        sealed_rule_details
    ):
        raise AttestationContractError(
            "public evidence sealed-file resources differ from the sandbox FD allowlist"
        )
    measured_sealed_files = tuple(
        (
            role,
            path,
            (
                stable_statement_sha256
                if role == "stableReleaseStatement"
                else sealed_rule_details[role][0]
            ),
            sealed_rule_details[role][1],
        )
        for role, path in sandbox_sealed_files
    )
    expected_named_roles = {
        "nonceRequest",
        "nonceResponse",
        "producerDescriptor",
        "producerEphemeralSeed",
        "producerExecutableMeasurement",
        "producerRequestSchema",
        "sandboxDescriptorMeasurement",
        "sandboxLauncher",
        "stableReleaseStatement",
        "trustRoots",
        "witnessRequest",
        "witnessResponse",
    }
    actual_named_roles = {
        item.get("role")
        for item in named_producer_fds
        if isinstance(item, dict)
    }
    if (
        len(named_producer_fds) != len(expected_named_roles)
        or actual_named_roles != expected_named_roles
        or [
            item.get("role")
            for item in named_producer_fds
            if isinstance(item, dict)
            and item.get("kind") == "sealed-ephemeral-secret"
        ]
        != ["producerEphemeralSeed"]
    ):
        raise AttestationContractError(
            "public evidence sandbox named FD contract is incomplete"
        )
    nonce_service_rules = {
        item.get("role"): item
        for item in named_producer_fds
        if isinstance(item, dict)
        and item.get("role") in {"nonceRequest", "nonceResponse"}
    }
    expected_challenge = {
        "apiVersion":
        "serverware.publicAttestationServiceChannelChallenge/v1",
        "challengeBytes": 32,
        "required": True,
    }
    for role, direction in (
        ("nonceRequest", "producer-to-service"),
        ("nonceResponse", "service-to-producer"),
    ):
        rule = _require_exact_fields(
            nonce_service_rules.get(role),
            {
                "access",
                "direction",
                "endpointCustodyClaim",
                "kind",
                "messageCredentials",
                "peerCgroupPath",
                "peerCgroupAncestorClosureSha256",
                "peerCgroupMigrationEnforcement",
                "peerExecutableMapClosureSha256",
                "peerExecutableSha256",
                "peerGid",
                "peerPostExecEnforcementProfileSha256",
                "peerRequiredSeccompFilterCount",
                "peerStaticElf",
                "peerUid",
                "protocol",
                "protocolChallenge",
                "rejectAncillaryFds",
                "rejectUnknownControlMessages",
                "role",
                "socketType",
                "targetFd",
            },
            f"public evidence {role} sandbox rule",
        )
        if (
            rule.get("access") != "read-write"
            or rule.get("direction") != direction
            or rule.get("kind") != "connected-unix-service"
            or rule.get("peerCgroupPath")
            != nonce_expected_peer_cgroup_path
            or rule.get("peerExecutableSha256")
            != nonce_expected_peer_executable_sha256
            or rule.get("peerGid") != nonce_expected_peer_gid
            or rule.get("peerUid") != nonce_expected_peer_uid
            or rule.get("protocol")
            != "serverware.attestationNonceService/v2"
            or rule.get("protocolChallenge") != expected_challenge
            or rule.get("role") != role
            or rule.get("socketType") != "SOCK_SEQPACKET"
            or rule.get("messageCredentials")
            != "SCM_CREDENTIALS-every-frame"
            or rule.get("rejectAncillaryFds") is not True
            or rule.get("rejectUnknownControlMessages") is not True
            or rule.get("endpointCustodyClaim")
            != "sender-authenticated-not-exclusive"
            or rule.get("peerStaticElf") is not True
            or rule.get("peerRequiredSeccompFilterCount") != 2
            or rule.get("peerCgroupMigrationEnforcement")
            != "nonroot-empty-caps-private-cgroupns-no-writable-cgroupfs-no-cgroup-fds-v1"
        ):
            raise AttestationContractError(
                f"public evidence {role} differs from the signed nonce-service contract"
            )
    nonce_request_rule = nonce_service_rules["nonceRequest"]
    nonce_response_rule = nonce_service_rules["nonceResponse"]
    nonce_expected_peer_executable_map_closure_sha256 = _require_digest(
        nonce_request_rule.get("peerExecutableMapClosureSha256"),
        "public evidence nonce-service executable-map closure",
    )
    nonce_expected_peer_cgroup_ancestor_closure_sha256 = _require_digest(
        nonce_request_rule.get("peerCgroupAncestorClosureSha256"),
        "public evidence nonce-service cgroup ancestor closure",
    )
    nonce_expected_peer_post_exec_profile_sha256 = _require_digest(
        nonce_request_rule.get("peerPostExecEnforcementProfileSha256"),
        "public evidence nonce-service post-exec profile",
    )
    if (
        nonce_response_rule.get("peerExecutableMapClosureSha256")
        != nonce_expected_peer_executable_map_closure_sha256
        or nonce_response_rule.get("peerCgroupAncestorClosureSha256")
        != nonce_expected_peer_cgroup_ancestor_closure_sha256
        or nonce_response_rule.get("peerPostExecEnforcementProfileSha256")
        != nonce_expected_peer_post_exec_profile_sha256
        or not isinstance(nonce_expected_peer_uid, int)
        or nonce_expected_peer_uid < 1
        or not isinstance(nonce_expected_peer_gid, int)
        or nonce_expected_peer_gid < 1
    ):
        raise AttestationContractError(
            "public evidence nonce-service closures are inconsistent"
        )
    sandbox_cgroup_path_value = cgroup.get("path")
    production_mode = sandbox.get("executionMode") == "production"
    if (
        sandbox.get("apiVersion") != PUBLIC_EVIDENCE_SANDBOX_VERSION
        or sandbox.get("noNewPrivileges") is not True
        or cgroup.get("disposable") is not True
        or cgroup.get("requireEmptyBeforeLaunch") is not True
        or cgroup.get("requireEmptyOnExit") is not True
        or cgroup.get("killMode")
        != "pid-namespace-init-plus-cgroup.kill"
        or cgroup.get("ancestorProtection")
        != "root-owned-nondelegated-no-acl-v1"
        or cgroup.get("migrationProtection")
        != "nonroot-no-cgroup-fds-no-writable-cgroupfs-v1"
        or network.get("mode") != "none"
        or network.get("loopback") != "down"
        or network.get("denyNewNetworkSockets") is not True
        or network.get("allowedAddressFamilies") != ["AF_UNIX"]
        or any(value != [] for value in capabilities.values())
        or root_filesystem.get("path")
        != os.fspath(sandbox_root_path)
        or sandbox_executable.get("executableSha256")
        != executable_sha256
        or sandbox_executable.get("executionSource")
        != "sealed-memfd"
        or sandbox_executable.get("format") != "elf"
        or sandbox_executable.get("architecture") != architecture
        or sandbox_executable.get("static") is not True
        or sandbox_executable.get("requireSealed") is not True
        or sandbox_process
        != {
            "absoluteCommandDeadline": True,
            "launcherIsSessionLeader": True,
            "namespaceInitIsProducer": True,
            "ownerLivenessFdRole": "ownerLiveness",
            "ownerLivenessTransport": "connected-unix-seqpacket-eof",
            "parentDeathSignal": "SIGKILL",
            "parentDeathSignalScope": "direct-producer-child-only",
            "producerIsProcessGroupLeader": True,
            "producerStartsNewSession": True,
            "reapEntireTreeBeforeExit": True,
        }
        or trust_boundary
        != {
            "claim": "measured-process-and-retained-fd-containment-v2",
            "hostKernelTrusted": True,
            "hostRootTrusted": True,
            "hostileHostProof": False,
            "launcherStaticElfRequired": True,
        }
        or sandbox_monitoring.get("limitMutationWatch")
        != "inotify-fail-on-write-attrib-delete-move"
        or type(bootstrap_profile.get("instructionCount")) is not int
        or bootstrap_profile["instructionCount"]
        != 4 + 2 * len(_PUBLIC_EVIDENCE_BOOTSTRAP_SYSCALLS) + 1
        or _require_exact_fields(
            fd_policy.get("immutableConfig"),
            {
                "access",
                "binding",
                "maxBytes",
                "requireSealed",
                "sourceFdRole",
                "targetFd",
            },
            "public evidence sandbox immutable config FD",
        ).get("binding")
        != {
            "configApiVersion": PUBLIC_EVIDENCE_CONFIG_VERSION,
            "releaseIdentityConfigurationField": "configuration",
            "releaseIdentityField": "releaseIdentity",
            "releaseIdentityPublicAttestationField":
            "publicAttestation",
            "releaseIdentitySandboxDescriptorSha256Field":
            "sandboxDescriptorSha256",
            "sandboxDescriptorSha256Field":
            "sandboxDescriptorSha256",
        }
        or {role for role, _ in sandbox_mount_sources}
        != set(expected_mount_roles)
        or {role for role, _ in sandbox_sealed_files}
        != set(expected_sealed_roles)
        or {role for role, _ in sandbox_producer_streams}
        != set(expected_stream_roles)
        or dict(sandbox_measurement_copies)
        != expected_measurement_copies
        or not isinstance(sandbox_cgroup_path_value, str)
    ):
        raise AttestationContractError(
            "public evidence producer requires the closed v2 no-network containment contract"
        )
    if (
        production_mode != (sandbox.get("productionClaim") is True)
        or production_mode
        != (
            nonce_authority_assurance.get("productionEligible")
            is True
        )
        or (
            production_mode
            and nonce_authority_assurance_evidence is None
        )
        or (
            not production_mode
            and (
                sandbox.get("executionMode")
                != "fixture-non-production"
                or sandbox.get("productionClaim") is not False
            )
        )
        or (_production_release() and not production_mode)
    ):
        raise AttestationContractError(
            "public evidence sandbox execution mode cannot support the requested production claim"
        )
    _require_normalized_absolute_path_text(
        sandbox_cgroup_path_value,
        "public evidence sandbox cgroup",
    )
    sandbox_cgroup_path = Path(sandbox_cgroup_path_value)
    if (
        not sandbox_cgroup_path.is_absolute()
        or ".." in sandbox_cgroup_path.parts
        or os.path.normpath(os.fspath(sandbox_cgroup_path))
        != os.fspath(sandbox_cgroup_path)
        or not os.fspath(sandbox_cgroup_path).startswith(
            "/sys/fs/cgroup/"
        )
    ):
        raise AttestationContractError(
            "public evidence sandbox cgroup path is invalid"
        )
    max_input_bytes = _require_positive_generation(
        descriptor.get("maxInputBytes"),
        "public evidence producer input bound",
    )
    max_output_bytes = _require_positive_generation(
        descriptor.get("maxOutputBytes"),
        "public evidence producer output bound",
    )
    timeout_milliseconds = _require_positive_generation(
        descriptor.get("timeoutMilliseconds"),
        "public evidence producer timeout",
    )
    concurrency_limit = _require_positive_generation(
        descriptor.get("concurrencyLimit"),
        "public evidence producer concurrency",
    )
    if (
        not 4096 <= max_input_bytes <= 256 * 1024
        or not 64 * 1024 <= max_output_bytes <= _MAX_PUBLIC_BUNDLE_BYTES
        or not 100 <= timeout_milliseconds <= 30_000
        or concurrency_limit != 1
        or sandbox_monitoring.get("commandDeadlineMilliseconds")
        != timeout_milliseconds
        or type(sandbox_monitoring.get("startupTimeoutMilliseconds")) is not int
        or not 100 <= sandbox_monitoring["startupTimeoutMilliseconds"] <= 10_000
        or type(sandbox_monitoring.get("membershipPollMilliseconds")) is not int
        or not 1 <= sandbox_monitoring["membershipPollMilliseconds"] <= 100
        or type(
            sandbox_monitoring.get("killAndReapTimeoutMilliseconds")
        ) is not int
        or not 100 <= sandbox_monitoring[
            "killAndReapTimeoutMilliseconds"
        ] <= 10_000
    ):
        raise AttestationContractError(
            "public evidence producer bounds are invalid"
        )
    if production_mode:
        raise AttestationContractError(
            "public evidence production is unavailable until the measured "
            "static producer entry stub installs the exact pinned runtime "
            "seccomp profile before application code, every measured static "
            "service peer has its signed post-exec filter identity externally "
            "attested, the measured static launcher brokers every service "
            "frame with SCM_CREDENTIALS while withholding external service "
            "endpoints from the producer, and the supervisor supplies a "
            "private read-only cgroup namespace "
            f"({_PUBLIC_EVIDENCE_POST_EXEC_PREREQUISITE})"
        )
    return PublicEvidenceProducerDescriptor(
        descriptor_sha256=descriptor_sha256,
        executable_path=Path(executable_path_value),
        executable_sha256=executable_sha256,
        immutable_config_bytes=immutable_config,
        immutable_config_sha256=immutable_config_sha256,
        minimum_rollback_continuity_commitment_sha256=(
            minimum_rollback_continuity_commitment_sha256
        ),
        release_identity=release_identity,
        release_identity_sha256=release_identity_sha256,
        tls_scope_signing_public_key_spki_der_base64url=str(
            tls_scope_key_encoded
        ),
        sandbox_launcher_path=Path(sandbox_launcher_path_value),
        sandbox_launcher_sha256=sandbox_launcher_sha256,
        sandbox_descriptor_bytes=sandbox_descriptor_bytes,
        sandbox_descriptor_sha256=sandbox_descriptor_sha256,
        stable_statement_sha256=stable_statement_sha256,
        sandbox_cgroup_path=sandbox_cgroup_path,
        sandbox_root_path=sandbox_root_path,
        sandbox_seccomp_profile_path=
        sandbox_seccomp_profile_path,
        sandbox_seccomp_profile_sha256=
        sandbox_seccomp_profile_sha256,
        sandbox_seccomp_profile_id=str(sandbox_seccomp_profile_id),
        sandbox_mount_sources=sandbox_mount_sources,
        sandbox_sealed_files=measured_sealed_files,
        sandbox_measurement_copies=
        sandbox_measurement_copies,
        sandbox_producer_streams=sandbox_producer_streams,
        sandbox_fixture_mode=not production_mode,
        nonce_store_identity_sha256=nonce_store_identity_sha256,
        nonce_store_key_spki_sha256=
        nonce_store_key_spki_sha256,
        nonce_store_signing_public_key_spki_der_base64url=str(
            nonce_store_key_encoded
        ),
        nonce_service_request_fd=nonce_service_request_fd,
        nonce_service_response_fd=nonce_service_response_fd,
        nonce_service_expected_peer_uid=
        nonce_expected_peer_uid,
        nonce_service_expected_peer_gid=
        nonce_expected_peer_gid,
        nonce_service_expected_peer_executable_sha256=
        nonce_expected_peer_executable_sha256,
        nonce_service_expected_peer_executable_map_closure_sha256=(
            nonce_expected_peer_executable_map_closure_sha256
        ),
        nonce_service_expected_peer_cgroup_ancestor_closure_sha256=(
            nonce_expected_peer_cgroup_ancestor_closure_sha256
        ),
        nonce_service_expected_peer_post_exec_profile_sha256=(
            nonce_expected_peer_post_exec_profile_sha256
        ),
        nonce_service_expected_peer_cgroup_path=
        nonce_expected_peer_cgroup_path,
        nonce_service_max_response_bytes=
        nonce_service_max_response_bytes,
        nonce_service_timeout_milliseconds=
        nonce_service_timeout_milliseconds,
        verifier_state_service_authority=parsed_endpoint.netloc,
        verifier_state_service_host=verifier_state_service_host,
        verifier_state_service_port=verifier_state_service_port,
        verifier_state_service_read_path="/v1/state/read",
        verifier_state_service_issue_challenge_path=(
            "/v1/state/issue-challenge"
        ),
        verifier_state_service_recover_challenge_path=(
            "/v1/state/recover-challenge"
        ),
        verifier_state_service_prepare_path="/v1/state/prepare",
        verifier_state_service_recovery_lookup_path=(
            "/v1/state/recovery-lookup"
        ),
        verifier_state_service_mark_consumption_path=(
            "/v1/state/mark-consumption"
        ),
        verifier_state_service_attach_nonce_status_path=(
            "/v1/state/attach-nonce-status"
        ),
        verifier_state_service_abort_path="/v1/state/abort",
        verifier_state_service_commit_path="/v1/state/commit",
        verifier_state_service_recover_path="/v1/state/recover",
        verifier_state_service_tls_context=(
            verifier_state_service_tls_context
        ),
        verifier_state_service_tls_material_snapshot_sha256=(
            verifier_state_service_tls_material_snapshot_sha256
        ),
        verifier_state_service_client_certificate_spki_sha256=(
            verifier_state_service_client_certificate_spki_sha256
        ),
        verifier_state_service_server_leaf_spki_sha256=(
            verifier_state_service_server_leaf_spki_sha256
        ),
        verifier_state_service_configuration_sha256=(
            verifier_state_service_configuration_sha256
        ),
        verifier_state_service_max_response_bytes=(
            verifier_state_service_max_response_bytes
        ),
        verifier_state_service_timeout_milliseconds=(
            verifier_state_service_timeout_milliseconds
        ),
        verifier_state_service_concurrency_limit=(
            verifier_state_service_concurrency_limit
        ),
        global_role_key_spki_sha256s=tuple(
            global_role_key_spki_sha256s
        ),
        nonce_authority_assurance=nonce_authority_assurance,
        nonce_authority_assurance_sha256=(
            nonce_authority_assurance_sha256
        ),
        nonce_authority_assurance_evidence=(
            nonce_authority_assurance_evidence
        ),
        nonce_authority_assurance_evidence_key_spki_sha256=(
            nonce_authority_assurance_evidence_key_spki_sha256
        ),
        nonce_authority_assurance_evidence_signing_public_key_spki_der_base64url=str(
            assurance_evidence_key_encoded
        ),
        nonce_authority_verifier_state_key_spki_sha256=(
            nonce_authority_verifier_state_key_spki_sha256
        ),
        nonce_authority_verifier_state_signing_public_key_spki_der_base64url=str(
            verifier_state_key_encoded
        ),
        nonce_authority_verifier_state_store_identity_sha256=(
            nonce_authority_verifier_state_store_identity_sha256
        ),
        nonce_authority_verifier_state_store_administrative_domain_sha256=(
            nonce_authority_verifier_state_store_administrative_domain_sha256
        ),
        nonce_authority_verifier_state_store_attestation_key_spki_sha256=(
            nonce_authority_verifier_state_store_attestation_key_spki_sha256
        ),
        nonce_authority_verifier_state_store_attestation_public_key_spki_der_base64url=str(
            verifier_state_store_attestation_key_encoded
        ),
        nonce_authority_verifier_state_store_assurance_evidence_sha256=(
            nonce_authority_verifier_state_store_assurance_evidence_sha256
        ),
        nonce_authority_verifier_state_store_assurance_evidence=dict(
            store_and_role_assurance["storeEvidence"]
        ),
        nonce_authority_verifier_state_store_assurance_evidence_signing_public_key_spki_der_base64url=str(
            immutable_config_document[
                "nonceAuthorityVerifierStateStoreAssuranceEvidenceSigningPublicKeySpkiDerBase64url"
            ]
        ),
        nonce_authority_verifier_state_store_assurance_issuer_administrative_domain_sha256=str(
            immutable_config_document[
                "nonceAuthorityVerifierStateStoreAssuranceIssuerAdministrativeDomainSha256"
            ]
        ),
        nonce_authority_verifier_state_store_assurance_issuer_credential_identity_sha256=str(
            immutable_config_document[
                "nonceAuthorityVerifierStateStoreAssuranceIssuerCredentialIdentitySha256"
            ]
        ),
        nonce_authority_verifier_state_store_assurance_issuer_identity_sha256=str(
            immutable_config_document[
                "nonceAuthorityVerifierStateStoreAssuranceIssuerIdentitySha256"
            ]
        ),
        nonce_authority_verifier_state_store_configuration_sha256=(
            nonce_authority_verifier_state_store_configuration_sha256
        ),
        nonce_authority_verifier_state_store_credential_identity_sha256=(
            nonce_authority_verifier_state_store_credential_identity_sha256
        ),
        nonce_authority_verifier_state_store_minimum_commit_index=(
            nonce_authority_verifier_state_store_minimum_commit_index
        ),
        nonce_authority_verifier_state_store_minimum_generation=(
            nonce_authority_verifier_state_store_minimum_generation
        ),
        nonce_authority_verifier_state_store_rollback_mechanism=(
            nonce_authority_verifier_state_store_rollback_mechanism
        ),
        nonce_authority_verifier_state_role_separation_evidence=dict(
            store_and_role_assurance["roleEvidence"]
        ),
        nonce_authority_verifier_state_role_separation_evidence_sha256=(
            store_and_role_assurance["roleEvidenceSha256"]
        ),
        nonce_authority_verifier_state_role_separation_evidence_signing_public_key_spki_der_base64url=str(
            immutable_config_document[
                "nonceAuthorityVerifierStateRoleSeparationEvidenceSigningPublicKeySpkiDerBase64url"
            ]
        ),
        nonce_authority_verifier_state_role_separation_evidence_issuer=dict(
            immutable_config_document[
                "nonceAuthorityVerifierStateRoleSeparationEvidenceIssuer"
            ]
        ),
        producer_request_schema_sha256=
        producer_request_schema_sha256,
        witness_store_identity_sha256=
        witness_store_identity_sha256,
        witness_store_key_spki_sha256=
        witness_store_key_spki_sha256,
        witness_store_signing_public_key_spki_der_base64url=str(
            witness_store_key_encoded
        ),
        trust_roots_sha256=trust_roots_sha256,
        max_input_bytes=max_input_bytes,
        max_output_bytes=max_output_bytes,
        timeout_milliseconds=timeout_milliseconds,
        concurrency_limit=concurrency_limit,
    )


def _open_public_evidence_executable(
    path: Path,
    expected_sha256: str,
    *,
    label: str,
) -> int:
    if (
        not path.is_absolute()
        or not path.name
        or ".." in path.parts
        or os.path.normpath(os.fspath(path)) != os.fspath(path)
    ):
        raise AttestationContractError(
            f"{label} path is invalid"
        )
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        raise AttestationContractError(
            f"{label} requires no-follow file operations"
        )
    directory_flags = (
        os.O_RDONLY
        | directory
        | no_follow
        | getattr(os, "O_CLOEXEC", 0)
    )
    directory_descriptor = os.open("/", directory_flags)
    executable_descriptor: int | None = None
    try:
        for component in path.parent.parts[1:]:
            next_descriptor = os.open(
                component,
                directory_flags,
                dir_fd=directory_descriptor,
            )
            directory_stat = os.fstat(next_descriptor)
            if (
                not stat.S_ISDIR(directory_stat.st_mode)
                or directory_stat.st_uid != 0
                or stat.S_IMODE(directory_stat.st_mode) & 0o022
            ):
                os.close(next_descriptor)
                raise AttestationContractError(
                    f"{label} path is not root-owned and immutable"
                )
            os.close(directory_descriptor)
            directory_descriptor = next_descriptor
        executable_descriptor = os.open(
            path.name,
            os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_descriptor,
        )
        before = os.fstat(executable_descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != 0
            or mode not in {0o500, 0o550, 0o555}
            or not 1 <= before.st_size <= 32 * 1024 * 1024
        ):
            raise AttestationContractError(
                f"{label} must be a root-owned, immutable executable"
            )
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(
                executable_descriptor, min(remaining, 1024 * 1024)
            )
            if not chunk:
                raise AttestationContractError(
                    f"{label} changed while being measured"
                )
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(executable_descriptor)
        if (
            (
                before.st_dev,
                before.st_ino,
                before.st_mode,
                before.st_nlink,
                before.st_uid,
                before.st_gid,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
                after.st_uid,
                after.st_gid,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            or not hmac.compare_digest(
                f"sha256:{digest.hexdigest()}",
                expected_sha256,
            )
        ):
            raise AttestationContractError(
                f"{label} measurement is invalid"
            )
        os.lseek(executable_descriptor, 0, os.SEEK_SET)
        result = executable_descriptor
        executable_descriptor = None
        return result
    except AttestationContractError:
        raise
    except OSError as exc:
        raise AttestationContractError(
            f"{label} is unavailable"
        ) from exc
    finally:
        if executable_descriptor is not None:
            os.close(executable_descriptor)
        os.close(directory_descriptor)


def _sealed_public_evidence_memfd(
    raw: bytes,
    *,
    label: str,
    maximum: int,
    executable: bool = False,
) -> int:
    if (
        type(raw) is not bytes
        or not 1 <= len(raw) <= maximum
        or not hasattr(os, "memfd_create")
        or not hasattr(fcntl, "F_ADD_SEALS")
    ):
        raise AttestationContractError(
            f"{label} cannot be represented as a bounded sealed memfd"
        )
    read_write_descriptor: int | None = None
    read_only_descriptor: int | None = None
    try:
        read_write_descriptor = os.memfd_create(
            "serverware-attestation",
            getattr(os, "MFD_CLOEXEC", 0)
            | getattr(os, "MFD_ALLOW_SEALING", 0),
        )
        offset = 0
        while offset < len(raw):
            written = os.write(read_write_descriptor, raw[offset:])
            if written < 1:
                raise OSError("short memfd write")
            offset += written
        os.fchmod(
            read_write_descriptor,
            0o500 if executable else 0o400,
        )
        seals = (
            fcntl.F_SEAL_SEAL
            | fcntl.F_SEAL_SHRINK
            | fcntl.F_SEAL_GROW
            | fcntl.F_SEAL_WRITE
        )
        fcntl.fcntl(read_write_descriptor, fcntl.F_ADD_SEALS, seals)
        read_only_descriptor = os.open(
            f"/proc/self/fd/{read_write_descriptor}",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
        result = read_only_descriptor
        read_only_descriptor = None
        return result
    except (AttributeError, OSError) as exc:
        raise AttestationContractError(
            f"{label} could not be sealed"
        ) from exc
    finally:
        if read_only_descriptor is not None:
            os.close(read_only_descriptor)
        if read_write_descriptor is not None:
            os.close(read_write_descriptor)


def _read_public_evidence_executable_fd(
    descriptor: int,
    *,
    maximum: int = 32 * 1024 * 1024,
    expected_sha256: str | None = None,
) -> bytes:
    before = os.fstat(descriptor)
    if (
        not stat.S_ISREG(before.st_mode)
        or not 1 <= before.st_size <= maximum
    ):
        raise AttestationContractError(
            "public evidence executable measurement is invalid"
        )
    chunks: list[bytes] = []
    offset = 0
    while offset < before.st_size:
        chunk = os.pread(
            descriptor,
            min(1024 * 1024, before.st_size - offset),
            offset,
        )
        if not chunk:
            raise AttestationContractError(
                "public evidence executable measurement ended early"
            )
        chunks.append(chunk)
        offset += len(chunk)
    after = os.fstat(descriptor)
    identity = lambda item: (
        item.st_dev,
        item.st_ino,
        item.st_mode,
        item.st_nlink,
        item.st_uid,
        item.st_gid,
        item.st_size,
        item.st_mtime_ns,
        item.st_ctime_ns,
    )
    raw = b"".join(chunks)
    if (
        identity(before) != identity(after)
        or len(raw) != before.st_size
        or (
            expected_sha256 is not None
            and not hmac.compare_digest(
                sha256_prefixed(raw),
                expected_sha256,
            )
        )
    ):
        raise AttestationContractError(
            "public evidence executable changed while being measured"
        )
    return raw


def _open_public_evidence_resource(
    path: Path,
    *,
    label: str,
    directory: bool,
) -> int:
    _require_normalized_absolute_path_text(os.fspath(path), label)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    try:
        return os.open(path, flags)
    except OSError as exc:
        raise AttestationContractError(
            f"{label} is unavailable"
        ) from exc


def _open_public_evidence_cgroup(
    descriptor: PublicEvidenceProducerDescriptor,
) -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory is None:
        raise AttestationContractError(
            "public evidence sandbox requires no-follow directory operations"
        )
    cgroup_descriptor: int | None = None
    try:
        cgroup_descriptor = os.open(
            descriptor.sandbox_cgroup_path,
            os.O_RDONLY
            | directory
            | no_follow
            | getattr(os, "O_CLOEXEC", 0),
        )
        cgroup_stat = os.fstat(cgroup_descriptor)
        if (
            not stat.S_ISDIR(cgroup_stat.st_mode)
            or cgroup_stat.st_uid != 0
            or stat.S_IMODE(cgroup_stat.st_mode) & 0o022
        ):
            raise AttestationContractError(
                "public evidence sandbox cgroup is not root-owned and immutable"
            )
        for name, flags in (
            ("cgroup.events", os.O_RDONLY),
            ("cgroup.kill", os.O_WRONLY),
        ):
            child = os.open(
                name,
                flags | no_follow | getattr(os, "O_CLOEXEC", 0),
                dir_fd=cgroup_descriptor,
            )
            os.close(child)
        return cgroup_descriptor
    except AttestationContractError:
        if cgroup_descriptor is not None:
            os.close(cgroup_descriptor)
        raise
    except OSError as exc:
        if cgroup_descriptor is not None:
            os.close(cgroup_descriptor)
        raise AttestationContractError(
            "public evidence disposable cgroup sandbox is unavailable"
        ) from exc


def _public_evidence_closed_seccomp_profile_bytes(
    architecture: str,
    *,
    syscall_names: tuple[str, ...],
) -> bytes:
    abi = _PUBLIC_EVIDENCE_KERNEL_ABIS.get(architecture)
    if abi is None:
        raise AttestationContractError(
            "public evidence seccomp architecture is unsupported"
        )
    syscall_table = abi["syscalls"]
    if (
        tuple(sorted(syscall_names)) != syscall_names
        or any(name not in syscall_table for name in syscall_names)
    ):
        raise AttestationContractError(
            "public evidence seccomp syscall allowlist is unsupported"
        )
    if (
        sha256_prefixed(
            canonical_json(syscall_table).encode("ascii")
        )
        != abi["syscallTableSha256"]
    ):
        raise AttestationContractError(
            "public evidence seccomp syscall table digest is invalid"
        )
    syscall_numbers = sorted(
        syscall_table[name]
        for name in syscall_names
    )
    if len(syscall_numbers) != len(set(syscall_numbers)):
        raise AttestationContractError(
            "public evidence seccomp syscall table is not canonical"
        )
    instructions = [
        (_BPF_LD_W_ABS, 0, 0, 4),
        (
            _BPF_JMP_JEQ_K,
            1,
            0,
            abi["auditArchitecture"],
        ),
        (_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS),
        (_BPF_LD_W_ABS, 0, 0, 0),
    ]
    for number in syscall_numbers:
        instructions.extend(
            (
                (_BPF_JMP_JEQ_K, 0, 1, number),
                (_BPF_RET_K, 0, 0, _SECCOMP_RET_ALLOW),
            )
        )
    instructions.append(
        (_BPF_RET_K, 0, 0, _SECCOMP_RET_KILL_PROCESS)
    )
    return b"".join(
        _CBPF_INSTRUCTION.pack(*instruction)
        for instruction in instructions
    )


def _validate_public_evidence_seccomp_profile(
    raw: bytes,
    *,
    expected_profile_id: str,
) -> None:
    machine = platform.machine().lower()
    architecture = {
        "amd64": "x86_64",
        "arm64": "aarch64",
    }.get(machine, machine)
    expected_id = f"serverware-producer-bootstrap-{architecture}-v1"
    expected = _public_evidence_closed_seccomp_profile_bytes(
        architecture,
        syscall_names=_PUBLIC_EVIDENCE_BOOTSTRAP_SYSCALLS,
    )
    if expected_profile_id != expected_id or not hmac.compare_digest(raw, expected):
        raise AttestationContractError(
            "public evidence seccomp bytes differ from the fixed reviewed "
            "kernel-ABI profile"
        )


def _public_evidence_cgroup_populated(cgroup_descriptor: int) -> bool:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    try:
        events_descriptor = os.open(
            "cgroup.events",
            os.O_RDONLY | no_follow | getattr(os, "O_CLOEXEC", 0),
            dir_fd=cgroup_descriptor,
        )
        try:
            raw = os.read(events_descriptor, 4097)
        finally:
            os.close(events_descriptor)
    except OSError as exc:
        raise AttestationContractError(
            "public evidence cgroup state is unavailable"
        ) from exc
    if len(raw) > 4096:
        raise AttestationContractError(
            "public evidence cgroup state exceeds its bound"
        )
    try:
        fields = {
            key: value
            for key, value in (
                line.split(" ", 1)
                for line in raw.decode("ascii").splitlines()
            )
        }
    except (UnicodeDecodeError, ValueError) as exc:
        raise AttestationContractError(
            "public evidence cgroup state is malformed"
        ) from exc
    if fields.get("populated") not in {"0", "1"}:
        raise AttestationContractError(
            "public evidence cgroup state is incomplete"
        )
    return fields["populated"] == "1"


def _kill_public_evidence_cgroup(cgroup_descriptor: int) -> None:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    kill_descriptor = os.open(
        "cgroup.kill",
        os.O_WRONLY | no_follow | getattr(os, "O_CLOEXEC", 0),
        dir_fd=cgroup_descriptor,
    )
    try:
        if os.write(kill_descriptor, b"1") != 1:
            raise OSError("short cgroup.kill write")
    finally:
        os.close(kill_descriptor)


def _open_public_evidence_pidfd(process_id: int) -> int:
    pidfd_open = getattr(os, "pidfd_open", None)
    pidfd_send_signal = getattr(signal, "pidfd_send_signal", None)
    if pidfd_open is None or pidfd_send_signal is None:
        raise AttestationContractError(
            "public evidence producer requires pidfd lifecycle control"
        )
    try:
        return pidfd_open(process_id, 0)
    except OSError as exc:
        raise AttestationContractError(
            "public evidence producer pidfd is unavailable"
        ) from exc


def _public_evidence_pidfd_exited(process_pidfd: int) -> bool:
    poller = select.poll()
    poller.register(
        process_pidfd,
        select.POLLIN
        | select.POLLERR
        | select.POLLHUP
        | select.POLLNVAL,
    )
    return bool(poller.poll(0))


def _terminate_public_evidence_tree(
    process: subprocess.Popen[bytes],
    process_pidfd: int | None,
    cgroup_descriptor: int,
    *,
    deadline: float,
) -> None:
    if process_pidfd is not None and (
        type(process_pidfd) is not int or process_pidfd < 0
    ):
        raise AttestationContractError(
            "public evidence producer pidfd is invalid"
        )
    try:
        _kill_public_evidence_cgroup(cgroup_descriptor)
    except OSError as exc:
        raise AttestationContractError(
            "public evidence sandbox cgroup could not be killed"
        ) from exc
    if process_pidfd is not None:
        try:
            signal.pidfd_send_signal(
                process_pidfd,
                signal.SIGKILL,
                None,
                0,
            )
        except ProcessLookupError:
            pass
        except OSError as exc:
            raise AttestationContractError(
                "public evidence producer pidfd could not be signaled"
            ) from exc
    elif process.poll() is None:
        raise AttestationContractError(
            "public evidence producer has no retained pidfd identity"
        )
    while time.monotonic() < deadline:
        if process.poll() is None:
            try:
                process.wait(timeout=0.01)
            except subprocess.TimeoutExpired:
                pass
        if (
            process.poll() is not None
            and (
                process_pidfd is None
                or _public_evidence_pidfd_exited(process_pidfd)
            )
            and not _public_evidence_cgroup_populated(cgroup_descriptor)
        ):
            return
        time.sleep(0.005)
    raise AttestationContractError(
        "public evidence producer tree could not be proven dead"
    )


def _reap_quarantined_public_evidence_trees() -> None:
    with _PUBLIC_EVIDENCE_QUARANTINE_LOCK:
        pending = tuple(_PUBLIC_EVIDENCE_QUARANTINED_TREES)
        _PUBLIC_EVIDENCE_QUARANTINED_TREES.clear()
    retained: list[_QuarantinedPublicEvidenceTree] = []
    for tree in pending:
        try:
            _terminate_public_evidence_tree(
                tree.process,
                tree.process_pidfd,
                tree.cgroup_descriptor,
                deadline=time.monotonic() + 1.0,
            )
        except Exception:
            retained.append(tree)
            continue
        if tree.process_pidfd is not None:
            try:
                os.close(tree.process_pidfd)
            except OSError:
                pass
        try:
            os.close(tree.cgroup_descriptor)
        except OSError:
            pass
        tree.semaphore.release()
    if retained:
        with _PUBLIC_EVIDENCE_QUARANTINE_LOCK:
            _PUBLIC_EVIDENCE_QUARANTINED_TREES.extend(retained)


def _public_evidence_quarantine_reaper() -> None:
    while True:
        _PUBLIC_EVIDENCE_QUARANTINE_EVENT.wait()
        _PUBLIC_EVIDENCE_QUARANTINE_EVENT.clear()
        while True:
            try:
                _reap_quarantined_public_evidence_trees()
            except Exception:
                _PUBLIC_EVIDENCE_QUARANTINE_EVENT.wait(0.25)
                _PUBLIC_EVIDENCE_QUARANTINE_EVENT.clear()
            with _PUBLIC_EVIDENCE_QUARANTINE_LOCK:
                pending = bool(_PUBLIC_EVIDENCE_QUARANTINED_TREES)
            if not pending:
                break
            _PUBLIC_EVIDENCE_QUARANTINE_EVENT.wait(0.25)
            _PUBLIC_EVIDENCE_QUARANTINE_EVENT.clear()


def _ensure_public_evidence_quarantine_reaper() -> None:
    global _PUBLIC_EVIDENCE_QUARANTINE_THREAD
    with _PUBLIC_EVIDENCE_QUARANTINE_THREAD_LOCK:
        thread = _PUBLIC_EVIDENCE_QUARANTINE_THREAD
        if thread is not None and thread.is_alive():
            return
        thread = threading.Thread(
            target=_public_evidence_quarantine_reaper,
            name="serverware-public-evidence-quarantine",
            daemon=True,
        )
        _PUBLIC_EVIDENCE_QUARANTINE_THREAD = thread
        thread.start()


def _quarantine_public_evidence_tree(
    tree: _QuarantinedPublicEvidenceTree,
) -> None:
    with _PUBLIC_EVIDENCE_QUARANTINE_LOCK:
        _PUBLIC_EVIDENCE_QUARANTINED_TREES.append(tree)
    _ensure_public_evidence_quarantine_reaper()
    _PUBLIC_EVIDENCE_QUARANTINE_EVENT.set()


def _public_evidence_producer_semaphore(
    descriptor: PublicEvidenceProducerDescriptor,
) -> threading.BoundedSemaphore:
    key = (
        f"{descriptor.descriptor_sha256}:"
        f"{descriptor.concurrency_limit}"
    )
    with _PUBLIC_EVIDENCE_PRODUCER_SEMAPHORES_LOCK:
        semaphore = _PUBLIC_EVIDENCE_PRODUCER_SEMAPHORES.get(key)
        if semaphore is None:
            semaphore = threading.BoundedSemaphore(
                descriptor.concurrency_limit
            )
            _PUBLIC_EVIDENCE_PRODUCER_SEMAPHORES[key] = semaphore
        return semaphore


def _invoke_public_evidence_producer(
    descriptor: PublicEvidenceProducerDescriptor,
    request_bytes: bytes,
    *,
    producer_ephemeral_seed: bytes,
) -> bytes:
    command_deadline_ns = (
        time.monotonic_ns()
        + descriptor.timeout_milliseconds * 1_000_000
    )
    if (
        not request_bytes
        or len(request_bytes) > descriptor.max_input_bytes
        or not request_bytes.endswith(b"\n")
        or type(producer_ephemeral_seed) is not bytes
        or len(producer_ephemeral_seed) != 32
    ):
        raise AttestationContractError(
            "public evidence producer request exceeds its closed byte contract"
        )
    executable_descriptor: int | None = None
    launcher_descriptor: int | None = None
    cgroup_descriptor: int | None = None
    try:
        executable_descriptor = _open_public_evidence_executable(
            descriptor.executable_path,
            descriptor.executable_sha256,
            label="public evidence producer executable",
        )
        launcher_descriptor = _open_public_evidence_executable(
            descriptor.sandbox_launcher_path,
            descriptor.sandbox_launcher_sha256,
            label="public evidence sandbox launcher",
        )
        cgroup_descriptor = _open_public_evidence_cgroup(descriptor)
    except Exception:
        for opened_descriptor in (
            executable_descriptor,
            launcher_descriptor,
            cgroup_descriptor,
        ):
            if opened_descriptor is not None:
                os.close(opened_descriptor)
        raise
    semaphore = _public_evidence_producer_semaphore(descriptor)
    acquired = semaphore.acquire(blocking=False)
    if not acquired:
        os.close(executable_descriptor)
        os.close(launcher_descriptor)
        os.close(cgroup_descriptor)
        raise AttestationContractError(
            "public evidence producer is at its concurrency limit"
        )
    process: subprocess.Popen[bytes] | None = None
    process_pidfd: int | None = None
    tree_proven_dead = False
    ready_read_descriptor: int | None = None
    ready_write_descriptor: int | None = None
    owner_control_socket: socket.socket | None = None
    owner_launcher_socket: socket.socket | None = None
    retained_resource_descriptors: list[int] = []
    try:
        if _public_evidence_cgroup_populated(cgroup_descriptor):
            raise AttestationContractError(
                "public evidence disposable cgroup is not empty before launch"
            )
        executable_raw = _read_public_evidence_executable_fd(
            executable_descriptor,
            maximum=256 * 1024 * 1024,
            expected_sha256=descriptor.executable_sha256,
        )
        executable_execution_descriptor = (
            _sealed_public_evidence_memfd(
                executable_raw,
                label="public evidence producer executable",
                maximum=256 * 1024 * 1024,
                executable=True,
            )
        )
        retained_resource_descriptors.append(
            executable_execution_descriptor
        )
        launcher_raw = _read_public_evidence_executable_fd(
            launcher_descriptor,
            maximum=256 * 1024 * 1024,
            expected_sha256=descriptor.sandbox_launcher_sha256,
        )
        launcher_execution_descriptor = (
            _sealed_public_evidence_memfd(
                launcher_raw,
                label="public evidence sandbox launcher",
                maximum=256 * 1024 * 1024,
                executable=True,
            )
        )
        retained_resource_descriptors.append(
            launcher_execution_descriptor
        )
        launcher_reference = (
            f"/proc/self/fd/{launcher_execution_descriptor}"
        )
        if not Path(launcher_reference).exists():
            raise AttestationContractError(
                "public evidence sandbox requires Linux descriptor execution"
            )
        if descriptor.sandbox_mount_sources:
            raise AttestationContractError(
                "public evidence sandbox v2 forbids production bind mounts"
            )
        request_descriptor = _sealed_public_evidence_memfd(
            request_bytes,
            label="public evidence producer request",
            maximum=descriptor.max_input_bytes,
        )
        retained_resource_descriptors.append(request_descriptor)
        immutable_config_descriptor = _sealed_public_evidence_memfd(
            descriptor.immutable_config_bytes,
            label="public evidence immutable configuration",
            maximum=256 * 1024,
        )
        retained_resource_descriptors.append(
            immutable_config_descriptor
        )
        sandbox_policy_descriptor = _sealed_public_evidence_memfd(
            descriptor.sandbox_descriptor_bytes,
            label="public evidence sandbox descriptor",
            maximum=64 * 1024,
        )
        retained_resource_descriptors.append(
            sandbox_policy_descriptor
        )
        seccomp_raw = _read_stable_root_owned_file(
            descriptor.sandbox_seccomp_profile_path,
            label="public evidence seccomp profile",
            maximum=256 * 1024,
        )
        if not hmac.compare_digest(
            sha256_prefixed(seccomp_raw),
            descriptor.sandbox_seccomp_profile_sha256,
        ):
            raise AttestationContractError(
                "public evidence seccomp profile digest is invalid"
            )
        if not descriptor.sandbox_fixture_mode:
            _validate_public_evidence_seccomp_profile(
                seccomp_raw,
                expected_profile_id=descriptor.sandbox_seccomp_profile_id,
            )
        seccomp_profile_descriptor = _sealed_public_evidence_memfd(
            seccomp_raw,
            label="public evidence seccomp profile",
            maximum=256 * 1024,
        )
        retained_resource_descriptors.append(
            seccomp_profile_descriptor
        )
        sandbox_root_descriptor = _open_public_evidence_resource(
            descriptor.sandbox_root_path,
            label="public evidence sandbox root",
            directory=True,
        )
        retained_resource_descriptors.append(
            sandbox_root_descriptor
        )
        named_descriptors: list[tuple[str, int]] = []
        for role, path, expected_sha256, maximum in (
            descriptor.sandbox_sealed_files
        ):
            raw = _read_stable_root_owned_file(
                path,
                label=f"public evidence sealed resource {role}",
                maximum=maximum,
            )
            if (
                expected_sha256 is not None
                and not hmac.compare_digest(
                    sha256_prefixed(raw),
                    expected_sha256,
                )
            ):
                raise AttestationContractError(
                    f"public evidence sealed resource {role} digest is invalid"
                )
            resource_descriptor = _sealed_public_evidence_memfd(
                raw,
                label=f"public evidence sealed resource {role}",
                maximum=maximum,
            )
            retained_resource_descriptors.append(resource_descriptor)
            named_descriptors.append((role, resource_descriptor))
        measurement_sources = {
            "producerExecutable": executable_raw,
            "sandboxDescriptor": descriptor.sandbox_descriptor_bytes,
        }
        for role, measurement_of in (
            descriptor.sandbox_measurement_copies
        ):
            measurement_descriptor = _sealed_public_evidence_memfd(
                measurement_sources[measurement_of],
                label=f"public evidence measurement copy {role}",
                maximum=256 * 1024 * 1024,
            )
            retained_resource_descriptors.append(
                measurement_descriptor
            )
            named_descriptors.append((role, measurement_descriptor))
        for role, source_descriptor in (
            descriptor.sandbox_producer_streams
        ):
            try:
                stream_descriptor = fcntl.fcntl(
                    source_descriptor,
                    fcntl.F_DUPFD_CLOEXEC,
                    128,
                )
            except OSError as exc:
                raise AttestationContractError(
                    f"public evidence retained stream {role} is unavailable"
                ) from exc
            retained_resource_descriptors.append(stream_descriptor)
            named_descriptors.append((role, stream_descriptor))
        ephemeral_seed_descriptor = _sealed_public_evidence_memfd(
            producer_ephemeral_seed,
            label="public evidence producer ephemeral seed",
            maximum=32,
        )
        retained_resource_descriptors.append(
            ephemeral_seed_descriptor
        )
        named_descriptors.append(
            ("producerEphemeralSeed", ephemeral_seed_descriptor)
        )
        named_descriptors.sort(key=lambda item: item[0])
        if (
            len({role for role, _ in named_descriptors})
            != len(named_descriptors)
        ):
            raise AttestationContractError(
                "public evidence named resource roles are not unique"
            )
        launcher_arguments = [
            launcher_reference,
            "--expected-stable-statement-sha256",
            descriptor.stable_statement_sha256,
            "--sandbox-descriptor-fd",
            str(sandbox_policy_descriptor),
            "--producer-executable-fd",
            str(executable_execution_descriptor),
            "--immutable-config-fd",
            str(immutable_config_descriptor),
            "--cgroup-fd",
            str(cgroup_descriptor),
            "--seccomp-profile-fd",
            str(seccomp_profile_descriptor),
            "--sandbox-root-fd",
            str(sandbox_root_descriptor),
            "--ready-fd",
        ]
        ready_read_descriptor, ready_write_descriptor = os.pipe2(
            getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0)
        )
        launcher_arguments.append(str(ready_write_descriptor))
        try:
            owner_control_socket, owner_launcher_socket = socket.socketpair(
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET,
            )
            owner_control_socket.set_inheritable(False)
            owner_launcher_socket.set_inheritable(False)
        except OSError as exc:
            raise AttestationContractError(
                "public evidence owner-liveness channel is unavailable"
            ) from exc
        launcher_arguments.extend(
            [
                "--owner-liveness-fd",
                str(owner_launcher_socket.fileno()),
                "--command-deadline-monotonic-ns",
                str(command_deadline_ns),
            ]
        )
        for role, resource_descriptor in named_descriptors:
            launcher_arguments.extend(
                [
                    "--producer-fd",
                    f"{role}={resource_descriptor}",
                ]
            )
        expected_ready_token = b"READY\n"
        if descriptor.sandbox_fixture_mode:
            launcher_arguments.append("--fixture-non-production")
            expected_ready_token = b"NON_PRODUCTION_FIXTURE_READY\n"
        with tempfile.TemporaryFile() as producer_stdout:
            producer_stdout_write_descriptor = os.open(
                f"/proc/self/fd/{producer_stdout.fileno()}",
                os.O_WRONLY | getattr(os, "O_CLOEXEC", 0),
            )
            retained_resource_descriptors.append(
                producer_stdout_write_descriptor
            )
            process = subprocess.Popen(
                launcher_arguments,
                stdin=request_descriptor,
                stdout=producer_stdout_write_descriptor,
                stderr=subprocess.DEVNULL,
                env={
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/usr/bin:/bin",
                },
                pass_fds=(
                    launcher_execution_descriptor,
                    executable_execution_descriptor,
                    immutable_config_descriptor,
                    sandbox_policy_descriptor,
                    cgroup_descriptor,
                    seccomp_profile_descriptor,
                    sandbox_root_descriptor,
                    ready_write_descriptor,
                    owner_launcher_socket.fileno(),
                    *(resource_descriptor for _, resource_descriptor in named_descriptors),
                ),
                start_new_session=True,
            )
            owner_launcher_socket.close()
            owner_launcher_socket = None
            process_pidfd = _open_public_evidence_pidfd(process.pid)
            os.close(ready_write_descriptor)
            ready_write_descriptor = None
            deadline = command_deadline_ns / 1_000_000_000
            sandbox_ready = False
            ready_closed = False
            ready_bytes = bytearray()
            while process.poll() is None:
                if not ready_closed:
                    try:
                        ready_chunk = os.read(ready_read_descriptor, 64)
                    except BlockingIOError:
                        pass
                    else:
                        if ready_chunk:
                            ready_bytes.extend(ready_chunk)
                        else:
                            ready_closed = True
                    if len(ready_bytes) > len(expected_ready_token):
                        raise AttestationContractError(
                            "public evidence sandbox readiness token is invalid"
                        )
                    if not expected_ready_token.startswith(ready_bytes):
                        raise AttestationContractError(
                            "public evidence sandbox readiness token is invalid"
                        )
                    sandbox_ready = (
                        ready_closed
                        and bytes(ready_bytes) == expected_ready_token
                    )
                if (
                    os.fstat(producer_stdout.fileno()).st_size
                    > descriptor.max_output_bytes
                ):
                    raise AttestationContractError(
                        "public evidence producer output exceeds its bound"
                    )
                if time.monotonic() >= deadline:
                    raise AttestationContractError(
                        "public evidence producer timed out"
                    )
                time.sleep(0.005)
            while not ready_closed:
                try:
                    ready_chunk = os.read(ready_read_descriptor, 64)
                except BlockingIOError:
                    break
                if ready_chunk:
                    ready_bytes.extend(ready_chunk)
                else:
                    ready_closed = True
            if (
                len(ready_bytes) > len(expected_ready_token)
                or not expected_ready_token.startswith(ready_bytes)
            ):
                raise AttestationContractError(
                    "public evidence sandbox readiness token is invalid"
                )
            if not sandbox_ready:
                sandbox_ready = (
                    ready_closed
                    and bytes(ready_bytes) == expected_ready_token
                )
            return_code = process.returncode
            _terminate_public_evidence_tree(
                process,
                process_pidfd,
                cgroup_descriptor,
                deadline=max(deadline, time.monotonic() + 1.0),
            )
            tree_proven_dead = True
            if owner_control_socket is not None:
                owner_control_socket.close()
                owner_control_socket = None
            if not sandbox_ready:
                raise AttestationContractError(
                    "public evidence sandbox never completed containment admission"
                )
            if return_code != 0:
                raise AttestationContractError(
                    "public evidence producer rejected the request"
                )
            producer_stdout.seek(0)
            raw = producer_stdout.read(
                descriptor.max_output_bytes + 1
            )
        if len(raw) > descriptor.max_output_bytes:
            raise AttestationContractError(
                "public evidence producer output exceeds its bound"
            )
        return raw
    except AttestationContractError:
        if process is not None and not tree_proven_dead:
            if owner_control_socket is not None:
                owner_control_socket.close()
                owner_control_socket = None
            _terminate_public_evidence_tree(
                process,
                process_pidfd,
                cgroup_descriptor,
                deadline=time.monotonic() + 1.0,
            )
            tree_proven_dead = True
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        if process is not None and not tree_proven_dead:
            if owner_control_socket is not None:
                owner_control_socket.close()
                owner_control_socket = None
            _terminate_public_evidence_tree(
                process,
                process_pidfd,
                cgroup_descriptor,
                deadline=time.monotonic() + 1.0,
            )
            tree_proven_dead = True
        raise AttestationContractError(
            "public evidence producer execution failed"
        ) from exc
    finally:
        if ready_read_descriptor is not None:
            os.close(ready_read_descriptor)
        if ready_write_descriptor is not None:
            os.close(ready_write_descriptor)
        if owner_launcher_socket is not None:
            owner_launcher_socket.close()
        if owner_control_socket is not None:
            owner_control_socket.close()
        for retained_descriptor in retained_resource_descriptors:
            os.close(retained_descriptor)
        os.close(executable_descriptor)
        os.close(launcher_descriptor)
        if process is not None and not tree_proven_dead:
            _quarantine_public_evidence_tree(
                _QuarantinedPublicEvidenceTree(
                    process=process,
                    process_pidfd=process_pidfd,
                    cgroup_descriptor=cgroup_descriptor,
                    semaphore=semaphore,
                )
            )
        else:
            if process_pidfd is not None:
                os.close(process_pidfd)
            os.close(cgroup_descriptor)
            semaphore.release()


def _public_evidence_nonce_channel_lock(
    descriptor: PublicEvidenceProducerDescriptor,
) -> threading.Lock:
    key = (
        descriptor.nonce_service_request_fd,
        descriptor.nonce_service_response_fd,
        descriptor.nonce_store_identity_sha256,
    )
    with _PUBLIC_EVIDENCE_NONCE_CHANNEL_LOCKS_LOCK:
        lock = _PUBLIC_EVIDENCE_NONCE_CHANNEL_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _PUBLIC_EVIDENCE_NONCE_CHANNEL_LOCKS[key] = lock
        return lock


def _public_evidence_service_peer_pid(
    fd: int,
    *,
    descriptor: PublicEvidenceProducerDescriptor,
    label: str,
) -> tuple[tuple[int, int, int], int]:
    try:
        metadata = os.fstat(fd)
        access_mode = fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE
        duplicate = os.dup(fd)
    except OSError as exc:
        raise AttestationContractError(
            f"{label} retained FD is unavailable"
        ) from exc
    if not stat.S_ISSOCK(metadata.st_mode) or access_mode != os.O_RDWR:
        os.close(duplicate)
        raise AttestationContractError(
            f"{label} retained FD is not a read-write socket"
        )
    try:
        channel = socket.socket(fileno=duplicate)
        duplicate = -1
        try:
            if (
                channel.family != socket.AF_UNIX
                or channel.type & 0xF != socket.SOCK_SEQPACKET
                or not hasattr(socket, "SO_PEERCRED")
                or not hasattr(socket, "SO_PASSCRED")
                or not hasattr(socket, "SCM_CREDENTIALS")
            ):
                raise AttestationContractError(
                    f"{label} is not the required Unix seqpacket channel"
                )
            channel.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            if channel.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1:
                raise AttestationContractError(
                    f"{label} cannot require per-message credentials"
                )
            credentials = channel.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                struct.calcsize("3i"),
            )
        finally:
            channel.close()
    except OSError as exc:
        raise AttestationContractError(
            f"{label} peer credentials are unavailable"
        ) from exc
    finally:
        if duplicate >= 0:
            os.close(duplicate)
    peer_pid, peer_uid, peer_gid = struct.unpack("3i", credentials)
    if (
        peer_pid < 1
        or peer_uid != descriptor.nonce_service_expected_peer_uid
        or peer_gid != descriptor.nonce_service_expected_peer_gid
    ):
        raise AttestationContractError(
            f"{label} peer identity differs from the signed descriptor"
        )
    peer_pidfd = _open_public_evidence_pidfd(peer_pid)
    executable_fd: int | None = None
    cgroup_fd: int | None = None
    try:
        try:
            executable_fd = os.open(
                f"/proc/{peer_pid}/exe",
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            )
            _read_public_evidence_executable_fd(
                executable_fd,
                maximum=256 * 1024 * 1024,
                expected_sha256=(
                    descriptor
                    .nonce_service_expected_peer_executable_sha256
                ),
            )
            cgroup_fd = os.open(
                f"/proc/{peer_pid}/cgroup",
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            )
            cgroup_raw = os.read(cgroup_fd, 4097)
            expected_cgroup = (
                "0::"
                + descriptor.nonce_service_expected_peer_cgroup_path
                + "\n"
            ).encode("ascii")
            if cgroup_raw != expected_cgroup:
                raise AttestationContractError(
                    f"{label} peer cgroup differs from the signed descriptor"
                )
            if _public_evidence_pidfd_exited(peer_pidfd):
                raise AttestationContractError(
                    f"{label} peer exited during identity admission"
                )
        except AttestationContractError:
            raise
        except OSError as exc:
            raise AttestationContractError(
                f"{label} peer process identity is unavailable"
            ) from exc
        finally:
            if executable_fd is not None:
                os.close(executable_fd)
            if cgroup_fd is not None:
                os.close(cgroup_fd)
    except BaseException:
        os.close(peer_pidfd)
        raise
    return (peer_pid, peer_uid, peer_gid), peer_pidfd


def _public_evidence_fd_write_line(
    fd: int,
    raw: bytes,
    *,
    deadline: float,
    label: str,
) -> None:
    duplicate = os.dup(fd)
    channel: socket.socket | None = None
    try:
        channel = socket.socket(fileno=duplicate)
        duplicate = -1
        channel.setblocking(False)
        poller = select.poll()
        poller.register(
            channel.fileno(),
            select.POLLOUT
            | select.POLLERR
            | select.POLLHUP
            | select.POLLNVAL,
        )
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _PublicEvidenceNonceChannelTransportError(
                    f"{label} write timed out"
                )
            events = poller.poll(max(1, int(remaining * 1000)))
            if not events:
                raise _PublicEvidenceNonceChannelTransportError(
                    f"{label} write timed out"
                )
            returned = events[0][1]
            if (
                returned
                & (
                    select.POLLERR
                    | select.POLLHUP
                    | select.POLLNVAL
                )
                or not returned & select.POLLOUT
            ):
                raise _PublicEvidenceNonceChannelTransportError(
                    f"{label} write failed"
                )
            try:
                written = channel.send(raw)
            except BlockingIOError:
                continue
            if written != len(raw):
                raise _PublicEvidenceNonceChannelTransportError(
                    f"{label} write was truncated"
                )
            return
    except OSError as exc:
        raise _PublicEvidenceNonceChannelTransportError(
            f"{label} write failed"
        ) from exc
    finally:
        if channel is not None:
            channel.close()
        if duplicate >= 0:
            os.close(duplicate)


def _public_evidence_fd_read_line(
    fd: int,
    *,
    maximum: int,
    deadline: float,
    expected_credentials: tuple[int, int, int],
    label: str,
) -> bytes:
    duplicate = os.dup(fd)
    channel: socket.socket | None = None
    try:
        channel = socket.socket(fileno=duplicate)
        duplicate = -1
        channel.setblocking(False)
        poller = select.poll()
        poller.register(
            channel.fileno(),
            select.POLLIN
            | select.POLLERR
            | select.POLLHUP
            | select.POLLNVAL,
        )
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _PublicEvidenceNonceChannelTransportError(
                    f"{label} read timed out"
                )
            events = poller.poll(max(1, int(remaining * 1000)))
            if not events:
                raise _PublicEvidenceNonceChannelTransportError(
                    f"{label} read timed out"
                )
            returned = events[0][1]
            if (
                returned & (select.POLLERR | select.POLLNVAL)
                or not returned
                & (select.POLLIN | select.POLLHUP)
            ):
                raise _PublicEvidenceNonceChannelTransportError(
                    f"{label} read failed"
                )
            try:
                raw, ancillary, flags, address = channel.recvmsg(
                    maximum + 1,
                    socket.CMSG_SPACE(
                        _PUBLIC_EVIDENCE_SCM_CREDENTIALS_SIZE
                    ),
                )
            except BlockingIOError:
                continue
            break
    except OSError as exc:
        raise _PublicEvidenceNonceChannelTransportError(
            f"{label} read failed"
        ) from exc
    finally:
        if channel is not None:
            channel.close()
        if duplicate >= 0:
            os.close(duplicate)
    if (
        address not in {None, "", b""}
        or not raw
        or len(raw) > maximum
        or not raw.endswith(b"\n")
        or raw.count(b"\n") != 1
        or flags
        & (
            getattr(socket, "MSG_TRUNC", 0)
            | getattr(socket, "MSG_CTRUNC", 0)
        )
    ):
        raise AttestationContractError(f"{label} frame is invalid")
    credentials: list[tuple[int, int, int]] = []
    for level, control_type, control_data in ancillary:
        if (
            level != socket.SOL_SOCKET
            or control_type != socket.SCM_CREDENTIALS
            or len(control_data) != _PUBLIC_EVIDENCE_SCM_CREDENTIALS_SIZE
        ):
            raise AttestationContractError(
                f"{label} contains an FD or unknown control message"
            )
        credentials.append(struct.unpack("3i", control_data))
    if credentials != [expected_credentials]:
        raise AttestationContractError(
            f"{label} sender differs from the pinned service peer"
        )
    return raw


def _challenge_public_evidence_service_channel(
    fd: int,
    *,
    role: str,
    direction: str,
    protocol: str,
    descriptor: PublicEvidenceProducerDescriptor,
    deadline: float,
    expected_credentials: tuple[int, int, int],
) -> None:
    challenge = b64e(secrets.token_bytes(32))
    request = {
        "apiVersion":
        "serverware.publicAttestationServiceChannelChallenge/v1",
        "challengeBase64url": challenge,
        "direction": direction,
        "protocol": protocol,
        "role": role,
    }
    _public_evidence_fd_write_line(
        fd,
        canonical_json(request).encode("ascii") + b"\n",
        deadline=deadline,
        label=f"public evidence {role} challenge",
    )
    response_raw = _public_evidence_fd_read_line(
        fd,
        maximum=64 * 1024,
        deadline=deadline,
        expected_credentials=expected_credentials,
        label=f"public evidence {role} challenge response",
    )
    response = _strict_json_document(
        response_raw,
        label=f"public evidence {role} challenge response",
    )
    expected = {
        "apiVersion":
        "serverware.publicAttestationServiceChannelChallengeResponse/v1",
        "challengeBase64url": challenge,
        "direction": direction,
        "peerCgroupPath":
        descriptor.nonce_service_expected_peer_cgroup_path,
        "peerExecutableSha256":
        descriptor.nonce_service_expected_peer_executable_sha256,
        "protocol": protocol,
        "role": role,
    }
    if (
        response_raw != canonical_json(response).encode("ascii") + b"\n"
        or response != expected
    ):
        raise AttestationContractError(
            f"public evidence {role} challenge crossed its service identity"
        )


def _public_evidence_nonce_consumption_response(
    *,
    descriptor: PublicEvidenceProducerDescriptor,
    consume_request: Mapping[str, Any],
    deadline: float,
) -> dict[str, Any]:
    request_bytes = (
        canonical_json(dict(consume_request)).encode("ascii") + b"\n"
    )
    if len(request_bytes) > 64 * 1024:
        raise AttestationContractError(
            "public evidence nonce consumption request exceeds its bound"
        )
    if deadline <= time.monotonic():
        raise AttestationContractError(
            "public evidence nonce consumption shared deadline expired"
        )
    with _public_evidence_nonce_channel_lock(descriptor):
        request_peer, request_peer_pidfd = _public_evidence_service_peer_pid(
            descriptor.nonce_service_request_fd,
            descriptor=descriptor,
            label="public evidence nonce request channel",
        )
        response_peer_pidfd: int | None = None
        try:
            (
                response_peer,
                response_peer_pidfd,
            ) = _public_evidence_service_peer_pid(
                descriptor.nonce_service_response_fd,
                descriptor=descriptor,
                label="public evidence nonce response channel",
            )
            if (
                request_peer != response_peer
                or _public_evidence_pidfd_exited(request_peer_pidfd)
                or _public_evidence_pidfd_exited(response_peer_pidfd)
            ):
                raise AttestationContractError(
                    "public evidence nonce channels have different or exited peers"
                )
            last_unknown: BaseException | None = None
            channels_authenticated = False
            while (
                not channels_authenticated
                and time.monotonic() < deadline
            ):
                try:
                    _challenge_public_evidence_service_channel(
                        descriptor.nonce_service_request_fd,
                        role="nonceRequest",
                        direction="producer-to-service",
                        protocol="serverware.attestationNonceService/v2",
                        descriptor=descriptor,
                        deadline=deadline,
                        expected_credentials=request_peer,
                    )
                    _challenge_public_evidence_service_channel(
                        descriptor.nonce_service_response_fd,
                        role="nonceResponse",
                        direction="service-to-producer",
                        protocol="serverware.attestationNonceService/v2",
                        descriptor=descriptor,
                        deadline=deadline,
                        expected_credentials=response_peer,
                    )
                    channels_authenticated = True
                except _PublicEvidenceNonceChannelTransportError as exc:
                    last_unknown = exc
                    remaining = deadline - time.monotonic()
                    if remaining > 0:
                        time.sleep(min(0.01, remaining))
            if not channels_authenticated:
                raise AttestationContractError(
                    "public evidence nonce channel identity remains unknown"
                ) from last_unknown
            response_bytes: bytes | None = None
            successful_consume_writes = 0
            while response_bytes is None and time.monotonic() < deadline:
                if (
                    canonical_json(dict(consume_request)).encode("ascii")
                    + b"\n"
                    != request_bytes
                ):
                    raise AttestationContractError(
                        "public evidence nonce recovery request drifted"
                    )
                try:
                    _public_evidence_fd_write_line(
                        descriptor.nonce_service_request_fd,
                        request_bytes,
                        deadline=deadline,
                        label="public evidence nonce request",
                    )
                    successful_consume_writes += 1
                    response_bytes = _public_evidence_fd_read_line(
                        descriptor.nonce_service_response_fd,
                        maximum=(
                            descriptor.nonce_service_max_response_bytes
                        ),
                        deadline=deadline,
                        expected_credentials=response_peer,
                        label="public evidence nonce response",
                    )
                except _PublicEvidenceNonceChannelTransportError as exc:
                    last_unknown = exc
                    remaining = deadline - time.monotonic()
                    if remaining > 0:
                        time.sleep(min(0.01, remaining))
            if response_bytes is None:
                raise AttestationContractError(
                    "public evidence nonce outcome remains unknown; "
                    "recover only the identical transaction and request"
                ) from last_unknown
            if successful_consume_writes > 1:
                # A request-channel challenge is an ordering barrier: the
                # service cannot answer it until every earlier consume retry
                # has produced its response on the response channel.
                _challenge_public_evidence_service_channel(
                    descriptor.nonce_service_request_fd,
                    role="nonceRequest",
                    direction="producer-to-service",
                    protocol="serverware.attestationNonceService/v2",
                    descriptor=descriptor,
                    deadline=deadline,
                    expected_credentials=request_peer,
                )
                for _ in range(successful_consume_writes - 1):
                    duplicate_response = _public_evidence_fd_read_line(
                        descriptor.nonce_service_response_fd,
                        maximum=(
                            descriptor.nonce_service_max_response_bytes
                        ),
                        deadline=deadline,
                        expected_credentials=response_peer,
                        label=(
                            "public evidence retained nonce recovery "
                            "response"
                        ),
                    )
                    if duplicate_response != response_bytes:
                        raise AttestationContractError(
                            "public evidence nonce recovery substituted "
                            "a retained response"
                        )
            post_response_peer, post_response_pidfd = (
                _public_evidence_service_peer_pid(
                    descriptor.nonce_service_response_fd,
                    descriptor=descriptor,
                    label="public evidence post-response nonce channel",
                )
            )
            try:
                if (
                    post_response_peer != response_peer
                    or _public_evidence_pidfd_exited(request_peer_pidfd)
                    or _public_evidence_pidfd_exited(response_peer_pidfd)
                ):
                    raise AttestationContractError(
                        "public evidence nonce peer drifted during its response"
                    )
            finally:
                os.close(post_response_pidfd)
        finally:
            os.close(request_peer_pidfd)
            if response_peer_pidfd is not None:
                os.close(response_peer_pidfd)
    response = _strict_json_document(
        response_bytes,
        label="public evidence nonce response",
    )
    if response_bytes != canonical_json(response).encode("ascii") + b"\n":
        raise AttestationContractError(
            "public evidence nonce response is not canonical JSON plus LF"
        )
    if (
        consume_request.get("apiVersion")
        == NONCE_TRANSACTION_STATUS_REQUEST_VERSION
    ):
        response = dict(
            _require_exact_fields(
                response,
                {
                    "apiVersion",
                    "nonceAuthorityAssurance",
                    "nonceAuthorityAssuranceSha256",
                    "nonceConsumptionReceipt",
                    "nonceStatusEvidence",
                    "nonceStatusEvidenceSha256",
                    "status",
                    "storeIdentitySha256",
                },
                "public evidence nonce status response",
            )
        )
        nonce_key, nonce_key_id = _load_ed25519_spki_der(
            descriptor
            .nonce_store_signing_public_key_spki_der_base64url,
            label="public evidence nonce status signing key",
        )
        status_envelope, status_payload, status_sha256 = (
            _verify_public_evidence_standard_envelope(
                response["nonceStatusEvidence"],
                api_version=(
                    SIGNED_NONCE_TRANSACTION_STATUS_EVIDENCE_VERSION
                ),
                domain=NONCE_TRANSACTION_STATUS_EVIDENCE_DOMAIN,
                signing_key=nonce_key,
                signing_key_id=nonce_key_id,
                label="public evidence nonce status evidence",
            )
        )
        status_payload = dict(
            _require_exact_fields(
                status_payload,
                {
                    "apiVersion",
                    "consumeRequestSha256",
                    "evidenceIssuedAtUnix",
                    "neverConsumable",
                    "nonceAuthorityVerifierStateAuthorizationSha256",
                    "nonceConsumptionReceiptSha256",
                    "nonceSha256",
                    "preparedOperationSha256",
                    "recoveryKeySha256",
                    "requestBindingSha256",
                    "requestOperation",
                    "status",
                    "transactionIdBase64url",
                },
                "public evidence nonce status payload",
            )
        )
        nonce_request = consume_request["consumeRequest"]
        expected_receipt_sha256 = (
            None
            if response["nonceConsumptionReceipt"] is None
            else sha256_prefixed(
                canonical_json(
                    response["nonceConsumptionReceipt"]
                ).encode("ascii")
            )
        )
        if (
            response["apiVersion"]
            != NONCE_TRANSACTION_STATUS_RESPONSE_VERSION
            or response["nonceAuthorityAssurance"]
            != descriptor.nonce_authority_assurance
            or response["nonceAuthorityAssuranceSha256"]
            != descriptor.nonce_authority_assurance_sha256
            or response["storeIdentitySha256"]
            != descriptor.nonce_store_identity_sha256
            or response["nonceStatusEvidence"] != status_envelope
            or response["nonceStatusEvidenceSha256"]
            != status_sha256
            or status_payload["apiVersion"]
            != NONCE_TRANSACTION_STATUS_EVIDENCE_VERSION
            or type(status_payload["evidenceIssuedAtUnix"]) is not int
            or not 1
            <= status_payload["evidenceIssuedAtUnix"]
            <= int(time.time())
            or int(time.time())
            - status_payload["evidenceIssuedAtUnix"]
            > 30
            or status_payload["consumeRequestSha256"]
            != sha256_prefixed(
                b"serverware.attestationNonceConsumeRequestDigest/v3\x00"
                + canonical_json(nonce_request).encode("ascii")
            )
            or status_payload["nonceAuthorityVerifierStateAuthorizationSha256"]
            != nonce_request[
                "nonceAuthorityVerifierStateAuthorizationSha256"
            ]
            or status_payload["nonceConsumptionReceiptSha256"]
            != expected_receipt_sha256
            or status_payload["nonceSha256"]
            != nonce_request["nonceSha256"]
            or status_payload["preparedOperationSha256"]
            != consume_request["preparedOperationSha256"]
            or status_payload["recoveryKeySha256"]
            != consume_request["recoveryKeySha256"]
            or status_payload["requestBindingSha256"]
            != consume_request["requestBindingSha256"]
            or status_payload["requestOperation"]
            != consume_request["requestOperation"]
            or status_payload["status"] != response["status"]
            or status_payload["transactionIdBase64url"]
            != nonce_request["transactionIdBase64url"]
        ):
            raise AttestationContractError(
                "public evidence nonce status crossed its prepared transaction"
            )
        if status_payload["status"] == "consumed":
            if (
                status_payload["neverConsumable"] is not False
                or response["nonceConsumptionReceipt"] is None
            ):
                raise AttestationContractError(
                    "consumed nonce status omitted its retained receipt"
                )
        elif status_payload["status"] == "neverConsumed":
            if (
                status_payload["neverConsumable"] is not True
                or response["nonceConsumptionReceipt"] is not None
            ):
                raise AttestationContractError(
                    "never-consumed status is not an irrevocable tombstone"
                )
        elif (
            status_payload["status"] != "notObserved"
            or status_payload["neverConsumable"] is not False
            or response["nonceConsumptionReceipt"] is not None
        ):
            raise AttestationContractError(
                "unknown nonce status carried actionable evidence"
            )
        return response
    response = _require_exact_fields(
        response,
        {
            "apiVersion",
            "nonceAuthorityAssurance",
            "nonceAuthorityAssuranceSha256",
            "nonceConsumption",
            "nonceConsumptionReceipt",
            "nonceConsumptionReceiptSha256",
            "nonceConsumptionSha256",
            "nonceStoreIdentitySha256",
        },
        "public evidence nonce response",
    )
    receipt = _require_exact_fields(
        response.get("nonceConsumptionReceipt"),
        {
            "apiVersion",
            "payload",
            "payloadSha256",
            "signatureAlgorithm",
            "signatureBase64url",
            "signingKeyId",
            "signingKeySpkiSha256",
        },
        "public evidence signed nonce receipt",
    )
    if (
        response.get("apiVersion")
        != "serverware.attestationNonceConsumeResponse/v2"
        or response.get("nonceAuthorityAssurance")
        != descriptor.nonce_authority_assurance
        or response.get("nonceAuthorityAssuranceSha256")
        != descriptor.nonce_authority_assurance_sha256
        or response.get("nonceAuthorityAssuranceSha256")
        != sha256_prefixed(
            canonical_json(
                response.get("nonceAuthorityAssurance")
            ).encode("ascii")
        )
        or response.get("nonceStoreIdentitySha256")
        != descriptor.nonce_store_identity_sha256
        or receipt.get("apiVersion")
        != "serverware.signedAttestationNonceConsumptionReceipt/v2"
        or receipt.get("signatureAlgorithm") != "Ed25519"
        or receipt.get("signingKeyId")
        != descriptor.nonce_store_key_spki_sha256
        or receipt.get("signingKeySpkiSha256")
        != descriptor.nonce_store_key_spki_sha256
        or receipt.get("payloadSha256")
        != sha256_prefixed(
            canonical_json(receipt.get("payload")).encode("ascii")
        )
        or response.get("nonceConsumptionReceiptSha256")
        != sha256_prefixed(
            canonical_json(receipt).encode("ascii")
        )
        or response.get("nonceConsumptionSha256")
        != sha256_prefixed(
            canonical_json(
                response.get("nonceConsumption")
            ).encode("ascii")
        )
    ):
        raise AttestationContractError(
            "public evidence nonce response crossed its signed pins"
        )
    try:
        signature = b64d(str(receipt.get("signatureBase64url")))
        nonce_key, nonce_key_id = _load_ed25519_spki_der(
            descriptor
            .nonce_store_signing_public_key_spki_der_base64url,
            label="public evidence nonce-store signing key",
        )
        if len(signature) != 64 or nonce_key_id != (
            descriptor.nonce_store_key_spki_sha256
        ):
            raise ValueError("nonce receipt signature shape is invalid")
        nonce_key.verify(
            signature,
            b"serverware.attestationNonceConsumptionReceipt/v2"
            b"\x00Ed25519\x00"
            + canonical_json(
                {
                    "payload": receipt["payload"],
                    "payloadSha256": receipt["payloadSha256"],
                }
            ).encode("ascii"),
        )
    except (InvalidSignature, TypeError, ValueError) as exc:
        raise AttestationContractError(
            "public evidence nonce receipt signature is invalid"
        ) from exc
    return dict(response)


class _PublicEvidenceUnknownVerifierStateOutcome(RuntimeError):
    pass


def _public_evidence_verifier_state_semaphore(
    descriptor: PublicEvidenceProducerDescriptor,
) -> threading.BoundedSemaphore:
    key = (
        descriptor.verifier_state_service_authority,
        descriptor.verifier_state_service_configuration_sha256,
        descriptor.nonce_authority_verifier_state_store_identity_sha256,
    )
    with _PUBLIC_EVIDENCE_VERIFIER_STATE_SEMAPHORES_LOCK:
        semaphore = _PUBLIC_EVIDENCE_VERIFIER_STATE_SEMAPHORES.get(
            key
        )
        if semaphore is None:
            semaphore = threading.BoundedSemaphore(
                descriptor.verifier_state_service_concurrency_limit
            )
            _PUBLIC_EVIDENCE_VERIFIER_STATE_SEMAPHORES[key] = semaphore
        return semaphore


def _public_evidence_connect_verifier_state_socket(
    *,
    descriptor: PublicEvidenceProducerDescriptor,
    deadline: float,
) -> socket.socket:
    started = time.monotonic()
    connect_deadline = min(
        deadline,
        started
        + descriptor.verifier_state_service_timeout_milliseconds / 1000.0,
    )
    if connect_deadline <= started:
        raise TimeoutError(
            "public evidence verifier-state connect deadline expired"
        )
    transport = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM | getattr(socket, "SOCK_CLOEXEC", 0),
    )
    try:
        transport.setblocking(False)
        result = transport.connect_ex(
            (
                descriptor.verifier_state_service_host,
                descriptor.verifier_state_service_port,
            )
        )
        if result not in {
            0,
            errno.EALREADY,
            errno.EINPROGRESS,
            errno.EINTR,
            errno.EWOULDBLOCK,
        }:
            raise OSError(result, os.strerror(result))
        if result != 0:
            poller = select.poll()
            poller.register(
                transport.fileno(),
                select.POLLOUT | select.POLLERR | select.POLLHUP,
            )
            timeout_milliseconds = max(
                1,
                int(
                    max(0.0, connect_deadline - time.monotonic())
                    * 1000
                ),
            )
            events = poller.poll(timeout_milliseconds)
            if (
                not events
                or time.monotonic() >= connect_deadline
                or any(
                    event & (select.POLLERR | select.POLLHUP)
                    for _, event in events
                )
            ):
                raise TimeoutError(
                    "public evidence verifier-state connect exceeded its shared deadline"
                )
            socket_error = transport.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_ERROR,
            )
            if socket_error:
                raise OSError(socket_error, os.strerror(socket_error))
        if time.monotonic() >= connect_deadline:
            raise TimeoutError(
                "public evidence verifier-state connect exceeded its shared deadline"
            )
        transport.setblocking(True)
        return transport
    except BaseException:
        transport.close()
        raise


def _public_evidence_verifier_state_post(
    *,
    descriptor: PublicEvidenceProducerDescriptor,
    path: str,
    request: Mapping[str, Any],
    deadline: float,
    outcome_may_be_unknown: bool,
) -> dict[str, Any]:
    def set_deadline_timeout(
        transport_socket: socket.socket,
        *,
        phase: str,
    ) -> None:
        remaining_seconds = deadline - time.monotonic()
        if remaining_seconds <= 0:
            error = TimeoutError(
                "public evidence verifier-state "
                f"{phase} exceeded its shared deadline"
            )
            if outcome_may_be_unknown:
                raise _PublicEvidenceUnknownVerifierStateOutcome(
                    "verifier-state mutating operation exceeded its deadline"
                ) from error
            raise AttestationContractError(
                "public evidence verifier-state deadline expired"
            ) from error
        transport_socket.settimeout(
            min(
                remaining_seconds,
                descriptor.verifier_state_service_timeout_milliseconds
                / 1000.0,
            )
        )

    allowed_paths = {
        descriptor.verifier_state_service_read_path,
        descriptor.verifier_state_service_issue_challenge_path,
        descriptor.verifier_state_service_recover_challenge_path,
        descriptor.verifier_state_service_prepare_path,
        descriptor.verifier_state_service_recovery_lookup_path,
        descriptor.verifier_state_service_mark_consumption_path,
        descriptor.verifier_state_service_attach_nonce_status_path,
        descriptor.verifier_state_service_abort_path,
        descriptor.verifier_state_service_commit_path,
        descriptor.verifier_state_service_recover_path,
    }
    if path not in allowed_paths or "?" in path or "#" in path:
        raise AttestationContractError(
            "public evidence verifier-state path is not descriptor-pinned"
        )
    body = canonical_json(dict(request)).encode("ascii")
    if not 1 <= len(body) <= 256 * 1024:
        raise AttestationContractError(
            "public evidence verifier-state request exceeds its bound"
        )
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        error: Exception = TimeoutError(
            "public evidence verifier-state deadline expired"
        )
        if outcome_may_be_unknown:
            raise _PublicEvidenceUnknownVerifierStateOutcome(
                "verifier-state mutating operation exceeded its deadline"
            ) from error
        raise AttestationContractError(
            "public evidence verifier-state deadline expired"
        ) from error
    transport: ssl.SSLSocket | None = None
    try:
        plain_socket = _public_evidence_connect_verifier_state_socket(
            descriptor=descriptor,
            deadline=deadline,
        )
        try:
            set_deadline_timeout(
                plain_socket,
                phase="TLS handshake",
            )
            transport = (
                descriptor.verifier_state_service_tls_context
                .wrap_socket(
                    plain_socket,
                    server_hostname=(
                        descriptor.verifier_state_service_host
                    ),
                )
            )
        except BaseException:
            plain_socket.close()
            raise
        if (
            transport.version() != "TLSv1.3"
            or transport.selected_alpn_protocol()
            != "http/1.1"
        ):
            raise AttestationContractError(
                "public evidence verifier-state transport is not exact TLS 1.3 HTTP/1.1"
            )
        peer_certificate = transport.getpeercert(binary_form=True)
        if (
            not isinstance(peer_certificate, bytes)
            or _public_evidence_certificate_spki_sha256(
                peer_certificate,
                label="public evidence verifier-state server certificate",
            )
            != descriptor.verifier_state_service_server_leaf_spki_sha256
        ):
            raise AttestationContractError(
                "public evidence verifier-state server leaf SPKI differs from its pin"
            )
        request_head = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: {descriptor.verifier_state_service_authority}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Cache-Control: no-store\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        set_deadline_timeout(
            transport,
            phase="request send",
        )
        transport.sendall(request_head + body)
        response_limit = (
            descriptor.verifier_state_service_max_response_bytes
            + 16 * 1024
        )
        response_raw = bytearray()
        while len(response_raw) <= response_limit:
            set_deadline_timeout(
                transport,
                phase="response read and EOF",
            )
            chunk = transport.recv(
                min(
                    64 * 1024,
                    response_limit + 1 - len(response_raw),
                )
            )
            if not chunk:
                break
            response_raw.extend(chunk)
        if (
            len(response_raw) > response_limit
            or not response_raw
        ):
            raise AttestationContractError(
                "public evidence verifier-state response did not reach bounded EOF"
            )
        header_raw, separator, raw = bytes(response_raw).partition(
            b"\r\n\r\n"
        )
        if (
            separator != b"\r\n\r\n"
            or not 1 <= len(header_raw) <= 16 * 1024
            or b"\n" in header_raw.replace(b"\r\n", b"")
            or b"\r" in header_raw.replace(b"\r\n", b"")
        ):
            raise AttestationContractError(
                "public evidence verifier-state response header framing is invalid"
            )
        lines = header_raw.split(b"\r\n")
        try:
            status_match = re.fullmatch(
                rb"HTTP/1\.1 ([1-5][0-9]{2}) [\x20-\x7e]+",
                lines[0],
            )
            if status_match is None:
                raise ValueError("status line is invalid")
            status = int(status_match.group(1), 10)
        except (IndexError, ValueError) as exc:
            raise AttestationContractError(
                "public evidence verifier-state HTTP status line is invalid"
            ) from exc
        normalized: dict[str, list[str]] = {}
        allowed_headers = {
            "cache-control",
            "connection",
            "content-length",
            "content-type",
            "date",
            "server",
        }
        for line in lines[1:]:
            if (
                not line
                or line[:1] in {b" ", b"\t"}
                or b":" not in line
            ):
                raise AttestationContractError(
                    "public evidence verifier-state response contains folded or malformed headers"
                )
            raw_name, raw_value = line.split(b":", 1)
            if (
                not raw_value.startswith(b" ")
                or raw_value.startswith(b"  ")
            ):
                raise AttestationContractError(
                    "public evidence verifier-state response header spacing is noncanonical"
                )
            try:
                name = raw_name.decode("ascii")
                value = raw_value[1:].decode("ascii")
            except UnicodeDecodeError as exc:
                raise AttestationContractError(
                    "public evidence verifier-state response headers are not ASCII"
                ) from exc
            if (
                re.fullmatch(r"[A-Za-z0-9-]+", name, re.ASCII)
                is None
                or value != value.strip()
                or not value
            ):
                raise AttestationContractError(
                    "public evidence verifier-state response header syntax is invalid"
                )
            lowered = name.lower()
            if lowered not in allowed_headers:
                raise AttestationContractError(
                    "public evidence verifier-state response contains an unapproved HTTP header"
                )
            normalized.setdefault(lowered, []).append(value)
        content_lengths = normalized.get("content-length", [])
        content_types = normalized.get("content-type", [])
        cache_controls = normalized.get("cache-control", [])
        if (
            len(content_lengths) != 1
            or re.fullmatch(
                r"[1-9][0-9]*", content_lengths[0], re.ASCII
            )
            is None
            or len(content_types) != 1
            or content_types[0] != "application/json"
            or len(cache_controls) != 1
            or cache_controls[0] != "no-store"
            or normalized.get("connection", [])
            not in ([], ["close"])
        ):
            raise AttestationContractError(
                "public evidence verifier-state response framing is ambiguous"
            )
        content_length = int(content_lengths[0])
        if not 1 <= content_length <= (
            descriptor.verifier_state_service_max_response_bytes
        ):
            raise AttestationContractError(
                "public evidence verifier-state response exceeds its bound"
            )
        if len(raw) != content_length:
            raise AttestationContractError(
                "public evidence verifier-state response has trailing, truncated, or undeclared bytes"
            )
        if status != 200:
            if outcome_may_be_unknown:
                raise _PublicEvidenceUnknownVerifierStateOutcome(
                    "verifier-state mutating operation returned a non-200 status"
                )
            raise AttestationContractError(
                "public evidence verifier-state operation returned a non-200 status"
            )
        document = _strict_json_document(
            raw, label="public evidence verifier-state response"
        )
        if raw != canonical_json(document).encode("ascii"):
            raise AttestationContractError(
                "public evidence verifier-state response is not canonical JSON"
            )
        if not isinstance(document, Mapping):
            raise AttestationContractError(
                "public evidence verifier-state response is not an object"
            )
        return dict(document)
    except _PublicEvidenceUnknownVerifierStateOutcome:
        raise
    except AttestationContractError as exc:
        if outcome_may_be_unknown:
            raise _PublicEvidenceUnknownVerifierStateOutcome(
                "verifier-state mutating response could not be authenticated"
            ) from exc
        raise
    except (
        OSError,
        ssl.SSLError,
        TimeoutError,
    ) as exc:
        if outcome_may_be_unknown:
            raise _PublicEvidenceUnknownVerifierStateOutcome(
                "verifier-state mutating transport outcome is unknown"
            ) from exc
        raise AttestationContractError(
            "public evidence verifier-state transport failed closed"
        ) from exc
    finally:
        if transport is not None:
            transport.close()


def _verify_public_evidence_verifier_state_authorization(
    value: Any,
    *,
    descriptor: PublicEvidenceProducerDescriptor,
    verifier_state_key: Ed25519PublicKey,
    prior: Mapping[str, Any],
    verifier_challenge: bytes,
    operation_id_base64url: str,
    now: int | None,
) -> dict[str, Any]:
    envelope, payload, envelope_sha256 = (
        _verify_public_evidence_standard_envelope(
            value,
            api_version=(
                NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_VERSION
            ),
            domain=NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_DOMAIN,
            signing_key=verifier_state_key,
            signing_key_id=(
                descriptor.nonce_authority_verifier_state_key_spki_sha256
            ),
            label="public evidence verifier-state authorization",
        )
    )
    payload = dict(
        _require_exact_fields(
            payload,
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
                "stateStoreAssuranceEvidenceSha256",
                "stateStoreAttestationKeySpkiSha256",
                "stateStoreConfigurationSha256",
                "stateStoreGeneration",
                "stateStoreHeadSha256",
                "stateStoreIdentitySha256",
                "verifierChallengeSha256",
            },
            "public evidence verifier-state authorization payload",
        )
    )
    issued = _require_positive_generation(
        payload.get("issuedAtUnix"),
        "public evidence verifier-state authorization issue time",
    )
    expires = _require_positive_generation(
        payload.get("expiresAtUnix"),
        "public evidence verifier-state authorization expiry",
    )
    prior_payload = prior["payload"]
    if (
        payload.get("apiVersion")
        != NONCE_AUTHORITY_VERIFIER_STATE_AUTHORIZATION_VERSION
        or payload.get("assuranceSha256")
        != descriptor.nonce_authority_assurance_sha256
        or payload.get("authorityEpoch")
        != descriptor.nonce_authority_assurance["authorityEpoch"]
        or payload.get("authorityGeneration")
        != descriptor.nonce_authority_assurance["authorityGeneration"]
        or payload.get("nonceReceiptSigningKeySpkiSha256")
        != descriptor.nonce_store_key_spki_sha256
        or payload.get("operationIdBase64url")
        != operation_id_base64url
        or payload.get("nonceTransactionIdBase64url")
        != operation_id_base64url
        or payload.get("priorCommittedAtUnix")
        != prior_payload["committedAtUnix"]
        or payload.get("priorVerifierStateSha256")
        != prior["envelopeSha256"]
        or payload.get("stateStoreAssuranceEvidenceSha256")
        != descriptor.nonce_authority_verifier_state_store_assurance_evidence_sha256
        or payload.get("stateStoreAttestationKeySpkiSha256")
        != descriptor.nonce_authority_verifier_state_store_attestation_key_spki_sha256
        or payload.get("stateStoreConfigurationSha256")
        != descriptor.nonce_authority_verifier_state_store_configuration_sha256
        or payload.get("stateStoreGeneration")
        != prior_payload["stateStoreGeneration"]
        or payload.get("stateStoreHeadSha256")
        != prior_payload["stateStoreHeadSha256"]
        or payload.get("stateStoreIdentitySha256")
        != descriptor.nonce_authority_verifier_state_store_identity_sha256
        or payload.get("highWaterSequence")
        != prior_payload["highWaterSequence"]
        or payload.get("highWaterCommitmentSha256")
        != prior_payload["highWaterCommitmentSha256"]
        or payload.get("highWaterReceiptSha256")
        != prior_payload["highWaterReceiptSha256"]
        or payload.get("verifierChallengeSha256")
        != sha256_prefixed(verifier_challenge)
        or payload.get("oneUse") is not True
        or any(
            not isinstance(payload.get(field), str)
            or _DIGEST_RE.fullmatch(payload[field]) is None
            for field in (
                "prepareRequestSha256",
                "recoveryIdentitySha256",
                "recoveryKeySha256",
                "requestBindingSha256",
            )
        )
        or (
            now is not None
            and not issued <= now < expires
        )
        or not issued < expires
        or expires - issued > 30
    ):
        raise AttestationContractError(
            "public evidence verifier-state authorization is stale or crossed"
        )
    return {
        "document": envelope,
        "envelopeSha256": envelope_sha256,
        "payload": payload,
    }


def _public_evidence_lookup_prepared_transition(
    *,
    descriptor: PublicEvidenceProducerDescriptor,
    recovery_identity: Mapping[str, Any],
    recovery_identity_sha256: str,
    recovery_key_sha256: str,
    operation_id_base64url: str,
    assurance_evidence: Mapping[str, Any] | None,
    verifier_state_key: Ed25519PublicKey,
    deadline: float,
) -> dict[str, Any] | None:
    lookup_request = {
        "apiVersion":
        NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_LOOKUP_REQUEST_VERSION,
        "recoveryIdentity": dict(recovery_identity),
        "recoveryIdentitySha256": recovery_identity_sha256,
        "recoveryKeySha256": recovery_key_sha256,
    }
    response = dict(
        _require_exact_fields(
            _public_evidence_verifier_state_post(
                descriptor=descriptor,
                path=(
                    descriptor
                    .verifier_state_service_recovery_lookup_path
                ),
                request=lookup_request,
                deadline=deadline,
                outcome_may_be_unknown=False,
            ),
            {
                "apiVersion",
                "commitReceipt",
                "nonActionable",
                "nonceConsumptionReceipt",
                "nonceRecoveryRequired",
                "nonceStatusEvidence",
                "preparedOperation",
                "preparedOperationSha256",
                "recoveryIdentity",
                "recoveryIdentitySha256",
                "recoveryKeySha256",
                "replacementForbidden",
                "requestBindingSha256",
                "status",
            },
            "public evidence verifier-state recovery lookup",
        )
    )
    if (
        response["apiVersion"]
        != NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_LOOKUP_RESPONSE_VERSION
        or response["nonActionable"] is not True
        or response["recoveryIdentity"] != recovery_identity
        or response["recoveryIdentitySha256"]
        != recovery_identity_sha256
        or response["recoveryKeySha256"] != recovery_key_sha256
    ):
        raise AttestationContractError(
            "verifier-state recovery lookup crossed its request-bound identity"
        )
    if response["status"] == "notFound":
        if (
            response["commitReceipt"] is not None
            or response["nonceConsumptionReceipt"] is not None
            or response["nonceStatusEvidence"] is not None
            or response["preparedOperation"] is not None
            or response["preparedOperationSha256"] is not None
            or response["requestBindingSha256"] is not None
            or response["nonceRecoveryRequired"] is not False
            or response["replacementForbidden"] is not False
        ):
            raise AttestationContractError(
                "empty recovery lookup carried operation artifacts"
            )
        return None
    status = response["status"]
    if (
        status
        not in {
            "prepared",
            "consumptionPending",
            "nonceConsumed",
            "casCommitted",
            "committed",
        }
        or response["replacementForbidden"] is not True
    ):
        raise AttestationContractError(
            "request-bound operation was aborted or has invalid recovery state"
        )
    prepared = dict(
        _require_exact_fields(
            response["preparedOperation"],
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
            "recovered public evidence prepared operation",
        )
    )
    prepare_request = dict(
        _require_exact_fields(
            prepared["prepareRequest"],
            {
                "apiVersion",
                "assuranceSha256",
                "expectedVerifierStateSha256",
                "operationIdBase64url",
                "priorStateRead",
                "priorStateReadSha256",
                "producerInvocation",
                "producerInvocationSha256",
                "recoveryIdentity",
                "recoveryIdentitySha256",
                "recoveryKeySha256",
                "requestBinding",
                "requestBindingSha256",
                "verifierChallengeBase64url",
            },
            "recovered verifier-state prepare request",
        )
    )
    prior_read = dict(
        _require_exact_fields(
            prepare_request["priorStateRead"],
            {
                "apiVersion",
                "challengeBase64url",
                "challengeExpiresAtUnix",
                "challengeIssuedAtUnix",
                "challengeSha256",
                "expectedVerifierStateSha256",
                "nonActionable",
                "state",
                "stateSha256",
            },
            "recovered verifier-state prior read",
        )
    )
    producer_invocation = dict(
        _require_exact_fields(
            prepare_request["producerInvocation"],
            {
                "apiVersion",
                "callerNonceSha256",
                "expiresAtUnix",
                "issuedAtUnix",
                "minimumReleaseIdentitySha256",
                "minimumRollbackContinuityCommitmentSha256",
                "nonceAuthorityVerifierChallengeBase64url",
                "nonceAuthorityVerifierStateOperationIdBase64url",
                "producerChannelChallengeBase64url",
                "producerEphemeralKeySpkiDerBase64url",
                "producerEphemeralKeySpkiSha256",
                "releaseIdentitySha256",
                "requestBodySha256",
                "staticPins",
                "tlsBindingSha256",
                "witnessVerifierChallengeBase64url",
            },
            "recovered producer invocation",
        )
    )
    request_binding = dict(prepared["requestBinding"])
    verifier_challenge = b64d(
        str(prepare_request["verifierChallengeBase64url"])
    )
    try:
        from scripts import verify_nitro_tee as public_verifier
    except ImportError as exc:
        raise AttestationContractError(
            "public verifier is unavailable for prepared-state recovery"
        ) from exc
    try:
        prior = public_verifier.verify_nonce_authority_verifier_state(
            prior_read["state"],
            signing_key=verifier_state_key,
            signing_key_id=(
                descriptor
                .nonce_authority_verifier_state_key_spki_sha256
            ),
            expected_state_store_identity_sha256=(
                descriptor
                .nonce_authority_verifier_state_store_identity_sha256
            ),
            assurance=descriptor.nonce_authority_assurance,
            assurance_sha256=(
                descriptor.nonce_authority_assurance_sha256
            ),
        )
    except (
        public_verifier.VerificationError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AttestationContractError(
            "recovered prepared predecessor is invalid"
        ) from exc
    authorization = (
        _verify_public_evidence_verifier_state_authorization(
            prepared["authorization"],
            descriptor=descriptor,
            verifier_state_key=verifier_state_key,
            prior=prior,
            verifier_challenge=verifier_challenge,
            operation_id_base64url=operation_id_base64url,
            now=(
                int(time.time())
                if status == "prepared"
                else None
            ),
        )
    )
    request_binding_sha256 = sha256_prefixed(
        NONCE_AUTHORITY_VERIFIER_STATE_REQUEST_BINDING_DOMAIN
        + canonical_json(request_binding).encode("ascii")
    )
    if (
        prepared["apiVersion"]
        != NONCE_AUTHORITY_VERIFIER_STATE_PREPARED_OPERATION_VERSION
        or response["preparedOperationSha256"]
        != sha256_prefixed(
            canonical_json(prepared).encode("ascii")
        )
        or response["requestBindingSha256"]
        != request_binding_sha256
        or prepared["prepareRequestSha256"]
        != sha256_prefixed(
            canonical_json(prepare_request).encode("ascii")
        )
        or prepared["authorizationSha256"]
        != authorization["envelopeSha256"]
        or authorization["payload"]["prepareRequestSha256"]
        != prepared["prepareRequestSha256"]
        or authorization["payload"]["recoveryIdentitySha256"]
        != recovery_identity_sha256
        or authorization["payload"]["recoveryKeySha256"]
        != recovery_key_sha256
        or authorization["payload"]["requestBindingSha256"]
        != request_binding_sha256
        or prepared["recoveryIdentity"] != recovery_identity
        or prepared["recoveryIdentitySha256"]
        != recovery_identity_sha256
        or prepared["recoveryKeySha256"] != recovery_key_sha256
        or prepared["requestBindingSha256"]
        != request_binding_sha256
        or prepare_request["operationIdBase64url"]
        != operation_id_base64url
        or prepare_request["priorStateReadSha256"]
        != sha256_prefixed(
            canonical_json(prior_read).encode("ascii")
        )
        or prepare_request["producerInvocationSha256"]
        != sha256_prefixed(
            canonical_json(producer_invocation).encode("ascii")
        )
        or prepare_request["recoveryIdentity"]
        != recovery_identity
        or prepare_request["recoveryIdentitySha256"]
        != recovery_identity_sha256
        or prepare_request["recoveryKeySha256"]
        != recovery_key_sha256
        or prepare_request["requestBinding"]
        != request_binding
        or prepare_request["requestBindingSha256"]
        != request_binding_sha256
        or prior_read["stateSha256"] != prior["envelopeSha256"]
        or prior_read["expectedVerifierStateSha256"]
        != prior["envelopeSha256"]
        or producer_invocation[
            "nonceAuthorityVerifierStateOperationIdBase64url"
        ]
        != operation_id_base64url
        or producer_invocation[
            "nonceAuthorityVerifierChallengeBase64url"
        ]
        != prepare_request["verifierChallengeBase64url"]
    ):
        raise AttestationContractError(
            "recovered prepared operation substituted exact saga context"
        )
    return {
        "assuranceEvidence": assurance_evidence,
        "authorization": authorization,
        "preparedOperation": prepared,
        "preparedOperationSha256":
        response["preparedOperationSha256"],
        "producerInvocation": producer_invocation,
        "producerInvocationSha256":
        prepare_request["producerInvocationSha256"],
        "recoveredStatus": status,
        "recoveryIdentity": dict(recovery_identity),
        "recoveryIdentitySha256": recovery_identity_sha256,
        "recoveryKeySha256": recovery_key_sha256,
        "requestBindingSha256": request_binding_sha256,
        "operationIdBase64url": operation_id_base64url,
        "priorRead": prior_read,
        "priorReadSha256":
        prepare_request["priorStateReadSha256"],
        "priorState": prior,
        "verifierChallengeBase64url":
        prepare_request["verifierChallengeBase64url"],
        "verifierChallengeSha256":
        prior_read["challengeSha256"],
        "verifierStateKey": verifier_state_key,
    }


def _public_evidence_begin_verifier_state_transition(
    *,
    descriptor: PublicEvidenceProducerDescriptor,
    operation_id: bytes,
    recovery_identity: Mapping[str, Any],
    caller_nonce_sha256: str,
    request_body_sha256: str,
    tls_binding_sha256: str,
    producer_invocation_base: Mapping[str, Any] | None,
    expires_at_unix: int | None,
    deadline: float,
    recover_only: bool = False,
) -> dict[str, Any] | None:
    try:
        from scripts import verify_nitro_tee as public_verifier

        verifier_state_key, verifier_state_key_id = (
            _load_ed25519_spki_der(
                descriptor
                .nonce_authority_verifier_state_signing_public_key_spki_der_base64url,
                label="public evidence verifier-state signing key",
            )
        )
        if (
            verifier_state_key_id
            != descriptor.nonce_authority_verifier_state_key_spki_sha256
        ):
            raise AttestationContractError(
                "public evidence verifier-state signing key crossed its descriptor pin"
            )
        assurance_evidence_key, assurance_evidence_key_id = (
            _load_ed25519_spki_der(
                descriptor
                .nonce_authority_assurance_evidence_signing_public_key_spki_der_base64url,
                label="public evidence assurance-evidence signing key",
            )
        )
        if (
            assurance_evidence_key_id
            != descriptor
            .nonce_authority_assurance_evidence_key_spki_sha256
        ):
            raise AttestationContractError(
                "public evidence assurance-evidence key crossed its descriptor pin"
            )
        assurance_evidence = (
            _validate_public_evidence_assurance_evidence(
                descriptor.nonce_authority_assurance_evidence,
                assurance=descriptor.nonce_authority_assurance,
                signing_key=assurance_evidence_key,
                signing_key_id=assurance_evidence_key_id,
                nonce_store_key_id=descriptor.nonce_store_key_spki_sha256,
                verifier_state_key_id=verifier_state_key_id,
                verifier_state_store_identity_sha256=(
                    descriptor
                    .nonce_authority_verifier_state_store_identity_sha256
                ),
                verifier_state_store_administrative_domain_sha256=(
                    descriptor
                    .nonce_authority_verifier_state_store_administrative_domain_sha256
                ),
                now=int(time.time()),
            )
        )
        operation_id_base64url = b64e(operation_id)
        recovery_identity = dict(
            _require_exact_fields(
                recovery_identity,
                {
                    "apiVersion",
                    "assuranceSha256",
                    "callerNonceSha256",
                    "immutableConfigSha256",
                    "releaseIdentitySha256",
                    "requestBodySha256",
                },
                "public evidence verifier-state recovery identity",
            )
        )
        recovery_identity_sha256 = sha256_prefixed(
            canonical_json(recovery_identity).encode("ascii")
        )
        expected_operation_id = hashlib.sha256(
            NONCE_AUTHORITY_VERIFIER_STATE_OPERATION_ID_DOMAIN
            + canonical_json(recovery_identity).encode("ascii")
        ).digest()
        if (
            recovery_identity["apiVersion"]
            != NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_IDENTITY_VERSION
            or recovery_identity["assuranceSha256"]
            != descriptor.nonce_authority_assurance_sha256
            or recovery_identity["callerNonceSha256"]
            != caller_nonce_sha256
            or recovery_identity["immutableConfigSha256"]
            != descriptor.immutable_config_sha256
            or recovery_identity["releaseIdentitySha256"]
            != descriptor.release_identity_sha256
            or recovery_identity["requestBodySha256"]
            != request_body_sha256
            or operation_id != expected_operation_id
        ):
            raise AttestationContractError(
                "public evidence recovery identity is not deterministic for its request"
            )
        recovery_key_sha256 = sha256_prefixed(
            NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_KEY_DOMAIN
            + canonical_json(recovery_identity).encode("ascii")
        )
        recovered_transition = (
            _public_evidence_lookup_prepared_transition(
                descriptor=descriptor,
                recovery_identity=recovery_identity,
                recovery_identity_sha256=recovery_identity_sha256,
                recovery_key_sha256=recovery_key_sha256,
                operation_id_base64url=operation_id_base64url,
                assurance_evidence=assurance_evidence,
                verifier_state_key=verifier_state_key,
                deadline=deadline,
            )
        )
        if recovered_transition is not None:
            return recovered_transition
        if recover_only:
            return None
        if (
            producer_invocation_base is None
            or type(expires_at_unix) is not int
        ):
            raise AttestationContractError(
                "new verifier-state preparation lacks exact invocation material"
            )
        read_request = {
            "apiVersion":
            NONCE_AUTHORITY_VERIFIER_STATE_READ_REQUEST_VERSION,
            "assuranceSha256":
            descriptor.nonce_authority_assurance_sha256,
        }
        read_response = dict(
            _require_exact_fields(
                _public_evidence_verifier_state_post(
                    descriptor=descriptor,
                    path=descriptor.verifier_state_service_read_path,
                    request=read_request,
                    deadline=deadline,
                    outcome_may_be_unknown=False,
                ),
                {
                    "apiVersion",
                    "nonActionable",
                    "state",
                    "stateSha256",
                },
                "public evidence verifier-state read response",
            )
        )
        if (
            read_response.get("apiVersion")
            != NONCE_AUTHORITY_VERIFIER_STATE_READ_RESPONSE_VERSION
            or read_response.get("nonActionable") is not True
        ):
            raise AttestationContractError(
                "public evidence verifier-state read response is invalid"
            )
        prior = public_verifier.verify_nonce_authority_verifier_state(
            read_response.get("state"),
            signing_key=verifier_state_key,
            signing_key_id=verifier_state_key_id,
            expected_state_store_identity_sha256=(
                descriptor
                .nonce_authority_verifier_state_store_identity_sha256
            ),
            assurance=descriptor.nonce_authority_assurance,
            assurance_sha256=(
                descriptor.nonce_authority_assurance_sha256
            ),
        )
        if (
            read_response.get("stateSha256")
            != prior["envelopeSha256"]
        ):
            raise AttestationContractError(
                "public evidence verifier-state read substituted or postdated its signed state"
            )
        producer_invocation_base_sha256 = sha256_prefixed(
            canonical_json(dict(producer_invocation_base)).encode(
                "ascii"
            )
        )
        challenge_issue_request = {
            "apiVersion":
            NONCE_AUTHORITY_VERIFIER_STATE_ISSUE_CHALLENGE_REQUEST_VERSION,
            "assuranceSha256":
            descriptor.nonce_authority_assurance_sha256,
            "expectedVerifierStateSha256": prior["envelopeSha256"],
            "operationIdBase64url": operation_id_base64url,
            "producerInvocationBaseSha256":
            producer_invocation_base_sha256,
            "recoveryIdentity": recovery_identity,
            "recoveryIdentitySha256": recovery_identity_sha256,
            "recoveryKeySha256": recovery_key_sha256,
        }
        challenge_issue_request_sha256 = sha256_prefixed(
            canonical_json(challenge_issue_request).encode("ascii")
        )
        challenge_recovery_request = {
            "apiVersion":
            NONCE_AUTHORITY_VERIFIER_STATE_RECOVER_CHALLENGE_REQUEST_VERSION,
            "assuranceSha256":
            descriptor.nonce_authority_assurance_sha256,
            "issueRequestSha256": challenge_issue_request_sha256,
            "operationIdBase64url": operation_id_base64url,
            "recoveryIdentity": recovery_identity,
            "recoveryIdentitySha256": recovery_identity_sha256,
            "recoveryKeySha256": recovery_key_sha256,
        }

        def recover_exact_challenge() -> dict[str, Any] | None:
            recovered = dict(
                _require_exact_fields(
                    _public_evidence_verifier_state_post(
                        descriptor=descriptor,
                        path=(
                            descriptor
                            .verifier_state_service_recover_challenge_path
                        ),
                        request=challenge_recovery_request,
                        deadline=deadline,
                        outcome_may_be_unknown=False,
                    ),
                    {
                        "apiVersion",
                        "challenge",
                        "nonActionable",
                        "replacementForbidden",
                        "status",
                    },
                    "public evidence challenge recovery response",
                )
            )
            if (
                recovered["apiVersion"]
                != NONCE_AUTHORITY_VERIFIER_STATE_RECOVER_CHALLENGE_RESPONSE_VERSION
                or recovered["nonActionable"] is not True
                or recovered["replacementForbidden"] is not True
                or recovered["status"]
                not in {"notFound", "issued", "bound", "expired"}
            ):
                raise AttestationContractError(
                    "public evidence challenge recovery response is invalid"
                )
            if recovered["status"] == "notFound":
                if recovered["challenge"] is not None:
                    raise AttestationContractError(
                        "missing challenge recovery carried challenge data"
                    )
                return None
            challenge = dict(
                _require_exact_fields(
                    recovered["challenge"],
                    {
                        "challengeBase64url",
                        "challengeExpiresAtUnix",
                        "challengeIssuedAtUnix",
                        "challengeSha256",
                        "expectedVerifierStateSha256",
                        "issueRequestSha256",
                        "operationIdBase64url",
                        "producerInvocationBaseSha256",
                        "recoveryKeySha256",
                        "replacementForbidden",
                        "status",
                    },
                    "public evidence recovered verifier challenge",
                )
            )
            if challenge["status"] != recovered["status"]:
                raise AttestationContractError(
                    "challenge recovery status is internally crossed"
                )
            return {
                "apiVersion":
                NONCE_AUTHORITY_VERIFIER_STATE_ISSUE_CHALLENGE_RESPONSE_VERSION,
                **challenge,
                "nonActionable": True,
            }

        challenge_issue = recover_exact_challenge()
        if challenge_issue is None:
            try:
                challenge_issue = dict(
                    _require_exact_fields(
                        _public_evidence_verifier_state_post(
                            descriptor=descriptor,
                            path=(
                                descriptor
                                .verifier_state_service_issue_challenge_path
                            ),
                            request=challenge_issue_request,
                            deadline=deadline,
                            outcome_may_be_unknown=True,
                        ),
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
                        "public evidence challenge issue response",
                    )
                )
            except _PublicEvidenceUnknownVerifierStateOutcome:
                challenge_issue = recover_exact_challenge()
                if challenge_issue is None:
                    raise AttestationContractError(
                        "unknown challenge issuance outcome has no exact authoritative recovery"
                    )
        if challenge_issue["status"] != "issued":
            raise AttestationContractError(
                "retained verifier challenge is bound or expired; replacement is forbidden"
            )
        verifier_challenge = b64d(
            str(challenge_issue["challengeBase64url"])
        )
        challenge_issued = _require_positive_generation(
            challenge_issue["challengeIssuedAtUnix"],
            "public evidence verifier challenge issue time",
        )
        challenge_expires = _require_positive_generation(
            challenge_issue["challengeExpiresAtUnix"],
            "public evidence verifier challenge expiry",
        )
        current_time = int(time.time())
        if (
            len(verifier_challenge) != 32
            or b64e(verifier_challenge)
            != challenge_issue["challengeBase64url"]
            or challenge_issue["apiVersion"]
            != NONCE_AUTHORITY_VERIFIER_STATE_ISSUE_CHALLENGE_RESPONSE_VERSION
            or challenge_issue["nonActionable"] is not True
            or challenge_issue["replacementForbidden"] is not True
            or challenge_issue["challengeSha256"]
            != sha256_prefixed(verifier_challenge)
            or challenge_issue["expectedVerifierStateSha256"]
            != prior["envelopeSha256"]
            or challenge_issue["issueRequestSha256"]
            != challenge_issue_request_sha256
            or challenge_issue["operationIdBase64url"]
            != operation_id_base64url
            or challenge_issue["producerInvocationBaseSha256"]
            != producer_invocation_base_sha256
            or challenge_issue["recoveryKeySha256"]
            != recovery_key_sha256
            or not challenge_issued <= current_time < challenge_expires
            or challenge_expires - challenge_issued > 30
            or prior["payload"]["committedAtUnix"] > challenge_issued
            or operation_id == verifier_challenge
        ):
            raise AttestationContractError(
                "public evidence verifier-state service-issued challenge is invalid"
            )
        producer_invocation = {
            **dict(producer_invocation_base),
            "nonceAuthorityVerifierChallengeBase64url":
            challenge_issue["challengeBase64url"],
            "nonceAuthorityVerifierStateOperationIdBase64url":
            operation_id_base64url,
        }
        producer_invocation_sha256 = sha256_prefixed(
            canonical_json(producer_invocation).encode("ascii")
        )
        request_binding = {
            "apiVersion":
            NONCE_AUTHORITY_VERIFIER_STATE_REQUEST_BINDING_VERSION,
            "expiresAtUnix": expires_at_unix,
            "nonceSha256": caller_nonce_sha256,
            "producerChannelChallengeBase64url":
            producer_invocation["producerChannelChallengeBase64url"],
            "producerEphemeralKeySha256":
            producer_invocation["producerEphemeralKeySpkiSha256"],
            "producerInvocationSha256":
            producer_invocation_sha256,
            "requestBodySha256": request_body_sha256,
            "tlsBindingSha256": tls_binding_sha256,
            "transactionIdBase64url": operation_id_base64url,
        }
        request_binding_sha256 = sha256_prefixed(
            NONCE_AUTHORITY_VERIFIER_STATE_REQUEST_BINDING_DOMAIN
            + canonical_json(request_binding).encode("ascii")
        )
        recovery_binding = {
            "apiVersion":
            NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_BINDING_VERSION,
            "assuranceSha256":
            descriptor.nonce_authority_assurance_sha256,
            "expectedVerifierStateSha256":
            prior["envelopeSha256"],
            "operationIdBase64url": operation_id_base64url,
            "requestBindingSha256": request_binding_sha256,
            "verifierChallengeSha256":
            challenge_issue["challengeSha256"],
        }
        prepare_request = {
            "apiVersion":
            NONCE_AUTHORITY_VERIFIER_STATE_PREPARE_REQUEST_VERSION,
            "assuranceSha256":
            descriptor.nonce_authority_assurance_sha256,
            "expectedVerifierStateSha256":
            prior["envelopeSha256"],
            "operationIdBase64url": operation_id_base64url,
            "priorStateRead": read_response,
            "priorStateReadSha256": sha256_prefixed(
                canonical_json(read_response).encode("ascii")
            ),
            "producerInvocation": producer_invocation,
            "producerInvocationBaseSha256":
            producer_invocation_base_sha256,
            "producerInvocationSha256":
            producer_invocation_sha256,
            "challengeIssue": challenge_issue,
            "challengeIssueSha256": sha256_prefixed(
                canonical_json(challenge_issue).encode("ascii")
            ),
            "recoveryIdentity": recovery_identity,
            "recoveryIdentitySha256": recovery_identity_sha256,
            "recoveryKeySha256": recovery_key_sha256,
            "requestBinding": request_binding,
            "requestBindingSha256": request_binding_sha256,
            "verifierChallengeBase64url":
            challenge_issue["challengeBase64url"],
        }
        prepare_request_bytes = canonical_json(
            prepare_request
        ).encode("ascii")
        prepare_response: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            try:
                prepare_response = (
                    _public_evidence_verifier_state_post(
                        descriptor=descriptor,
                        path=(
                            descriptor
                            .verifier_state_service_prepare_path
                        ),
                        request=prepare_request,
                        deadline=deadline,
                        outcome_may_be_unknown=True,
                    )
                )
                break
            except _PublicEvidenceUnknownVerifierStateOutcome:
                if (
                    canonical_json(prepare_request).encode(
                        "ascii"
                    )
                    != prepare_request_bytes
                ):
                    raise AttestationContractError(
                        "public evidence prepare recovery request drifted"
                    )
        if prepare_response is None:
            raise AttestationContractError(
                "public evidence prepare outcome remains unknown; recover the deterministic request-bound key"
            )
        prepare_response = dict(
            _require_exact_fields(
                prepare_response,
                {
                    "apiVersion",
                    "nonActionable",
                    "preparedOperation",
                    "preparedOperationSha256",
                    "recoveryKeySha256",
                    "replacementForbidden",
                    "status",
                },
                "public evidence prepared verifier-state operation",
            )
        )
        prepared_operation = dict(
            _require_exact_fields(
                prepare_response["preparedOperation"],
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
                "public evidence retained prepared operation",
            )
        )
        if (
            prepare_response["apiVersion"]
            != NONCE_AUTHORITY_VERIFIER_STATE_PREPARE_RESPONSE_VERSION
            or prepare_response["nonActionable"] is not True
            or prepare_response["replacementForbidden"] is not True
            or prepare_response["status"]
            not in {
                "prepared",
                "consumptionPending",
                "nonceConsumed",
                "casCommitted",
                "committed",
            }
            or prepare_response["preparedOperationSha256"]
            != sha256_prefixed(
                canonical_json(prepared_operation).encode("ascii")
            )
            or prepare_response["recoveryKeySha256"]
            != recovery_key_sha256
            or prepared_operation["apiVersion"]
            != NONCE_AUTHORITY_VERIFIER_STATE_PREPARED_OPERATION_VERSION
            or prepared_operation["prepareRequest"] != prepare_request
            or prepared_operation["prepareRequestSha256"]
            != sha256_prefixed(prepare_request_bytes)
            or prepared_operation["recoveryBinding"]
            != recovery_binding
            or prepared_operation["recoveryIdentity"]
            != recovery_identity
            or prepared_operation["recoveryIdentitySha256"]
            != recovery_identity_sha256
            or prepared_operation["recoveryKeySha256"]
            != recovery_key_sha256
            or prepared_operation["requestBinding"] != request_binding
            or prepared_operation["requestBindingSha256"]
            != request_binding_sha256
        ):
            raise AttestationContractError(
                "public evidence prepared operation crossed its deterministic request"
            )
        authorization = (
            _verify_public_evidence_verifier_state_authorization(
                prepared_operation["authorization"],
                descriptor=descriptor,
                verifier_state_key=verifier_state_key,
                prior=prior,
                verifier_challenge=verifier_challenge,
                operation_id_base64url=operation_id_base64url,
                now=int(time.time()),
            )
        )
        authorization_payload = authorization["payload"]
        if not (
            challenge_issued
            <= authorization_payload["issuedAtUnix"]
            < authorization_payload["expiresAtUnix"]
            <= challenge_expires
        ):
            raise AttestationContractError(
                "public evidence verifier-state authorization escaped its service-issued challenge"
            )
        if (
            prepared_operation["authorizationSha256"]
            != authorization["envelopeSha256"]
            or authorization_payload["prepareRequestSha256"]
            != prepared_operation["prepareRequestSha256"]
            or authorization_payload["recoveryIdentitySha256"]
            != recovery_identity_sha256
            or authorization_payload["recoveryKeySha256"]
            != recovery_key_sha256
            or authorization_payload["requestBindingSha256"]
            != request_binding_sha256
            or authorization_payload[
                "nonceTransactionIdBase64url"
            ]
            != operation_id_base64url
        ):
            raise AttestationContractError(
                "prepared authorization did not bind the exact durable saga"
            )
    except AttestationContractError:
        raise
    except (
        ImportError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AttestationContractError(
            "public evidence verifier-state admission failed closed"
        ) from exc
    return {
        "assuranceEvidence": assurance_evidence,
        "authorization": authorization,
        "preparedOperation": prepared_operation,
        "preparedOperationSha256":
        prepare_response["preparedOperationSha256"],
        "producerInvocation": producer_invocation,
        "producerInvocationSha256": producer_invocation_sha256,
        "recoveredStatus": prepare_response["status"],
        "recoveryIdentity": recovery_identity,
        "recoveryIdentitySha256": recovery_identity_sha256,
        "recoveryKeySha256": recovery_key_sha256,
        "requestBindingSha256": request_binding_sha256,
        "operationIdBase64url": operation_id_base64url,
        "priorRead": read_response,
        "priorReadSha256": sha256_prefixed(
            canonical_json(read_response).encode("ascii")
        ),
        "priorState": prior,
        "verifierChallengeBase64url":
        read_response["challengeBase64url"],
        "verifierChallengeSha256":
        read_response["challengeSha256"],
        "verifierStateKey": verifier_state_key,
    }


def _public_evidence_verifier_state_head_sha256(
    *,
    descriptor: PublicEvidenceProducerDescriptor,
    authorization_sha256: str,
    operation_id_base64url: str,
    nonce_authority_state_sha256: str,
    nonce_receipt_sha256: str,
    previous_head_sha256: str,
    generation: int,
) -> str:
    return sha256_prefixed(
        NONCE_AUTHORITY_VERIFIER_STATE_HEAD_DOMAIN
        + canonical_json(
            {
                "assuranceSha256":
                descriptor.nonce_authority_assurance_sha256,
                "authorizationSha256": authorization_sha256,
                "commitOperationIdBase64url":
                operation_id_base64url,
                "nonceAuthorityStateSha256":
                nonce_authority_state_sha256,
                "nonceConsumptionReceiptSha256":
                nonce_receipt_sha256,
                "previousStateStoreHeadSha256":
                previous_head_sha256,
                "stateStoreGeneration": generation,
            }
        ).encode("ascii")
    )


def _public_evidence_verifier_state_commit_candidate(
    *,
    descriptor: PublicEvidenceProducerDescriptor,
    transition: Mapping[str, Any],
    nonce_receipt: Mapping[str, Any],
    commit_request_sha256: str,
) -> dict[str, Any]:
    authorization = transition["authorization"]
    prior = transition["priorState"]
    prior_payload = prior["payload"]
    next_generation = _require_positive_generation(
        prior_payload["stateStoreGeneration"],
        "public evidence prior verifier-state generation",
    ) + 1
    if next_generation > (1 << 64) - 1:
        raise AttestationContractError(
            "public evidence verifier-state generation is terminal"
        )
    return {
        "apiVersion": VERIFIER_STATE_STORE_COMMIT_CANDIDATE_VERSION,
        "assuranceSha256":
        descriptor.nonce_authority_assurance_sha256,
        "authorizationSha256": authorization["envelopeSha256"],
        "commitRequestSha256": commit_request_sha256,
        "expectedVerifierStateSha256": prior["envelopeSha256"],
        "nonceAuthorityStateSha256":
        nonce_receipt["authorityStateSha256"],
        "nonceConsumptionReceiptSha256":
        nonce_receipt["receiptSha256"],
        "nonceConsumptionSha256":
        nonce_receipt["consumptionSha256"],
        "operationIdBase64url":
        transition["operationIdBase64url"],
        "previousCommittedAtUnix":
        prior_payload["committedAtUnix"],
        "previousStateStoreGeneration":
        prior_payload["stateStoreGeneration"],
        "previousStateStoreHeadSha256":
        prior_payload["stateStoreHeadSha256"],
        "proposedStateStoreGeneration": next_generation,
        "proposedStateStoreHeadSha256":
        _public_evidence_verifier_state_head_sha256(
            descriptor=descriptor,
            authorization_sha256=authorization["envelopeSha256"],
            operation_id_base64url=transition[
                "operationIdBase64url"
            ],
            nonce_authority_state_sha256=nonce_receipt[
                "authorityStateSha256"
            ],
            nonce_receipt_sha256=nonce_receipt["receiptSha256"],
            previous_head_sha256=prior_payload[
                "stateStoreHeadSha256"
            ],
            generation=next_generation,
        ),
        "verifierChallengeSha256":
        transition["verifierChallengeSha256"],
    }


def _verify_public_evidence_verifier_state_commit_receipt(
    value: Any,
    *,
    descriptor: PublicEvidenceProducerDescriptor,
    transition: Mapping[str, Any],
    nonce_receipt: Mapping[str, Any],
    commit_request_sha256: str,
    commit_candidate: Mapping[str, Any],
    now: int,
) -> dict[str, Any]:
    envelope, payload, envelope_sha256 = (
        _verify_public_evidence_standard_envelope(
            value,
            api_version=(
                NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_VERSION
            ),
            domain=NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_DOMAIN,
            signing_key=transition["verifierStateKey"],
            signing_key_id=(
                descriptor.nonce_authority_verifier_state_key_spki_sha256
            ),
            label="public evidence verifier-state commit receipt",
        )
    )
    payload = dict(
        _require_exact_fields(
            payload,
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
            "public evidence verifier-state commit-receipt payload",
        )
    )
    store_key, store_key_id = _load_ed25519_spki_der(
        descriptor
        .nonce_authority_verifier_state_store_attestation_public_key_spki_der_base64url,
        label="public evidence verifier-state store attestation key",
    )
    if (
        store_key_id
        != descriptor
        .nonce_authority_verifier_state_store_attestation_key_spki_sha256
    ):
        raise AttestationContractError(
            "public evidence verifier-state store attestation key crossed its pin"
        )
    store_proof_envelope, store_proof, store_proof_sha256 = (
        _verify_public_evidence_standard_envelope(
            payload.get("signedStoreCommitProof"),
            api_version=SIGNED_VERIFIER_STATE_STORE_COMMIT_PROOF_VERSION,
            domain=VERIFIER_STATE_STORE_COMMIT_PROOF_DOMAIN,
            signing_key=store_key,
            signing_key_id=store_key_id,
            label="public evidence signed verifier-state store proof",
        )
    )
    store_proof = dict(
        _require_exact_fields(
            store_proof,
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
            "public evidence verifier-state store-proof payload",
        )
    )
    authorization = transition["authorization"]
    authorization_payload = authorization["payload"]
    prior = transition["priorState"]
    prior_payload = prior["payload"]
    committed_at = _require_positive_generation(
        store_proof.get("committedAtUnix"),
        "public evidence durable verifier-state commit time",
    )
    store_generation = _require_positive_generation(
        store_proof.get("stateStoreGeneration"),
        "public evidence durable verifier-state store generation",
    )
    store_commit_index = _require_positive_generation(
        store_proof.get("stateStoreCommitIndex"),
        "public evidence durable verifier-state store commit index",
    )
    proof_observed_at = int(time.time())
    nonce_consumed_at = _require_positive_generation(
        nonce_receipt["payload"].get("consumedAtUnix"),
        "public evidence durable nonce consumption time",
    )
    expected_production_eligible = (
        descriptor.nonce_authority_assurance.get(
            "productionEligible"
        )
        is True
    )
    if (
        store_proof.get("apiVersion")
        != VERIFIER_STATE_STORE_COMMIT_PROOF_VERSION
        or store_proof.get("authorizationSha256")
        != authorization["envelopeSha256"]
        or store_proof.get("casCommitted") is not True
        or store_proof.get("commitCandidateSha256")
        != sha256_prefixed(
            canonical_json(commit_candidate).encode("ascii")
        )
        or store_proof.get("commitClockMonotonic") is not True
        or store_proof.get("commitRequestSha256")
        != commit_request_sha256
        or store_proof.get("operationIdBase64url")
        != transition["operationIdBase64url"]
        or store_proof.get("previousCommittedAtUnix")
        != prior_payload["committedAtUnix"]
        or store_proof.get("previousVerifierStateSha256")
        != prior["envelopeSha256"]
        or store_proof.get("productionEligible")
        is not expected_production_eligible
        or store_proof.get(
            "stateStoreAdministrativeDomainSha256"
        )
        != descriptor
        .nonce_authority_verifier_state_store_administrative_domain_sha256
        or store_proof.get("stateStoreAssuranceEvidenceSha256")
        != descriptor
        .nonce_authority_verifier_state_store_assurance_evidence_sha256
        or store_proof.get("stateStoreAttestationKeySpkiSha256")
        != store_key_id
        or store_proof.get("stateStoreConfigurationSha256")
        != descriptor
        .nonce_authority_verifier_state_store_configuration_sha256
        or store_generation
        != commit_candidate["proposedStateStoreGeneration"]
        or store_commit_index
        != store_generation
        or store_generation
        < descriptor
        .nonce_authority_verifier_state_store_minimum_generation
        or store_commit_index
        < descriptor
        .nonce_authority_verifier_state_store_minimum_commit_index
        or store_proof.get("stateStoreIdentitySha256")
        != descriptor
        .nonce_authority_verifier_state_store_identity_sha256
        or not nonce_consumed_at
        <= committed_at
        <= proof_observed_at
        or not prior_payload["committedAtUnix"]
        <= committed_at
    ):
        raise AttestationContractError(
            "public evidence signed store proof crossed its exact CAS candidate"
        )
    committed_state_payload = {
        "apiVersion": NONCE_AUTHORITY_VERIFIER_STATE_VERSION,
        "assuranceSha256":
        descriptor.nonce_authority_assurance_sha256,
        "authorityEpoch":
        descriptor.nonce_authority_assurance["authorityEpoch"],
        "authorityGeneration":
        descriptor.nonce_authority_assurance["authorityGeneration"],
        "commitOperationIdBase64url":
        transition["operationIdBase64url"],
        "committedAtUnix": committed_at,
        "highWaterCommitmentSha256":
        nonce_receipt["authorityState"][
            "highWaterCommitmentSha256"
        ],
        "highWaterReceiptSha256": nonce_receipt["receiptSha256"],
        "highWaterSequence":
        nonce_receipt["authorityState"]["highWaterSequence"],
        "priorVerifierStateSha256": prior["envelopeSha256"],
        "stateStoreGeneration":
        commit_candidate["proposedStateStoreGeneration"],
        "stateStoreHeadSha256":
        commit_candidate["proposedStateStoreHeadSha256"],
        "stateStoreIdentitySha256":
        descriptor
        .nonce_authority_verifier_state_store_identity_sha256,
    }
    if (
        payload.get("apiVersion")
        != NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_RECEIPT_VERSION
        or payload.get("assuranceSha256")
        != descriptor.nonce_authority_assurance_sha256
        or payload.get("authorizationSha256")
        != authorization["envelopeSha256"]
        or payload.get("casCommitted") is not True
        or payload.get("commitOperationIdBase64url")
        != transition["operationIdBase64url"]
        or payload.get("commitRequestSha256")
        != commit_request_sha256
        or payload.get("committedAtUnix") != committed_at
        or payload.get("committedVerifierState")
        != committed_state_payload
        or payload.get("committedVerifierStateSha256")
        != sha256_prefixed(
            canonical_json(committed_state_payload).encode("ascii")
        )
        or payload.get("nonceAuthorityStateSha256")
        != nonce_receipt["authorityStateSha256"]
        or payload.get("nonceConsumptionReceiptSha256")
        != nonce_receipt["receiptSha256"]
        or payload.get("nonceConsumptionSha256")
        != nonce_receipt["consumptionSha256"]
        or payload.get("nonceReceiptSigningKeySpkiSha256")
        != descriptor.nonce_store_key_spki_sha256
        or payload.get("oneUseAuthorizationConsumed") is not True
        or payload.get("preparedOperationSha256")
        != transition["preparedOperationSha256"]
        or payload.get("previousStateStoreGeneration")
        != prior_payload["stateStoreGeneration"]
        or payload.get("previousStateStoreHeadSha256")
        != prior_payload["stateStoreHeadSha256"]
        or payload.get("priorVerifierStateSha256")
        != prior["envelopeSha256"]
        or payload.get("recoveryKeySha256")
        != transition["recoveryKeySha256"]
        or payload.get("recoveryIdentitySha256")
        != transition["recoveryIdentitySha256"]
        or payload.get("requestBindingSha256")
        != transition["requestBindingSha256"]
        or payload.get("signedStoreCommitProof")
        != store_proof_envelope
        or payload.get("signedStoreCommitProofSha256")
        != store_proof_sha256
        or payload.get(
            "stateStoreAdministrativeDomainSha256"
        )
        != descriptor
        .nonce_authority_verifier_state_store_administrative_domain_sha256
        or payload.get("stateStoreAssuranceEvidenceSha256")
        != descriptor
        .nonce_authority_verifier_state_store_assurance_evidence_sha256
        or payload.get("stateStoreAttestationKeySpkiSha256")
        != store_key_id
        or payload.get("stateStoreConfigurationSha256")
        != descriptor
        .nonce_authority_verifier_state_store_configuration_sha256
        or payload.get("stateStoreGeneration")
        != store_proof.get("stateStoreGeneration")
        or payload.get("stateStoreCommitIndex")
        != store_proof.get("stateStoreCommitIndex")
        or payload.get("stateStoreIdentitySha256")
        != descriptor
        .nonce_authority_verifier_state_store_identity_sha256
        or payload.get("verifierChallengeSha256")
        != transition["verifierChallengeSha256"]
    ):
        raise AttestationContractError(
            "public evidence verifier-state commit receipt crossed its proof or successor"
        )
    return {
        "committedState": committed_state_payload,
        "document": envelope,
        "envelopeSha256": envelope_sha256,
        "payload": payload,
        "storeProof": store_proof_envelope,
        "storeProofSha256": store_proof_sha256,
    }


def _verify_public_evidence_recovered_nonce_status(
    value: Any,
    *,
    descriptor: PublicEvidenceProducerDescriptor,
    transition: Mapping[str, Any],
    nonce_receipt: Mapping[str, Any],
) -> dict[str, Any]:
    nonce_key, nonce_key_id = _load_ed25519_spki_der(
        descriptor.nonce_store_signing_public_key_spki_der_base64url,
        label="recovered nonce-status signing key",
    )
    if nonce_key_id != descriptor.nonce_store_key_spki_sha256:
        raise AttestationContractError(
            "recovered nonce-status key crossed its descriptor pin"
        )
    envelope, payload, _envelope_sha256 = (
        _verify_public_evidence_standard_envelope(
            value,
            api_version=(
                SIGNED_NONCE_TRANSACTION_STATUS_EVIDENCE_VERSION
            ),
            domain=NONCE_TRANSACTION_STATUS_EVIDENCE_DOMAIN,
            signing_key=nonce_key,
            signing_key_id=nonce_key_id,
            label="recovered nonce transaction status evidence",
        )
    )
    payload = dict(
        _require_exact_fields(
            payload,
            {
                "apiVersion",
                "consumeRequestSha256",
                "evidenceIssuedAtUnix",
                "neverConsumable",
                "nonceAuthorityVerifierStateAuthorizationSha256",
                "nonceConsumptionReceiptSha256",
                "nonceSha256",
                "preparedOperationSha256",
                "recoveryKeySha256",
                "requestBindingSha256",
                "requestOperation",
                "status",
                "transactionIdBase64url",
            },
            "recovered nonce transaction status payload",
        )
    )
    prepared = transition["preparedOperation"]
    consume_request = prepared["nonceConsumeRequest"]
    evidence_issued_at = _require_positive_generation(
        payload["evidenceIssuedAtUnix"],
        "recovered nonce-status issue time",
    )
    if (
        payload["apiVersion"]
        != NONCE_TRANSACTION_STATUS_EVIDENCE_VERSION
        or evidence_issued_at > int(time.time())
        or payload["status"] != "consumed"
        or payload["neverConsumable"] is not False
        or payload["requestOperation"] != "recoverExact"
        or payload["consumeRequestSha256"]
        != prepared["nonceConsumeRequestSha256"]
        or payload[
            "nonceAuthorityVerifierStateAuthorizationSha256"
        ]
        != prepared["authorizationSha256"]
        or payload["nonceConsumptionReceiptSha256"]
        != nonce_receipt["receiptSha256"]
        or payload["nonceSha256"] != consume_request["nonceSha256"]
        or payload["preparedOperationSha256"]
        != transition["preparedOperationSha256"]
        or payload["recoveryKeySha256"]
        != transition["recoveryKeySha256"]
        or payload["requestBindingSha256"]
        != transition["requestBindingSha256"]
        or payload["transactionIdBase64url"]
        != transition["operationIdBase64url"]
    ):
        raise AttestationContractError(
            "recovered nonce status crossed the exact consumed saga"
        )
    return envelope


def _public_evidence_commit_verifier_state_transition(
    *,
    descriptor: PublicEvidenceProducerDescriptor,
    transition: Mapping[str, Any],
    nonce_receipt: Mapping[str, Any],
    deadline: float,
) -> dict[str, Any]:
    authorization = transition["authorization"]
    commit_request = {
        "apiVersion":
        NONCE_AUTHORITY_VERIFIER_STATE_COMMIT_REQUEST_VERSION,
        "authorization": authorization["document"],
        "nonceConsumptionReceipt": nonce_receipt["document"],
        "preparedOperationSha256":
        transition["preparedOperationSha256"],
        "recoveryKeySha256": transition["recoveryKeySha256"],
        "requestBindingSha256":
        transition["requestBindingSha256"],
        "verifierChallengeBase64url":
        transition["verifierChallengeBase64url"],
    }
    commit_request_bytes = canonical_json(commit_request).encode("ascii")
    commit_request_sha256 = sha256_prefixed(commit_request_bytes)
    commit_candidate = (
        _public_evidence_verifier_state_commit_candidate(
            descriptor=descriptor,
            transition=transition,
            nonce_receipt=nonce_receipt,
            commit_request_sha256=commit_request_sha256,
        )
    )
    commit_receipt_document: dict[str, Any] | None = None
    try:
        commit_receipt_document = (
            _public_evidence_verifier_state_post(
                descriptor=descriptor,
                path=descriptor.verifier_state_service_commit_path,
                request=commit_request,
                deadline=deadline,
                outcome_may_be_unknown=True,
            )
        )
    except _PublicEvidenceUnknownVerifierStateOutcome:
        recovery_request = {
            "apiVersion":
            NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_REQUEST_VERSION,
            "recoveryIdentity": transition["recoveryIdentity"],
            "recoveryIdentitySha256":
            transition["recoveryIdentitySha256"],
            "recoveryKeySha256": transition["recoveryKeySha256"],
        }
        recovery_request_bytes = canonical_json(
            recovery_request
        ).encode("ascii")
        while time.monotonic() < deadline:
            try:
                recovered = _public_evidence_verifier_state_post(
                    descriptor=descriptor,
                    path=(
                        descriptor
                        .verifier_state_service_recover_path
                    ),
                    request=recovery_request,
                    deadline=deadline,
                    outcome_may_be_unknown=False,
                )
            except AttestationContractError:
                continue
            if (
                canonical_json(commit_request).encode("ascii")
                != commit_request_bytes
                or canonical_json(recovery_request).encode("ascii")
                != recovery_request_bytes
            ):
                raise AttestationContractError(
                    "public evidence verifier-state recovery request drifted"
                )
            recovered = dict(
                _require_exact_fields(
                    recovered,
                    {
                        "apiVersion",
                        "commitRequestSha256",
                        "commitReceipt",
                        "nonActionable",
                        "nonceConsumptionReceipt",
                        "nonceRecoveryRequired",
                        "nonceStatusEvidence",
                        "operationIdBase64url",
                        "preparedOperation",
                        "preparedOperationSha256",
                        "recoveryIdentity",
                        "recoveryIdentitySha256",
                        "recoveryKeySha256",
                        "replacementForbidden",
                        "requestBindingSha256",
                        "sameOperationOnly",
                        "status",
                    },
                    "public evidence verifier-state recovery response",
                )
            )
            status = recovered.get("status")
            if (
                recovered.get("apiVersion")
                != NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_RESPONSE_VERSION
                or recovered.get("nonActionable") is not True
                or recovered.get("operationIdBase64url")
                != transition["operationIdBase64url"]
                or recovered.get("commitRequestSha256")
                != commit_request_sha256
                or recovered.get("preparedOperation")
                != transition["preparedOperation"]
                or recovered.get("preparedOperationSha256")
                != transition["preparedOperationSha256"]
                or recovered.get("recoveryKeySha256")
                != transition["recoveryKeySha256"]
                or recovered.get("recoveryIdentity")
                != transition["recoveryIdentity"]
                or recovered.get("recoveryIdentitySha256")
                != transition["recoveryIdentitySha256"]
                or recovered.get("requestBindingSha256")
                != transition["requestBindingSha256"]
                or recovered.get("replacementForbidden") is not True
                or recovered.get("sameOperationOnly") is not True
                or recovered.get("nonceRecoveryRequired") is not False
                or status not in {"committed"}
                or recovered.get("nonceConsumptionReceipt")
                != nonce_receipt["document"]
            ):
                raise AttestationContractError(
                    "public evidence verifier-state recovery crossed its operation"
                )
            _verify_public_evidence_recovered_nonce_status(
                recovered.get("nonceStatusEvidence"),
                descriptor=descriptor,
                transition=transition,
                nonce_receipt=nonce_receipt,
            )
            receipt = recovered.get("commitReceipt")
            if not isinstance(receipt, Mapping):
                raise AttestationContractError(
                    "public evidence verifier-state recovery omitted its commit receipt"
                )
            commit_receipt_document = dict(receipt)
            break
        if commit_receipt_document is None:
            raise AttestationContractError(
                "public evidence verifier-state outcome remains unknown; the same operation must be recovered"
            )
    try:
        from scripts import verify_nitro_tee as public_verifier

        commit_receipt = (
            _verify_public_evidence_verifier_state_commit_receipt(
                commit_receipt_document,
                descriptor=descriptor,
                transition=transition,
                nonce_receipt=nonce_receipt,
                commit_request_sha256=commit_request_sha256,
                commit_candidate=commit_candidate,
                now=int(time.time()),
            )
        )
        final_read_request = {
            "apiVersion":
            NONCE_AUTHORITY_VERIFIER_STATE_READ_REQUEST_VERSION,
            "assuranceSha256":
            descriptor.nonce_authority_assurance_sha256,
        }
        final_read_response = dict(
            _require_exact_fields(
                _public_evidence_verifier_state_post(
                    descriptor=descriptor,
                    path=descriptor.verifier_state_service_read_path,
                    request=final_read_request,
                    deadline=deadline,
                    outcome_may_be_unknown=False,
                ),
                {
                    "apiVersion",
                    "nonActionable",
                    "state",
                    "stateSha256",
                },
                "public evidence committed verifier-state read",
            )
        )
        committed_state = (
            public_verifier
            .verify_nonce_authority_verifier_state(
                final_read_response.get("state"),
                signing_key=transition["verifierStateKey"],
                signing_key_id=(
                    descriptor
                    .nonce_authority_verifier_state_key_spki_sha256
                ),
                expected_state_store_identity_sha256=(
                    descriptor
                    .nonce_authority_verifier_state_store_identity_sha256
                ),
                assurance=descriptor.nonce_authority_assurance,
                assurance_sha256=(
                    descriptor.nonce_authority_assurance_sha256
                ),
            )
        )
        if (
            final_read_response.get("apiVersion")
            != NONCE_AUTHORITY_VERIFIER_STATE_READ_RESPONSE_VERSION
            or final_read_response.get("nonActionable") is not True
            or final_read_response.get("stateSha256")
            != committed_state["envelopeSha256"]
            or committed_state["payload"]
            != commit_receipt["committedState"]
        ):
            raise AttestationContractError(
                "public evidence verifier-state service did not expose the exact committed successor"
            )
    except AttestationContractError:
        raise
    except (
        ImportError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AttestationContractError(
            "public evidence committed verifier-state transition is invalid"
        ) from exc
    return {
        "apiVersion":
        NONCE_AUTHORITY_VERIFIER_STATE_TRANSITION_VERSION,
        "assurance": descriptor.nonce_authority_assurance,
        "assuranceEvidence": transition["assuranceEvidence"],
        "assuranceEvidenceSha256": (
            None
            if transition["assuranceEvidence"] is None
            else sha256_prefixed(
                canonical_json(
                    transition["assuranceEvidence"]
                ).encode("ascii")
            )
        ),
        "assuranceSha256":
        descriptor.nonce_authority_assurance_sha256,
        "authorization": authorization["document"],
        "authorizationSha256": authorization["envelopeSha256"],
        "commitRequest": commit_request,
        "commitRequestSha256": commit_request_sha256,
        "commitReceipt": commit_receipt["document"],
        "commitReceiptSha256": commit_receipt["envelopeSha256"],
        "committedState": committed_state["document"],
        "committedStateRead": final_read_response,
        "committedStateReadSha256": sha256_prefixed(
            canonical_json(final_read_response).encode("ascii")
        ),
        "committedStateSha256": committed_state["envelopeSha256"],
        "nonActionable": True,
        "nonceAuthorityState": nonce_receipt["authorityState"],
        "nonceAuthorityStateSha256":
        nonce_receipt["authorityStateSha256"],
        "nonceConsumptionReceipt": nonce_receipt["document"],
        "nonceConsumptionReceiptSha256":
        nonce_receipt["receiptSha256"],
        "nonceConsumptionSha256": nonce_receipt["consumptionSha256"],
        "operationIdBase64url":
        transition["operationIdBase64url"],
        "preparedOperation": transition["preparedOperation"],
        "preparedOperationSha256":
        transition["preparedOperationSha256"],
        "priorState": transition["priorState"]["document"],
        "priorStateRead": transition["priorRead"],
        "priorStateReadSha256": transition["priorReadSha256"],
        "priorStateSha256":
        transition["priorState"]["envelopeSha256"],
        "roleSeparationEvidence": (
            descriptor
            .nonce_authority_verifier_state_role_separation_evidence
        ),
        "roleSeparationEvidenceSha256": (
            descriptor
            .nonce_authority_verifier_state_role_separation_evidence_sha256
        ),
        "recoveryKeySha256": transition["recoveryKeySha256"],
        "recoveryIdentity": transition["recoveryIdentity"],
        "recoveryIdentitySha256":
        transition["recoveryIdentitySha256"],
        "requestBindingSha256":
        transition["requestBindingSha256"],
        "serviceBinding": {
            "apiVersion":
            PUBLIC_EVIDENCE_VERIFIER_STATE_CLIENT_VERSION,
            "clientCertificateSpkiSha256": (
                descriptor
                .verifier_state_service_client_certificate_spki_sha256
            ),
            "endpoint": (
                "https://"
                + descriptor.verifier_state_service_authority
            ),
            "serverLeafSpkiSha256": (
                descriptor
                .verifier_state_service_server_leaf_spki_sha256
            ),
            "serviceConfigurationSha256": (
                descriptor
                .verifier_state_service_configuration_sha256
            ),
            "signingKeySpkiSha256": (
                descriptor
                .nonce_authority_verifier_state_key_spki_sha256
            ),
            "stateStoreAdministrativeDomainSha256": (
                descriptor
                .nonce_authority_verifier_state_store_administrative_domain_sha256
            ),
            "stateStoreAssuranceEvidenceSha256": (
                descriptor
                .nonce_authority_verifier_state_store_assurance_evidence_sha256
            ),
            "stateStoreAttestationKeySpkiSha256": (
                descriptor
                .nonce_authority_verifier_state_store_attestation_key_spki_sha256
            ),
            "stateStoreIdentitySha256": (
                descriptor
                .nonce_authority_verifier_state_store_identity_sha256
            ),
            "stateStoreConfigurationSha256": (
                descriptor
                .nonce_authority_verifier_state_store_configuration_sha256
            ),
            "stateStoreMinimumCommitIndex": (
                descriptor
                .nonce_authority_verifier_state_store_minimum_commit_index
            ),
            "stateStoreMinimumGeneration": (
                descriptor
                .nonce_authority_verifier_state_store_minimum_generation
            ),
            "roleSeparationEvidenceSha256": (
                descriptor
                .nonce_authority_verifier_state_role_separation_evidence_sha256
            ),
        },
        "signedStoreCommitProof": commit_receipt["storeProof"],
        "signedStoreCommitProofSha256":
        commit_receipt["storeProofSha256"],
        "storeAssuranceEvidence": (
            descriptor
            .nonce_authority_verifier_state_store_assurance_evidence
        ),
        "storeAssuranceEvidenceSha256": (
            descriptor
            .nonce_authority_verifier_state_store_assurance_evidence_sha256
        ),
        "transactionIdBase64url":
        nonce_receipt["payload"]["transactionIdBase64url"],
        "verifierChallengeBase64url":
        transition["verifierChallengeBase64url"],
        "verifierChallengeSha256":
        transition["verifierChallengeSha256"],
    }


def _public_evidence_abort_prepared_transition(
    *,
    descriptor: PublicEvidenceProducerDescriptor,
    transition: Mapping[str, Any],
    deadline: float,
) -> bool:
    prepared = transition["preparedOperation"]
    status_request = {
        "apiVersion": NONCE_TRANSACTION_STATUS_REQUEST_VERSION,
        "consumeRequest": prepared["nonceConsumeRequest"],
        "preparedOperationSha256":
        transition["preparedOperationSha256"],
        "recoveryKeySha256": transition["recoveryKeySha256"],
        "requestBindingSha256":
        transition["requestBindingSha256"],
        "requestOperation": "proveNeverConsumedAndBlock",
    }
    status_response = _public_evidence_nonce_consumption_response(
        descriptor=descriptor,
        consume_request=status_request,
        deadline=deadline,
    )
    if status_response["status"] != "neverConsumed":
        return False
    abort_request = {
        "apiVersion":
        NONCE_AUTHORITY_VERIFIER_STATE_ABORT_REQUEST_VERSION,
        "nonceStatusEvidence":
        status_response["nonceStatusEvidence"],
        "preparedOperationSha256":
        transition["preparedOperationSha256"],
        "recoveryKeySha256": transition["recoveryKeySha256"],
        "requestBindingSha256":
        transition["requestBindingSha256"],
    }
    abort_response_raw: dict[str, Any] | None = None
    while time.monotonic() < deadline:
        try:
            abort_response_raw = (
                _public_evidence_verifier_state_post(
                    descriptor=descriptor,
                    path=descriptor
                    .verifier_state_service_abort_path,
                    request=abort_request,
                    deadline=deadline,
                    outcome_may_be_unknown=True,
                )
            )
            break
        except _PublicEvidenceUnknownVerifierStateOutcome:
            continue
    if abort_response_raw is None:
        raise AttestationContractError(
            "authenticated abort outcome remains unknown; recover only the exact operation"
        )
    abort_response = dict(
        _require_exact_fields(
            abort_response_raw,
            {
                "apiVersion",
                "nonceStatusEvidence",
                "nonActionable",
                "operationIdBase64url",
                "preparedOperationSha256",
                "recoveryKeySha256",
                "replacementForbidden",
                "requestBindingSha256",
                "status",
            },
            "public evidence authenticated prepared abort",
        )
    )
    if (
        abort_response["apiVersion"]
        != NONCE_AUTHORITY_VERIFIER_STATE_ABORT_RESPONSE_VERSION
        or abort_response["nonceStatusEvidence"]
        != status_response["nonceStatusEvidence"]
        or abort_response["nonActionable"] is not True
        or abort_response["operationIdBase64url"]
        != transition["operationIdBase64url"]
        or abort_response["preparedOperationSha256"]
        != transition["preparedOperationSha256"]
        or abort_response["recoveryKeySha256"]
        != transition["recoveryKeySha256"]
        or abort_response["replacementForbidden"] is not False
        or abort_response["requestBindingSha256"]
        != transition["requestBindingSha256"]
        or abort_response["status"] != "aborted"
    ):
        raise AttestationContractError(
            "authenticated abort crossed its exact never-consumed operation"
        )
    return True


def _public_evidence_consume_and_commit_nonce(
    *,
    descriptor: PublicEvidenceProducerDescriptor,
    operation_id: bytes,
    recovery_identity: Mapping[str, Any],
    caller_nonce_sha256: str,
    request_body_sha256: str,
    tls_binding_sha256: str,
    producer_invocation_base: Mapping[str, Any],
    issued_at_unix: int,
    expires_at_unix: int,
    deadline: float,
) -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    str,
]:
    immutable_config_document = _strict_json_document(
        descriptor.immutable_config_bytes,
        label="public evidence immutable configuration",
    )
    _validate_public_evidence_store_and_role_assurance(
        immutable_config_document,
        assurance=descriptor.nonce_authority_assurance,
        nonce_store_key_id=descriptor.nonce_store_key_spki_sha256,
        verifier_state_key_id=(
            descriptor.nonce_authority_verifier_state_key_spki_sha256
        ),
        store_attestation_key_id=(
            descriptor
            .nonce_authority_verifier_state_store_attestation_key_spki_sha256
        ),
        service=immutable_config_document[
            "nonceAuthorityVerifierStateService"
        ],
        now=int(time.time()),
    )
    semaphore = _public_evidence_verifier_state_semaphore(
        descriptor
    )
    if not semaphore.acquire(
        timeout=max(0.0, deadline - time.monotonic())
    ):
        raise AttestationContractError(
            "public evidence verifier-state concurrency limit is exhausted"
        )
    try:
        transition = _public_evidence_begin_verifier_state_transition(
            descriptor=descriptor,
            operation_id=operation_id,
            recovery_identity=recovery_identity,
            caller_nonce_sha256=caller_nonce_sha256,
            request_body_sha256=request_body_sha256,
            tls_binding_sha256=tls_binding_sha256,
            producer_invocation_base=producer_invocation_base,
            expires_at_unix=expires_at_unix,
            deadline=deadline,
        )
        if transition is None:
            raise AttestationContractError(
                "verifier-state transition unexpectedly remained unprepared"
            )
        producer_invocation = transition["producerInvocation"]
        producer_invocation_sha256 = transition[
            "producerInvocationSha256"
        ]
        if (
            set(producer_invocation)
            != {
                *producer_invocation_base,
                "nonceAuthorityVerifierChallengeBase64url",
                "nonceAuthorityVerifierStateOperationIdBase64url",
            }
            or any(
                producer_invocation[field] != retained_value
                for field, retained_value
                in producer_invocation_base.items()
            )
        ):
            raise AttestationContractError(
                "recovered producer invocation crossed its durable journal material"
            )
        prepared_operation = transition["preparedOperation"]
        authorized_consume_request = prepared_operation[
            "nonceConsumeRequest"
        ]
        expected_consume_request = {
            "apiVersion":
            "serverware.attestationNonceConsumeOnceRequest/v3",
            "expiresAtUnix": expires_at_unix,
            "nonceAuthorityVerifierStateAuthorizationSha256":
            transition["authorization"]["envelopeSha256"],
            "nonceSha256": caller_nonce_sha256,
            "producerChannelChallengeBase64url":
            producer_invocation["producerChannelChallengeBase64url"],
            "producerEphemeralKeySha256":
            producer_invocation["producerEphemeralKeySpkiSha256"],
            "producerInvocationSha256":
            producer_invocation_sha256,
            "requestBodySha256": request_body_sha256,
            "tlsBindingSha256": tls_binding_sha256,
            "transactionIdBase64url": b64e(operation_id),
        }
        if authorized_consume_request != expected_consume_request:
            _public_evidence_abort_prepared_transition(
                descriptor=descriptor,
                transition=transition,
                deadline=deadline,
            )
            raise AttestationContractError(
                "durably prepared nonce request differs from the exact invocation"
            )
        authorization_payload = transition["authorization"]["payload"]
        authorization_fresh = (
            authorization_payload["issuedAtUnix"]
            <= int(time.time())
            < authorization_payload["expiresAtUnix"]
        )
        if (
            not authorization_fresh
            and transition["recoveredStatus"] == "prepared"
        ):
            _public_evidence_abort_prepared_transition(
                descriptor=descriptor,
                transition=transition,
                deadline=deadline,
            )
            raise AttestationContractError(
                "public evidence verifier-state authorization expired before nonce consumption"
            )
        mark_request = {
            "apiVersion":
            NONCE_AUTHORITY_VERIFIER_STATE_MARK_CONSUMPTION_REQUEST_VERSION,
            "preparedOperationSha256":
            transition["preparedOperationSha256"],
            "recoveryKeySha256": transition["recoveryKeySha256"],
            "requestBindingSha256":
            transition["requestBindingSha256"],
        }
        mark_response_raw: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            try:
                mark_response_raw = (
                    _public_evidence_verifier_state_post(
                        descriptor=descriptor,
                        path=descriptor
                        .verifier_state_service_mark_consumption_path,
                        request=mark_request,
                        deadline=deadline,
                        outcome_may_be_unknown=True,
                    )
                )
                break
            except _PublicEvidenceUnknownVerifierStateOutcome:
                continue
        if mark_response_raw is None:
            raise AttestationContractError(
                "consumption-attempt outcome remains unknown; recover only the exact prepared operation"
            )
        mark_response = dict(
            _require_exact_fields(
                mark_response_raw,
                {
                    "apiVersion",
                    "nonActionable",
                    "nonceConsumeRequestSha256",
                    "operationIdBase64url",
                    "preparedOperationSha256",
                    "recoveryKeySha256",
                    "requestBindingSha256",
                    "status",
                },
                "public evidence consumption-attempt marker",
            )
        )
        if (
            mark_response["apiVersion"]
            != NONCE_AUTHORITY_VERIFIER_STATE_MARK_CONSUMPTION_RESPONSE_VERSION
            or mark_response["nonActionable"] is not True
            or mark_response["status"]
            not in {
                "consumptionPending",
                "nonceConsumed",
                "casCommitted",
                "committed",
            }
            or mark_response["nonceConsumeRequestSha256"]
            != prepared_operation["nonceConsumeRequestSha256"]
            or mark_response["operationIdBase64url"]
            != transition["operationIdBase64url"]
            or mark_response["preparedOperationSha256"]
            != transition["preparedOperationSha256"]
            or mark_response["recoveryKeySha256"]
            != transition["recoveryKeySha256"]
            or mark_response["requestBindingSha256"]
            != transition["requestBindingSha256"]
        ):
            raise AttestationContractError(
                "consumption marker crossed the durable prepared saga"
            )
        nonce_response: dict[str, Any] | None = None
        consume_error: BaseException | None = None
        if authorization_fresh:
            try:
                nonce_response = (
                    _public_evidence_nonce_consumption_response(
                        descriptor=descriptor,
                        consume_request=authorized_consume_request,
                        deadline=deadline,
                    )
                )
            except AttestationContractError as exc:
                consume_error = exc
        status_request = {
            "apiVersion": NONCE_TRANSACTION_STATUS_REQUEST_VERSION,
            "consumeRequest": authorized_consume_request,
            "preparedOperationSha256":
            transition["preparedOperationSha256"],
            "recoveryKeySha256": transition["recoveryKeySha256"],
            "requestBindingSha256":
            transition["requestBindingSha256"],
            "requestOperation": "recoverExact",
        }
        status_response = _public_evidence_nonce_consumption_response(
            descriptor=descriptor,
            consume_request=status_request,
            deadline=deadline,
        )
        if status_response["status"] != "consumed":
            raise AttestationContractError(
                "prepared nonce transaction remains unconsumed or unknown; "
                "recover this exact transaction without replacement"
            ) from consume_error
        retained_receipt = status_response[
            "nonceConsumptionReceipt"
        ]
        if nonce_response is None:
            nonce_response = {
                "apiVersion":
                "serverware.attestationNonceConsumeResponse/v2",
                "nonceAuthorityAssurance":
                descriptor.nonce_authority_assurance,
                "nonceAuthorityAssuranceSha256":
                descriptor.nonce_authority_assurance_sha256,
                "nonceConsumption":
                retained_receipt["payload"]["nonceConsumption"],
                "nonceConsumptionReceipt": retained_receipt,
                "nonceConsumptionReceiptSha256":
                sha256_prefixed(
                    canonical_json(retained_receipt).encode("ascii")
                ),
                "nonceConsumptionSha256":
                retained_receipt["payload"][
                    "nonceConsumptionSha256"
                ],
                "nonceStoreIdentitySha256":
                descriptor.nonce_store_identity_sha256,
            }
        elif (
            nonce_response["nonceConsumptionReceipt"]
            != retained_receipt
        ):
            raise AttestationContractError(
                "nonce status recovery substituted the consume response"
            )
        attach_request = {
            "apiVersion":
            NONCE_AUTHORITY_VERIFIER_STATE_ATTACH_NONCE_STATUS_REQUEST_VERSION,
            "nonceConsumptionReceipt": retained_receipt,
            "nonceStatusEvidence":
            status_response["nonceStatusEvidence"],
            "preparedOperationSha256":
            transition["preparedOperationSha256"],
            "recoveryKeySha256": transition["recoveryKeySha256"],
            "requestBindingSha256":
            transition["requestBindingSha256"],
        }
        attach_response_raw: dict[str, Any] | None = None
        while time.monotonic() < deadline:
            try:
                attach_response_raw = (
                    _public_evidence_verifier_state_post(
                        descriptor=descriptor,
                        path=descriptor
                        .verifier_state_service_attach_nonce_status_path,
                        request=attach_request,
                        deadline=deadline,
                        outcome_may_be_unknown=True,
                    )
                )
                break
            except _PublicEvidenceUnknownVerifierStateOutcome:
                continue
        if attach_response_raw is None:
            raise AttestationContractError(
                "nonce-status attachment outcome remains unknown; recover only the exact prepared operation"
            )
        attach_response = dict(
            _require_exact_fields(
                attach_response_raw,
                {
                    "apiVersion",
                    "nonActionable",
                    "nonceConsumptionReceipt",
                    "nonceStatusEvidence",
                    "preparedOperationSha256",
                    "recoveryKeySha256",
                    "requestBindingSha256",
                    "status",
                },
                "public evidence retained nonce-status attachment",
            )
        )
        if (
            attach_response["apiVersion"]
            != NONCE_AUTHORITY_VERIFIER_STATE_ATTACH_NONCE_STATUS_RESPONSE_VERSION
            or attach_response["nonActionable"] is not True
            or attach_response["status"] != "nonceConsumed"
            or attach_response["nonceConsumptionReceipt"]
            != retained_receipt
            or attach_response["nonceStatusEvidence"]
            != status_response["nonceStatusEvidence"]
            or attach_response["preparedOperationSha256"]
            != transition["preparedOperationSha256"]
            or attach_response["recoveryKeySha256"]
            != transition["recoveryKeySha256"]
            or attach_response["requestBindingSha256"]
            != transition["requestBindingSha256"]
        ):
            raise AttestationContractError(
                "verifier-state service did not retain the exact nonce evidence"
            )
        try:
            from scripts import verify_nitro_tee as public_verifier

            nonce_key, nonce_key_id = _load_ed25519_spki_der(
                descriptor
                .nonce_store_signing_public_key_spki_der_base64url,
                label="public evidence nonce-store signing key",
            )
            if nonce_key_id != descriptor.nonce_store_key_spki_sha256:
                raise AttestationContractError(
                    "public evidence nonce-store key crossed its descriptor pin"
                )
            verified_envelope = (
                public_verifier
                .verify_public_attestation_nonce_receipt_envelope(
                    nonce_response["nonceConsumptionReceipt"],
                    key=nonce_key,
                    key_id=nonce_key_id,
                )
            )
            prior_with_authorization = {
                **transition["priorState"],
                "authorizationSha256": (
                    transition["authorization"]["envelopeSha256"]
                ),
            }
            verified_receipt = (
                public_verifier
                .validate_public_attestation_nonce_receipt_bindings(
                    verified_envelope,
                    caller_nonce_sha256=caller_nonce_sha256,
                    request_body_sha256=request_body_sha256,
                    tls_binding_sha256=tls_binding_sha256,
                    expected_store_identity_sha256=(
                        descriptor.nonce_store_identity_sha256
                    ),
                    producer_invocation=dict(producer_invocation),
                    producer_invocation_sha256=(
                        producer_invocation_sha256
                    ),
                    issued_at_unix=issued_at_unix,
                    expires_at_unix=expires_at_unix,
                    nonce_authority_assurance=(
                        descriptor.nonce_authority_assurance
                    ),
                    nonce_authority_assurance_sha256=(
                        descriptor.nonce_authority_assurance_sha256
                    ),
                    prior_nonce_authority_verifier_state=(
                        prior_with_authorization
                    ),
                )
            )
        except AttestationContractError:
            raise
        except (
            ImportError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise AttestationContractError(
                "public evidence nonce receipt failed complete verifier-state validation"
            ) from exc
        if (
            nonce_response.get("nonceConsumption")
            != verified_receipt["consumption"]
            or nonce_response.get("nonceConsumptionSha256")
            != verified_receipt["consumptionSha256"]
            or nonce_response.get("nonceConsumptionReceiptSha256")
            != verified_receipt["receiptSha256"]
            or verified_receipt["payload"].get(
                "nonceAuthorityVerifierStateAuthorizationSha256"
            )
            != transition["authorization"]["envelopeSha256"]
        ):
            raise AttestationContractError(
                "public evidence nonce service substituted its verified response projection"
            )
        consumed_at_unix = _require_positive_generation(
            verified_receipt["payload"].get("consumedAtUnix"),
            "public evidence signed nonce receipt consumption time",
        )
        if not (
            authorization_payload["issuedAtUnix"]
            <= consumed_at_unix
            < authorization_payload["expiresAtUnix"]
        ):
            raise AttestationContractError(
                "public evidence signed nonce receipt escaped its authorization window"
            )
        completed_transition = (
            _public_evidence_commit_verifier_state_transition(
                descriptor=descriptor,
                transition=transition,
                nonce_receipt=verified_receipt,
                deadline=deadline,
            )
        )
        return (
            dict(nonce_response),
            dict(verified_receipt),
            completed_transition,
            producer_invocation,
            producer_invocation_sha256,
        )
    finally:
        semaphore.release()


def _public_evidence_recovery_journal_key(
) -> tuple[bytes | None, str | None, bool]:
    fixture_plaintext = (
        os.environ.get(
            "SERVERWARE_PUBLIC_ATTESTATION_RECOVERY_JOURNAL_FIXTURE_PLAINTEXT"
        )
        == "1"
    )
    if fixture_plaintext:
        if TEE_QUOTE_PROVIDER != "dev-signed-quote":
            raise AttestationContractError(
                "plaintext recovery journal is restricted to explicit non-production fixtures"
            )
        return None, None, True
    fd_text = os.environ.get(
        "SERVERWARE_PUBLIC_ATTESTATION_RECOVERY_JOURNAL_KEY_FD"
    )
    if (
        not isinstance(fd_text, str)
        or not fd_text.isascii()
        or not fd_text.isdecimal()
    ):
        raise AttestationContractError(
            "production recovery journal requires an explicitly retained TEE/HSM journal-key FD"
        )
    key_fd = int(fd_text)
    if not 3 <= key_fd <= 1_048_575:
        raise AttestationContractError(
            "production recovery journal key FD is invalid"
        )
    required_seals = (
        getattr(fcntl, "F_SEAL_SEAL", 0)
        | getattr(fcntl, "F_SEAL_SHRINK", 0)
        | getattr(fcntl, "F_SEAL_GROW", 0)
        | getattr(fcntl, "F_SEAL_WRITE", 0)
    )
    try:
        metadata = os.fstat(key_fd)
        seals = fcntl.fcntl(key_fd, fcntl.F_GET_SEALS)
        key = os.pread(key_fd, 33, 0)
    except (AttributeError, OSError) as exc:
        raise AttestationContractError(
            "production recovery journal key is not an immutable retained secret"
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or required_seals == 0
        or seals & required_seals != required_seals
        or len(key) != 32
    ):
        raise AttestationContractError(
            "production recovery journal key must be an exactly 32-byte sealed retained secret"
        )
    return key, sha256_prefixed(key), False


def _public_evidence_terminal_journal_recovery_identities_locked(
    *,
    directory_fd: int,
    directory_owner: int,
    maximum_entries: int,
) -> tuple[dict[str, Any], ...]:
    identities: list[dict[str, Any]] = []
    suffix = ".terminal.json"
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            if not entry.name.endswith(suffix):
                continue
            identity_key = entry.name[: -len(suffix)]
            if re.fullmatch(r"[0-9a-f]{64}", identity_key) is None:
                raise AttestationContractError(
                    "terminal journal contains an unknown entry"
                )
            if len(identities) >= maximum_entries:
                raise AttestationContractError(
                    "terminal journal inventory exceeds its hard bound"
                )
            flags = os.O_RDONLY
            flags |= getattr(os, "O_NOFOLLOW", 0)
            flags |= getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(
                entry.name,
                flags,
                dir_fd=directory_fd,
            )
            try:
                before = _terminal_journal_validate_locked_file(
                    directory_fd=directory_fd,
                    name=entry.name,
                    descriptor=descriptor,
                    directory_owner=directory_owner,
                    label="terminal journal inventory entry",
                )
                if before.st_size > 4 * 1024 * 1024:
                    raise AttestationContractError(
                        "terminal journal inventory entry is oversized"
                    )
                raw = os.read(descriptor, before.st_size + 1)
                after = _terminal_journal_validate_locked_file(
                    directory_fd=directory_fd,
                    name=entry.name,
                    descriptor=descriptor,
                    directory_owner=directory_owner,
                    label="terminal journal inventory entry",
                )
                if (
                    len(raw) != before.st_size
                    or (
                        before.st_dev,
                        before.st_ino,
                        before.st_size,
                        before.st_mtime_ns,
                        before.st_ctime_ns,
                    )
                    != (
                        after.st_dev,
                        after.st_ino,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    )
                ):
                    raise AttestationContractError(
                        "terminal journal inventory entry changed "
                        "while it was read"
                    )
            finally:
                os.close(descriptor)
            try:
                envelope = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise AttestationContractError(
                    "terminal journal inventory entry is invalid"
                ) from exc
            recovery_identity = (
                envelope.get("recoveryIdentity")
                if isinstance(envelope, Mapping)
                else None
            )
            if (
                not isinstance(recovery_identity, Mapping)
                or _terminal_journal_identity_key(
                    recovery_identity
                )
                != identity_key
            ):
                raise AttestationContractError(
                    "terminal journal inventory crossed its recovery "
                    "identity"
                )
            identities.append(dict(recovery_identity))
    return tuple(identities)


def _public_evidence_terminal_journal_recovery_identities(
    *,
    directory: str,
    maximum_entries: int,
) -> tuple[dict[str, Any], ...]:
    with _terminal_journal_directory_lock(
        directory
    ) as (directory_fd, directory_metadata):
        return (
            _public_evidence_terminal_journal_recovery_identities_locked(
                directory_fd=directory_fd,
                directory_owner=directory_metadata.st_uid,
                maximum_entries=maximum_entries,
            )
        )


def _public_evidence_terminal_authority_evidence(
    document: Mapping[str, Any],
    status: str,
    evidence_at_unix: int,
) -> dict[str, Any]:
    if status not in {"aborted", "expired"}:
        raise AttestationContractError(
            "terminal authority status is invalid"
        )
    response_key = response_public_key_info()
    core = {
        "apiVersion":
        "serverware.publicAttestationTerminalAuthorityEvidence/v1",
        "status": status,
        "recoveryIdentity": document["recoveryIdentity"],
        "terminalResultSha256": document["terminalResultSha256"],
        "evidenceAtUnix": evidence_at_unix,
        "issuer": {
            "provider": "serverware-response-identity",
            "keyId": response_key["spki_sha256"],
        },
    }
    return {
        **core,
        "signature": sign_response_statement(core),
    }


def _verify_public_evidence_terminal_authority_evidence(
    evidence: Mapping[str, Any],
) -> bool:
    try:
        response_key = response_public_key_info()
        if (
            evidence["issuer"]
            != {
                "provider": "serverware-response-identity",
                "keyId": response_key["spki_sha256"],
            }
            or not isinstance(evidence["signature"], str)
            or not evidence["signature"].startswith("ed25519:")
        ):
            return False
        public_key = serialization.load_pem_public_key(
            response_key["pem"].encode("ascii")
        )
        if not isinstance(public_key, Ed25519PublicKey):
            return False
        core = {
            key: value
            for key, value in evidence.items()
            if key != "signature"
        }
        public_key.verify(
            b64d(evidence["signature"].split(":", 1)[1]),
            canonical_json(core).encode("ascii"),
        )
        return True
    except (
        InvalidSignature,
        KeyError,
        TypeError,
        UnicodeEncodeError,
        ValueError,
    ):
        return False


def _public_evidence_terminal_journal_runtime(
    *,
    now_unix: int,
) -> tuple[str, bytes, int]:
    journal_key, _journal_key_sha256, fixture_plaintext = (
        _public_evidence_recovery_journal_key()
    )
    if fixture_plaintext or journal_key is None:
        raise AttestationContractError(
            "the active public attestation path requires a sealed terminal journal"
        )
    directory = os.fspath(
        _configured_production_path(
            "SERVERWARE_PUBLIC_ATTESTATION_RECOVERY_JOURNAL_DIR",
            "public attestation terminal journal directory",
        )
    )
    os.makedirs(directory, mode=0o700, exist_ok=True)
    directory_metadata = os.stat(directory, follow_symlinks=False)
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or directory_metadata.st_uid != 0
        or stat.S_IMODE(directory_metadata.st_mode) != 0o700
    ):
        raise AttestationContractError(
            "public attestation terminal journal must be a root-owned mode-0700 directory"
        )
    maximum_entries = _environment_positive_int(
        "SERVERWARE_PUBLIC_ATTESTATION_TERMINAL_JOURNAL_MAX_ENTRIES",
        1024,
        1,
        maximum=100_000,
    )
    _public_evidence_terminal_journal_prune(
        directory=directory,
        retained_sealing_key=journal_key,
        recovery_identities=(),
        maximum_entries=maximum_entries,
        verify_terminal_authority_evidence=(
            _verify_public_evidence_terminal_authority_evidence
        ),
        now_unix=now_unix,
        terminal_authority_evidence_for=(
            _public_evidence_terminal_authority_evidence
        ),
    )
    return directory, journal_key, maximum_entries


def _public_evidence_recovery_journal_material(
    *,
    recovery_identity: Mapping[str, Any],
    operation_id: bytes,
    issued_at_unix: int,
    expires_at_unix: int,
    tls_binding: Mapping[str, Any],
    create_if_missing: bool,
) -> dict[str, Any] | None:
    journal_key, journal_key_sha256, fixture_plaintext = (
        _public_evidence_recovery_journal_key()
    )
    tls_binding_fields = {
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
    }

    def validated_tls_binding(
        value: Any, *, label: str
    ) -> dict[str, Any]:
        binding = dict(
            _require_exact_fields(
                value,
                tls_binding_fields,
                label,
            )
        )
        binding_sha256 = _require_digest(
            binding["bindingSha256"],
            f"{label} digest",
        )
        unsigned_binding = dict(binding)
        del unsigned_binding["bindingSha256"]
        if binding_sha256 != sha256_prefixed(
            canonical_json(unsigned_binding).encode("ascii")
        ):
            raise AttestationContractError(
                f"{label} digest is invalid"
            )
        return binding

    current_tls_binding = validated_tls_binding(
        tls_binding,
        label="current public attestation TLS binding",
    )
    current_tls_binding_sha256 = current_tls_binding[
        "bindingSha256"
    ]
    directory_path = _configured_production_path(
        "SERVERWARE_PUBLIC_ATTESTATION_RECOVERY_JOURNAL_DIR",
        "public attestation recovery journal directory",
    )
    if (
        not directory_path.is_absolute()
        or "." in directory_path.parts
        or ".." in directory_path.parts
        or os.path.normpath(os.fspath(directory_path))
        != os.fspath(directory_path)
    ):
        raise AttestationContractError(
            "public attestation recovery journal path is not normalized and absolute"
        )
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if no_follow is None or directory_flag is None:
        raise AttestationContractError(
            "public attestation recovery journal requires no-follow file operations"
        )
    directory_fd = os.open(
        directory_path,
        os.O_RDONLY
        | directory_flag
        | no_follow
        | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        directory_stat = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != 0
            or stat.S_IMODE(directory_stat.st_mode) != 0o700
        ):
            raise AttestationContractError(
                "public attestation recovery journal must be a root-owned mode-0700 directory"
            )
        recovery_identity_sha256 = sha256_prefixed(
            canonical_json(recovery_identity).encode("ascii")
        )
        recovery_key_sha256 = sha256_prefixed(
            NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_KEY_DOMAIN
            + canonical_json(recovery_identity).encode("ascii")
        )
        filename = recovery_key_sha256[7:] + ".json"
        expected_identity = {
            "apiVersion":
            "serverware.publicAttestationRecoveryJournalEntry/v2",
            "operationIdBase64url": b64e(operation_id),
            "recoveryIdentity": dict(recovery_identity),
            "recoveryIdentitySha256": recovery_identity_sha256,
            "recoveryKeySha256": recovery_key_sha256,
        }
        journal_aad = canonical_json(
            {
                **expected_identity,
                "journalKeySha256": journal_key_sha256,
            }
        ).encode("ascii")

        def encode_retained(
            retained: Mapping[str, Any],
        ) -> bytes:
            plaintext = (
                canonical_json(dict(retained)).encode("ascii") + b"\n"
            )
            if fixture_plaintext:
                return plaintext
            if journal_key is None or journal_key_sha256 is None:
                raise AttestationContractError(
                    "production recovery journal key is unavailable"
                )
            nonce = secrets.token_bytes(12)
            ciphertext = AESGCM(journal_key).encrypt(
                nonce,
                plaintext,
                journal_aad,
            )
            sealed = {
                "apiVersion":
                PUBLIC_ATTESTATION_RECOVERY_JOURNAL_SEALED_ENTRY_VERSION,
                "ciphertextBase64url": b64e(ciphertext),
                "journalKeySha256": journal_key_sha256,
                "nonceBase64url": b64e(nonce),
                "plaintextSha256": sha256_prefixed(plaintext),
                "recoveryKeySha256": recovery_key_sha256,
            }
            return canonical_json(sealed).encode("ascii") + b"\n"

        def decode_retained(raw: bytes) -> tuple[dict[str, Any], bytes]:
            outer = _strict_json_document(
                raw,
                label="public attestation recovery journal entry",
            )
            if fixture_plaintext:
                plaintext = raw
            else:
                sealed = _require_exact_fields(
                    outer,
                    {
                        "apiVersion",
                        "ciphertextBase64url",
                        "journalKeySha256",
                        "nonceBase64url",
                        "plaintextSha256",
                        "recoveryKeySha256",
                    },
                    "sealed public attestation recovery journal entry",
                )
                if (
                    journal_key is None
                    or journal_key_sha256 is None
                    or sealed["apiVersion"]
                    != PUBLIC_ATTESTATION_RECOVERY_JOURNAL_SEALED_ENTRY_VERSION
                    or sealed["journalKeySha256"]
                    != journal_key_sha256
                    or sealed["recoveryKeySha256"]
                    != recovery_key_sha256
                ):
                    raise AttestationContractError(
                        "sealed recovery journal entry crossed its retained key or recovery identity"
                    )
                try:
                    nonce = b64d(sealed["nonceBase64url"])
                    ciphertext = b64d(
                        sealed["ciphertextBase64url"]
                    )
                    if len(nonce) != 12:
                        raise ValueError(
                            "journal nonce length is invalid"
                        )
                    plaintext = AESGCM(journal_key).decrypt(
                        nonce,
                        ciphertext,
                        journal_aad,
                    )
                except (
                    binascii.Error,
                    InvalidTag,
                    TypeError,
                    UnicodeEncodeError,
                    ValueError,
                ) as exc:
                    raise AttestationContractError(
                        "sealed recovery journal entry authentication failed"
                    ) from exc
                if sealed["plaintextSha256"] != sha256_prefixed(
                    plaintext
                ):
                    raise AttestationContractError(
                        "sealed recovery journal plaintext digest is invalid"
                    )
            retained_document = _strict_json_document(
                plaintext,
                label="public attestation recovery journal plaintext",
            )
            return dict(retained_document), plaintext

        def recovery_material(label: bytes) -> bytes:
            if fixture_plaintext:
                return secrets.token_bytes(32)
            if journal_key is None:
                raise AttestationContractError(
                    "production recovery material key is unavailable"
                )
            return hmac.new(
                journal_key,
                PUBLIC_ATTESTATION_RECOVERY_MATERIAL_DOMAIN
                + label
                + canonical_json(recovery_identity).encode("ascii"),
                hashlib.sha256,
            ).digest()

        class JournalEntryMissing(Exception):
            pass

        def read_retained() -> dict[str, Any]:
            try:
                file_fd = os.open(
                    filename,
                    os.O_RDONLY
                    | no_follow
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=directory_fd,
                )
            except FileNotFoundError as exc:
                raise JournalEntryMissing from exc
            try:
                before = os.fstat(file_fd)
                if before.st_nlink == 2:
                    linked_temporaries: list[str] = []
                    with os.scandir(directory_fd) as entries:
                        for item in entries:
                            if (
                                item.name.startswith(
                                    "." + filename + "."
                                )
                                and item.name.endswith(".tmp")
                            ):
                                item_stat = item.stat(
                                    follow_symlinks=False
                                )
                                if (
                                    item_stat.st_dev == before.st_dev
                                    and item_stat.st_ino
                                    == before.st_ino
                                ):
                                    linked_temporaries.append(
                                        item.name
                                    )
                    if len(linked_temporaries) != 1:
                        raise AttestationContractError(
                            "public attestation recovery journal has an ambiguous linked temporary"
                        )
                    os.unlink(
                        linked_temporaries[0],
                        dir_fd=directory_fd,
                    )
                    os.fsync(directory_fd)
                    before = os.fstat(file_fd)
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or before.st_uid != 0
                    or stat.S_IMODE(before.st_mode) != 0o600
                    or not 1 <= before.st_size <= 16_384
                ):
                    raise AttestationContractError(
                        "public attestation recovery journal entry is unsafe"
                    )
                raw = bytearray()
                while len(raw) <= 16_384:
                    chunk = os.read(file_fd, 16_385 - len(raw))
                    if not chunk:
                        break
                    raw.extend(chunk)
                after = os.fstat(file_fd)
                if (
                    (
                        before.st_dev,
                        before.st_ino,
                        before.st_mode,
                        before.st_nlink,
                        before.st_uid,
                        before.st_gid,
                        before.st_size,
                        before.st_mtime_ns,
                        before.st_ctime_ns,
                    )
                    != (
                        after.st_dev,
                        after.st_ino,
                        after.st_mode,
                        after.st_nlink,
                        after.st_uid,
                        after.st_gid,
                        after.st_size,
                        after.st_mtime_ns,
                        after.st_ctime_ns,
                    )
                    or len(raw) != before.st_size
                    or len(raw) > 16_384
                ):
                    raise AttestationContractError(
                        "public attestation recovery journal entry changed while read"
                    )
            finally:
                os.close(file_fd)
            retained_document, retained_raw = decode_retained(bytes(raw))
            retained = dict(
                _require_exact_fields(
                    retained_document,
                    {
                        *expected_identity,
                        "expiresAtUnix",
                        "issuedAtUnix",
                        "producerChannelChallengeBase64url",
                        "producerEphemeralSeedBase64url",
                        "tlsBinding",
                        "tlsBindingSha256",
                        "witnessVerifierChallengeBase64url",
                    },
                    "public attestation recovery journal entry",
                )
            )
            retained_tls_binding = validated_tls_binding(
                retained["tlsBinding"],
                label=(
                    "retained public attestation TLS binding"
                ),
            )
            if (
                canonical_json(retained).encode("ascii") + b"\n"
                != retained_raw
                or any(
                    retained[field] != expected_identity[field]
                    for field in expected_identity
                )
                or type(retained["issuedAtUnix"]) is not int
                or type(retained["expiresAtUnix"]) is not int
                or not 1
                <= retained["issuedAtUnix"]
                <= issued_at_unix
                or not retained["issuedAtUnix"]
                < retained["expiresAtUnix"]
                or not 15
                <= retained["expiresAtUnix"]
                - retained["issuedAtUnix"]
                <= 30
                or retained["tlsBindingSha256"]
                != retained_tls_binding["bindingSha256"]
                or retained_tls_binding["peerIdentity"]
                != current_tls_binding["peerIdentity"]
                or retained_tls_binding["peerSpkiSha256"]
                != current_tls_binding["peerSpkiSha256"]
                or len(
                    b64d(retained["producerEphemeralSeedBase64url"])
                )
                != 32
                or len(
                    b64d(
                        retained[
                            "producerChannelChallengeBase64url"
                        ]
                    )
                )
                != 32
                or len(
                    b64d(
                        retained[
                            "witnessVerifierChallengeBase64url"
                        ]
                    )
                )
                != 32
            ):
                raise AttestationContractError(
                    "public attestation recovery journal crossed its exact request"
                )
            retained["tlsBinding"] = retained_tls_binding
            retained["recoveryJournalPath"] = os.path.join(
                os.fspath(directory_path),
                filename,
            )
            return retained

        try:
            return read_retained()
        except JournalEntryMissing:
            if not create_if_missing:
                return None
        entry = {
            **expected_identity,
            "expiresAtUnix": expires_at_unix,
            "issuedAtUnix": issued_at_unix,
            "producerChannelChallengeBase64url":
            b64e(recovery_material(b"producer-channel-challenge\x00")),
            "producerEphemeralSeedBase64url":
            b64e(recovery_material(b"producer-ephemeral-seed\x00")),
            "tlsBinding": current_tls_binding,
            "tlsBindingSha256": current_tls_binding_sha256,
            "witnessVerifierChallengeBase64url":
            b64e(recovery_material(b"witness-verifier-challenge\x00")),
        }
        encoded = encode_retained(entry)
        if len(encoded) > 16_384:
            raise AttestationContractError(
                "public attestation recovery journal entry exceeds its bound"
            )
        entry_count = 0
        with os.scandir(directory_fd) as entries:
            for item in entries:
                entry_count += 1
                if entry_count >= 1024:
                    raise AttestationContractError(
                        "public attestation recovery journal is full"
                    )
                if not (
                    item.name.endswith(".json")
                    or item.name.endswith(".tmp")
                ):
                    raise AttestationContractError(
                        "public attestation recovery journal contains an unknown entry"
                    )
        temporary_name = (
            "."
            + filename
            + "."
            + secrets.token_hex(16)
            + ".tmp"
        )
        try:
            file_fd = os.open(
                temporary_name,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | no_follow
                | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=directory_fd,
            )
        except FileExistsError as exc:
            raise AttestationContractError(
                "public attestation recovery journal temporary name collided"
            ) from exc
        try:
            written = 0
            while written < len(encoded):
                count = os.write(file_fd, encoded[written:])
                if count <= 0:
                    raise OSError("short recovery journal write")
                written += count
            os.fsync(file_fd)
        finally:
            os.close(file_fd)
        try:
            try:
                os.link(
                    temporary_name,
                    filename,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                os.fsync(directory_fd)
            except FileExistsError:
                pass
        finally:
            os.unlink(temporary_name, dir_fd=directory_fd)
            os.fsync(directory_fd)
        try:
            return read_retained()
        except JournalEntryMissing as exc:
            raise AttestationContractError(
                "public attestation recovery journal lost its retained entry"
            ) from exc
    except AttestationContractError:
        raise
    except OSError as exc:
        raise AttestationContractError(
            "public attestation recovery journal failed closed"
        ) from exc
    finally:
        os.close(directory_fd)


def _public_evidence_request_context(
    *,
    raw_request_body: bytes,
    tls_scope: TrustedTlsScope,
    descriptor: PublicEvidenceProducerDescriptor,
    now: int,
    terminal_journal: tuple[str, bytes, int] | None = None,
) -> tuple[dict[str, Any], bytes]:
    if not 1 <= len(raw_request_body) <= 4096:
        raise AttestationContractError(
            "public evidence request body exceeds its bound"
        )
    request = _strict_json_document(
        raw_request_body, label="public evidence request"
    )
    if raw_request_body != canonical_json(request).encode("ascii"):
        raise AttestationContractError(
            "public evidence request must be canonical JSON without a newline"
        )
    request = _require_exact_fields(
        request,
        {"apiVersion", "callerNonceBase64url"},
        "public evidence request",
    )
    if request.get("apiVersion") != PUBLIC_EVIDENCE_REQUEST_VERSION:
        raise AttestationContractError(
            "public evidence request version is invalid"
        )
    encoded_nonce = request.get("callerNonceBase64url")
    if not isinstance(encoded_nonce, str) or len(encoded_nonce) != 43:
        raise AttestationContractError(
            "public evidence caller nonce is invalid"
        )
    try:
        caller_nonce = b64d(encoded_nonce)
    except (binascii.Error, UnicodeEncodeError, ValueError) as exc:
        raise AttestationContractError(
            "public evidence caller nonce is invalid"
        ) from exc
    if len(caller_nonce) != 32 or b64e(caller_nonce) != encoded_nonce:
        raise AttestationContractError(
            "public evidence caller nonce is not canonical"
        )
    if (
        type(now) is not int
        or not tls_scope.issued_at_unix <= now < tls_scope.expires_at_unix
    ):
        raise AttestationContractError(
            "public evidence TLS scope is stale"
        )
    expires_at = min(now + 30, tls_scope.expires_at_unix)
    if expires_at - now < 15:
        raise AttestationContractError(
            "public evidence TLS scope has insufficient remaining lifetime"
        )
    tls_binding = tls_scope.binding_document()
    tls_binding_sha256 = _require_digest(
        tls_binding.get("bindingSha256"),
        "public evidence TLS binding",
    )
    current_tls_binding = dict(tls_binding)
    current_tls_binding_sha256 = tls_binding_sha256
    request_body_sha256 = sha256_prefixed(raw_request_body)
    caller_nonce_sha256 = sha256_prefixed(caller_nonce)
    static_pins = {
        "descriptorSha256": descriptor.descriptor_sha256,
        "executableSha256": descriptor.executable_sha256,
        "immutableConfigSha256": descriptor.immutable_config_sha256,
        "nonceStoreIdentitySha256":
        descriptor.nonce_store_identity_sha256,
        "nonceStoreKeySpkiSha256":
        descriptor.nonce_store_key_spki_sha256,
        "producerRequestSchemaSha256":
        descriptor.producer_request_schema_sha256,
        "sandboxDescriptorSha256":
        descriptor.sandbox_descriptor_sha256,
        "sandboxLauncherSha256":
        descriptor.sandbox_launcher_sha256,
        "trustRootsSha256": descriptor.trust_roots_sha256,
        "witnessStoreIdentitySha256":
        descriptor.witness_store_identity_sha256,
        "witnessStoreKeySpkiSha256":
        descriptor.witness_store_key_spki_sha256,
    }
    verifier_state_recovery_identity = {
        "apiVersion":
        NONCE_AUTHORITY_VERIFIER_STATE_RECOVERY_IDENTITY_VERSION,
        "assuranceSha256":
        descriptor.nonce_authority_assurance_sha256,
        "callerNonceSha256": caller_nonce_sha256,
        "immutableConfigSha256": descriptor.immutable_config_sha256,
        "releaseIdentitySha256": descriptor.release_identity_sha256,
        "requestBodySha256": request_body_sha256,
    }
    nonce_authority_verifier_state_operation_id = hashlib.sha256(
        NONCE_AUTHORITY_VERIFIER_STATE_OPERATION_ID_DOMAIN
        + canonical_json(
            verifier_state_recovery_identity
        ).encode("ascii")
    ).digest()
    if terminal_journal is not None:
        terminal_directory, terminal_key, maximum_entries = (
            terminal_journal
        )
        try:
            with _terminal_journal_lock(
                terminal_directory,
                verifier_state_recovery_identity,
            ) as (directory_fd, directory_metadata):
                terminal_result = (
                    _public_evidence_terminal_journal_load_locked(
                        directory_fd=directory_fd,
                        directory_owner=directory_metadata.st_uid,
                        retained_sealing_key=terminal_key,
                        recovery_identity=(
                            verifier_state_recovery_identity
                        ),
                    )
                )
                _terminal_journal_remove_prepared_locked(
                    directory_fd=directory_fd,
                    directory_owner=directory_metadata.st_uid,
                    prepared_path=(
                        _public_evidence_prepared_journal_path(
                            terminal_directory,
                            verifier_state_recovery_identity,
                        )
                    ),
                )
        except FileNotFoundError:
            terminal_result = None
        if terminal_result is not None:
            return (
                {
                    "callerNonce": caller_nonce,
                    "callerNonceSha256": caller_nonce_sha256,
                    "currentTlsBinding": current_tls_binding,
                    "currentTlsBindingSha256":
                    current_tls_binding_sha256,
                    "recoveredTerminalResult": terminal_result,
                    "recoveryIdentity":
                    verifier_state_recovery_identity,
                    "requestBody": raw_request_body,
                    "requestBodySha256": request_body_sha256,
                    "terminalJournalDirectory":
                    terminal_directory,
                    "terminalJournalKey": terminal_key,
                    "terminalJournalMaximumEntries":
                    maximum_entries,
                },
                b"",
            )
        retained_identities = (
            _public_evidence_terminal_journal_recovery_identities(
                directory=terminal_directory,
                maximum_entries=maximum_entries + 1,
            )
        )
        if len(retained_identities) >= maximum_entries:
            raise AttestationContractError(
                "terminal journal capacity is occupied by unexpired "
                "response-pending results"
            )
    deadline = time.monotonic() + min(
        12.0,
        descriptor.nonce_service_timeout_milliseconds / 1000.0,
        descriptor.verifier_state_service_timeout_milliseconds / 1000.0,
    )
    journal_material = _public_evidence_recovery_journal_material(
        recovery_identity=verifier_state_recovery_identity,
        operation_id=nonce_authority_verifier_state_operation_id,
        issued_at_unix=now,
        expires_at_unix=expires_at,
        tls_binding=tls_binding,
        create_if_missing=False,
    )
    if journal_material is None:
        recovered_without_journal = (
            _public_evidence_begin_verifier_state_transition(
                descriptor=descriptor,
                operation_id=(
                    nonce_authority_verifier_state_operation_id
                ),
                recovery_identity=(
                    verifier_state_recovery_identity
                ),
                caller_nonce_sha256=caller_nonce_sha256,
                request_body_sha256=request_body_sha256,
                tls_binding_sha256=tls_binding_sha256,
                producer_invocation_base=None,
                expires_at_unix=None,
                deadline=deadline,
                recover_only=True,
            )
        )
        if recovered_without_journal is not None:
            raise AttestationContractError(
                "authoritative prepared operation exists but its exact local producer key material is unavailable"
            )
        journal_material = (
            _public_evidence_recovery_journal_material(
                recovery_identity=(
                    verifier_state_recovery_identity
                ),
                operation_id=(
                    nonce_authority_verifier_state_operation_id
                ),
                issued_at_unix=now,
                expires_at_unix=expires_at,
                tls_binding=tls_binding,
                create_if_missing=True,
            )
        )
    if journal_material is None:
        raise AttestationContractError(
            "public attestation recovery journal did not retain exact material"
        )
    issued_at = journal_material["issuedAtUnix"]
    expires_at = journal_material["expiresAtUnix"]
    tls_binding = journal_material["tlsBinding"]
    tls_binding_sha256 = journal_material["tlsBindingSha256"]
    producer_ephemeral_seed = b64d(
        journal_material["producerEphemeralSeedBase64url"]
    )
    ephemeral_private_key = Ed25519PrivateKey.from_private_bytes(
        producer_ephemeral_seed
    )
    ephemeral_spki_der = (
        ephemeral_private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    producer_ephemeral_key_spki_sha256 = sha256_prefixed(
        ephemeral_spki_der
    )
    historical_tls_role_keys = {
        "historicalTlsLeaf": _require_digest(
            tls_binding.get("leafSpkiSha256"),
            "public evidence TLS leaf SPKI",
        ),
        "historicalTlsPeer": _require_digest(
            tls_binding.get("peerSpkiSha256"),
            "public evidence TLS peer SPKI",
        ),
    }
    current_tls_role_keys = {
        "currentTlsLeaf": _require_digest(
            current_tls_binding.get("leafSpkiSha256"),
            "current public evidence TLS leaf SPKI",
        ),
        "currentTlsPeer": _require_digest(
            current_tls_binding.get("peerSpkiSha256"),
            "current public evidence TLS peer SPKI",
        ),
    }
    _validate_global_attestation_key_role_separation(
        historical_tls_role_keys
    )
    _validate_global_attestation_key_role_separation(
        current_tls_role_keys
    )
    dynamic_role_keys = tuple(
        dict.fromkeys(
            (
                producer_ephemeral_key_spki_sha256,
                *historical_tls_role_keys.values(),
                *current_tls_role_keys.values(),
            )
        )
    )
    _validate_global_attestation_key_role_separation(
        {
            **{
                f"configuredRole:{index}": key_id
                for index, key_id in enumerate(
                    descriptor.global_role_key_spki_sha256s
                )
            },
            **{
                f"dynamicRole:{index}": key_id
                for index, key_id in enumerate(dynamic_role_keys)
            },
        }
    )
    producer_channel_challenge_base64url = journal_material[
        "producerChannelChallengeBase64url"
    ]
    witness_verifier_challenge_base64url = journal_material[
        "witnessVerifierChallengeBase64url"
    ]
    if (
        nonce_authority_verifier_state_operation_id
        in {
            caller_nonce,
            b64d(producer_channel_challenge_base64url),
            b64d(witness_verifier_challenge_base64url),
        }
    ):
        raise AttestationContractError(
            "deterministic verifier-state operation identity collided with a request challenge"
        )
    producer_invocation_base = {
        "apiVersion":
        "serverware.publicAttestationProducerInvocation/v1",
        "callerNonceSha256": caller_nonce_sha256,
        "expiresAtUnix": expires_at,
        "issuedAtUnix": issued_at,
        "minimumReleaseIdentitySha256":
        descriptor.release_identity_sha256,
        "minimumRollbackContinuityCommitmentSha256":
        descriptor.minimum_rollback_continuity_commitment_sha256,
        "producerChannelChallengeBase64url":
        producer_channel_challenge_base64url,
        "producerEphemeralKeySpkiDerBase64url":
        b64e(ephemeral_spki_der),
        "producerEphemeralKeySpkiSha256":
        producer_ephemeral_key_spki_sha256,
        "releaseIdentitySha256":
        descriptor.release_identity_sha256,
        "requestBodySha256": request_body_sha256,
        "staticPins": static_pins,
        "tlsBindingSha256": tls_binding_sha256,
        "witnessVerifierChallengeBase64url":
        witness_verifier_challenge_base64url,
    }
    (
        nonce_response,
        verified_nonce_receipt,
        verifier_state_transition,
        producer_invocation,
        producer_invocation_sha256,
    ) = _public_evidence_consume_and_commit_nonce(
        descriptor=descriptor,
        operation_id=(
            nonce_authority_verifier_state_operation_id
        ),
        recovery_identity=verifier_state_recovery_identity,
        caller_nonce_sha256=caller_nonce_sha256,
        request_body_sha256=request_body_sha256,
        tls_binding_sha256=tls_binding_sha256,
        producer_invocation_base=producer_invocation_base,
        issued_at_unix=issued_at,
        expires_at_unix=expires_at,
        deadline=deadline,
    )
    nonce_consumption = verified_nonce_receipt["consumption"]
    nonce_receipt = verified_nonce_receipt["document"]
    producer_request = {
        "apiVersion": PUBLIC_EVIDENCE_PRODUCER_REQUEST_VERSION,
        "liveSessionRequest": {
            "apiVersion": PUBLIC_EVIDENCE_LIVE_REQUEST_VERSION,
            "callerNonceBase64url": encoded_nonce,
            "callerNonceSha256": caller_nonce_sha256,
            "expiresAtUnix": expires_at,
            "httpRequest": {
                "bodySha256": request_body_sha256,
                "method": "POST",
                "path": "/attestation/public-evidence",
            },
            "issuedAtUnix": issued_at,
            "nonceConsumption": nonce_consumption,
            "nonceConsumptionReceipt": nonce_receipt,
            "nonceConsumptionReceiptSha256":
            nonce_response["nonceConsumptionReceiptSha256"],
            "nonceAuthorityVerifierStateTransition":
            verifier_state_transition,
            "oneUse": True,
            "producerInvocation": producer_invocation,
            "producerInvocationSha256":
            producer_invocation_sha256,
            "tlsBinding": tls_binding,
            "tlsBindingSha256": tls_binding_sha256,
        },
        "releaseIdentitySha256": descriptor.release_identity_sha256,
        "staticPins": static_pins,
    }
    request_bytes = (
        canonical_json(producer_request).encode("ascii") + b"\n"
    )
    if len(request_bytes) > descriptor.max_input_bytes:
        raise AttestationContractError(
            "public evidence producer request exceeds its configured bound"
        )
    context = {
        "callerNonce": caller_nonce,
        "callerNonceBase64url": encoded_nonce,
        "callerNonceSha256": caller_nonce_sha256,
        "expiresAtUnix": expires_at,
        "issuedAtUnix": issued_at,
        "nonceConsumption": nonce_consumption,
        "nonceConsumptionSha256": sha256_prefixed(
            canonical_json(nonce_consumption).encode("ascii")
        ),
        "nonceConsumptionReceipt": nonce_receipt,
        "nonceConsumptionReceiptSha256":
        nonce_response["nonceConsumptionReceiptSha256"],
        "nonceAuthorityVerifierChallengeBase64url":
        verifier_state_transition["verifierChallengeBase64url"],
        "nonceAuthorityVerifierStateOperationIdBase64url":
        b64e(nonce_authority_verifier_state_operation_id),
        "nonceAuthorityVerifierStateTransition":
        verifier_state_transition,
        "nonceAuthorityVerifierStateTransitionSha256":
        sha256_prefixed(
            canonical_json(
                verifier_state_transition
            ).encode("ascii")
        ),
        "producerEphemeralKeySpkiSha256":
        producer_ephemeral_key_spki_sha256,
        "producerEphemeralSeed": producer_ephemeral_seed,
        "preparedJournalPath":
        journal_material["recoveryJournalPath"],
        "producerInvocation": producer_invocation,
        "producerInvocationSha256":
        producer_invocation_sha256,
        "producerRequestSha256": sha256_prefixed(request_bytes),
        "requestBody": raw_request_body,
        "requestBodySha256": request_body_sha256,
        "currentTlsBinding": current_tls_binding,
        "currentTlsBindingSha256": current_tls_binding_sha256,
        "recoveryIdentity": verifier_state_recovery_identity,
        "recoveryIdentitySha256": sha256_prefixed(
            canonical_json(
                verifier_state_recovery_identity
            ).encode("ascii")
        ),
        "tlsBinding": tls_binding,
        "tlsBindingSha256": tls_binding_sha256,
        "terminalJournalDirectory": (
            None if terminal_journal is None else terminal_journal[0]
        ),
        "terminalJournalKey": (
            None if terminal_journal is None else terminal_journal[1]
        ),
        "terminalJournalMaximumEntries": (
            None if terminal_journal is None else terminal_journal[2]
        ),
        "witnessVerifierChallengeBase64url":
        witness_verifier_challenge_base64url,
    }
    return context, request_bytes


def _verify_public_evidence_producer_binding(
    value: Any,
    *,
    context: Mapping[str, Any],
    descriptor: PublicEvidenceProducerDescriptor,
    witness_current_request_sha256: str,
    now: int,
) -> dict[str, Any]:
    envelope = dict(
        _require_exact_fields(
            value,
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
    )
    transition = context["nonceAuthorityVerifierStateTransition"]
    expected_payload = {
        "apiVersion": PUBLIC_EVIDENCE_PRODUCER_BINDING_VERSION,
        "callerNonceSha256": context["callerNonceSha256"],
        "descriptorSha256": descriptor.descriptor_sha256,
        "executableSha256": descriptor.executable_sha256,
        "expiresAtUnix": context["expiresAtUnix"],
        "immutableConfigSha256": descriptor.immutable_config_sha256,
        "issuedAtUnix": context["issuedAtUnix"],
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
        descriptor.verifier_state_service_configuration_sha256,
        "nonceAuthorityVerifierStateSigningKeySpkiSha256":
        descriptor.nonce_authority_verifier_state_key_spki_sha256,
        "nonceAuthorityVerifierStateStoreAdministrativeDomainSha256":
        descriptor
        .nonce_authority_verifier_state_store_administrative_domain_sha256,
        "nonceAuthorityVerifierStateStoreAssuranceEvidenceSha256":
        descriptor
        .nonce_authority_verifier_state_store_assurance_evidence_sha256,
        "nonceAuthorityVerifierStateRoleSeparationEvidenceSha256":
        descriptor
        .nonce_authority_verifier_state_role_separation_evidence_sha256,
        "nonceAuthorityVerifierStateStoreAttestationKeySpkiSha256":
        descriptor
        .nonce_authority_verifier_state_store_attestation_key_spki_sha256,
        "nonceAuthorityVerifierStateStoreCommitProofSha256":
        transition["signedStoreCommitProofSha256"],
        "nonceAuthorityVerifierStateStoreConfigurationSha256":
        descriptor
        .nonce_authority_verifier_state_store_configuration_sha256,
        "nonceAuthorityVerifierStateStoreIdentitySha256":
        descriptor
        .nonce_authority_verifier_state_store_identity_sha256,
        "nonceAuthorityVerifierStateStoreMinimumCommitIndex":
        descriptor
        .nonce_authority_verifier_state_store_minimum_commit_index,
        "nonceAuthorityVerifierStateStoreMinimumGeneration":
        descriptor
        .nonce_authority_verifier_state_store_minimum_generation,
        "nonceAuthorityVerifierStateTransitionSha256":
        context["nonceAuthorityVerifierStateTransitionSha256"],
        "nonceConsumptionReceiptSha256":
        context["nonceConsumptionReceiptSha256"],
        "nonceConsumptionSha256":
        context["nonceConsumptionSha256"],
        "nonceStoreIdentitySha256":
        descriptor.nonce_store_identity_sha256,
        "nonceStoreKeySpkiSha256":
        descriptor.nonce_store_key_spki_sha256,
        "producerEphemeralKeySpkiSha256":
        context["producerEphemeralKeySpkiSha256"],
        "producerInvocationSha256":
        context["producerInvocationSha256"],
        "producerRequestSchemaSha256":
        descriptor.producer_request_schema_sha256,
        "producerRequestSha256": context["producerRequestSha256"],
        "requestBodySha256": context["requestBodySha256"],
        "sandboxDescriptorSha256":
        descriptor.sandbox_descriptor_sha256,
        "sandboxLauncherSha256": descriptor.sandbox_launcher_sha256,
        "tlsBindingSha256": context["tlsBindingSha256"],
        "transactionIdBase64url":
        transition["transactionIdBase64url"],
        "trustRootsSha256": descriptor.trust_roots_sha256,
        "witnessCurrentRequestSha256":
        witness_current_request_sha256,
        "witnessStoreIdentitySha256":
        descriptor.witness_store_identity_sha256,
        "witnessStoreKeySpkiSha256":
        descriptor.witness_store_key_spki_sha256,
    }
    payload = dict(
        _require_exact_fields(
            envelope.get("payload"),
            set(expected_payload),
            "public v3 producer binding payload",
        )
    )
    encoded_public_key = context["producerInvocation"][
        "producerEphemeralKeySpkiDerBase64url"
    ]
    public_key, public_key_id = _load_ed25519_spki_der(
        encoded_public_key,
        label="public v3 producer ephemeral key",
    )
    payload_sha256 = sha256_prefixed(
        canonical_json(payload).encode("ascii")
    )
    if (
        envelope.get("apiVersion")
        != SIGNED_PUBLIC_EVIDENCE_PRODUCER_BINDING_VERSION
        or envelope.get("signatureAlgorithm") != "Ed25519"
        or envelope.get("signingKeySpkiDerBase64url")
        != encoded_public_key
        or envelope.get("signingKeySpkiSha256") != public_key_id
        or public_key_id
        != context["producerEphemeralKeySpkiSha256"]
        or envelope.get("payloadSha256") != payload_sha256
        or payload != expected_payload
        or not context["issuedAtUnix"] <= now
    ):
        raise AttestationContractError(
            "public v3 producer binding crossed its exact request, transition, or release pins"
        )
    try:
        signature = b64d(str(envelope.get("signatureBase64url")))
        if len(signature) != 64:
            raise ValueError("producer binding signature length is invalid")
        public_key.verify(
            signature,
            PUBLIC_EVIDENCE_PRODUCER_BINDING_DOMAIN
            + canonical_json(
                {
                    "payload": payload,
                    "payloadSha256": payload_sha256,
                    "signingKeySpkiSha256": public_key_id,
                }
            ).encode("ascii"),
        )
    except (
        binascii.Error,
        InvalidSignature,
        TypeError,
        UnicodeEncodeError,
        ValueError,
    ) as exc:
        raise AttestationContractError(
            "public v3 producer binding possession signature is invalid"
        ) from exc
    return payload


def _validate_public_evidence_bundle_bytes(
    raw: bytes,
    *,
    context: Mapping[str, Any],
    descriptor: PublicEvidenceProducerDescriptor,
    now: int,
) -> dict[str, Any]:
    if not 1 <= len(raw) <= descriptor.max_output_bytes:
        raise AttestationContractError(
            "public attestation bundle exceeds its producer bound"
        )
    document = _strict_json_document(raw, label="public attestation bundle")
    if raw != canonical_json(document).encode("ascii") + b"\n":
        raise AttestationContractError(
            "public attestation bundle is not canonical JSON plus exactly one LF"
        )
    _validate_public_json_grammar(
        document, label="public attestation bundle"
    )
    envelope = _require_exact_fields(
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
        "public attestation bundle",
    )
    if envelope.get("apiVersion") != PUBLIC_EVIDENCE_BUNDLE_VERSION:
        raise AttestationContractError(
            "public attestation bundle version is invalid"
        )
    bundle = _require_exact_fields(
        envelope.get("bundle"),
        {
            "artifacts",
            "generatedAtUnix",
            "releaseGraph",
            "schemaVersions",
        },
        "public v3 attestation bundle payload",
    )
    bundle_sha256 = sha256_prefixed(
        canonical_json(bundle).encode("ascii")
    )
    if not hmac.compare_digest(
        bundle_sha256,
        _require_digest(
            envelope.get("bundleSha256"),
            "public v3 bundle payload",
        ),
    ):
        raise AttestationContractError(
            "public v3 attestation bundle payload digest is invalid"
        )
    if (
        envelope.get("nonceAuthorityVerifierStateTransition")
        != context["nonceAuthorityVerifierStateTransition"]
        or sha256_prefixed(
            canonical_json(
                envelope["nonceAuthorityVerifierStateTransition"]
            ).encode("ascii")
        )
        != context["nonceAuthorityVerifierStateTransitionSha256"]
    ):
        raise AttestationContractError(
            "public v3 bundle substituted the verified verifier-state transition"
        )
    generated_at = bundle.get("generatedAtUnix")
    if (
        type(generated_at) is not int
        or generated_at < 1
        or generated_at > now
    ):
        raise AttestationContractError(
            "public v3 bundle generation time is invalid"
        )
    documents, raw_documents, digests = _public_v3_artifacts(
        bundle.get("artifacts")
    )
    try:
        from scripts import verify_nitro_tee as public_verifier

        expected_schema_versions = {
            "endpointBundle": PUBLIC_EVIDENCE_BUNDLE_VERSION,
            "liveSessionProof": LIVE_SESSION_PROOF_VERSION,
            "liveWitnessHead": LIVE_WITNESS_HEAD_VERSION,
            "nonceAuthorityVerifierStateTransition":
            NONCE_AUTHORITY_VERIFIER_STATE_TRANSITION_VERSION,
            "protectedLiveWitnessState":
            PROTECTED_LIVE_WITNESS_STATE_VERSION,
            "releaseConfig": PUBLIC_EVIDENCE_CONFIG_VERSION,
            "releaseIdentity": RELEASE_IDENTITY_VERSION,
            "stableReleaseStatement":
            STABLE_RELEASE_STATEMENT_VERSION,
            "trustRoots": public_verifier.TRUST_ROOTS_VERSION,
        }
        if bundle.get("schemaVersions") != expected_schema_versions:
            raise AttestationContractError(
                "public v3 schema-version bridge is invalid"
            )
        public_verifier.require(
            digests["nitro-trust-roots"]
            == descriptor.trust_roots_sha256,
            "public v3 trust roots differ from the independently pinned static roots",
        )
        public_verifier.require(
            raw_documents["release-config"]
            == descriptor.immutable_config_bytes
            and digests["release-config"]
            == descriptor.immutable_config_sha256,
            "public v3 release config differs from the independently pinned static config",
        )
        trust = public_verifier.load_trust_roots(
            documents["nitro-trust-roots"],
            raw_documents["nitro-trust-roots"],
            independently_expected_sha256=digests["nitro-trust-roots"],
        )
        verified_release = public_verifier.verify_stable_release(
            documents["stable-release-statement"],
            trust=trust,
        )
        expected_statement_pins = {
            "descriptorSha256": descriptor.descriptor_sha256,
            "executableSha256": descriptor.executable_sha256,
            "immutableConfigSha256":
            descriptor.immutable_config_sha256,
            "nonceStoreIdentitySha256":
            descriptor.nonce_store_identity_sha256,
            "nonceStoreKeySpkiSha256":
            descriptor.nonce_store_key_spki_sha256,
            "producerRequestSchemaSha256":
            descriptor.producer_request_schema_sha256,
            "sandboxDescriptorSha256":
            descriptor.sandbox_descriptor_sha256,
            "sandboxLauncherSha256":
            descriptor.sandbox_launcher_sha256,
            "trustRootsSha256": descriptor.trust_roots_sha256,
            "witnessStoreIdentitySha256":
            descriptor.witness_store_identity_sha256,
            "witnessStoreKeySpkiSha256":
            descriptor.witness_store_key_spki_sha256,
        }
        remeasured_release_identity = _release_identity_from_descriptor(
            descriptor
        )
        public_verifier.require(
            verified_release["releaseIdentity"]
            == remeasured_release_identity
            and verified_release["releaseIdentitySha256"]
            == public_verifier.sha256_json(
                remeasured_release_identity
            )
            and verified_release["statementSha256"]
            == digests["stable-release-statement"]
            and verified_release["attestationPins"]
            == expected_statement_pins,
            "public v3 stable release statement differs from remeasured release state",
        )
        _validate_public_release_graph(
            bundle.get("releaseGraph"),
            verified_release=verified_release,
            release_config_sha256=digests["release-config"],
            stable_statement_sha256=digests[
                "stable-release-statement"
            ],
            trust_root_bundle_sha256=digests[
                "nitro-trust-roots"
            ],
            public_verifier=public_verifier,
        )
        witness_store_key, witness_store_key_id = (
            _load_ed25519_spki_der(
                descriptor.witness_store_signing_public_key_spki_der_base64url,
                label="public v3 witness-store signing key",
            )
        )
        verified_protected_witness = (
            public_verifier.validate_protected_live_witness_state(
                envelope["protectedLiveWitnessState"],
                expected_release_identity_sha256=(
                    descriptor.release_identity_sha256
                ),
                signing_key=witness_store_key,
                signing_key_id=witness_store_key_id,
                expected_store_identity_sha256=(
                    descriptor.witness_store_identity_sha256
                ),
                expected_witness_signing_key_id=(
                    trust["keyIds"]["witness"]
                ),
                now=now,
                require_current=True,
            )
        )
        _verify_public_evidence_producer_binding(
            envelope["producerBinding"],
            context=context,
            descriptor=descriptor,
            witness_current_request_sha256=(
                verified_protected_witness["invocationBinding"][
                    "currentRequestSha256"
                ]
            ),
            now=now,
        )
        current_witness = public_verifier.verify_live_witness_head(
            envelope["liveWitnessHead"],
            trust=trust,
            expected_release_identity=remeasured_release_identity,
            expected_witness=verified_protected_witness["current"],
            expected_invocation_binding=(
                verified_protected_witness["invocationBinding"]
            ),
            expected_live_witness_payload_sha256=(
                verified_protected_witness["current"][
                    "liveWitnessHeadPayloadSha256"
                ]
            ),
            now=now,
        )
    except AttestationContractError:
        raise
    except (
        ImportError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AttestationContractError(
            "public v3 evidence failed full offline-verifier reconstruction"
        ) from exc
    return {
        "document": document,
        "currentWitness": current_witness,
        "currentWitnessExpiresAtUnix":
        envelope["liveWitnessHead"]["payload"]["expiresAtUnix"],
        "releaseIdentity": remeasured_release_identity,
        "releaseIdentitySha256":
        public_verifier.sha256_json(remeasured_release_identity),
    }


def _public_evidence_http_response(
    *,
    body: bytes,
    live_session_proof: Mapping[str, Any],
    live_session_signature: str,
    delivery_rebind: Mapping[str, Any],
    response_signing_key_id: str,
) -> PublicEvidenceHttpResponse:
    proof_bytes = canonical_json(
        dict(live_session_proof)
    ).encode("ascii")
    delivery_rebind_bytes = canonical_json(
        dict(delivery_rebind)
    ).encode("ascii")
    body_sha256 = sha256_prefixed(body)
    headers = (
        (b"content-type", b"application/json"),
        (b"cache-control", b"no-store"),
        (b"pragma", b"no-cache"),
        (
            b"x-serverware-public-evidence-body-sha256",
            body_sha256.encode("ascii"),
        ),
        (
            b"x-serverware-public-evidence-body-length",
            str(len(body)).encode("ascii"),
        ),
        (
            b"x-serverware-live-session-proof-b64",
            b64e(proof_bytes).encode("ascii"),
        ),
        (
            b"x-serverware-live-session-proof-sha256",
            sha256_prefixed(proof_bytes).encode("ascii"),
        ),
        (
            b"x-serverware-live-session-signature",
            live_session_signature.encode("ascii"),
        ),
        (
            b"x-serverware-live-session-key-id",
            response_signing_key_id.encode("ascii"),
        ),
        (
            b"x-serverware-live-session-delivery-rebind-b64",
            b64e(delivery_rebind_bytes).encode("ascii"),
        ),
        (
            b"x-serverware-live-session-delivery-rebind-sha256",
            sha256_prefixed(delivery_rebind_bytes).encode("ascii"),
        ),
    )
    return PublicEvidenceHttpResponse(
        body=body,
        status_code=200,
        raw_headers=headers,
        body_sha256=body_sha256,
    )


def production_public_evidence_response(
    *,
    raw_request_body: bytes,
    tls_scope: TrustedTlsScope,
    descriptor: PublicEvidenceProducerDescriptor,
) -> PublicEvidenceHttpResponse:
    now = int(time.time())
    terminal_journal = _public_evidence_terminal_journal_runtime(
        now_unix=now
    )
    context, producer_request_bytes = (
        _public_evidence_request_context(
            raw_request_body=raw_request_body,
            tls_scope=tls_scope,
            descriptor=descriptor,
            now=now,
            terminal_journal=terminal_journal,
        )
    )
    response_key = response_public_key_info()
    recovered_terminal = context.get("recoveredTerminalResult")
    if recovered_terminal is not None:
        response_attempted_at = int(time.time())
        if (
            response_attempted_at
            >= context["currentTlsBinding"]["expiresAtUnix"]
        ):
            raise AttestationContractError(
                "current TLS response binding expired before terminal recovery"
            )
        recovered = _public_evidence_terminal_journal_recover_delivery(
            directory=context["terminalJournalDirectory"],
            retained_sealing_key=context["terminalJournalKey"],
            recovery_identity=context["recoveryIdentity"],
            current_tls_binding=context["currentTlsBinding"],
            rebind_issued_at_unix=response_attempted_at,
            response_signing_key_id=response_key["spki_sha256"],
            sign_delivery_rebind=sign_response_statement,
        )
        recovered_proof = dict(recovered["liveSessionProof"])
        recovered_signature = recovered["liveSessionSignature"]
        recovered_rebind = dict(recovered["deliveryRebind"])
        if (
            not isinstance(recovered_signature, str)
            or recovered_proof.get("releaseIdentitySha256")
            != descriptor.release_identity_sha256
            or recovered_proof.get("responseSigningKeyId")
            != response_key["spki_sha256"]
        ):
            raise AttestationContractError(
                "recovered terminal result crossed the pinned release or response key"
            )
        try:
            from scripts import verify_nitro_tee as public_verifier

            public_verifier.verify_live_session_proof(
                recovered_proof,
                signature=recovered_signature,
                response_signing_public_key_pem=response_key["pem"],
                evidence_body=recovered["responseBody"],
                caller_nonce=context["callerNonce"],
                request_body=raw_request_body,
                expected_tls_binding=context["currentTlsBinding"],
                delivery_rebind=recovered_rebind,
                expected_release_identity=recovered_proof[
                    "releaseIdentity"
                ],
                expected_witness=recovered_proof["witness"],
                now=response_attempted_at,
            )
        except AttestationContractError:
            raise
        except (
            ImportError,
            KeyError,
            TypeError,
            ValueError,
        ) as exc:
            raise AttestationContractError(
                "recovered terminal result failed independent verification"
            ) from exc
        return _public_evidence_http_response(
            body=recovered["responseBody"],
            live_session_proof=recovered_proof,
            live_session_signature=recovered_signature,
            delivery_rebind=recovered_rebind,
            response_signing_key_id=response_key["spki_sha256"],
        )
    body = _invoke_public_evidence_producer(
        descriptor,
        producer_request_bytes,
        producer_ephemeral_seed=context[
            "producerEphemeralSeed"
        ],
    )
    verified = _validate_public_evidence_bundle_bytes(
        body,
        context=context,
        descriptor=descriptor,
        now=int(time.time()),
    )
    if (
        response_key.get("spki_sha256")
        != verified["releaseIdentity"]["configuration"][
            "responseKeySpkiSha256"
        ]
    ):
        raise AttestationContractError(
            "live session response key differs from stable release custody"
        )
    produced_at = int(time.time())
    if produced_at >= verified["currentWitnessExpiresAtUnix"]:
        raise AttestationContractError(
            "live witness head expired before proof production"
        )
    if produced_at >= context["currentTlsBinding"]["expiresAtUnix"]:
        raise AttestationContractError(
            "current TLS response binding expired before response production"
        )
    verified_current_witness = verified["currentWitness"]
    live_session_proof = {
        "apiVersion": LIVE_SESSION_PROOF_VERSION,
        "callerNonceSha256": context["callerNonceSha256"],
        "evidenceBodySha256": sha256_prefixed(body),
        "expiresAtUnix": min(
            context["expiresAtUnix"],
            verified["currentWitnessExpiresAtUnix"],
            produced_at + 30,
        ),
        "producedAtUnix": produced_at,
        "releaseIdentity": verified["releaseIdentity"],
        "releaseIdentitySha256":
        verified["releaseIdentitySha256"],
        "request": {
            "bodySha256": context["requestBodySha256"],
            "method": "POST",
            "path": "/attestation/public-evidence",
        },
        "responseSigningKeyId": response_key["spki_sha256"],
        "tlsBinding": context["tlsBinding"],
        "tlsBindingSha256": context["tlsBindingSha256"],
        "witness": dict(verified_current_witness),
    }
    proof_bytes = canonical_json(live_session_proof).encode("ascii")
    proof_signature = sign_response_statement(live_session_proof)
    delivery_rebind_payload = {
        "apiVersion": PUBLIC_ATTESTATION_DELIVERY_REBIND_VERSION,
        "currentTlsBinding": context["currentTlsBinding"],
        "currentTlsBindingSha256":
        context["currentTlsBindingSha256"],
        "rebindIssuedAtUnix": produced_at,
        "expiresAtUnix": min(
            context["currentTlsBinding"]["expiresAtUnix"],
            produced_at + 30,
        ),
        "historicalResult": {
            "evidenceBodySha256": sha256_prefixed(body),
            "liveSessionProofSha256": sha256_prefixed(proof_bytes),
            "liveSessionSignatureSha256": sha256_prefixed(
                proof_signature.encode("ascii")
            ),
        },
        "historicalTlsBindingSha256":
        context["tlsBindingSha256"],
        "recoveryIdentity": context["recoveryIdentity"],
        "recoveryIdentitySha256":
        context["recoveryIdentitySha256"],
        "responseSigningKeyId": response_key["spki_sha256"],
    }
    delivery_rebind_payload["historicalResultSha256"] = (
        sha256_prefixed(
            canonical_json(
                delivery_rebind_payload["historicalResult"]
            ).encode("ascii")
        )
    )
    delivery_rebind_core = {
        "apiVersion":
        SIGNED_PUBLIC_ATTESTATION_DELIVERY_REBIND_VERSION,
        "payload": delivery_rebind_payload,
        "payloadSha256": sha256_prefixed(
            canonical_json(delivery_rebind_payload).encode("ascii")
        ),
        "responseSigningKeyId": response_key["spki_sha256"],
        "signatureAlgorithm": "Ed25519",
    }
    delivery_rebind = {
        **delivery_rebind_core,
        "signature": sign_response_statement(
            delivery_rebind_core
        ),
    }
    try:
        from scripts import verify_nitro_tee as public_verifier

        public_verifier.verify_live_session_proof(
            live_session_proof,
            signature=proof_signature,
            response_signing_public_key_pem=response_key["pem"],
            evidence_body=body,
            caller_nonce=context["callerNonce"],
            request_body=raw_request_body,
            expected_tls_binding=context["currentTlsBinding"],
            delivery_rebind=delivery_rebind,
            expected_release_identity=verified["releaseIdentity"],
            expected_witness=verified_current_witness,
            now=produced_at,
        )
    except (
        ImportError,
        KeyError,
        TypeError,
        ValueError,
    ) as exc:
        raise AttestationContractError(
            "live session proof failed independent verification"
        ) from exc
    _public_evidence_terminal_journal_store(
        directory=context["terminalJournalDirectory"],
        retained_sealing_key=context["terminalJournalKey"],
        recovery_identity=context["recoveryIdentity"],
        historical_tls_binding=context["tlsBinding"],
        response_body=body,
        live_session_proof=live_session_proof,
        live_session_signature=proof_signature,
        terminal_at_unix=produced_at,
        prepared_journal_path=context["preparedJournalPath"],
        maximum_entries=context["terminalJournalMaximumEntries"],
        verify_terminal_authority_evidence=(
            _verify_public_evidence_terminal_authority_evidence
        ),
        terminal_authority_evidence_for=(
            _public_evidence_terminal_authority_evidence
        ),
        now_unix=produced_at,
    )
    return _public_evidence_http_response(
        body=body,
        live_session_proof=live_session_proof,
        live_session_signature=proof_signature,
        delivery_rebind=delivery_rebind,
        response_signing_key_id=response_key["spki_sha256"],
    )


def _run_json_command(command: str, payload: dict[str, Any], label: str) -> dict[str, Any]:
    if not command:
        raise ValueError(f"{label} is not configured")
    helper_env = {
        key: os.environ[key]
        for key in _TEE_HELPER_ENV_NAMES
        if key in os.environ
    }
    with tempfile.TemporaryFile() as helper_stdin, tempfile.TemporaryFile() as helper_stdout:
        helper_stdin.write((canonical_json(payload) + "\n").encode("utf-8"))
        helper_stdin.seek(0)
        process = subprocess.Popen(
            shlex.split(command),
            stdin=helper_stdin,
            stdout=helper_stdout,
            stderr=subprocess.DEVNULL,
            env=helper_env,
            start_new_session=True,
        )
        deadline = time.monotonic() + 10.0
        while process.poll() is None:
            if os.fstat(helper_stdout.fileno()).st_size > 64 * 1024:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise ValueError(f"{label} output exceeds 64 KiB")
            if time.monotonic() >= deadline:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                raise ValueError(f"{label} timed out")
            time.sleep(0.005)
        if process.returncode != 0:
            raise ValueError(f"{label} rejected the request")
        helper_stdout.seek(0)
        raw_output = helper_stdout.read(64 * 1024 + 1)
    if len(raw_output) > 64 * 1024:
        raise ValueError(f"{label} output exceeds 64 KiB")
    try:
        value = json.loads(raw_output.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} returned invalid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must return a JSON object")
    return value


def _load_dev_quote_key() -> Ed25519PrivateKey:
    ensure_data_dirs()
    if TEE_QUOTE_SIGNING_KEY_PATH.exists():
        return serialization.load_pem_private_key(TEE_QUOTE_SIGNING_KEY_PATH.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    TEE_QUOTE_SIGNING_KEY_PATH.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(TEE_QUOTE_SIGNING_KEY_PATH, 0o600)
    return key


def quote_public_key_info() -> dict[str, str]:
    public_key = _load_dev_quote_key().public_key()
    pem = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {"pem": pem, "spki_sha256": sha256_prefixed(der)}


def runtime_manifest() -> dict[str, Any]:
    return {
        "mode": "dev" if TEE_QUOTE_PROVIDER == "dev-signed-quote" else "tee",
        "tee_quote_provider": TEE_QUOTE_PROVIDER,
        "tee_platform": TEE_PLATFORM,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "serverware_version": __version__,
        "policy_signing_key_id": policy_public_key_hash(),
        "policy_high_water_store": db.metadata_store_backend_name(),
        "policy_minimum_sequence": POLICY_MIN_SEQUENCE,
        "policy_minimum_rollback_epoch": POLICY_MIN_ROLLBACK_EPOCH,
        "release_channel": RELEASE_CHANNEL,
        "key_release_required": KEY_RELEASE_REQUIRED,
        "key_release_require_data_plane_digest": KEY_RELEASE_REQUIRE_DATA_PLANE_DIGEST,
        "master_key_source": "memory-unseal-command" if MASTER_KEY_UNSEAL_COMMAND else "development-local",
        "master_key_persisted_in_production": False,
        "master_key_unseal_command_sha256": (
            sha256_prefixed(MASTER_KEY_UNSEAL_COMMAND.encode("utf-8")) if MASTER_KEY_UNSEAL_COMMAND else None
        ),
        "master_key_unseal_command_measurement": _command_artifact_measurements(MASTER_KEY_UNSEAL_COMMAND),
        "nitro_nsm_unseal_command_sha256": (
            sha256_prefixed(NITRO_NSM_UNSEAL_COMMAND_TEMPLATE.encode("utf-8"))
            if NITRO_NSM_UNSEAL_COMMAND_TEMPLATE
            else None
        ),
        "nitro_nsm_unseal_command_measurement": _command_artifact_measurements(
            NITRO_NSM_UNSEAL_COMMAND_TEMPLATE
        ),
        "expected_data_plane_binary_digest": EXPECTED_DATA_PLANE_BINARY_DIGEST,
        "credential_lease_capability": {
            "apiVersion": "serverware.credentialLeaseCapability/v1",
            "controlledDispatch": {
                "request": "serverware.credentialLeaseRequest/v4",
                "requestAuthority": (
                    "serverware.credentialLeaseRequestAuthority/v1"
                ),
                "envelope": "serverware.credentialLeaseEnvelope/v3",
                "set": "serverware.credentialLeaseSet/v4",
                "releaseKinds": [
                    "atomicReservation",
                    "decisionBound",
                    "jitGrant",
                ],
                "decisionBound": True,
            },
            "uncontrolledDispatchCompatibility": {
                "request": "serverware.credentialLeaseRequest/v3",
                "requestAuthority": None,
                "envelope": "serverware.credentialLeaseEnvelope/v2",
                "set": "serverware.credentialLeaseSet/v3",
                "releaseKinds": [],
                "decisionBound": False,
            },
            "legacyCompatibilityScope": "uncontrolledDispatchOnly",
        },
        "credential_lease_transport": "recipient-bound-encrypted-pull",
        "credential_lease_ttl_seconds": SECRET_LEASE_TTL_SECONDS,
        "credential_lease_recipient_attestation_required": DATA_PLANE_LEASE_RECIPIENT_ATTESTATION_REQUIRED,
        "credential_lease_recipient_verifier_command_sha256": (
            sha256_prefixed(DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND.encode("utf-8"))
            if DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND
            else None
        ),
        "credential_lease_recipient_verifier_measurement": _command_artifact_measurements(
            DATA_PLANE_LEASE_RECIPIENT_VERIFY_COMMAND
        ),
        "plaintext_credential_delivery": False,
    }


def runtime_manifest_digest(manifest: dict[str, Any] | None = None) -> str:
    value = runtime_manifest() if manifest is None else manifest
    envelope = {
        "apiVersion": RUNTIME_MANIFEST_DIGEST_VERSION,
        "manifest": value,
    }
    return sha256_prefixed(canonical_json(envelope).encode("ascii"))


def _read_stable_regular_file(
    path: Path,
    *,
    maximum_bytes: int,
    missing_ok: bool = False,
) -> bytes | None:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory is None:
        raise RuntimeError(
            "attestation file admission requires O_NOFOLLOW and O_DIRECTORY"
        )
    path = Path(path)
    parts = path.parts
    if not parts or path.name in {"", ".", ".."}:
        raise ValueError(f"attestation input path is invalid: {path}")
    parent_flags = (
        os.O_RDONLY
        | directory
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    file_flags = (
        os.O_RDONLY
        | nofollow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    parent_descriptor = os.open("/" if path.is_absolute() else ".", parent_flags)
    try:
        parent_parts = parts[1:-1] if path.is_absolute() else parts[:-1]
        for component in parent_parts:
            if component in {"", ".", ".."}:
                raise ValueError(
                    f"attestation input path contains an unsafe component: {path}"
                )
            next_descriptor = os.open(
                component,
                parent_flags,
                dir_fd=parent_descriptor,
            )
            os.close(parent_descriptor)
            parent_descriptor = next_descriptor
        try:
            descriptor = os.open(
                path.name,
                file_flags,
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            if missing_ok:
                return None
            raise
    except FileNotFoundError:
        if missing_ok:
            return None
        raise
    finally:
        os.close(parent_descriptor)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 1
            or before.st_size > maximum_bytes
        ):
            raise ValueError(f"attestation input is not a bounded regular file: {path}")
        raw = bytearray()
        while len(raw) < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        trailing = os.read(descriptor, 1)
        after = os.fstat(descriptor)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        identity_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if (
            len(raw) != before.st_size
            or trailing
            or identity_before != identity_after
        ):
            raise ValueError(f"attestation input changed while being measured: {path}")
        return bytes(raw)
    finally:
        os.close(descriptor)


def _attestation_json_artifact(
    path: Path,
    *,
    digest_field: str,
) -> tuple[dict[str, Any] | None, str | None]:
    raw = _read_stable_regular_file(
        path,
        maximum_bytes=16 * 1024 * 1024,
        missing_ok=True,
    )
    if raw is None:
        return None, None
    try:
        value = strict_json_loads(raw)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return None, None
    if not isinstance(value, dict):
        return None, None
    digest = value.get(digest_field)
    if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
        return None, None
    if digest_field == "provenance_digest":
        payload = value.get("provenance")
    elif digest_field == "image_signature_bundle_digest":
        payload = copy.deepcopy(value)
        payload.pop("image_signature_bundle_digest", None)
        payload.pop("bundle_signature", None)
        metadata = payload.get("metadata")
        if isinstance(metadata, dict):
            metadata.pop("signature", None)
            metadata.pop("transparency", None)
            metadata.pop("bundleSigstore", None)
    else:
        return None, None
    if not isinstance(payload, dict) or digest != sha256_prefixed(
        canonical_json(payload).encode("utf-8")
    ):
        return None, None
    return value, digest


def attestation_artifact_digests() -> dict[str, str | None]:
    provenance, provenance_digest = _attestation_json_artifact(
        RELEASE_PROVENANCE_PATH,
        digest_field="provenance_digest",
    )
    signature_bundle, signature_digest = _attestation_json_artifact(
        IMAGE_SIGNATURES_PATH,
        digest_field="image_signature_bundle_digest",
    )
    source_tree = ((provenance or {}).get("provenance") or {}).get("source_tree") or {}
    source_digest = source_tree.get("digest") if isinstance(source_tree, dict) else None
    if not isinstance(source_digest, str) or _SHA256_RE.fullmatch(source_digest) is None:
        source_digest = None
    signature_metadata = (
        signature_bundle.get("metadata")
        if isinstance(signature_bundle, dict)
        and isinstance(signature_bundle.get("metadata"), dict)
        else None
    )
    if signature_bundle is not None and (
        signature_metadata is None
        or signature_metadata.get("provenanceDigest") != provenance_digest
        or signature_metadata.get("sourceTreeDigest") != source_digest
    ):
        return {
            "provenance_digest": None,
            "image_signatures_digest": None,
            "source_tree_digest": None,
        }
    return {
        "provenance_digest": provenance_digest,
        "image_signatures_digest": signature_digest,
        "source_tree_digest": source_digest,
    }


def ca_spki_hash() -> str | None:
    ca_path = MITMPROXY_CONF_DIR / "mitmproxy-ca-cert.pem"
    raw = _read_stable_regular_file(
        ca_path,
        maximum_bytes=1024 * 1024,
        missing_ok=True,
    )
    if raw is None:
        return None
    cert = x509.load_pem_x509_certificate(raw)
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_prefixed(der)


def service_tls_spki_hash() -> str | None:
    if not WEB_TLS_CERT_FILE:
        return None
    cert_path = Path(WEB_TLS_CERT_FILE)
    raw = _read_stable_regular_file(cert_path, maximum_bytes=1024 * 1024)
    if raw is None:
        raise ValueError("configured service TLS certificate is unavailable")
    cert = x509.load_pem_x509_certificate(raw)
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256_prefixed(der)


def _command_artifact_measurements(command: str) -> dict[str, Any] | None:
    if not command:
        return None
    artifacts: list[dict[str, Any]] = []
    seen: set[Path] = set()
    for value in shlex.split(command):
        candidate = Path(value)
        if not candidate.is_file() and len(candidate.parts) == 1:
            resolved = shutil.which(value)
            candidate = Path(resolved) if resolved else candidate
        if not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        raw = _read_stable_regular_file(resolved, maximum_bytes=256 * 1024 * 1024)
        if raw is None:
            raise ValueError(f"measured command artifact is unavailable: {resolved}")
        artifacts.append(
            {"path": str(resolved), "sha256": sha256_prefixed(raw), "size_bytes": len(raw)}
        )
    return {
        "command_sha256": sha256_prefixed(command.encode("utf-8")),
        "artifacts": artifacts,
    }


def release_provenance_digest() -> str | None:
    return attestation_artifact_digests()["provenance_digest"]


def image_signatures_digest() -> str | None:
    return attestation_artifact_digests()["image_signatures_digest"]


def release_provenance_document() -> dict[str, Any] | None:
    value, _ = _attestation_json_artifact(
        RELEASE_PROVENANCE_PATH,
        digest_field="provenance_digest",
    )
    return value


def image_signatures_document() -> dict[str, Any] | None:
    value, _ = _attestation_json_artifact(
        IMAGE_SIGNATURES_PATH,
        digest_field="image_signature_bundle_digest",
    )
    return value


def source_tree_digest() -> str | None:
    return attestation_artifact_digests()["source_tree_digest"]


def _unsigned_quote(payload: dict[str, Any]) -> dict[str, Any]:
    copied = json.loads(json.dumps(payload))
    copied.pop("signature", None)
    return copied


def sign_quote(
    claims: dict[str, Any], *, production_state: dict[str, Any] | None = None
) -> dict[str, Any]:
    if TEE_QUOTE_PROVIDER != "dev-signed-quote":
        if (
            TEE_QUOTE_PROVIDER not in {"aws-nitro-enclaves", "aws-nitro-nsm"}
            or TEE_PLATFORM != "aws-nitro"
        ):
            raise AttestationContractError(
                "production attestation requires the AWS Nitro NSM provider"
            )
        if production_state is None:
            raise AttestationContractError(
                "production quote generation requires remeasured workload state"
            )
        challenge = _require_exact_fields(
            claims.get("challenge"),
            {
                "challengeId",
                "connectionId",
                "expiresAtUnix",
                "issuedAtUnix",
                "peerSpkiSha256",
                "value",
                "valueSha256",
            },
            "production quote challenge",
        )
        binding = {
            "challenge": dict(challenge),
            "requestSha256": _require_digest(
                claims.get("requestSha256"), "attestation request"
            ),
            "tlsBinding": dict(
                _require_exact_fields(
                    claims.get("tlsBinding"),
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
                    "production TLS binding",
                )
            ),
        }
        expected_remeasurements = {
            "keyCustodySha256": production_state["digests"]["keyCustody"],
            "productionIdentitySha256": production_state["digests"][
                "productionIdentity"
            ],
            "promotedManifestSha256": production_state["digests"][
                "promotedManifest"
            ],
            "runtimeStateSha256": production_state["digests"]["runtimeState"],
        }
        request_without_digest = {
            "apiVersion": "serverware.nitroAttestationRequest/v2",
            "binding": binding,
            "expectedRemeasurements": expected_remeasurements,
            "kind": "ProductionWorkloadRemeasurement",
            "provider": "aws-nitro-enclaves",
            "tee_platform": "aws-nitro",
        }
        request = {
            **request_without_digest,
            "request_digest": sha256_prefixed(
                canonical_json(request_without_digest).encode("ascii")
            ),
        }
        quote = _run_json_command(TEE_QUOTE_COMMAND, request, "TEE quote command")
        if set(quote) != {
            "attestation_document_b64",
            "attestation_document_sha256",
            "claims",
            "debug",
            "document_claims",
            "provider",
            "request_digest",
            "tee_platform",
            "user_data_sha256",
            "version",
        }:
            raise AttestationContractError(
                "TEE quote command returned fields outside the production contract"
            )
        if (
            "ok" in quote
            or quote.get("version") != 2
            or quote.get("provider") != "aws-nitro-nsm"
            or quote.get("tee_platform") != "aws-nitro"
            or quote.get("debug") is not False
            or quote.get("request_digest") != request["request_digest"]
        ):
            raise AttestationContractError(
                "TEE quote command did not return production Nitro evidence"
            )
        quote_claims = quote.get("claims")
        if not isinstance(quote_claims, dict) or not hmac.compare_digest(
            canonical_json(quote_claims), canonical_json(claims)
        ):
            raise AttestationContractError(
                "TEE quote claims do not match workload remeasurement"
            )
        expected_user_data = NITRO_USER_DATA_PREFIX + hashlib.sha256(
            canonical_json(claims).encode("ascii")
        ).hexdigest().encode("ascii")
        if quote.get("user_data_sha256") != sha256_prefixed(expected_user_data):
            raise AttestationContractError(
                "TEE quote user_data does not bind the remeasured claims"
            )
        raw_document = quote.get("attestation_document_b64")
        if not isinstance(raw_document, str):
            raise AttestationContractError(
                "TEE quote command omitted the raw Nitro document"
            )
        try:
            raw_quote = b64d(raw_document)
        except Exception as exc:
            raise AttestationContractError(
                "TEE quote command returned invalid Nitro document encoding"
            ) from exc
        if (
            not raw_quote
            or len(raw_quote) > 1024 * 1024
            or b64e(raw_quote) != raw_document
            or quote.get("attestation_document_sha256")
            != sha256_prefixed(raw_quote)
        ):
            raise AttestationContractError(
                "TEE quote command returned an invalid Nitro document"
            )
        parsed_document = _parse_nitro_attestation_document(raw_quote)
        expected_pcrs = production_state["identity"]["pcrs"]
        expected_nonce = b64d(str(challenge["value"]))
        expected_document_claims = {
            "debug": False,
            "nonceSha256": sha256_prefixed(expected_nonce),
            "payloadSha256": parsed_document["payloadSha256"],
            "pcrs": expected_pcrs,
            "timestamp": parsed_document["timestamp"],
            "userDataSha256": sha256_prefixed(expected_user_data),
        }
        if (
            parsed_document["nonce"] != expected_nonce
            or parsed_document["userData"] != expected_user_data
            or parsed_document["pcrs"] != expected_pcrs
            or parsed_document["debug"] is not False
            or quote.get("document_claims") != expected_document_claims
            or quote.get("debug") is not parsed_document["debug"]
        ):
            raise AttestationContractError(
                "raw Nitro COSE payload does not match the requested production evidence"
            )
        return quote
    key = _load_dev_quote_key()
    key_info = quote_public_key_info()
    quote = {
        "version": 1,
        "provider": "dev-signed-quote",
        "tee_platform": "none-dev",
        "issued_at_ms": int(time.time() * 1000),
        "debug": True,
        "quote_signing_key_id": key_info["spki_sha256"],
        "quote_signing_public_key_pem": key_info["pem"],
        "claims": claims,
    }
    quote["signature"] = "ed25519:" + b64e(key.sign(canonical_json(_unsigned_quote(quote)).encode("utf-8")))
    return quote


def verify_quote_signature(quote: dict[str, Any]) -> None:
    if quote.get("provider") != "dev-signed-quote":
        if not TEE_QUOTE_VERIFY_COMMAND:
            raise ValueError("external TEE quote verification command is not configured")
        return
    signature = quote.get("signature")
    public_key_pem = quote.get("quote_signing_public_key_pem")
    if not isinstance(signature, str) or not signature.startswith("ed25519:"):
        raise ValueError("quote is missing an ed25519 signature")
    if not isinstance(public_key_pem, str):
        raise ValueError("quote is missing public key")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("ascii"))
    try:
        public_key.verify(b64d(signature.split(":", 1)[1]), canonical_json(_unsigned_quote(quote)).encode("utf-8"))
    except InvalidSignature as exc:
        raise ValueError("quote signature verification failed") from exc
    key_info_der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if quote.get("quote_signing_key_id") != sha256_prefixed(key_info_der):
        raise ValueError("quote signing key id does not match public key")


def verify_attestation_quote(attestation: dict[str, Any]) -> dict[str, Any]:
    quote = attestation.get("quote")
    if not isinstance(quote, dict):
        raise ValueError("attestation quote is missing")
    if quote.get("provider") == "dev-signed-quote":
        verify_quote_signature(quote)
        claims = quote.get("claims")
    else:
        verified = _run_json_command(
            TEE_QUOTE_VERIFY_COMMAND,
            {"attestation": attestation},
            "TEE quote verification command",
        )
        claims = verified.get("claims", verified)
    if not isinstance(claims, dict):
        raise ValueError("attestation quote claims are missing")
    return claims


def _production_request_digest(
    *,
    method: str,
    path: str,
    raw_query: str,
    challenge: AttestationChallenge,
    tls_scope: TrustedTlsScope,
) -> str:
    request = {
        "apiVersion": "serverware.attestationRequestBinding/v1",
        "challengeId": challenge.challenge_id,
        "challengeSha256": challenge.value_sha256,
        "method": method.upper(),
        "path": path,
        "querySha256": sha256_prefixed(raw_query.encode("utf-8")),
        "tlsBindingSha256": tls_scope.binding_document()["bindingSha256"],
    }
    return sha256_prefixed(canonical_json(request).encode("ascii"))


def _material_by_name(custody: Mapping[str, Any], name: str) -> Mapping[str, Any]:
    materials = custody.get("materials")
    if not isinstance(materials, list):
        raise AttestationContractError("key-custody material inventory is missing")
    for value in materials:
        if isinstance(value, Mapping) and value.get("name") == name:
            return value
    raise AttestationContractError(f"{name} custody material is missing")


def _production_claims(
    *,
    challenge: AttestationChallenge,
    tls_scope: TrustedTlsScope,
    request_sha256: str,
    state: dict[str, Any],
    response_key_info: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    runtime = state["runtime"]
    identity = state["identity"]
    custody = state["custody"]
    tls_material = _material_by_name(custody, "tls")
    tls_scope_material = tls_material.get("scopeSigningKey")
    if not isinstance(tls_scope_material, Mapping):
        raise AttestationContractError(
            "TLS scope-signing custody evidence is missing"
        )
    response_material = _material_by_name(custody, "response")
    ca_material = _material_by_name(custody, "ca")
    release_material = _material_by_name(custody, "release")
    credential_material = _material_by_name(custody, "credentials")
    broker_material = _material_by_name(custody, "broker-kek")
    generations = _validate_key_generations(runtime["keyGenerations"])
    tls_binding = tls_scope.binding_document()
    if not hmac.compare_digest(
        challenge.tls_binding_sha256, tls_binding["bindingSha256"]
    ):
        raise AttestationContractError(
            "attestation challenge crossed its enclave TLS channel"
        )
    response_key = (
        dict(response_key_info)
        if response_key_info is not None
        else response_public_key_info()
    )
    response_key_id = _require_digest(
        response_key.get("spki_sha256"), "response signing key"
    )
    if not isinstance(response_key.get("pem"), str) or not response_key["pem"]:
        raise AttestationContractError(
            "response signing public key is unavailable"
        )
    binding_checks = (
        (
            tls_scope.leaf_spki_sha256,
            tls_material["identitySpkiSha256"],
            "TLS leaf SPKI",
        ),
        (
            tls_scope.tls_key_generation,
            generations["tls"],
            "TLS key generation",
        ),
        (
            tls_scope.tls_scope_key_generation,
            generations["tlsScope"],
            "TLS scope key generation",
        ),
        (
            tls_scope.tls_scope_key_generation,
            tls_scope_material.get("keyGeneration"),
            "TLS scope custody generation",
        ),
        (
            tls_scope.tls_scope_key_spki_sha256,
            tls_scope_material.get("publicKeySpkiSha256"),
            "TLS scope signing key",
        ),
        (
            tls_scope.envelope_sha256,
            runtime["activeTlsConnection"]["envelopeSha256"],
            "TLS scope envelope",
        ),
        (
            runtime["caSpkiSha256"],
            ca_material["identitySpkiSha256"],
            "CA SPKI",
        ),
        (
            response_key_id,
            response_material["identitySpkiSha256"],
            "response signing key",
        ),
        (
            generations["brokerKek"],
            broker_material["keyGeneration"],
            "broker KEK generation",
        ),
        (
            generations["credentialRelease"],
            credential_material["keyGeneration"],
            "credential release generation",
        ),
        (generations["ca"], ca_material["keyGeneration"], "CA key generation"),
        (
            generations["tls"],
            tls_material["keyGeneration"],
            "TLS custody generation",
        ),
        (
            generations["response"],
            response_material["keyGeneration"],
            "response key generation",
        ),
        (
            generations["release"],
            release_material["keyGeneration"],
            "release key generation",
        ),
        (
            tls_scope.enclave_instance_id,
            runtime["enclaveInstanceId"],
            "enclave instance",
        ),
        (tls_scope.enclave_boot_id, runtime["enclaveBootId"], "enclave boot"),
    )
    for actual, expected, label in binding_checks:
        if actual != expected:
            raise AttestationContractError(
                f"{label} does not match remeasured production state"
            )
    snapshot = get_policy_snapshot()
    metadata = snapshot.raw.get("metadata") if snapshot else None
    if (
        snapshot is None
        or not isinstance(metadata, Mapping)
        or snapshot.hash != runtime["policyHash"]
        or metadata.get("sequence") != runtime["policySequence"]
        or metadata.get("rollbackEpoch") != runtime["rollbackEpoch"]
    ):
        raise AttestationContractError(
            "active policy does not match remeasured production runtime state"
        )
    high_water = db.get_policy_high_water()
    if not high_water or (
        high_water.get("policy_hash") != runtime["policyHash"]
        or high_water.get("sequence") != runtime["policySequence"]
        or high_water.get("rollback_epoch") != runtime["rollbackEpoch"]
    ):
        raise AttestationContractError(
            "policy high-water does not match remeasured production state"
        )
    completion_identity = identity["completionIdentity"]
    if (
        completion_identity["challengeNonceSha256"]
        != challenge.value_sha256
        or completion_identity["releaseGeneration"]
        != runtime["releaseGeneration"]
        or completion_identity["rollbackEpoch"] != runtime["rollbackEpoch"]
    ):
        raise AttestationContractError(
            "completion identity crossed the live challenge or remeasured release coordinates"
        )
    return {
        "apiVersion": PRODUCTION_ATTESTATION_CLAIMS_VERSION,
        "candidate": {
            "builderStatementSha256s": identity["builderStatementSha256s"],
            "buildWatchdogReceiptSha256": identity[
                "buildWatchdogReceiptSha256"
            ],
            "candidateManifestFileSha256": identity[
                "candidateManifestFileSha256"
            ],
            "candidateManifestPayloadSha256": identity[
                "candidateManifestPayloadSha256"
            ],
            "dependencyClosureSha256": identity["dependencyClosureSha256"],
            "importedImageMappingsSha256": identity[
                "importedImageMappingsSha256"
            ],
            "promotionReceiptSha256": identity["promotionReceiptSha256"],
            "sourceClosureSha256": identity["sourceClosureSha256"],
            "sourceInputApprovalSha256": identity[
                "sourceInputApprovalSha256"
            ],
            "sourceInputManifestFileSha256": identity[
                "sourceInputManifestFileSha256"
            ],
            "sourceInputManifestPayloadSha256": identity[
                "sourceInputManifestPayloadSha256"
            ],
        },
        "challenge": {
            "challengeId": challenge.challenge_id,
            "connectionId": challenge.connection_id,
            "expiresAtUnix": challenge.expires_at_unix,
            "issuedAtUnix": challenge.issued_at_unix,
            "peerSpkiSha256": challenge.peer_spki_sha256,
            "value": challenge.value,
            "valueSha256": challenge.value_sha256,
        },
        "completion": {
            "completionIdentity": identity["completionIdentity"],
            "completionIdentitySha256": identity["completionIdentitySha256"],
            "keyCustodyEvidenceSha256": state["digests"]["keyCustody"],
            "monotonicWitnessSha256": identity["monotonicWitnessSha256"],
            "productionContinuitySha256": identity[
                "productionContinuitySha256"
            ],
            "productionReleaseIdentitySha256": identity[
                "productionReleaseIdentitySha256"
            ],
        },
        "eif": {
            "imageSha384": identity["eifImageSha384"],
            "pcrs": identity["pcrs"],
        },
        "keyCustodySha256": state["digests"]["keyCustody"],
        "keyGenerations": generations,
        "pipeline": PRODUCTION_PIPELINE,
        "policy": {
            "hash": runtime["policyHash"],
            "rollbackEpoch": runtime["rollbackEpoch"],
            "sequence": runtime["policySequence"],
        },
        "productionIdentitySha256": state["digests"]["productionIdentity"],
        "promotedManifestSha256": state["digests"]["promotedManifest"],
        "release": {
            "caSpkiSha256": runtime["caSpkiSha256"],
            "generation": runtime["releaseGeneration"],
            "responseKeySpkiSha256": response_material["identitySpkiSha256"],
            "releaseKeySpkiSha256": release_material["identitySpkiSha256"],
        },
        "requestSha256": request_sha256,
        "runtimeStateSha256": state["digests"]["runtimeState"],
        "tlsBinding": tls_binding,
    }


def production_attestation_response(
    *,
    challenge: AttestationChallenge,
    tls_scope: TrustedTlsScope,
    method: str,
    path: str,
    raw_query: str,
    production_state: dict[str, Any],
) -> ProductionAttestationHttpResponse:
    if not _production_release():
        raise AttestationContractError(
            "the production attestation bridge requires a production release channel"
        )
    if TEE_QUOTE_PROVIDER == "dev-signed-quote":
        raise AttestationContractError(
            "development quotes are forbidden by the production attestation bridge"
        )
    state = production_state
    if not isinstance(state, dict):
        raise AttestationContractError(
            "production response requires remeasured workload state"
        )
    response_key = response_public_key_info()
    request_sha256 = _production_request_digest(
        method=method,
        path=path,
        raw_query=raw_query,
        challenge=challenge,
        tls_scope=tls_scope,
    )
    claims = _production_claims(
        challenge=challenge,
        tls_scope=tls_scope,
        request_sha256=request_sha256,
        state=state,
        response_key_info=response_key,
    )
    quote = sign_quote(claims, production_state=state)
    document = {
        "apiVersion": PRODUCTION_ATTESTATION_API_VERSION,
        "assurance": {
            "class": "production-nitro-evidence",
            "completionEligible": False,
            "externalVerificationRequired": True,
            "hostTlsAccepted": False,
            "reason": (
                "The server remeasured production state and obtained a Nitro document "
                "through an enclave TLS scope. A remote verifier must still validate "
                "the AWS chain, PCRs, release evidence, witness, and revocation state."
            ),
        },
        "claims": claims,
        "quote": quote,
        "responseSigningPublicKeyPem": response_key["pem"],
    }
    body = canonical_json(document).encode("ascii")
    tls_binding = tls_scope.binding_document()
    quote_sha256 = sha256_prefixed(
        canonical_json(quote).encode("ascii")
    )
    body_sha256 = sha256_prefixed(body)
    core_headers = (
        ("cache-control", "no-store"),
        ("pragma", "no-cache"),
        ("content-type", "application/json"),
        ("content-length", str(len(body))),
        ("x-serverware-attestation-body-sha256", body_sha256),
        (
            "x-serverware-attestation-key-id",
            str(response_key["spki_sha256"]),
        ),
        ("x-serverware-attestation-request-sha256", request_sha256),
        (
            "x-serverware-attestation-tls-binding-sha256",
            str(tls_binding["bindingSha256"]),
        ),
        ("x-serverware-attestation-quote-sha256", quote_sha256),
    )
    statement = {
        "apiVersion": ATTESTATION_RESPONSE_STATEMENT_VERSION,
        "bodySha256": body_sha256,
        "challengeId": challenge.challenge_id,
        "challengeSha256": challenge.value_sha256,
        "issuedAtUnix": int(time.time()),
        "keyGenerations": claims["keyGenerations"],
        "policy": claims["policy"],
        "httpResponse": {
            "apiVersion": "serverware.attestationHttpResponse/v1",
            "bodyLength": len(body),
            "bodySha256": body_sha256,
            "coreHeaders": [
                {"name": name, "value": value}
                for name, value in core_headers
            ],
            "detachedProofHeaders": {
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
            "ordinaryHostTlsAccepted": False,
            "status": 200,
            "transport": (
                "enclave-owned-tls-stack-with-authenticated-asgi-extension"
            ),
        },
        "quoteSha256": quote_sha256,
        "release": claims["release"],
        "requestSha256": request_sha256,
        "responseSigningKeyId": response_key["spki_sha256"],
        "tlsBindingSha256": tls_binding["bindingSha256"],
    }
    response_core = _completion_core(
        "response",
        {
            "challengeId": statement["challengeId"],
            "challengeSha256": statement["challengeSha256"],
            "exporterSha256": tls_binding["exporterSha256"],
            "httpStatus": 200,
            "issuedAtUnix": statement["issuedAtUnix"],
            "keyGenerations": statement["keyGenerations"],
            "leafSpkiSha256": tls_binding["leafSpkiSha256"],
            "peerSpkiSha256": tls_binding["peerSpkiSha256"],
            "policy": statement["policy"],
            "release": statement["release"],
            "requestSha256": request_sha256,
            "responseSigningKeyId": response_key["spki_sha256"],
            "tlsBindingSha256": tls_binding["bindingSha256"],
        },
    )
    response_core_sha256 = sha256_prefixed(
        canonical_json(response_core).encode("ascii")
    )
    if (
        state["identity"]["completionIdentity"]["coreDigests"]["response"]
        != response_core_sha256
    ):
        raise AttestationContractError(
            "completion identity response core does not match the live enclave TLS response"
        )
    signature = sign_response_statement(statement)
    statement_bytes = canonical_json(statement).encode("ascii")
    proof_headers = (
        (
            "x-serverware-attestation-statement-b64",
            b64e(statement_bytes),
        ),
        (
            "x-serverware-attestation-statement-sha256",
            sha256_prefixed(statement_bytes),
        ),
        ("x-serverware-attestation-signature", signature),
    )
    raw_headers = tuple(
        (name.encode("ascii"), value.encode("ascii"))
        for name, value in (*core_headers, *proof_headers)
    )
    return ProductionAttestationHttpResponse(
        body=body,
        status_code=200,
        raw_headers=raw_headers,
        statement=statement,
        signature=signature,
    )


def attestation_document(nonce: str | None = None) -> dict[str, Any]:
    if _production_release():
        raise AttestationContractError(
            "production attestation requires a one-use challenge and enclave TLS scope"
        )
    snapshot = get_policy_snapshot()
    metadata = snapshot.raw.get("metadata") if snapshot else {}
    manifest = runtime_manifest()
    policy_hash = snapshot.hash if snapshot else None
    rollback_epoch = metadata.get("rollbackEpoch") if isinstance(metadata, dict) else None
    policy_sequence = metadata.get("sequence") if isinstance(metadata, dict) else None
    high_water = db.get_policy_high_water() if snapshot else None
    if snapshot:
        expected_high_water = {
            "policy_id": metadata.get("id"),
            "sequence": policy_sequence,
            "rollback_epoch": rollback_epoch,
            "policy_hash": policy_hash,
        }
        if not high_water or any(high_water.get(key) != value for key, value in expected_high_water.items()):
            raise ValueError("active policy does not match the persisted policy high-water record")
    high_water_evidence = (
        {
            "store": db.metadata_store_backend_name(),
            "policyId": high_water["policy_id"],
            "sequence": high_water["sequence"],
            "rollbackEpoch": high_water["rollback_epoch"],
            "policyHash": high_water["policy_hash"],
            "updatedAt": high_water["updated_at"],
        }
        if high_water
        else None
    )
    high_water_digest = (
        sha256_prefixed(canonical_json(high_water_evidence).encode("utf-8"))
        if high_water_evidence
        else None
    )
    ca_hash = ca_spki_hash()
    artifact_digests = attestation_artifact_digests()
    service_tls_spki = service_tls_spki_hash()
    response_key_info = response_public_key_info()
    data_plane_digest = EXPECTED_DATA_PLANE_BINARY_DIGEST
    quote_claims = {
        "nonce": nonce,
        "runtime_manifest_digest": runtime_manifest_digest(manifest),
        "policy_bundle_digest": policy_hash,
        "policy_sequence": policy_sequence,
        "policy_high_water_digest": high_water_digest,
        "policy_signing_key_id": metadata.get("signingKeyId") if isinstance(metadata, dict) else None,
        "ca_intermediate_spki_sha256": ca_hash,
        "data_plane_binary_digest": data_plane_digest,
        "service_tls_spki_sha256": service_tls_spki,
        "rollback_epoch": rollback_epoch,
        **artifact_digests,
        "response_signing_key_id": response_key_info["spki_sha256"],
        "release_channel": RELEASE_CHANNEL,
        "debug": TEE_QUOTE_PROVIDER == "dev-signed-quote",
        "key_release_required": KEY_RELEASE_REQUIRED,
        "key_release_allow_debug": KEY_RELEASE_ALLOW_DEBUG,
        "materials": ["broker-kek", "decision-gate-ca"],
        "sealing_public_key_id": quote_public_key_info()["spki_sha256"],
    }
    quote = sign_quote(quote_claims)
    assurance = {
        "class": "development-consistency" if quote_claims["debug"] else "host-supplied-quote",
        "hardware_proof": False,
        "workload_custody_proven": False,
        "tls_peer_binding_proven": False,
        "fact_origin": "host-supplied",
        "completion_eligible": False,
        "reason": (
            "The current document correlates signed runtime facts but does not prove that "
            "policy enforcement, credential custody, and response generation ran inside one measured TEE."
        ),
    }
    return {
        "tee_platform": quote.get("tee_platform", TEE_PLATFORM),
        "quote": quote,
        "runtime_manifest": manifest,
        "runtime_manifest_digest": quote_claims["runtime_manifest_digest"],
        "policy_bundle_digest": policy_hash,
        "policy_sequence": policy_sequence,
        "policy_high_water": high_water_evidence,
        "policy_high_water_digest": high_water_digest,
        "policy_bundle_signature": metadata.get("signature") if isinstance(metadata, dict) else None,
        "policy_signing_key_id": metadata.get("signingKeyId") if isinstance(metadata, dict) else None,
        "policy_signing_public_key_pem": policy_public_key_pem(),
        "ca_intermediate_spki_sha256": ca_hash,
        "data_plane_binary_digest": data_plane_digest,
        "service_tls_spki_sha256": service_tls_spki,
        "rollback_epoch": rollback_epoch,
        **artifact_digests,
        "response_signing_key_id": response_key_info["spki_sha256"],
        "response_signing_public_key_pem": response_key_info["pem"],
        "release_channel": RELEASE_CHANNEL,
        "nonce": nonce,
        "tls_exporter_binding": None,
        "assurance": assurance,
    }
